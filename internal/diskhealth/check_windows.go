//go:build windows

package diskhealth

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Check reads the drive list and Windows' disk error log. Neither needs
// administrator rights, and neither touches the drives themselves.
func Check() *Report {
	r := &Report{}
	if err := readDisks(r); err != nil {
		r.Err = "couldn't list the drives: " + err.Error()
	}
	events, err := readEvents()
	if err != nil {
		if r.Err != "" {
			r.Err += "; "
		}
		r.Err += "couldn't read the disk error log: " + err.Error()
	}
	attribute(r, events)
	return r
}

func run(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(errb.String()); msg != "" {
			return nil, fmt.Errorf("%s", msg)
		}
		return nil, err
	}
	return out.Bytes(), nil
}

const diskScript = `@{disks=@(Get-PhysicalDisk | Select-Object DeviceId,FriendlyName,MediaType,BusType,HealthStatus);` +
	`parts=@(Get-Partition | Where-Object DriveLetter | Select-Object DiskNumber,DriveLetter)} | ConvertTo-Json -Depth 3 -Compress`

func readDisks(r *Report) error {
	out, err := run("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", diskScript)
	if err != nil {
		return err
	}
	var doc struct {
		Disks []struct {
			DeviceID     string `json:"DeviceId"`
			FriendlyName string
			MediaType    any
			BusType      any
			HealthStatus any
		}
		Parts []struct {
			DiskNumber  int
			DriveLetter any
		}
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return err
	}
	for _, d := range doc.Disks {
		n, err := strconv.Atoi(d.DeviceID)
		if err != nil {
			continue
		}
		disk := Disk{Number: n, Model: strings.TrimSpace(d.FriendlyName), Bus: enumText(d.BusType, busNames),
			Media: enumText(d.MediaType, mediaNames), Health: enumText(d.HealthStatus, healthNames)}
		for _, p := range doc.Parts {
			if p.DiskNumber == n {
				if l := letterText(p.DriveLetter); l != "" {
					disk.Letters = append(disk.Letters, l+":")
				}
			}
		}
		r.Disks = append(r.Disks, disk)
	}
	return nil
}

// Depending on the PowerShell version, enums arrive as names or numbers.
var (
	busNames    = map[int]string{1: "SCSI", 3: "ATA", 7: "USB", 8: "RAID", 9: "iSCSI", 10: "SAS", 11: "SATA", 12: "SD", 13: "MMC", 15: "File-backed", 16: "Spaces", 17: "NVMe"}
	mediaNames  = map[int]string{0: "Unspecified", 3: "HDD", 4: "SSD", 5: "SCM"}
	healthNames = map[int]string{0: "Healthy", 1: "Warning", 2: "Unhealthy", 5: "Unknown"}
)

func enumText(v any, names map[int]string) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		if s, ok := names[int(x)]; ok {
			return s
		}
		return strconv.Itoa(int(x))
	}
	return ""
}

func letterText(v any) string {
	switch x := v.(type) {
	case string:
		return strings.ToUpper(strings.TrimSpace(x))
	case float64: // a [char] can arrive as its code
		if x >= 'A' && x <= 'z' {
			return strings.ToUpper(string(rune(int(x))))
		}
	}
	return ""
}

func readEvents() ([]rawEvent, error) {
	var ids []string
	for id := range eventWhat {
		ids = append(ids, "EventID="+strconv.Itoa(id))
	}
	q := fmt.Sprintf("*[System[(%s) and TimeCreated[timediff(@SystemTime) <= %d]]]", strings.Join(ids, " or "), int64(Days)*24*3600*1000)
	out, err := run("wevtutil.exe", "qe", "System", "/q:"+q, "/f:xml", "/c:2000", "/rd:true")
	if err != nil {
		return nil, err
	}
	return parseEvents(out)
}

// parseEvents reads wevtutil's XML, which is a list of <Event> elements
// without a root element.
func parseEvents(out []byte) ([]rawEvent, error) {
	var doc struct {
		Events []struct {
			System struct {
				Provider struct {
					Name string `xml:"Name,attr"`
				}
				EventID     int `xml:"EventID"`
				Level       int `xml:"Level"`
				TimeCreated struct {
					SystemTime string `xml:"SystemTime,attr"`
				}
			}
			Data []string `xml:"EventData>Data"`
		} `xml:"Event"`
	}
	wrapped := append(append([]byte("<Events>"), out...), []byte("</Events>")...)
	if err := xml.Unmarshal(wrapped, &doc); err != nil {
		return nil, err
	}
	var events []rawEvent
	for _, e := range doc.Events {
		t, _ := time.Parse(time.RFC3339Nano, e.System.TimeCreated.SystemTime)
		events = append(events, rawEvent{id: e.System.EventID, provider: e.System.Provider.Name, level: e.System.Level, time: t.Local(), data: e.Data})
	}
	return events, nil
}
