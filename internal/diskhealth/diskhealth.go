// Package diskhealth checks the drives before pcaudit reads them. A drive
// with bad blocks can crash Windows when it's read heavily (that's how this
// package came to exist), so pcaudit looks at Windows' own disk error log
// and the drive health status first, and slows down when anything is wrong.
package diskhealth

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Days is how far back the error log is read.
const Days = 30

// Disk is one physical drive.
type Disk struct {
	Number  int      `json:"number"`
	Model   string   `json:"model"`
	Bus     string   `json:"bus"`   // NVMe, SATA, USB, ...
	Media   string   `json:"media"` // SSD, HDD or Unspecified
	Health  string   `json:"health"`
	Letters []string `json:"letters"`
	Events  []Event  `json:"events,omitempty"`
}

// Event counts one kind of disk error Windows logged for a drive.
type Event struct {
	What   string    `json:"what"`
	ID     int       `json:"id"`
	Count  int       `json:"count"`
	Latest time.Time `json:"latest"`
}

// Report is everything the check found.
type Report struct {
	Disks []Disk `json:"disks"`
	// Other holds errors Windows couldn't tie to one drive, such as a
	// storage controller resetting.
	Other []Event `json:"other,omitempty"`
	Err   string  `json:"error,omitempty"`
}

// Problem reports whether the drive logged errors or isn't healthy.
func (d *Disk) Problem() bool {
	return len(d.Events) > 0 || (d.Health != "" && !strings.EqualFold(d.Health, "Healthy"))
}

// Name is a short label such as "Disk 1 (HS-SSD-WAVE(P) 512G, C:)".
func (d *Disk) Name() string {
	s := fmt.Sprintf("Disk %d (%s", d.Number, d.Model)
	if len(d.Letters) > 0 {
		s += ", " + strings.Join(d.Letters, " ")
	}
	return s + ")"
}

// Errors totals the logged errors.
func (d *Disk) Errors() (n int, latest time.Time) {
	for _, e := range d.Events {
		n += e.Count
		if e.Latest.After(latest) {
			latest = e.Latest
		}
	}
	return
}

// ForPath returns the drive that holds path, or nil when unknown.
func (r *Report) ForPath(path string) *Disk {
	if r == nil || len(path) < 2 || path[1] != ':' {
		return nil
	}
	letter := strings.ToUpper(path[:1]) + ":"
	for i := range r.Disks {
		for _, l := range r.Disks[i].Letters {
			if l == letter {
				return &r.Disks[i]
			}
		}
	}
	return nil
}

// Recommend suggests how many parallel readers are safe for these drives.
func Recommend(disks []*Disk) (readers int, why string) {
	readers, why = 4, "solid-state drive"
	for _, d := range disks {
		if d == nil {
			continue
		}
		switch {
		case d.Problem():
			return 1, d.Name() + " has logged errors"
		case strings.EqualFold(d.Media, "HDD"):
			readers, why = 2, d.Name()+" is a spinning hard drive"
		case strings.EqualFold(d.Bus, "USB") && readers > 2:
			readers, why = 2, d.Name()+" is a USB drive"
		}
	}
	return readers, why
}

// What each logged event means, keyed by event ID.
var eventWhat = map[int]string{
	7:   "bad block",
	11:  "controller error",
	51:  "error during a paging operation",
	55:  "file system corruption",
	98:  "volume needs repair",
	129: "device stopped responding and was reset",
	153: "read or write had to be retried",
	157: "disk was removed unexpectedly",
}

type rawEvent struct {
	id       int
	provider string
	level    int
	time     time.Time
	data     []string
}

// attribute assigns parsed log entries to drives.
func attribute(r *Report, events []rawEvent) {
	byDisk := map[int]map[int]*Event{}
	other := map[int]*Event{}
	add := func(m map[int]*Event, e rawEvent) {
		ev := m[e.id]
		if ev == nil {
			ev = &Event{What: eventWhat[e.id], ID: e.id}
			m[e.id] = ev
		}
		ev.Count++
		if e.time.After(ev.Latest) {
			ev.Latest = e.time
		}
	}
	for _, e := range events {
		if !relevant(e) {
			continue
		}
		disk := diskOf(r, e.data)
		if disk < 0 {
			add(other, e)
			continue
		}
		if byDisk[disk] == nil {
			byDisk[disk] = map[int]*Event{}
		}
		add(byDisk[disk], e)
	}
	flatten := func(m map[int]*Event) []Event {
		var out []Event
		for _, e := range m {
			out = append(out, *e)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
		return out
	}
	for i := range r.Disks {
		r.Disks[i].Events = flatten(byDisk[r.Disks[i].Number])
	}
	r.Other = flatten(other)
}

// relevant keeps disk, storage-driver and NTFS errors, and drops the
// informational "volume is healthy" entries that share ID 98.
func relevant(e rawEvent) bool {
	if _, ok := eventWhat[e.id]; !ok {
		return false
	}
	p := strings.ToLower(e.provider)
	storage := p == "disk" || strings.Contains(p, "stor") || strings.Contains(p, "nvme") || strings.Contains(p, "ntfs") || strings.Contains(p, "volmgr")
	if !storage {
		return false
	}
	if strings.Contains(p, "ntfs") && e.level > 3 { // 4 = information
		return false
	}
	return true
}

// diskOf finds the drive an entry is about: "\Device\Harddisk1\DR1" names
// the disk number, NTFS entries name the volume ("C:").
func diskOf(r *Report, data []string) int {
	for _, d := range data {
		low := strings.ToLower(d)
		if i := strings.Index(low, `\device\harddisk`); i >= 0 {
			rest := low[i+len(`\device\harddisk`):]
			n, digits := 0, 0
			for _, c := range rest {
				if c < '0' || c > '9' {
					break
				}
				n = n*10 + int(c-'0')
				digits++
			}
			if digits > 0 {
				return n
			}
		}
		if len(d) == 2 && d[1] == ':' {
			if disk := r.ForPath(d); disk != nil {
				return disk.Number
			}
		}
	}
	return -1
}
