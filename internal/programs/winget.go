package programs

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
)

// WingetResult is what `winget export` produced.
type WingetResult struct {
	Path     string   // the export file, ready for `winget import -i <file>`
	Packages []string // package IDs in the export
	// Missing holds the names winget couldn't find in any source. Those
	// programs have to be downloaded by hand after a reset.
	Missing map[string]bool
}

const missingPrefix = "Installed package is not available from any source: "

// parseWinget reads the export file and winget's console output.
func parseWinget(path string, exportJSON, console []byte) (*WingetResult, error) {
	var doc struct {
		Sources []struct {
			Packages []struct {
				PackageIdentifier string
			}
		}
	}
	if err := json.Unmarshal(exportJSON, &doc); err != nil {
		return nil, err
	}
	res := &WingetResult{Path: path, Missing: map[string]bool{}}
	for _, s := range doc.Sources {
		for _, p := range s.Packages {
			res.Packages = append(res.Packages, p.PackageIdentifier)
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(console))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if name, ok := strings.CutPrefix(line, missingPrefix); ok {
			res.Missing[strings.ToLower(strings.TrimSpace(name))] = true
		}
	}
	return res, nil
}

// Mark fills in each program's Winget field. winget names a missing program
// by its display name, sometimes followed by the version.
func Mark(ps []Program, w *WingetResult) {
	if w == nil {
		return
	}
	for i := range ps {
		n := strings.ToLower(ps[i].Name)
		if w.Missing[n] || (ps[i].Version != "" && w.Missing[n+" "+strings.ToLower(ps[i].Version)]) {
			ps[i].Winget = "no"
		} else {
			ps[i].Winget = "yes"
		}
	}
}
