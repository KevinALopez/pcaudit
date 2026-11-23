// Package programs lists installed programs, so a reset can be followed by
// a reinstall checklist, and asks winget which of them it can reinstall.
package programs

import (
	"sort"
	"strings"
)

// Program is one entry from the system's list of installed programs.
type Program struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Publisher string `json:"publisher,omitempty"`
	Installed string `json:"installed,omitempty"` // YYYY-MM-DD when known
	SizeKB    uint32 `json:"sizeKB,omitempty"`    // as reported by the installer, often missing
	Location  string `json:"location,omitempty"`
	Scope     string `json:"scope"`  // "All users" or "Current user"
	Kind      string `json:"kind"`   // "Program" or "Game" (Steam, Epic, ...)
	Winget    string `json:"winget"` // "yes", "no" or "" (unknown)
	Source    string `json:"source"` // where the entry came from
}

// isGame guesses whether an entry was installed by a game launcher.
func isGame(p Program, key string) bool {
	k := strings.ToLower(key)
	if strings.HasPrefix(k, "steam app ") || strings.HasPrefix(k, "uplay install") {
		return true
	}
	loc := strings.ToLower(p.Location)
	for _, s := range []string{`steamapps\common`, `epic games\`, `gog galaxy\games`, `xboxgames\`, `riot games\`} {
		if strings.Contains(loc, s) {
			return true
		}
	}
	return false
}

// tidy drops duplicates and sorts by name.
func tidy(ps []Program) []Program {
	seen := map[string]bool{}
	out := ps[:0]
	for _, p := range ps {
		k := strings.ToLower(p.Name + "\x00" + p.Version)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// formatDate turns the registry's YYYYMMDD into YYYY-MM-DD.
func formatDate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 8 {
		for _, c := range s {
			if c < '0' || c > '9' {
				return ""
			}
		}
		return s[:4] + "-" + s[4:6] + "-" + s[6:]
	}
	return ""
}
