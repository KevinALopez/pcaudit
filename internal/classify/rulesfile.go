package classify

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// RuleFile is the format of pcaudit-rules.json.
//
//	{
//	  "rules": [
//	    {"where": "user", "pattern": "Documents/Clients", "verdict": "backup", "strong": true, "reason": "Client work"},
//	    {"where": "path", "pattern": "D:/Archive", "verdict": "safe", "reason": "Mirrored to my NAS"},
//	    {"where": "anywhere", "pattern": "renders", "verdict": "junk", "strong": true, "reason": "Render output"}
//	  ]
//	}
type RuleFile struct {
	Rules []RuleJSON `json:"rules"`
}

// RuleJSON is one rule in a rules file.
//
// where:
//
//	anywhere  a folder with this name (or a/b sub-path) anywhere on disk
//	drive     a folder path from the root of any drive, e.g. "Games/"
//	user      a folder path inside any user profile, e.g. "Documents/Clients"
//	path      one exact folder, e.g. "D:/Archive"
//
// verdict is one of backup, safe, reinstall, junk or review. A strong rule
// beats the file type; a weak one only applies where the type doesn't decide.
type RuleJSON struct {
	Where   string `json:"where"`
	Pattern string `json:"pattern"`
	Verdict string `json:"verdict"`
	Strong  bool   `json:"strong,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

var verdictWords = map[string]Verdict{
	"backup": Backup, "back up": Backup, "back-up": Backup,
	"safe": Safe, "already safe": Safe,
	"reinstall": Reinstall, "reinstallable": Reinstall,
	"junk":   Junk,
	"review": Review,
}

var whereWords = map[string]ruleKind{
	"anywhere": anywhere, "drive": driveRel, "user": userRel, "path": absPrefix,
}

var kindWords = map[ruleKind]string{anywhere: "anywhere", driveRel: "drive", userRel: "user", absPrefix: "path"}

var verdictKeys = [NumVerdicts]string{"backup", "safe", "reinstall", "junk", "review"}

// LoadRules reads a rules file.
func LoadRules(path string) ([]RuleJSON, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f RuleFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i, r := range f.Rules {
		if _, err := r.compile(); err != nil {
			return nil, fmt.Errorf("%s: rule %d: %w", path, i+1, err)
		}
	}
	return f.Rules, nil
}

func (r RuleJSON) compile() (Rule, error) {
	kind, ok := whereWords[strings.ToLower(strings.TrimSpace(r.Where))]
	if !ok {
		return Rule{}, fmt.Errorf("where %q: use anywhere, drive, user or path", r.Where)
	}
	v, ok := verdictWords[strings.ToLower(strings.TrimSpace(r.Verdict))]
	if !ok {
		return Rule{}, fmt.Errorf("verdict %q: use backup, safe, reinstall, junk or review", r.Verdict)
	}
	p := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(r.Pattern), `\`, "/"))
	switch kind {
	case anywhere:
		p = strings.Trim(p, "/")
	case driveRel, userRel:
		p = strings.TrimPrefix(p, "/")
		if !strings.HasSuffix(p, "/") {
			p += "/"
		}
	case absPrefix:
		p = Normalize(p)
	}
	if strings.Trim(p, "/") == "" {
		return Rule{}, fmt.Errorf("empty pattern")
	}
	why := r.Reason
	if why == "" {
		why = "Your rule: " + r.Pattern
	}
	return Rule{kind: kind, pat: p, V: v, Strong: r.Strong, Reason: reason(why)}, nil
}

// DefaultRules returns the built-in rules in the rules-file format, in the
// order they're checked.
func DefaultRules() RuleFile {
	var f RuleFile
	for _, s := range specs {
		for _, p := range s.pats {
			f.Rules = append(f.Rules, RuleJSON{Where: kindWords[s.kind], Pattern: p, Verdict: verdictKeys[s.V], Strong: s.strong, Reason: s.reason})
		}
	}
	return f
}
