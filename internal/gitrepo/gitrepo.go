// Package gitrepo asks git whether a repository's work exists anywhere else:
// uncommitted changes, commits that were never pushed, stashes.
package gitrepo

import (
	"bytes"
	"context"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Status is what git says about one repository.
type Status struct {
	Root         string `json:"root"`
	Remote       string `json:"remote,omitempty"`
	Branch       string `json:"branch,omitempty"`
	Changed      int    `json:"changed"`      // modified, added or deleted tracked files
	Untracked    int    `json:"untracked"`    // new files git doesn't know about (not ignored)
	HeadUnpushed int    `json:"headUnpushed"` // commits in the checked-out branch that no remote has
	AllUnpushed  int    `json:"allUnpushed"`  // the same, across every local branch
	Stashes      int    `json:"stashes"`
	Err          string `json:"error,omitempty"`

	changed      map[string]bool // relative paths with "/" separators
	ignoredFiles map[string]bool
	ignoredDirs  map[string]bool // with a trailing "/"
}

// Known reports whether git could be asked at all.
func (s *Status) Known() bool { return s.Err == "" }

// HasRemote reports whether the repository has anywhere to push to.
func (s *Status) HasRemote() bool { return s.Remote != "" }

// HeadPushed: the checked-out files are all committed somewhere a remote has.
func (s *Status) HeadPushed() bool { return s.Known() && s.HasRemote() && s.HeadUnpushed == 0 }

// AllPushed: nothing in the repository's history exists only here.
func (s *Status) AllPushed() bool {
	return s.Known() && s.HasRemote() && s.AllUnpushed == 0 && s.Stashes == 0
}

// Clean: pushed, and nothing uncommitted either.
func (s *Status) Clean() bool { return s.AllPushed() && s.Changed == 0 && s.Untracked == 0 }

// IsChanged reports whether rel (relative to the root, "/" separated) is a
// modified or untracked file.
func (s *Status) IsChanged(rel string) bool { return s.changed[rel] }

// IsIgnored reports whether git ignores this file.
func (s *Status) IsIgnored(rel string) bool { return s.ignoredFiles[rel] }

// IsIgnoredDir reports whether git ignores this folder. dirRel ends with "/".
func (s *Status) IsIgnoredDir(dirRel string) bool { return s.ignoredDirs[dirRel] }

var (
	gitOnce sync.Once
	gitPath string
)

// Available reports whether git is installed.
func Available() bool {
	gitOnce.Do(func() { gitPath, _ = exec.LookPath("git") })
	return gitPath != ""
}

const timeout = 60 * time.Second

func run(root string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// safe.directory=* : repos owned by another account would otherwise be refused.
	full := append([]string{"-c", "safe.directory=*", "-c", "core.quotepath=off", "-C", root}, args...)
	cmd := exec.CommandContext(ctx, gitPath, full...)
	hideWindow(cmd)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, &gitError{msg}
	}
	return out.Bytes(), nil
}

type gitError struct{ msg string }

func (e *gitError) Error() string { return e.msg }

func count(root string, args ...string) int {
	out, err := run(root, args...)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return n
}

// Check asks git about the repository at root.
func Check(root string) *Status {
	s := &Status{Root: root, changed: map[string]bool{}, ignoredFiles: map[string]bool{}, ignoredDirs: map[string]bool{}}
	if !Available() {
		s.Err = "git is not installed"
		return s
	}

	out, err := run(root, "status", "--porcelain=v1", "-z", "--ignored=matching", "--untracked-files=all")
	if err != nil {
		s.Err = err.Error()
		return s
	}
	s.parseStatus(out)

	if out, err := run(root, "remote", "-v"); err == nil {
		if line, _, _ := strings.Cut(string(out), "\n"); line != "" {
			if f := strings.Fields(line); len(f) >= 2 {
				s.Remote = f[1]
			}
		}
	}
	if out, err := run(root, "rev-parse", "--abbrev-ref", "HEAD"); err == nil {
		s.Branch = strings.TrimSpace(string(out))
	}
	// A repo with no commits yet has no HEAD; the counts below just stay 0.
	if _, err := run(root, "rev-parse", "--verify", "-q", "HEAD"); err == nil {
		s.HeadUnpushed = count(root, "rev-list", "--count", "HEAD", "--not", "--remotes")
		s.AllUnpushed = count(root, "rev-list", "--count", "--branches", "--not", "--remotes")
	}
	if out, err := run(root, "stash", "list"); err == nil {
		s.Stashes = bytes.Count(out, []byte("\n"))
	}
	return s
}

// parseStatus reads "XY path\0" entries. Renames add a second "\0old-path".
func (s *Status) parseStatus(out []byte) {
	entries := strings.Split(string(out), "\x00")
	for i := 0; i < len(entries); i++ {
		e := entries[i]
		if len(e) < 4 {
			continue
		}
		xy, path := e[:2], e[3:]
		switch {
		case xy == "!!":
			if strings.HasSuffix(path, "/") {
				s.ignoredDirs[path] = true
			} else {
				s.ignoredFiles[path] = true
			}
		case xy == "??":
			s.Untracked++
			s.changed[path] = true
		default:
			s.Changed++
			s.changed[path] = true
			if xy[0] == 'R' || xy[0] == 'C' {
				i++ // skip the original path
			}
		}
	}
}
