package dupes

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFind(t *testing.T) {
	dir := t.TempDir()
	big := bytes.Repeat([]byte("abcdefgh"), 100_000) // 800 KB, bigger than both edges
	sameEdges := append([]byte(nil), big...)
	sameEdges[len(big)/2] = 'X' // differs only in the middle
	files := map[string][]byte{
		"a.bin": big, "b.bin": big, "c.bin": sameEdges,
		"small1.txt": []byte("hello"), "small2.txt": []byte("hello"), "small3.txt": []byte("hellO"),
	}
	var cands []Candidate
	for name, data := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		cands = append(cands, Candidate{Path: p, Size: int64(len(data)), Name: name})
	}

	groups, err := Find(cands, 2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2: %+v", len(groups), groups)
	}
	names := func(g Group) (s []string) {
		for _, f := range g.Files {
			s = append(s, f.Name)
		}
		return
	}
	if n := names(groups[0]); len(n) != 2 || n[0] != "a.bin" || n[1] != "b.bin" {
		t.Errorf("biggest group = %v, want [a.bin b.bin]", n)
	}
	if n := names(groups[1]); len(n) != 2 || n[0] != "small1.txt" || n[1] != "small2.txt" {
		t.Errorf("small group = %v, want [small1.txt small2.txt]", n)
	}
	if w := groups[0].Wasted(); w != int64(len(big)) {
		t.Errorf("wasted = %d, want %d", w, len(big))
	}

	// A drive error stops everything. Here a missing file stands in for one.
	missing := append(cands, Candidate{Path: filepath.Join(dir, "gone.bin"), Size: int64(len(big)), Name: "gone.bin"})
	groups, err = Find(missing, 2, nil, func(err error) bool { return os.IsNotExist(err) })
	var de *ErrDisk
	if !errors.As(err, &de) || groups != nil {
		t.Errorf("expected a disk error and no groups, got %v, %d groups", err, len(groups))
	}
}
