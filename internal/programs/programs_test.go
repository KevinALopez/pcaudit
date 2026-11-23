package programs

import (
	"runtime"
	"testing"
)

func TestParseAndMark(t *testing.T) {
	export := []byte(`{"Sources":[{"Packages":[{"PackageIdentifier":"Git.Git"},{"PackageIdentifier":"Valve.Steam"}]}]}`)
	console := []byte("Installed package is not available from any source: NVM for Windows 1.2.2\r\n" +
		"Installed package is not available from any source: FINAL FANTASY\r\n" +
		"Installed version of package is not available from any source: Google.PlayGames 26.11.281.0\r\n")
	w, err := parseWinget("x.json", export, console)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Packages) != 2 {
		t.Errorf("packages = %v", w.Packages)
	}
	ps := []Program{
		{Name: "Git", Version: "2.55.0"},
		{Name: "NVM for Windows", Version: "1.2.2"},
		{Name: "FINAL FANTASY"},
		{Name: "Google Play Games", Version: "26.11.281.0"},
	}
	Mark(ps, w)
	want := []string{"yes", "no", "no", "yes"}
	for i, p := range ps {
		if p.Winget != want[i] {
			t.Errorf("%s: winget = %q, want %q", p.Name, p.Winget, want[i])
		}
	}
}

func TestListFindsSomething(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("program list is Windows-only for now")
	}
	ps, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) == 0 {
		t.Fatal("no installed programs found")
	}
	for _, p := range ps {
		if p.Name == "" || p.Scope == "" {
			t.Errorf("incomplete entry: %+v", p)
		}
	}
}

func TestFormatDate(t *testing.T) {
	for in, want := range map[string]string{"20260705": "2026-07-05", "2026": "", "abcdefgh": "", "": ""} {
		if got := formatDate(in); got != want {
			t.Errorf("formatDate(%q) = %q, want %q", in, got, want)
		}
	}
}
