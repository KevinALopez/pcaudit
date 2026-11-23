package main

import (
	"io"
	"os"
	"testing"
	"time"

	"github.com/KevinALopez/pcaudit/internal/diskhealth"
)

func quiet(t *testing.T) {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	go io.Copy(io.Discard, r)
	t.Cleanup(func() { w.Close(); os.Stdout = old })
}

func TestDecide(t *testing.T) {
	quiet(t)
	healthy := &diskhealth.Report{Disks: []diskhealth.Disk{
		{Number: 0, Model: "Good SSD", Media: "SSD", Bus: "SATA", Health: "Healthy", Letters: []string{"D:"}},
	}}
	sick := &diskhealth.Report{Disks: []diskhealth.Disk{
		{Number: 0, Model: "Good SSD", Media: "SSD", Bus: "SATA", Health: "Healthy", Letters: []string{"D:"}},
		{Number: 1, Model: "Bad SSD", Media: "SSD", Bus: "NVMe", Health: "Healthy", Letters: []string{"C:"},
			Events: []diskhealth.Event{{What: "bad block", ID: 7, Count: 500, Latest: time.Now()}}},
	}}

	cases := []struct {
		name        string
		h           *diskhealth.Report
		roots       []string
		readers     int
		dupes       bool
		force       bool
		wantReaders int
		wantDupes   bool
	}{
		{"healthy default", healthy, []string{`D:\`}, 0, false, false, 4, false},
		{"healthy, user picks 8", healthy, []string{`D:\`}, 8, true, false, 8, true},
		{"too many is capped", healthy, []string{`D:\`}, 500, false, false, maxReaders, false},
		{"sick drive is scanned gently", sick, []string{`C:\`, `D:\`}, 0, false, false, 1, false},
		{"sick drive overrides what was asked", sick, []string{`C:\`}, 16, true, false, 1, false},
		{"only the healthy drive is scanned", sick, []string{`D:\games`}, 0, true, false, 4, true},
		{"-force keeps what was asked", sick, []string{`C:\`}, 16, true, true, 16, true},
		{"no health info", nil, []string{`C:\`}, 0, false, false, 4, false},
	}
	for _, c := range cases {
		p, ok := decide(c.h, c.roots, c.readers, c.dupes, c.force, false, false)
		if !ok || p.readers != c.wantReaders || p.dupes != c.wantDupes {
			t.Errorf("%s: got readers=%d dupes=%v ok=%v, want readers=%d dupes=%v", c.name, p.readers, p.dupes, ok, c.wantReaders, c.wantDupes)
		}
	}
}
