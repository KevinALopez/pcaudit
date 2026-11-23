package diskhealth

import (
	"testing"
	"time"
)

func TestAttributeAndRecommend(t *testing.T) {
	now := time.Now()
	r := &Report{Disks: []Disk{
		{Number: 0, Model: "Games SSD", Media: "SSD", Bus: "SATA", Health: "Healthy", Letters: []string{"D:"}},
		{Number: 1, Model: "System SSD", Media: "SSD", Bus: "NVMe", Health: "Healthy", Letters: []string{"C:"}},
		{Number: 2, Model: "Old HDD", Media: "HDD", Bus: "SATA", Health: "Healthy", Letters: []string{"E:"}},
	}}
	attribute(r, []rawEvent{
		{id: 7, provider: "disk", level: 2, time: now.Add(-time.Hour), data: []string{`\Device\Harddisk1\DR1`}},
		{id: 7, provider: "disk", level: 2, time: now, data: []string{`\Device\Harddisk1\DR1`}},
		{id: 98, provider: "Microsoft-Windows-Ntfs", level: 4, data: []string{"D:"}},            // "healthy": ignored
		{id: 55, provider: "Microsoft-Windows-Ntfs", level: 2, time: now, data: []string{"C:"}}, // by volume letter
		{id: 129, provider: "stornvme", level: 3, time: now, data: []string{`\Device\RaidPort0`}},
		{id: 7, provider: "SomethingElse", level: 2, data: []string{`\Device\Harddisk0\DR0`}}, // not a storage source
	})

	c, d, e := r.ForPath(`C:\Users`), r.ForPath(`d:\games`), r.ForPath(`E:\`)
	if c == nil || c.Number != 1 || d == nil || d.Number != 0 || e == nil || e.Number != 2 {
		t.Fatalf("ForPath mapping wrong: %v %v %v", c, d, e)
	}
	if n, latest := c.Errors(); n != 3 || !latest.Equal(now) {
		t.Errorf("C: errors = %d (latest %v), want 3", n, latest)
	}
	if d.Problem() {
		t.Errorf("D: should be fine, has %+v", d.Events)
	}
	if len(r.Other) != 1 || r.Other[0].ID != 129 {
		t.Errorf("unattributed events = %+v", r.Other)
	}

	if n, _ := Recommend([]*Disk{d}); n != 4 {
		t.Errorf("healthy SSD: %d readers, want 4", n)
	}
	if n, _ := Recommend([]*Disk{d, e}); n != 2 {
		t.Errorf("with a hard drive: %d readers, want 2", n)
	}
	if n, why := Recommend([]*Disk{d, e, c}); n != 1 || why == "" {
		t.Errorf("with a failing drive: %d readers (%s), want 1", n, why)
	}
	unhealthy := Disk{Number: 3, Health: "Warning"}
	if !unhealthy.Problem() {
		t.Error("a drive in Warning health should count as a problem")
	}
}
