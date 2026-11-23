package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/KevinALopez/pcaudit/internal/diskhealth"
)

// maxReaders caps -readers. Beyond this, parallel reads only add stress.
const maxReaders = 64

// plan is how hard the scan may read the drives.
type plan struct {
	readers int
	dupes   bool
	note    string // why the plan differs from what was asked, for the report
}

var stdin = bufio.NewReader(os.Stdin)

func ask(prompt string) string {
	fmt.Print(prompt)
	line, _ := stdin.ReadString('\n')
	return strings.TrimSpace(strings.ToLower(line))
}

// decide picks the number of readers and whether to run the duplicate check,
// based on the drives' health and what was asked for. It returns false when
// the user cancels.
func decide(h *diskhealth.Report, roots []string, requested int, dupes, force, interactive, doubleClicked bool) (plan, bool) {
	var disks []*diskhealth.Disk
	seen := map[int]bool{}
	for _, r := range roots {
		if d := h.ForPath(r); d != nil && !seen[d.Number] {
			seen[d.Number] = true
			disks = append(disks, d)
		}
	}
	rec, why := diskhealth.Recommend(disks)
	p := plan{readers: requested, dupes: dupes}
	if p.readers <= 0 {
		p.readers = rec
	}
	if p.readers > maxReaders {
		fmt.Printf("%d readers is more than pcaudit allows; using %d.\n", p.readers, maxReaders)
		p.readers = maxReaders
	}

	var sick []*diskhealth.Disk
	for _, d := range disks {
		if d.Problem() {
			sick = append(sick, d)
		}
	}

	if len(sick) > 0 {
		warnDisks(sick)
		risky := p.readers > 1 || p.dupes
		switch {
		case !risky:
			fmt.Println("pcaudit will scan gently: 1 reader, no duplicate check.")
		case interactive && !force:
			fmt.Println("How should pcaudit read this drive?")
			fmt.Println("  1) Gently: 1 reader, no duplicate check (recommended)")
			fmt.Printf("  2) As asked: %d readers%s. This can crash Windows on a failing drive.\n", p.readers, map[bool]string{true: " and the duplicate check", false: ""}[p.dupes])
			fmt.Println("  3) Cancel")
			switch ask("Choose 1, 2 or 3 [1]: ") {
			case "3", "c", "cancel", "q":
				return p, false
			case "2":
				p.note = "Scanned at full speed on a drive with errors, at the user's request."
			default:
				p.readers, p.dupes = 1, false
				p.note = "Scanned gently (1 reader, no duplicate check) because a drive has logged errors."
			}
		case force:
			fmt.Printf("-force: reading with %d readers anyway.\n", p.readers)
			p.note = "Scanned at full speed on a drive with errors (-force)."
		default:
			fmt.Println("Scanning gently instead: 1 reader, no duplicate check. Add -force to override.")
			p.readers, p.dupes = 1, false
			p.note = "Scanned gently (1 reader, no duplicate check) because a drive has logged errors."
		}
		fmt.Println()
		return p, true
	}

	if p.readers > rec*2 {
		fmt.Printf("\nWarning: %d parallel readers is a lot. pcaudit recommends %d here (%s).\n", p.readers, rec, why)
		fmt.Println("More readers add little speed but a lot of stress, and a drive with hidden problems can crash under it.")
		if interactive && !force {
			if a := ask(fmt.Sprintf("Continue with %d readers? [y/N]: ", p.readers)); a != "y" && a != "yes" {
				p.readers = rec
				fmt.Printf("Using %d readers.\n", rec)
			}
		}
	}

	if doubleClicked && !p.dupes {
		fmt.Println("\nThe duplicate check finds identical copies of your files, but it reads every possible")
		fmt.Println("copy in full, which can be tens of GB and take several minutes.")
		if a := ask("Look for duplicate files too? [y/N]: "); a == "y" || a == "yes" {
			p.dupes = true
		}
	}
	return p, true
}

func warnDisks(sick []*diskhealth.Disk) {
	line := strings.Repeat("!", 78)
	fmt.Println()
	fmt.Println(line)
	fmt.Println("  WARNING: a drive pcaudit is about to read has problems")
	fmt.Println(line)
	for _, d := range sick {
		n, latest := d.Errors()
		fmt.Printf("\n  %s\n", d.Name())
		if d.Health != "" && !strings.EqualFold(d.Health, "Healthy") {
			fmt.Printf("    Windows reports its health as: %s\n", d.Health)
		}
		if n > 0 {
			fmt.Printf("    Windows logged %d disk errors in the last %d days, the latest on %s:\n", n, diskhealth.Days, latest.Format("2006-01-02 15:04"))
			for _, e := range d.Events {
				fmt.Printf("      %5d x %s\n", e.Count, e.What)
			}
		}
	}
	fmt.Println()
	fmt.Println("  A drive with bad blocks can crash Windows (a blue screen, often 0x154) when")
	fmt.Println("  it's read heavily, and a crash can damage the boot files. Before anything else:")
	fmt.Println("    - copy what you can't lose to another drive")
	fmt.Println("    - plan to replace this drive, ideally before a reset or reinstall")
	fmt.Println(line)
	fmt.Println()
}
