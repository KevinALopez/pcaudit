// pcaudit inventories a computer before a factory reset. It walks your drives,
// sorts every file into "back up / already safe / reinstallable / junk / review",
// and writes an offline HTML report next to a full CSV listing.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/KevinALopez/pcaudit/internal/classify"
	"github.com/KevinALopez/pcaudit/internal/diskhealth"
	"github.com/KevinALopez/pcaudit/internal/dupes"
	"github.com/KevinALopez/pcaudit/internal/gitrepo"
	"github.com/KevinALopez/pcaudit/internal/programs"
	"github.com/KevinALopez/pcaudit/internal/report"
	"github.com/KevinALopez/pcaudit/internal/scan"
)

// version is set at release time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	code := run()
	pauseIfOwnConsole()
	os.Exit(code)
}

func run() int {
	outFlag := flag.String("out", "", "folder for the report (default: ./pcaudit-<host>-<date>)")
	readersFlag := flag.Int("readers", 0, "how many folders or files to read at once (default: picked from your drives' health and type, usually 4; 1 on a drive with errors)")
	force := flag.Bool("force", false, "don't ask or slow down, even when a drive has logged errors (not recommended)")
	noCSV := flag.Bool("no-csv", false, "skip the full files.csv listing")
	noOpen := flag.Bool("no-open", false, "don't open the report when done")
	noGit := flag.Bool("no-git", false, "don't ask git about repositories")
	dupesFlag := flag.Bool("dupes", false, "also find duplicate files (reads every possible copy in full: heavy on the drive)")
	noPrograms := flag.Bool("no-programs", false, "don't list installed programs")
	noWinget := flag.Bool("no-winget", false, "don't export a winget reinstall list")
	rulesFlag := flag.String("rules", "", "your own rules file (default: "+rulesFileName+" next to pcaudit or in the current folder)")
	printRules := flag.Bool("print-rules", false, "print the built-in rules in rules-file format and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "pcaudit %s: see what's on this computer before you wipe it.\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: pcaudit [flags] [folders...]\n\nWith no folders, every fixed drive is scanned.\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Println("pcaudit", version)
		return 0
	}
	if *printRules {
		b, _ := json.MarshalIndent(classify.DefaultRules(), "", "  ")
		fmt.Println(string(b))
		fmt.Fprintf(os.Stderr, "\nThese are the built-in rules, first match wins. Put your own in %s:\nthey're checked before all of these.\n", rulesFileName)
		return 0
	}

	rulesPath, custom, err := loadRules(*rulesFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "can't use the rules file:", err)
		return 1
	}

	roots := flag.Args()
	if len(roots) == 0 {
		roots = scan.DefaultRoots()
	}

	// Check the drives before reading them. pcaudit once crashed a PC whose
	// system drive had bad blocks; this is what stops that from happening.
	fmt.Printf("pcaudit %s: checking drive health...\n", version)
	health := diskhealth.Check()
	if health != nil && health.Err != "" {
		fmt.Println("  Couldn't fully check the drives:", health.Err)
	}
	p, ok := decide(health, roots, *readersFlag, *dupesFlag, *force, interactive(), ownConsole() && flag.NFlag() == 0)
	if !ok {
		fmt.Println("Cancelled. Nothing was scanned.")
		return 0
	}
	scan.LowPriority()

	host, _ := os.Hostname()
	userName := ""
	if u, err := user.Current(); err == nil {
		userName = u.Username
	}
	started := time.Now()

	outDir := *outFlag
	if outDir == "" {
		outDir = fmt.Sprintf("pcaudit-%s-%s", safeName(host), started.Format("20060102-1504"))
	}
	outDir, _ = filepath.Abs(outDir)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "can't create output folder:", err)
		return 1
	}

	csvPath := ""
	if !*noCSV {
		csvPath = filepath.Join(outDir, "files.csv")
	}
	col, err := report.NewCollector(csvPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "can't create files.csv:", err)
		return 1
	}

	col.FindDupes = p.dupes
	cls := classify.New([]string{os.Getenv("OneDrive"), os.Getenv("OneDriveCommercial"), os.Getenv("OneDriveConsumer")}, custom...)
	useGit := !*noGit && gitrepo.Available()

	fmt.Printf("Scanning %s with %d reader%s at low priority.\n", strings.Join(roots, ", "), p.readers, map[bool]string{true: "", false: "s"}[p.readers == 1])
	if rulesPath != "" {
		fmt.Printf("Using %d rules from %s\n", len(custom), rulesPath)
	}
	if !*noGit && !useGit {
		fmt.Println("git isn't installed, so repositories won't be checked for unpushed work.")
	}
	fmt.Println("Read-only: nothing is changed, moved or uploaded.")

	// Installed programs and the winget export run alongside the file scan.
	type progResult struct {
		list      []programs.Program
		winget    *programs.WingetResult
		wingetErr error
	}
	progCh := make(chan progResult, 1)
	go func() {
		var r progResult
		if !*noPrograms {
			r.list, _ = programs.List()
			if !*noWinget {
				r.winget, r.wingetErr = programs.Winget(filepath.Join(outDir, wingetFileName))
				programs.Mark(r.list, r.winget)
			}
		}
		progCh <- r
	}()

	res := scan.Run(scan.Options{
		Git:        useGit,
		Roots:      roots,
		Workers:    p.readers,
		Exclude:    []string{outDir},
		Classifier: cls,
		OnBatch:    col.Add,
		Progress: func(s scan.Stats) {
			line := fmt.Sprintf("  %s files, %s, %d unreadable  %s", commas(s.Files), human(s.Bytes), s.Errors, s.Current)
			if s.DiskErrors > 0 {
				line = fmt.Sprintf("  DISK ERRORS: %d, slowed down to 1 reader. %s files  %s", s.DiskErrors, commas(s.Files), s.Current)
			}
			fmt.Printf("\r%-110.110s", line)
		},
	})
	fmt.Printf("\r%-110s\r", "")
	if err := col.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "writing files.csv failed:", err)
	}
	if res.DiskErrors > 0 {
		fmt.Printf("\nWARNING: the drive failed to read %d folders or files during the scan.\n", res.DiskErrors)
		fmt.Println("They're listed under Problems in the report. Copy what you can't lose off that drive soon.")
		if col.FindDupes {
			fmt.Println("Skipping the duplicate check so the drive isn't read any harder.")
			col.FindDupes = false
			p.note = "Duplicate check skipped: the drive reported read errors during the scan."
		}
		fmt.Println()
	}

	var dupeGroups []dupes.Group
	if col.FindDupes {
		t := time.Now()
		var mu sync.Mutex // the callback runs on every hashing goroutine
		var last, fullStart time.Time
		var dupeErr error
		dupeGroups, dupeErr = dupes.Find(col.Candidates, p.readers, func(phase string, done, total int64) {
			mu.Lock()
			defer mu.Unlock()
			if time.Since(last) < 250*time.Millisecond && done != total {
				return
			}
			last = time.Now()
			if phase == "sample" {
				fmt.Printf("\r  Looking for duplicates: sampled %s of %s files%20s", commas(done), commas(total), "")
			} else {
				if fullStart.IsZero() {
					fullStart = time.Now()
				}
				eta := ""
				if el := time.Since(fullStart); el > 3*time.Second && done > 0 && done < total {
					left := time.Duration(float64(el) * float64(total-done) / float64(done))
					eta = fmt.Sprintf(", about %s left", left.Round(time.Second))
				}
				fmt.Printf("\r  Looking for duplicates: read %s of %s%s%20s", human(done), human(total), eta, "")
			}
		}, scan.IsDiskError)
		fmt.Printf("\r%-110s\r", "")
		if dupeErr != nil {
			fmt.Printf("WARNING: stopped the duplicate check: %v\n", dupeErr)
			p.note = "Duplicate check stopped: " + dupeErr.Error()
			col.FindDupes = false
		} else {
			fmt.Printf("Duplicate check took %s.\n", time.Since(t).Round(time.Second))
		}
	}

	meta := report.Meta{
		Tool: "pcaudit", Version: version, Host: host, User: userName,
		OS: runtime.GOOS + "/" + runtime.GOARCH, Started: started.Format(time.RFC3339),
		DurationSec: time.Since(started).Seconds(), Roots: roots,
		Files: res.Files, Dirs: res.Dirs, Bytes: res.Bytes, CloudOnly: col.CloudOnlyBytes,
		Errors: res.Errors, Links: res.Links, RulesFile: rulesPath, CustomRules: len(custom),
		GitChecked: useGit, DupesChecked: col.FindDupes,
		Readers: p.readers, SafetyNote: p.note, DiskErrors: res.DiskErrors, Health: health,
	}
	if csvPath != "" {
		meta.CSV = "files.csv"
	}

	if !*noPrograms && !*noWinget {
		fmt.Print("  Waiting for the winget export...\r")
	}
	progs := <-progCh
	meta.ProgramsChecked = !*noPrograms
	if progs.winget != nil {
		meta.WingetFile = wingetFileName
		meta.WingetPackages = len(progs.winget.Packages)
	}
	if progs.wingetErr != nil {
		meta.WingetError = progs.wingetErr.Error()
	}
	meta.DurationSec = time.Since(started).Seconds()

	reportPath, err := report.Write(outDir, meta, res, col, cls, report.Extras{Dupes: dupeGroups, Programs: progs.list})
	if err != nil {
		fmt.Fprintln(os.Stderr, "writing the report failed:", err)
		return 1
	}

	var all scan.Agg
	for i := range res.Nodes {
		if res.Nodes[i].Parent < 0 {
			all.Add(&res.Nodes[i].Total)
		}
	}
	fmt.Printf("Scanned %s files in %s folders (%s) in %s.\n\n", commas(res.Files), commas(res.Dirs), human(res.Bytes), res.Elapsed.Round(time.Second))
	for v := 0; v < int(classify.NumVerdicts); v++ {
		fmt.Printf("  %-14s %10s  %12s files\n", classify.VerdictNames[v], human(all.Size[v]), commas(all.Count[v]))
	}
	fmt.Println()
	if len(res.Repos) > 0 {
		atRisk := 0
		for _, r := range res.Repos {
			if !r.Status.Clean() {
				atRisk++
			}
		}
		fmt.Printf("  %d git repositories, %d with work that isn't pushed anywhere.\n", len(res.Repos), atRisk)
	}
	if len(dupeGroups) > 0 {
		var wasted int64
		for _, g := range dupeGroups {
			wasted += g.Wasted()
		}
		fmt.Printf("  %s in duplicate copies (%d sets of identical files).\n", human(wasted), len(dupeGroups))
	}
	if len(progs.list) > 0 {
		manual, games := 0, 0
		for _, p := range progs.list {
			switch {
			case p.Kind == "Game":
				games++
			case p.Winget == "no":
				manual++
			}
		}
		fmt.Printf("  %d installed programs, %d of them games.", len(progs.list), games)
		if progs.winget != nil {
			fmt.Printf(" %d programs aren't in the winget list and need a manual reinstall.\n", manual)
			fmt.Printf("  %d winget packages can be reinstalled in one go with: winget import -i %s", len(progs.winget.Packages), wingetFileName)
		}
		fmt.Println()
	}
	if progs.wingetErr != nil {
		fmt.Printf("  The winget export failed: %v\n", progs.wingetErr)
	}
	if res.Errors > 0 {
		fmt.Printf("  %d folders or files couldn't be read (listed in the report).\n", res.Errors)
	}
	fmt.Printf("\nReport: %s\n", reportPath)

	if !*noOpen {
		openFile(reportPath)
	}
	return 0
}

const (
	rulesFileName  = "pcaudit-rules.json"
	wingetFileName = "winget-packages.json"
)

// loadRules reads the rules file named by -rules, or else pcaudit-rules.json
// next to the executable or in the current folder, if one exists.
func loadRules(flagPath string) (string, []classify.RuleJSON, error) {
	path := flagPath
	if path == "" {
		var tries []string
		if exe, err := os.Executable(); err == nil {
			tries = append(tries, filepath.Join(filepath.Dir(exe), rulesFileName))
		}
		tries = append(tries, rulesFileName)
		for _, p := range tries {
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
	}
	if path == "" {
		return "", nil, nil
	}
	rules, err := classify.LoadRules(path)
	if err != nil {
		return "", nil, err
	}
	abs, _ := filepath.Abs(path)
	return abs, rules, nil
}

func safeName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || strings.ContainsRune(`<>:"/\|?*`, r) {
			return '_'
		}
		return r
	}, s)
	if s == "" {
		return "pc"
	}
	return s
}

func openFile(p string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", p)
	case "darwin":
		cmd = exec.Command("open", p)
	case "linux":
		cmd = exec.Command("xdg-open", p)
	default:
		return
	}
	_ = cmd.Start()
}

func human(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func commas(n int64) string {
	s := fmt.Sprint(n)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}
