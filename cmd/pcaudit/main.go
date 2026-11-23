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
	"github.com/KevinALopez/pcaudit/internal/dupes"
	"github.com/KevinALopez/pcaudit/internal/gitrepo"
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
	workers := flag.Int("workers", 0, "parallel folder readers (default: 2x CPU cores, at least 8)")
	noCSV := flag.Bool("no-csv", false, "skip the full files.csv listing")
	noOpen := flag.Bool("no-open", false, "don't open the report when done")
	noGit := flag.Bool("no-git", false, "don't ask git about repositories")
	noDupes := flag.Bool("no-dupes", false, "don't look for duplicate files (skips reading file contents)")
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
	if *workers <= 0 {
		*workers = max(8, runtime.NumCPU()*2)
	}

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

	col.FindDupes = !*noDupes
	cls := classify.New([]string{os.Getenv("OneDrive"), os.Getenv("OneDriveCommercial"), os.Getenv("OneDriveConsumer")}, custom...)
	useGit := !*noGit && gitrepo.Available()

	fmt.Printf("pcaudit %s: scanning %s\n", version, strings.Join(roots, ", "))
	if rulesPath != "" {
		fmt.Printf("Using %d rules from %s\n", len(custom), rulesPath)
	}
	if !*noGit && !useGit {
		fmt.Println("git isn't installed, so repositories won't be checked for unpushed work.")
	}
	fmt.Println("Read-only: nothing is changed, moved or uploaded.")
	res := scan.Run(scan.Options{
		Git:        useGit,
		Roots:      roots,
		Workers:    *workers,
		Exclude:    []string{outDir},
		Classifier: cls,
		OnBatch:    col.Add,
		Progress: func(s scan.Stats) {
			line := fmt.Sprintf("  %s files, %s, %d unreadable  %s", commas(s.Files), human(s.Bytes), s.Errors, s.Current)
			fmt.Printf("\r%-110.110s", line)
		},
	})
	fmt.Printf("\r%-110s\r", "")
	if err := col.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "writing files.csv failed:", err)
	}

	var dupeGroups []dupes.Group
	if col.FindDupes {
		t := time.Now()
		var mu sync.Mutex // the callback runs on every hashing goroutine
		var last, fullStart time.Time
		dupeGroups = dupes.Find(col.Candidates, *workers, func(phase string, done, total int64) {
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
					eta = fmt.Sprintf(", about %s left (-no-dupes skips this)", left.Round(time.Second))
				}
				fmt.Printf("\r  Looking for duplicates: read %s of %s%s%20s", human(done), human(total), eta, "")
			}
		})
		fmt.Printf("\r%-110s\r", "")
		fmt.Printf("Duplicate check took %s.\n", time.Since(t).Round(time.Second))
	}

	meta := report.Meta{
		Tool: "pcaudit", Version: version, Host: host, User: userName,
		OS: runtime.GOOS + "/" + runtime.GOARCH, Started: started.Format(time.RFC3339),
		DurationSec: time.Since(started).Seconds(), Roots: roots,
		Files: res.Files, Dirs: res.Dirs, Bytes: res.Bytes, CloudOnly: col.CloudOnlyBytes,
		Errors: res.Errors, Links: res.Links, RulesFile: rulesPath, CustomRules: len(custom),
		GitChecked: useGit, DupesChecked: col.FindDupes,
	}
	if csvPath != "" {
		meta.CSV = "files.csv"
	}
	reportPath, err := report.Write(outDir, meta, res, col, cls, dupeGroups)
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
	if res.Errors > 0 {
		fmt.Printf("  %d folders or files couldn't be read (listed in the report).\n", res.Errors)
	}
	fmt.Printf("\nReport: %s\n", reportPath)

	if !*noOpen {
		openFile(reportPath)
	}
	return 0
}

const rulesFileName = "pcaudit-rules.json"

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
