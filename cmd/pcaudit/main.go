// pcaudit inventories a computer before a factory reset. It walks your drives,
// sorts every file into "back up / already safe / reinstallable / junk / review",
// and writes an offline HTML report next to a full CSV listing.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/KevinALopez/pcaudit/internal/classify"
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

	cls := classify.New([]string{os.Getenv("OneDrive"), os.Getenv("OneDriveCommercial"), os.Getenv("OneDriveConsumer")})

	fmt.Printf("pcaudit %s: scanning %s\n", version, strings.Join(roots, ", "))
	fmt.Println("Read-only: only folder listings and file details are read, never file contents.")
	res := scan.Run(scan.Options{
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

	meta := report.Meta{
		Tool: "pcaudit", Version: version, Host: host, User: userName,
		OS: runtime.GOOS + "/" + runtime.GOARCH, Started: started.Format(time.RFC3339),
		DurationSec: res.Elapsed.Seconds(), Roots: roots,
		Files: res.Files, Dirs: res.Dirs, Bytes: res.Bytes, CloudOnly: col.CloudOnlyBytes,
		Errors: res.Errors, Links: res.Links,
	}
	if csvPath != "" {
		meta.CSV = "files.csv"
	}
	reportPath, err := report.Write(outDir, meta, res, col, cls)
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
	if res.Errors > 0 {
		fmt.Printf("\n  %d folders or files couldn't be read (listed in the report).\n", res.Errors)
	}
	fmt.Printf("\nReport: %s\n", reportPath)

	if !*noOpen {
		openFile(reportPath)
	}
	return 0
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
