// Package report turns scan results into a files.csv, a summary.json and a
// self-contained report.html that opens offline in any browser.
package report

import (
	"bufio"
	"container/heap"
	"encoding/csv"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/KevinALopez/pcaudit/internal/classify"
	"github.com/KevinALopez/pcaudit/internal/scan"
)

// How many files of each verdict the HTML report carries. Everything else is
// still counted in the folder totals and listed in files.csv.
var embedCaps = [classify.NumVerdicts]int{
	classify.Backup:    60000,
	classify.Safe:      5000,
	classify.Reinstall: 3000,
	classify.Junk:      3000,
	classify.Review:    25000,
}

// Collector receives file batches during the scan.
type Collector struct {
	csvFile *os.File
	csvBuf  *bufio.Writer
	csv     *csv.Writer
	heaps   [classify.NumVerdicts]fileHeap

	CatAgg         [classify.NumCategories]scan.Agg
	CloudOnlyBytes int64
	CSVPath        string
}

// NewCollector creates a collector. When csvPath is empty no CSV is written.
func NewCollector(csvPath string) (*Collector, error) {
	c := &Collector{CSVPath: csvPath}
	if csvPath != "" {
		f, err := os.Create(csvPath)
		if err != nil {
			return nil, err
		}
		c.csvFile = f
		c.csvBuf = bufio.NewWriterSize(f, 1<<20)
		c.csvBuf.WriteString("\xEF\xBB\xBF") // so Excel reads it as UTF-8
		c.csv = csv.NewWriter(c.csvBuf)
		c.csv.Write([]string{"path", "size_bytes", "size_on_disk", "modified", "category", "verdict", "reason", "hidden", "cloud_synced", "cloud_only", "link"})
	}
	return c, nil
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return ""
}

// Add handles one folder's files. The scanner calls it from one goroutine.
func (c *Collector) Add(b scan.Batch) {
	for _, f := range b.Files {
		agg := &c.CatAgg[f.Res.Cat]
		agg.Size[f.Res.V] += f.Size
		agg.Count[f.Res.V]++
		if f.Flags&scan.FlagCloudOnly != 0 {
			c.CloudOnlyBytes += f.Size
		}

		h := &c.heaps[f.Res.V]
		if limit := embedCaps[f.Res.V]; h.Len() < limit {
			heap.Push(h, f)
		} else if limit > 0 && (*h)[0].Size < f.Size {
			(*h)[0] = f
			heap.Fix(h, 0)
		}

		if c.csv != nil {
			c.csv.Write([]string{
				filepath.Join(b.Dir, f.Name),
				strconv.FormatInt(f.Logical, 10),
				strconv.FormatInt(f.Size, 10),
				time.Unix(f.MTime, 0).Format("2006-01-02 15:04"),
				classify.CategoryNames[f.Res.Cat],
				classify.VerdictNames[f.Res.V],
				classify.Reasons[f.Res.Reason],
				yn(f.Flags&scan.FlagHidden != 0),
				yn(f.Flags&scan.FlagCloud != 0),
				yn(f.Flags&scan.FlagCloudOnly != 0),
				yn(f.Flags&scan.FlagLink != 0),
			})
		}
	}
}

// Close flushes the CSV.
func (c *Collector) Close() error {
	if c.csv == nil {
		return nil
	}
	c.csv.Flush()
	if err := c.csvBuf.Flush(); err != nil {
		return err
	}
	return c.csvFile.Close()
}

// Embedded returns the files kept for the HTML report.
func (c *Collector) Embedded() []scan.File {
	var out []scan.File
	for i := range c.heaps {
		out = append(out, c.heaps[i]...)
	}
	return out
}

// fileHeap is a min-heap by size, so the biggest files stay in.
type fileHeap []scan.File

func (h fileHeap) Len() int           { return len(h) }
func (h fileHeap) Less(i, j int) bool { return h[i].Size < h[j].Size }
func (h fileHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *fileHeap) Push(x any)        { *h = append(*h, x.(scan.File)) }
func (h *fileHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}
