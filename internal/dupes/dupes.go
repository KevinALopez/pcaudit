// Package dupes finds files with identical contents. It narrows candidates
// down cheaply first (same size, then same first and last 64 KB) and only
// reads whole files when those still match.
package dupes

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sort"
	"sync"
	"sync/atomic"
)

// Candidate is a file that might have duplicates.
type Candidate struct {
	Path string
	Size int64
	Node int32
	Name string
}

// Group is a set of files with the same contents.
type Group struct {
	Size  int64
	Hash  string
	Files []Candidate
}

// Wasted is the space the extra copies take.
func (g Group) Wasted() int64 { return g.Size * int64(len(g.Files)-1) }

const edge = 64 << 10

// Progress reports how far Find is. Phase "sample" counts files whose first
// and last 64 KB are compared; phase "full" counts bytes read in full.
type Progress func(phase string, done, total int64)

// ErrDisk is returned when the drive failed a read. Find stops right away
// then: reading a failing drive harder can crash the computer.
type ErrDisk struct {
	Path string
	Err  error
}

func (e *ErrDisk) Error() string { return "the drive failed to read " + e.Path + ": " + e.Err.Error() }

// Find returns groups of identical files, biggest waste first. isDiskErr
// tells a failing drive apart from ordinary errors such as a locked file.
func Find(cands []Candidate, workers int, progress Progress, isDiskErr func(error) bool) ([]Group, error) {
	var stop atomic.Pointer[ErrDisk]
	guard := func(hash func(Candidate) (string, error)) func(Candidate) (string, error) {
		return func(c Candidate) (string, error) {
			if stop.Load() != nil {
				return "", errStopped
			}
			h, err := hash(c)
			if err != nil && isDiskErr != nil && isDiskErr(err) {
				stop.CompareAndSwap(nil, &ErrDisk{c.Path, err})
			}
			return h, err
		}
	}
	if workers <= 0 {
		workers = 4
	}
	bySize := map[int64][]Candidate{}
	for _, c := range cands {
		bySize[c.Size] = append(bySize[c.Size], c)
	}
	var stage [][]Candidate
	for _, g := range bySize {
		if len(g) > 1 {
			stage = append(stage, g)
		}
	}

	if progress == nil {
		progress = func(string, int64, int64) {}
	}
	var files int64
	for _, g := range stage {
		files += int64(len(g))
	}
	var done atomic.Int64
	stage = refine(stage, workers, guard(partialHash), func(Candidate) { progress("sample", done.Add(1), files) })
	if e := stop.Load(); e != nil {
		return nil, e
	}

	// Files no bigger than the two sampled edges were already read whole.
	var bytesTotal int64
	for _, g := range stage {
		if g[0].Size > 2*edge {
			bytesTotal += g[0].Size * int64(len(g))
		}
	}
	var bytesDone atomic.Int64
	stage = refine(stage, workers, guard(func(c Candidate) (string, error) {
		if c.Size <= 2*edge {
			return partialHash(c)
		}
		return fullHash(c)
	}), func(c Candidate) {
		if c.Size > 2*edge {
			progress("full", bytesDone.Add(c.Size), bytesTotal)
		}
	})

	if e := stop.Load(); e != nil {
		return nil, e
	}

	out := make([]Group, 0, len(stage))
	for _, g := range stage {
		h, _ := partialHash(g[0]) // only for a stable id in the report
		sort.Slice(g, func(i, j int) bool { return g[i].Path < g[j].Path })
		out = append(out, Group{Size: g[0].Size, Hash: h[:16], Files: g})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Wasted() > out[j].Wasted() })
	return out, nil
}

var errStopped = errors.New("stopped after a disk error")

// refine splits every group by a hash and keeps the subgroups that still
// hold more than one file. Files that can't be read drop out.
func refine(groups [][]Candidate, workers int, hash func(Candidate) (string, error), tick func(Candidate)) [][]Candidate {
	type item struct {
		g, i int
	}
	keys := make([][]string, len(groups))
	jobs := make(chan item)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range jobs {
				c := groups[it.g][it.i]
				if h, err := hash(c); err == nil {
					keys[it.g][it.i] = h
				}
				tick(c)
			}
		}()
	}
	for g := range groups {
		keys[g] = make([]string, len(groups[g]))
		for i := range groups[g] {
			jobs <- item{g, i}
		}
	}
	close(jobs)
	wg.Wait()

	var out [][]Candidate
	for g, group := range groups {
		byKey := map[string][]Candidate{}
		for i, c := range group {
			if k := keys[g][i]; k != "" {
				byKey[k] = append(byKey[k], c)
			}
		}
		for _, sub := range byKey {
			if len(sub) > 1 {
				out = append(out, sub)
			}
		}
	}
	return out
}

// partialHash hashes the size, the first 64 KB and the last 64 KB.
func partialHash(c Candidate) (string, error) {
	f, err := os.Open(c.Path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, edge)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return "", err
	}
	h.Write(buf[:n])
	if c.Size > 2*edge {
		if _, err := f.ReadAt(buf, c.Size-edge); err != nil && err != io.EOF {
			return "", err
		}
		h.Write(buf)
	} else if c.Size > edge {
		rest, err := io.ReadAll(f)
		if err != nil {
			return "", err
		}
		h.Write(rest)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fullHash(c Candidate) (string, error) {
	f, err := os.Open(c.Path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	// Big reads: each read call has a fixed cost (antivirus filters included).
	if _, err := io.CopyBuffer(h, f, make([]byte, 1<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
