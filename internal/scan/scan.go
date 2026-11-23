// Package scan walks folders in parallel and classifies every file it finds.
// It only reads folder listings and file metadata, never file contents.
package scan

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KevinALopez/pcaudit/internal/classify"
	"github.com/KevinALopez/pcaudit/internal/gitrepo"
)

const nv = classify.NumVerdicts

// Agg is a size and file count per verdict.
type Agg struct {
	Size  [nv]int64
	Count [nv]int64
}

func (a *Agg) Add(b *Agg) {
	for i := 0; i < int(nv); i++ {
		a.Size[i] += b.Size[i]
		a.Count[i] += b.Count[i]
	}
}

func (a *Agg) TotalSize() (t int64) {
	for _, s := range a.Size {
		t += s
	}
	return
}

func (a *Agg) TotalCount() (t int64) {
	for _, c := range a.Count {
		t += c
	}
	return
}

// Node is one folder. Parents always have a lower index than their children.
type Node struct {
	Parent int32
	Name   string
	Depth  uint16
	Rule   int16
	Own    Agg // files directly in this folder
	Total  Agg // this folder and everything below it
	Err    bool
}

// File flags.
const (
	FlagCloudOnly = 1 << iota // contents live only in the cloud
	FlagHidden
	FlagSystem
	FlagLink
	FlagCloud  // managed by a sync client
	FlagSparse // sparse file: Size is what it really uses on disk, Logical is its nominal size
	FlagDupe   // has an identical copy elsewhere (set when the report is written)
)

type File struct {
	Node    int32
	Name    string
	Size    int64
	Logical int64
	MTime   int64
	Res     classify.Result
	Flags   uint8
}

// Batch is the files of one folder, handed to OnBatch.
type Batch struct {
	Dir   string
	Files []File
}

type Stats struct {
	Files, Dirs, Bytes, Errors, Links int64
	Current                           string
}

// ErrEntry is something that couldn't be read. Expected means it's in a
// system, junk or reinstallable place where "access denied" is normal.
type ErrEntry struct {
	Path, Msg string
	Expected  bool
}

type Options struct {
	Roots      []string
	Workers    int
	Exclude    []string
	Classifier *classify.Classifier
	OnBatch    func(Batch) // always called from one goroutine
	Progress   func(Stats)
	Git        bool // ask git about every repository found
}

// Repo is a git repository found during the scan.
type Repo struct {
	Node   int32
	Status *gitrepo.Status
}

type Result struct {
	Nodes   []Node
	ErrList []ErrEntry // the first maxErrors problems; Stats.Errors has the full count
	Repos   []Repo
	Stats
	Elapsed time.Duration
}

const maxErrors = 2000

type job struct {
	node int32
	path string
	repo *repoCtx // nil outside git repositories
}

// repoCtx is a folder's position inside a git repository.
type repoCtx struct {
	st      *gitrepo.Status
	state   classify.RepoState
	rel     string // folder relative to the repo root: "" or "src/app/"
	ignored bool   // git ignores this folder
	gitDir  bool   // inside .git
}

type scanner struct {
	opt   Options
	cls   *classify.Classifier
	excl  map[string]bool
	mu    sync.Mutex // guards nodes and errors
	nodes []Node
	errs  []ErrEntry
	repos []Repo

	qmu     sync.Mutex
	qcond   *sync.Cond
	queue   []job
	pending int

	files, dirs, bytes, nerr, links atomic.Int64
	current                         atomic.Value
	batches                         chan Batch
}

// Run scans all roots and returns the folder tree with per-verdict totals.
func Run(opt Options) *Result {
	start := time.Now()
	if opt.Workers <= 0 {
		opt.Workers = 16
	}
	s := &scanner{opt: opt, cls: opt.Classifier, excl: map[string]bool{}, batches: make(chan Batch, 256)}
	s.qcond = sync.NewCond(&s.qmu)
	s.current.Store("")
	for _, e := range opt.Exclude {
		s.excl[classify.Normalize(e)] = true
	}

	for _, r := range opt.Roots {
		abs, err := filepath.Abs(r)
		if err != nil {
			abs = r
		}
		idx := int32(len(s.nodes))
		s.nodes = append(s.nodes, Node{Parent: -1, Name: abs, Rule: int16(s.cls.DirRule(abs))})
		s.push(job{node: idx, path: abs})
	}

	collected := make(chan struct{})
	go func() {
		for b := range s.batches {
			if opt.OnBatch != nil {
				opt.OnBatch(b)
			}
		}
		close(collected)
	}()

	stopProgress := make(chan struct{})
	if opt.Progress != nil {
		go func() {
			t := time.NewTicker(500 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					opt.Progress(s.stats())
				case <-stopProgress:
					return
				}
			}
		}()
	}

	var wg sync.WaitGroup
	for i := 0; i < opt.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				j, ok := s.pop()
				if !ok {
					return
				}
				s.process(j)
				s.done()
			}
		}()
	}
	wg.Wait()
	close(s.batches)
	<-collected
	close(stopProgress)

	// Roll totals up. Children come after parents, so walk backwards.
	for i := len(s.nodes) - 1; i >= 0; i-- {
		n := &s.nodes[i]
		n.Total.Add(&n.Own)
		if n.Parent >= 0 {
			s.nodes[n.Parent].Total.Add(&n.Total)
		}
	}
	return &Result{Nodes: s.nodes, ErrList: s.errs, Repos: s.repos, Stats: s.stats(), Elapsed: time.Since(start)}
}

func (s *scanner) stats() Stats {
	return Stats{
		Files: s.files.Load(), Dirs: s.dirs.Load(), Bytes: s.bytes.Load(),
		Errors: s.nerr.Load(), Links: s.links.Load(), Current: s.current.Load().(string),
	}
}

func (s *scanner) push(j job) {
	s.qmu.Lock()
	s.queue = append(s.queue, j)
	s.pending++
	s.qmu.Unlock()
	s.qcond.Signal()
}

// pop takes the newest job (depth-first keeps the queue small). It returns
// false once nothing is queued and no worker can add more.
func (s *scanner) pop() (job, bool) {
	s.qmu.Lock()
	defer s.qmu.Unlock()
	for len(s.queue) == 0 && s.pending > 0 {
		s.qcond.Wait()
	}
	if len(s.queue) == 0 {
		return job{}, false
	}
	j := s.queue[len(s.queue)-1]
	s.queue = s.queue[:len(s.queue)-1]
	return j, true
}

func (s *scanner) done() {
	s.qmu.Lock()
	s.pending--
	finished := s.pending == 0
	s.qmu.Unlock()
	if finished {
		s.qcond.Broadcast()
	}
}

func (s *scanner) addErr(path string, err error) {
	s.nerr.Add(1)
	expected := false
	if r := s.cls.DirRule(path); r >= 0 {
		v := s.cls.Rule(r).V
		expected = v == classify.Junk || v == classify.Reinstall
	}
	if base := strings.ToLower(filepath.Base(path)); base == "system volume information" || base == "perflogs" || base == "config.msi" {
		expected = true
	}
	// ProgramData folders that services lock down (Defender, antivirus, etc.).
	if strings.Contains(classify.Normalize(path), ":/programdata/") {
		expected = true
	}
	s.mu.Lock()
	if len(s.errs) < maxErrors {
		s.errs = append(s.errs, ErrEntry{path, err.Error(), expected})
	}
	s.mu.Unlock()
}

type subdir struct {
	name, path string
	rule       int16
	repo       *repoCtx
}

// repoHere starts a repo context when this folder is a git repository root.
// Repos inside junk or reinstallable places (node_modules, editor extensions)
// aren't worth a git call.
func (s *scanner) repoHere(j job, dirRule int, entries []os.DirEntry) *repoCtx {
	if !s.opt.Git || (j.repo != nil && j.repo.gitDir) {
		return j.repo
	}
	if dirRule >= 0 {
		if r := s.cls.Rule(dirRule); r.Strong && (r.V == classify.Junk || r.V == classify.Reinstall) {
			return j.repo
		}
	}
	found := false
	for _, e := range entries {
		if e.Name() == ".git" {
			found = true
			break
		}
	}
	if !found {
		return j.repo
	}
	st := gitrepo.Check(j.path)
	s.mu.Lock()
	s.repos = append(s.repos, Repo{Node: j.node, Status: st})
	s.mu.Unlock()
	return &repoCtx{st: st, state: classify.RepoState{
		Known: st.Known(), HasRemote: st.HasRemote(), HeadPushed: st.HeadPushed(), AllPushed: st.AllPushed(),
	}}
}

// child returns the repo context for a subfolder.
func (c *repoCtx) child(name string) *repoCtx {
	if c == nil {
		return nil
	}
	n := *c
	n.rel = c.rel + name + "/"
	switch {
	case c.rel == "" && name == ".git":
		n.gitDir = true
	case !c.ignored && !c.gitDir && c.st.IsIgnoredDir(n.rel):
		n.ignored = true
	}
	return &n
}

// place says how git sees a file in this folder.
func (c *repoCtx) place(name string) classify.RepoPlace {
	rel := c.rel + name
	switch {
	case c.gitDir:
		return classify.RepoGitDir
	case c.ignored || c.st.IsIgnored(rel):
		return classify.NotInRepo
	case c.st.IsChanged(rel):
		return classify.RepoChanged
	}
	return classify.RepoTracked
}

func (s *scanner) process(j job) {
	s.current.Store(j.path)
	s.dirs.Add(1)

	s.mu.Lock()
	dirRule := int(s.nodes[j.node].Rule)
	depth := s.nodes[j.node].Depth
	s.mu.Unlock()

	// ReadDir can return some entries along with an error, so use both.
	entries, err := os.ReadDir(j.path)
	if err != nil {
		s.addErr(j.path, err)
	}
	repo := s.repoHere(j, dirRule, entries)

	var own Agg
	var subs []subdir
	files := make([]File, 0, len(entries))
	var nbytes int64

	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			s.addErr(filepath.Join(j.path, e.Name()), err)
			continue
		}
		a := attrsOf(fi)
		full := filepath.Join(j.path, e.Name())
		isDir := a&classify.AttrDirectory != 0 || fi.IsDir()
		reparse := a&classify.AttrReparsePoint != 0
		cloud := a&classify.AttrCloudAny != 0

		if isDir {
			if s.excl[classify.Normalize(full)] {
				continue
			}
			rule := s.cls.DirRule(full)
			inCloudFolder := rule >= 0 && s.cls.Rule(rule).Cloud
			// Junctions and symlinks would cause loops and double counting.
			// Cloud sync folders are reparse points too, so those are fine.
			if reparse && !cloud && !inCloudFolder {
				s.links.Add(1)
				continue
			}
			subs = append(subs, subdir{e.Name(), full, int16(rule), repo.child(e.Name())})
			continue
		}

		var flags uint8
		if a&classify.AttrHidden != 0 {
			flags |= FlagHidden
		}
		if a&classify.AttrSystem != 0 {
			flags |= FlagSystem
		}
		if cloud {
			flags |= FlagCloud
		}
		if a&classify.AttrCloudOnly != 0 {
			flags |= FlagCloudOnly
		}

		nameL := strings.ToLower(e.Name())
		var res classify.Result
		inCloudFolder := dirRule >= 0 && s.cls.Rule(dirRule).Cloud
		if reparse && !cloud && !inCloudFolder {
			flags |= FlagLink
			s.links.Add(1)
			res = classify.Result{Cat: classify.CategoryOf(nameL), V: classify.Review, Reason: classify.LinkReason()}
		} else if repo != nil {
			res = s.cls.FileInRepo(dirRule, nameL, a, repo.place(e.Name()), repo.state)
		} else {
			res = s.cls.File(dirRule, nameL, a)
		}

		logical := fi.Size()
		size, sparse := allocatedSize(full, a, logical)
		if sparse {
			flags |= FlagSparse
		}
		own.Size[res.V] += size
		own.Count[res.V]++
		nbytes += size
		files = append(files, File{
			Node: j.node, Name: e.Name(), Size: size, Logical: logical, MTime: fi.ModTime().Unix(), Res: res, Flags: flags,
		})
	}

	s.mu.Lock()
	n := &s.nodes[j.node]
	n.Own = own
	n.Err = err != nil
	first := int32(len(s.nodes))
	for _, sd := range subs {
		s.nodes = append(s.nodes, Node{Parent: j.node, Name: sd.name, Depth: depth + 1, Rule: sd.rule})
	}
	s.mu.Unlock()

	for i, sd := range subs {
		s.push(job{node: first + int32(i), path: sd.path, repo: sd.repo})
	}

	s.files.Add(int64(len(files)))
	s.bytes.Add(nbytes)
	if len(files) > 0 {
		s.batches <- Batch{Dir: j.path, Files: files}
	}
}
