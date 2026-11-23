package report

import (
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/KevinALopez/pcaudit/internal/classify"
	"github.com/KevinALopez/pcaudit/internal/dupes"
	"github.com/KevinALopez/pcaudit/internal/gitrepo"
	"github.com/KevinALopez/pcaudit/internal/scan"
)

//go:embed report.html
var htmlTemplate string

const dataMarker = "__PCAUDIT_DATA__"

// Meta describes the scan.
type Meta struct {
	Tool        string   `json:"tool"`
	Version     string   `json:"version"`
	Host        string   `json:"host"`
	User        string   `json:"user"`
	OS          string   `json:"os"`
	Started     string   `json:"started"`
	DurationSec float64  `json:"durationSec"`
	Roots       []string `json:"roots"`
	Files       int64    `json:"files"`
	Dirs        int64    `json:"dirs"`
	Bytes       int64    `json:"bytes"`
	CloudOnly   int64    `json:"cloudOnlyBytes"`
	Errors      int64    `json:"errors"`
	Links       int64    `json:"links"`
	Embedded    int      `json:"embeddedFiles"`
	KeptNodes   int      `json:"keptFolders"`
	CSV         string   `json:"csv,omitempty"`

	RulesFile    string `json:"rulesFile,omitempty"`
	CustomRules  int    `json:"customRules,omitempty"`
	GitChecked   bool   `json:"gitChecked"`
	DupesChecked bool   `json:"dupesChecked"`
	DupeMinSize  int64  `json:"dupeMinSize"`
}

// maxDupeGroups caps how many duplicate sets the report lists.
const maxDupeGroups = 1000

type payload struct {
	Meta       Meta      `json:"meta"`
	Verdicts   []string  `json:"verdicts"`
	Categories []string  `json:"categories"`
	Reasons    []string  `json:"reasons"`
	CatSizes   [][]int64 `json:"catSizes"`  // [category][verdict] bytes
	CatCounts  [][]int64 `json:"catCounts"` // [category][verdict] files
	Nodes      [][]any   `json:"nodes"`     // parent, name, totalCount, [sizes per verdict], [own sizes per verdict], ownCount, reason, err
	Files      [][]any   `json:"files"`     // node, name, size, mtime, category, verdict, reason, flags
	Groups     [][]any   `json:"groups"`    // node, reason, [sizes per verdict], [counts per verdict]
	Errors     [][]any   `json:"errors"`    // path, message, expected (0/1); unexpected ones first
	Repos      [][]any   `json:"repos"`     // node, remote, branch, changed, untracked, headUnpushed, allUnpushed, stashes, error, [sizes per verdict]
	Dupes      [][]any   `json:"dupes"`     // size, [[node, name], ...]
}

// Write produces report.html and summary.json in outDir. It returns the
// report path.
func Write(outDir string, meta Meta, res *scan.Result, col *Collector, cls *classify.Classifier, dupeGroups []dupes.Group) (string, error) {
	nodes := res.Nodes
	files := col.Embedded()
	sort.Slice(files, func(i, j int) bool { return files[i].Size > files[j].Size })
	if len(dupeGroups) > maxDupeGroups {
		dupeGroups = dupeGroups[:maxDupeGroups]
	}
	meta.DupeMinSize = DupeMinSize

	// Flag the embedded files that have an identical copy somewhere.
	type fileKey struct {
		node int32
		name string
	}
	isDupe := map[fileKey]bool{}
	for _, g := range dupeGroups {
		for _, f := range g.Files {
			isDupe[fileKey{f.Node, f.Name}] = true
		}
	}
	for i := range files {
		if isDupe[fileKey{files[i].Node, files[i].Name}] {
			files[i].Flags |= scan.FlagDupe
		}
	}

	groupOf := computeGroups(nodes)

	// Decide which folders the HTML carries: shallow ones, big ones, group
	// roots and every folder that holds an embedded file.
	var grand int64
	for i := range nodes {
		if nodes[i].Parent < 0 {
			grand += nodes[i].Total.TotalSize()
		}
	}
	threshold := grand / 100000
	if threshold < 1<<20 {
		threshold = 1 << 20
	}
	keep := make([]bool, len(nodes))
	mark := func(i int32) {
		for i >= 0 && !keep[i] {
			keep[i] = true
			i = nodes[i].Parent
		}
	}
	for i := range nodes {
		if nodes[i].Depth <= 2 || nodes[i].Total.TotalSize() >= threshold {
			mark(int32(i))
		}
		mark(groupOf[i])
	}
	for _, f := range files {
		mark(f.Node)
	}
	for _, r := range res.Repos {
		mark(r.Node)
	}
	for _, g := range dupeGroups {
		for _, f := range g.Files {
			mark(f.Node)
		}
	}

	remap := make([]int32, len(nodes))
	p := payload{
		Verdicts:   classify.VerdictNames[:],
		Categories: classify.CategoryNames[:],
		Reasons:    classify.Reasons,
	}
	ruleReason := func(n *scan.Node) int {
		if n.Rule < 0 {
			return -1
		}
		return int(cls.Rule(int(n.Rule)).Reason)
	}
	for i := range nodes {
		if !keep[i] {
			remap[i] = -1
			continue
		}
		n := &nodes[i]
		remap[i] = int32(len(p.Nodes))
		parent := int32(-1)
		if n.Parent >= 0 {
			parent = remap[n.Parent]
		}
		errFlag := 0
		if n.Err {
			errFlag = 1
		}
		p.Nodes = append(p.Nodes, []any{
			parent, n.Name, n.Total.TotalCount(), n.Total.Size[:], n.Own.Size[:], n.Own.TotalCount(), ruleReason(n), errFlag,
		})
	}
	for _, f := range files {
		p.Files = append(p.Files, []any{remap[f.Node], f.Name, f.Size, f.MTime, f.Res.Cat, f.Res.V, f.Res.Reason, f.Flags})
	}

	// Groups: total Own sizes per group root.
	gm := map[int32]*groupOut{}
	for i := range nodes {
		g := groupOf[i]
		ga := gm[g]
		if ga == nil {
			ga = &groupOut{root: g}
			gm[g] = ga
		}
		ga.agg.Add(&nodes[i].Own)
	}
	groups := make([]*groupOut, 0, len(gm))
	for _, g := range gm {
		if g.agg.TotalSize() > 0 || g.agg.TotalCount() > 0 {
			groups = append(groups, g)
		}
	}
	sort.Slice(groups, func(i, j int) bool {
		a, b := groups[i].agg, groups[j].agg
		if a.Size[classify.Backup] != b.Size[classify.Backup] {
			return a.Size[classify.Backup] > b.Size[classify.Backup]
		}
		return a.TotalSize() > b.TotalSize()
	})
	if len(groups) > 500 {
		groups = groups[:500]
	}
	for _, g := range groups {
		p.Groups = append(p.Groups, []any{remap[g.root], ruleReason(&nodes[g.root]), g.agg.Size[:], g.agg.Count[:]})
	}

	for c := 0; c < int(classify.NumCategories); c++ {
		p.CatSizes = append(p.CatSizes, col.CatAgg[c].Size[:])
		p.CatCounts = append(p.CatCounts, col.CatAgg[c].Count[:])
	}
	errs := append([]scan.ErrEntry(nil), res.ErrList...)
	sort.SliceStable(errs, func(i, j int) bool { return !errs[i].Expected && errs[j].Expected })
	for _, e := range errs {
		exp := 0
		if e.Expected {
			exp = 1
		}
		p.Errors = append(p.Errors, []any{e.Path, e.Msg, exp})
	}

	repos := sortedRepos(res)
	for _, r := range repos {
		st := r.Status
		p.Repos = append(p.Repos, []any{remap[r.Node], st.Remote, st.Branch, st.Changed, st.Untracked,
			st.HeadUnpushed, st.AllUnpushed, st.Stashes, st.Err, nodes[r.Node].Total.Size[:]})
	}
	for _, g := range dupeGroups {
		list := make([][]any, len(g.Files))
		for i, f := range g.Files {
			list[i] = []any{remap[f.Node], f.Name}
		}
		p.Dupes = append(p.Dupes, []any{g.Size, list})
	}

	meta.Embedded = len(p.Files)
	meta.KeptNodes = len(p.Nodes)
	p.Meta = meta

	data, err := json.Marshal(p) // escapes <, > and &, so it is safe inside <script>
	if err != nil {
		return "", err
	}
	html := strings.Replace(htmlTemplate, dataMarker, string(data), 1)
	reportPath := filepath.Join(outDir, "report.html")
	if err := os.WriteFile(reportPath, []byte(html), 0o644); err != nil {
		return "", err
	}

	if err := writeSummary(outDir, meta, nodes, groups, col, cls, repos, dupeGroups); err != nil {
		return "", err
	}
	return reportPath, nil
}

// sortedRepos puts repositories with work at risk first, biggest first.
func sortedRepos(res *scan.Result) []scan.Repo {
	repos := append([]scan.Repo(nil), res.Repos...)
	sort.SliceStable(repos, func(i, j int) bool {
		a, b := repos[i].Status.Clean(), repos[j].Status.Clean()
		if a != b {
			return !a
		}
		return res.Nodes[repos[i].Node].Total.TotalSize() > res.Nodes[repos[j].Node].Total.TotalSize()
	})
	return repos
}

// groupOut is the total size of one group of folders (see computeGroups).
type groupOut struct {
	root int32
	agg  scan.Agg
}

// computeGroups assigns every folder to a "group": the folder where its rule
// starts (Desktop, .ssh, node_modules...). Folders without a rule are grouped
// by their top-level folder, or by the first folder inside a user profile.
func computeGroups(nodes []scan.Node) []int32 {
	group := make([]int32, len(nodes))
	inProfile := make([]bool, len(nodes))
	profileRoot := make([]bool, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		if n.Parent < 0 {
			group[i] = int32(i)
			continue
		}
		par := &nodes[n.Parent]
		if n.Depth == 2 {
			pn := strings.ToLower(par.Name)
			profileRoot[i] = pn == "users" || pn == "home"
		}
		inProfile[i] = profileRoot[i] || inProfile[n.Parent]
		switch {
		case n.Rule >= 0 && n.Rule == par.Rule:
			group[i] = group[n.Parent]
		case n.Rule >= 0:
			group[i] = int32(i)
		case n.Depth <= 1, profileRoot[i], inProfile[i] && profileRoot[n.Parent]:
			group[i] = int32(i)
		default:
			group[i] = group[n.Parent]
		}
	}
	return group
}

func nodePath(nodes []scan.Node, i int32) string {
	var parts []string
	for i >= 0 {
		parts = append(parts, nodes[i].Name)
		i = nodes[i].Parent
	}
	for l, r := 0, len(parts)-1; l < r; l, r = l+1, r-1 {
		parts[l], parts[r] = parts[r], parts[l]
	}
	return filepath.Join(parts...)
}

type repo struct {
	*gitrepo.Status
	Clean bool `json:"clean"`
}

type dupe struct {
	Size   int64    `json:"size"`
	Wasted int64    `json:"wasted"`
	Paths  []string `json:"paths"`
}

type verdictTotal struct {
	Verdict string `json:"verdict"`
	Bytes   int64  `json:"bytes"`
	Files   int64  `json:"files"`
}

func totals(a scan.Agg) []verdictTotal {
	out := make([]verdictTotal, classify.NumVerdicts)
	for v := range out {
		out[v] = verdictTotal{classify.VerdictNames[v], a.Size[v], a.Count[v]}
	}
	return out
}

func writeSummary(outDir string, meta Meta, nodes []scan.Node, groups []*groupOut, col *Collector, cls *classify.Classifier, repos []scan.Repo, dupeGroups []dupes.Group) error {
	var all scan.Agg
	for i := range nodes {
		if nodes[i].Parent < 0 {
			all.Add(&nodes[i].Total)
		}
	}
	type group struct {
		Path   string         `json:"path"`
		Reason string         `json:"reason,omitempty"`
		Totals []verdictTotal `json:"totals"`
	}
	type category struct {
		Category string         `json:"category"`
		Totals   []verdictTotal `json:"totals"`
	}
	out := struct {
		Meta       Meta           `json:"meta"`
		Generated  string         `json:"generated"`
		Totals     []verdictTotal `json:"totals"`
		Categories []category     `json:"categories"`
		Groups     []group        `json:"groups"`
		Repos      []repo         `json:"repos"`
		Duplicates []dupe         `json:"duplicates"`
	}{Meta: meta, Generated: time.Now().Format(time.RFC3339), Totals: totals(all)}

	for _, r := range repos {
		out.Repos = append(out.Repos, repo{r.Status, r.Status.Clean()})
	}
	for _, g := range dupeGroups {
		d := dupe{Size: g.Size, Wasted: g.Wasted()}
		for _, f := range g.Files {
			d.Paths = append(d.Paths, f.Path)
		}
		out.Duplicates = append(out.Duplicates, d)
	}

	for c := range col.CatAgg {
		out.Categories = append(out.Categories, category{classify.CategoryNames[c], totals(col.CatAgg[c])})
	}
	for _, g := range groups {
		r := ""
		if n := nodes[g.root]; n.Rule >= 0 {
			r = classify.Reasons[cls.Rule(int(n.Rule)).Reason]
		}
		out.Groups = append(out.Groups, group{nodePath(nodes, g.root), r, totals(g.agg)})
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, "summary.json"), b, 0o644)
}
