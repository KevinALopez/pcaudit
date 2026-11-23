package scan

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/KevinALopez/pcaudit/internal/classify"
	"github.com/KevinALopez/pcaudit/internal/gitrepo"
)

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	full := append([]string{"-C", dir, "-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "init.defaultBranch=main", "-c", "core.autocrlf=false"}, args...)
	if out, err := exec.Command("git", full...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// workDir makes a folder next to the test instead of in the system temp
// folder: Temp is classified as junk, which would hide what we're testing.
func workDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", "testscan-")
	if err != nil {
		t.Fatal(err)
	}
	dir, _ = filepath.Abs(dir)
	t.Cleanup(func() {
		// git makes its object files read-only, which blocks deleting on Windows.
		filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err == nil {
				os.Chmod(p, 0o777)
			}
			return nil
		})
		os.RemoveAll(dir)
	})
	return dir
}

func TestGitVerdicts(t *testing.T) {
	if !gitrepo.Available() {
		t.Skip("git not installed")
	}
	root := workDir(t)

	// A repo pushed to a (local, bare) remote, then changed.
	remote := filepath.Join(root, "remote.git")
	git(t, root, "init", "-q", "--bare", remote)
	proj := filepath.Join(root, "proj")
	write(t, filepath.Join(proj, "pushed.txt"), "v1")
	write(t, filepath.Join(proj, "edited.txt"), "v1")
	write(t, filepath.Join(proj, ".gitignore"), "build/\n")
	git(t, proj, "init", "-q")
	git(t, proj, "add", ".")
	git(t, proj, "commit", "-q", "-m", "first")
	git(t, proj, "remote", "add", "origin", remote)
	git(t, proj, "push", "-q", "origin", "HEAD")
	write(t, filepath.Join(proj, "edited.txt"), "v2")
	write(t, filepath.Join(proj, "new.txt"), "new")
	write(t, filepath.Join(proj, "build", "out.exe"), "x")

	// A repo with no remote at all.
	local := filepath.Join(root, "local")
	write(t, filepath.Join(local, "notes.txt"), "mine")
	git(t, local, "init", "-q")
	git(t, local, "add", ".")
	git(t, local, "commit", "-q", "-m", "first")

	got := map[string]classify.Verdict{}
	res := Run(Options{
		Roots:      []string{proj, local},
		Workers:    4,
		Classifier: classify.New(nil),
		Git:        true,
		OnBatch: func(b Batch) {
			for _, f := range b.Files {
				rel, _ := filepath.Rel(root, filepath.Join(b.Dir, f.Name))
				got[filepath.ToSlash(rel)] = f.Res.V
			}
		},
	})

	want := map[string]classify.Verdict{
		"proj/pushed.txt":    classify.Safe,
		"proj/edited.txt":    classify.Backup,
		"proj/new.txt":       classify.Backup,
		"proj/.git/HEAD":     classify.Safe,
		"local/notes.txt":    classify.Backup,
		"local/.git/HEAD":    classify.Backup,
		"proj/build/out.exe": classify.Reinstall, // ignored by git, so the normal rules apply
	}
	for path, v := range want {
		if g, ok := got[path]; !ok {
			t.Errorf("%s: not scanned", path)
		} else if g != v {
			t.Errorf("%s: got %s, want %s", path, classify.VerdictNames[g], classify.VerdictNames[v])
		}
	}

	if len(res.Repos) != 2 {
		t.Fatalf("found %d repos, want 2", len(res.Repos))
	}
	for _, r := range res.Repos {
		st := r.Status
		switch filepath.Base(st.Root) {
		case "proj":
			if st.Changed != 1 || st.Untracked != 1 || !st.HeadPushed() {
				t.Errorf("proj status: %+v", st)
			}
		case "local":
			if st.HasRemote() || st.HeadUnpushed != 1 {
				t.Errorf("local status: %+v", st)
			}
		}
	}
}
