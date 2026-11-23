// Package classify decides, for every file, what kind of file it is (Category)
// and what a factory reset means for it (Verdict).
package classify

import (
	"strings"
)

// Verdict answers "what happens to this if I wipe the machine?".
type Verdict uint8

const (
	Backup    Verdict = iota // only exists here, so copy it somewhere
	Safe                     // already exists somewhere else (cloud sync, server)
	Reinstall                // can be downloaded or reinstalled again
	Junk                     // caches and temp files, fine to lose
	Review                   // can't tell, a human should look
	NumVerdicts
)

var VerdictNames = [NumVerdicts]string{"Back up", "Already safe", "Reinstallable", "Junk", "Review"}

// Windows file attribute bits. Other platforms synthesize the few that matter.
const (
	AttrHidden            = 0x2
	AttrSystem            = 0x4
	AttrDirectory         = 0x10
	AttrReparsePoint      = 0x400
	AttrOffline           = 0x1000
	AttrRecallOnOpen      = 0x40000
	AttrPinned            = 0x80000
	AttrUnpinned          = 0x100000
	AttrRecallOnDataAcces = 0x400000

	// A file the cloud sync engine manages: placeholder, pinned, or online-only.
	AttrCloudAny = AttrOffline | AttrRecallOnOpen | AttrPinned | AttrUnpinned | AttrRecallOnDataAcces
	// Contents are not on this disk at all.
	AttrCloudOnly = AttrOffline | AttrRecallOnDataAcces
)

type ruleKind uint8

const (
	anywhere  ruleKind = iota // path contains /pat/ somewhere
	driveRel                  // path relative to the drive root starts with pat
	userRel                   // path relative to a user profile (Users/<name>/) starts with pat
	absPrefix                 // absolute normalized path starts with pat
)

// Rule maps a folder to a verdict. A Strong rule beats the file type;
// a weak one is only a default for files the type rules don't settle.
type Rule struct {
	kind   ruleKind
	pat    string
	V      Verdict
	Strong bool
	// Cloud means "safe only if the file shows cloud-sync attributes".
	Cloud  bool
	Reason uint8
}

var Reasons []string

func reason(s string) uint8 {
	for i, r := range Reasons {
		if r == s {
			return uint8(i)
		}
	}
	Reasons = append(Reasons, s)
	return uint8(len(Reasons) - 1)
}

type ruleSpec struct {
	kind   ruleKind
	V      Verdict
	strong bool
	reason string
	pats   []string
}

// Order matters: the first matching rule wins, so specific rules go first.
var specs = []ruleSpec{
	// Junk: caches, temp, crash dumps, leftovers.
	{anywhere, Junk, true, "Recycle bin", []string{"$recycle.bin"}},
	{anywhere, Junk, true, "Cache folder", []string{"cache", "caches", "code cache", "gpucache", "shadercache",
		"dawncache", "grshadercache", "graphitedawncache", "cachestorage", "inetcache", ".cache", "__pycache__",
		".pytest_cache", ".mypy_cache", ".ruff_cache", ".parcel-cache", ".turbo", "npm-cache", "_cacache",
		"d3dscache", "thumbcache", "crashpad", "crashdumps", "crash reports", "steamapps/downloading", "steamapps/shadercache"}},
	{userRel, Junk, true, "Temp folder", []string{"appdata/local/temp/", "appdata/locallow/temp/"}},
	{userRel, Junk, true, "Windows cache", []string{"appdata/local/microsoft/windows/explorer/",
		"appdata/local/microsoft/windows/webcache/", "appdata/local/microsoft/windows/inetcookies/",
		"appdata/local/microsoft/windows/wer/", "appdata/local/nvidia/", "appdata/local/pip/cache/",
		"appdata/local/yarn/cache/", "appdata/local/go-build/"}},
	// Windows.old/Users is treated as a normal profile (see split), the rest is junk.
	{driveRel, Junk, true, "Windows leftovers", []string{"windows.old/windows/", "windows.old/program files/",
		"windows.old/program files (x86)/", "windows.old/programdata/", "$windows.~bt/", "$windows.~ws/",
		"$winreagent/", "$getcurrent/", "$sysreset/", "perflogs/", "onedrivetemp/", "msocache/", "esd/",
		"intel/", "amd/", "nvidia/", "swsetup/", "programdata/package cache/", "programdata/microsoft/windows/wer/",
		"windows/temp/", "windows/softwaredistribution/download/", "windows/prefetch/", "temp/", "tmp/"}},
	{anywhere, Junk, true, "System restore data", []string{"system volume information"}},

	// Cloud folders: safe when the sync client really manages the file.
	{userRel, Safe, true, "OneDrive", []string{"onedrive"}},
	{userRel, Safe, true, "Cloud sync folder", []string{"dropbox/", "google drive/", "my drive/", "iclouddrive/", "icloud drive/", "box/", "mega/", "pcloud drive/", "nextcloud/"}},

	// Reinstallable: Windows itself, programs, package managers, game installs.
	{driveRel, Reinstall, true, "Windows system", []string{"windows/", "recovery/", "boot/", "efi/"}},
	{driveRel, Reinstall, true, "Installed programs", []string{"program files/", "program files (x86)/", "programdata/microsoft/windows/start menu/"}},
	{driveRel, Reinstall, true, "Default user profile", []string{"users/default/", "users/all users/", "users/default user/"}},
	{anywhere, Reinstall, true, "Dependencies (re-downloadable)", []string{"node_modules", "bower_components", ".venv", "venv",
		"site-packages", ".gradle", ".m2/repository", "go/pkg/mod", ".cargo/registry", ".rustup", ".nuget/packages",
		".pnpm-store", ".yarn/cache", "vcpkg/downloads", ".conda/pkgs", "anaconda3/pkgs", "miniconda3/pkgs"}},
	{anywhere, Reinstall, true, "Build output", []string{"target/debug", "target/release", "bin/debug", "bin/release", "obj/debug", "obj/release", ".next", ".nuxt", ".angular"}},
	{anywhere, Reinstall, true, "Game install", []string{"steamapps/common", "steamlibrary/steamapps/common", "epic games", "xboxgames",
		"windowsapps", "riot games", "gog galaxy/games", "ubisoft game launcher/games", "ea games", "battle.net"}},
	{userRel, Reinstall, true, "User-installed programs", []string{"appdata/local/programs/", "appdata/local/microsoft/windowsapps/",
		"appdata/local/microsoft/onedrive/", "appdata/roaming/microsoft/windows/start menu/", "appdata/local/microsoft/windows/inetcache/",
		".vscode/extensions/", ".cursor/extensions/", "appdata/local/jetbrains/", "appdata/local/docker/", ".android/avd/", "appdata/local/android/sdk/"}},

	// Back up for sure: keys, dotfiles, editor settings, shell history.
	{userRel, Backup, true, "Keys & credentials", []string{".ssh/", ".gnupg/", ".aws/", ".azure/", ".kube/", ".docker/", ".gcloud/",
		".config/gcloud/", "appdata/roaming/gnupg/", ".password-store/"}},
	{userRel, Backup, true, "Editor & shell settings", []string{"appdata/roaming/code/user/", "appdata/roaming/cursor/user/",
		"appdata/roaming/microsoft/windows/powershell/psreadline/", "appdata/roaming/notepad++/",
		"appdata/local/packages/microsoft.windowsterminal_8wekyb3d8bbwe/localstate/", "appdata/roaming/jetbrains/"}},
	{userRel, Backup, true, "Game saves", []string{"saved games/", "documents/my games/"}},

	// Weak defaults: your own folders, app data, browser profiles.
	{userRel, Backup, false, "Your files", []string{"desktop/", "documents/", "pictures/", "videos/", "music/", "downloads/",
		"favorites/", "contacts/", "links/", "3d objects/", "source/", "projects/", "dev/", "repos/", "code/", "work/"}},
	{userRel, Review, false, "Browser profile (check sync is on)", []string{"appdata/local/google/chrome/user data/",
		"appdata/local/microsoft/edge/user data/", "appdata/roaming/mozilla/firefox/profiles/",
		"appdata/local/bravesoftware/", "appdata/roaming/opera software/", "appdata/local/vivaldi/"}},
	{userRel, Review, false, "Game data (may include saves)", []string{"appdata/locallow/"}},
	{userRel, Review, false, "App data", []string{"appdata/"}},
	{driveRel, Review, false, "Shared app data", []string{"programdata/"}},
	{driveRel, Review, false, "Public user folder", []string{"users/public/"}},
}

// Reasons used for file-level decisions.
var (
	rCloudFile      = reason("Cloud-synced file")
	rCloudUnsure    = reason("In a sync folder, but sync status not confirmed")
	rTempFile       = reason("Temp or log file")
	rSystemJunk     = reason("Page, hibernate or swap file")
	rKeysFile       = reason("Keys or secrets (store them securely)")
	rEmailArchive   = reason("Email archive")
	rOutlookCache   = reason("Outlook cache (re-syncs from the server)")
	rInstaller      = reason("Program or installer")
	rPersonal       = reason("Personal file type")
	rCode           = reason("Source code (check it's pushed)")
	rArchive        = reason("Archive or disk image")
	rUnclassified   = reason("Unclassified")
	rDotfile        = reason("Config dotfile")
	rProgramBinary  = reason("Program files")
	rLinkNotScanned = reason("Link or junction (not followed)")
)

var junkNames = map[string]bool{
	"pagefile.sys": true, "hiberfil.sys": true, "swapfile.sys": true, "memory.dmp": true,
	"thumbs.db": true, "desktop.ini": true, ".ds_store": true, "ehthumbs.db": true,
}

// Classifier holds the compiled rules.
type Classifier struct {
	rules []Rule
}

// New builds a classifier. extraCloudRoots are absolute folders (such as the
// OneDrive path from the environment) that should be treated as cloud-synced.
func New(extraCloudRoots []string) *Classifier {
	c := &Classifier{}
	for _, s := range specs {
		r := reason(s.reason)
		for _, p := range s.pats {
			c.rules = append(c.rules, Rule{kind: s.kind, pat: p, V: s.V, Strong: s.strong, Cloud: s.V == Safe, Reason: r})
		}
	}
	// Cloud roots from the environment go first so they beat "Your files".
	var extra []Rule
	for _, root := range extraCloudRoots {
		if root == "" {
			continue
		}
		extra = append(extra, Rule{kind: absPrefix, pat: Normalize(root), V: Safe, Strong: true, Cloud: true, Reason: reason("OneDrive")})
	}
	c.rules = append(extra, c.rules...)
	return c
}

// Rule returns the rule with index i.
func (c *Classifier) Rule(i int) *Rule { return &c.rules[i] }

// Normalize lowercases a path, uses forward slashes and adds a trailing slash.
func Normalize(p string) string {
	p = strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p
}

// split returns the path relative to the drive root, and relative to a user
// profile when it is inside one.
func split(np string) (drel, urel string, inUser bool) {
	drel = np
	if len(np) >= 3 && np[1] == ':' && np[2] == '/' {
		drel = np[3:]
	} else {
		drel = strings.TrimPrefix(np, "/")
	}
	var rest string
	switch {
	case strings.HasPrefix(drel, "users/"):
		rest = drel[len("users/"):]
	case strings.HasPrefix(drel, "windows.old/users/"):
		// A previous install's profiles follow the same rules as current ones.
		rest = drel[len("windows.old/users/"):]
	case strings.HasPrefix(drel, "home/"):
		rest = drel[len("home/"):]
	default:
		return drel, "", false
	}
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return drel, "", false
	}
	return drel, rest[i+1:], true
}

// DirRule finds the rule for a folder, or -1 if none applies.
func (c *Classifier) DirRule(dirPath string) int {
	np := Normalize(dirPath)
	drel, urel, inUser := split(np)
	for i := range c.rules {
		r := &c.rules[i]
		switch r.kind {
		case anywhere:
			if strings.Contains(np, "/"+r.pat+"/") {
				return i
			}
		case driveRel:
			if strings.HasPrefix(drel, r.pat) {
				return i
			}
		case userRel:
			if inUser && strings.HasPrefix(urel, r.pat) {
				return i
			}
		case absPrefix:
			if strings.HasPrefix(np, r.pat) {
				return i
			}
		}
	}
	return -1
}

// Result is the classification of one file.
type Result struct {
	Cat    Category
	V      Verdict
	Reason uint8
}

// File classifies one file given its folder's rule (-1 for none), its
// lowercased name and its file attributes.
func (c *Classifier) File(dirRule int, nameLower string, attrs uint32) Result {
	cat := CategoryOf(nameLower)
	res := func(v Verdict, r uint8) Result { return Result{cat, v, r} }

	if junkNames[nameLower] {
		return res(Junk, rSystemJunk)
	}
	var rule *Rule
	if dirRule >= 0 {
		rule = &c.rules[dirRule]
	}
	if attrs&AttrCloudAny != 0 {
		return res(Safe, rCloudFile)
	}
	if rule != nil && rule.Strong {
		if rule.Cloud {
			// In a sync folder, but nothing says the sync client owns this file.
			if attrs&AttrReparsePoint != 0 {
				return res(Safe, rCloudFile)
			}
			return res(Review, rCloudUnsure)
		}
		return res(rule.V, rule.Reason)
	}
	if strings.HasSuffix(nameLower, ".ost") {
		return res(Safe, rOutlookCache)
	}
	switch cat {
	case TempLogs:
		return res(Junk, rTempFile)
	case Keys:
		return res(Backup, rKeysFile)
	case Email:
		return res(Backup, rEmailArchive)
	case Programs:
		return res(Reinstall, rInstaller)
	case Archives, DiskImages:
		// ISOs and zips are usually downloads you can get again, but not always.
		return res(Review, rArchive)
	}
	if rule != nil {
		return res(rule.V, rule.Reason)
	}
	switch cat {
	case Documents, Images, Video, Audio, Design, Data:
		return res(Backup, rPersonal)
	case Code:
		return res(Review, rCode)
	case Libraries:
		return res(Reinstall, rProgramBinary)
	case Config:
		if strings.HasPrefix(nameLower, ".") {
			return res(Backup, rDotfile)
		}
	}
	return res(Review, rUnclassified)
}

// LinkReason is the reason shown for links that the scanner did not follow.
func LinkReason() uint8 { return rLinkNotScanned }
