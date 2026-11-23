package classify

import (
	"strings"
	"testing"
)

func TestCustomRules(t *testing.T) {
	c := New(nil,
		RuleJSON{Where: "path", Pattern: `D:\Archive`, Verdict: "safe", Reason: "On my NAS"},
		RuleJSON{Where: "user", Pattern: "Documents/Scratch", Verdict: "junk", Strong: true},
		RuleJSON{Where: "anywhere", Pattern: "renders", Verdict: "reinstall", Strong: true},
	)
	cases := []struct {
		path string
		want Verdict
	}{
		{`D:\Archive\2019\taxes.pdf`, Safe},
		{`D:\Archived\taxes.pdf`, Backup}, // "path" matches the folder, not a name prefix
		{`C:\Users\me\Documents\Scratch\notes.txt`, Junk},
		{`C:\Users\me\Documents\Real\notes.txt`, Backup},
		{`E:\proj\renders\frame001.png`, Reinstall},
	}
	for _, tc := range cases {
		i := strings.LastIndex(tc.path, `\`)
		r := c.File(c.DirRule(tc.path[:i+1]), strings.ToLower(tc.path[i+1:]), 0)
		if r.V != tc.want {
			t.Errorf("%s: got %s (%s), want %s", tc.path, VerdictNames[r.V], Reasons[r.Reason], VerdictNames[tc.want])
		}
	}

	for _, bad := range []RuleJSON{
		{Where: "everywhere", Pattern: "x", Verdict: "junk"},
		{Where: "user", Pattern: "x", Verdict: "delete"},
		{Where: "user", Pattern: "/", Verdict: "junk"},
	} {
		if _, err := bad.compile(); err == nil {
			t.Errorf("%+v: expected an error", bad)
		}
	}

	// The defaults round-trip through the file format.
	if n := len(DefaultRules().Rules); n < 100 {
		t.Errorf("only %d default rules exported", n)
	}
	for _, r := range DefaultRules().Rules {
		if _, err := r.compile(); err != nil {
			t.Errorf("default rule %+v doesn't compile: %v", r, err)
		}
	}
}

func TestVerdicts(t *testing.T) {
	c := New([]string{`C:\Users\me\OneDrive`})
	cases := []struct {
		path  string
		attrs uint32
		want  Verdict
	}{
		{`C:\Users\me\Desktop\taxes.pdf`, 0, Backup},
		{`C:\Users\me\Documents\notes.txt`, 0, Backup},
		{`C:\Users\me\Downloads\setup.exe`, 0, Reinstall},
		{`C:\Users\me\Downloads\photo.jpg`, 0, Backup},
		{`C:\Users\me\.ssh\id_ed25519`, 0, Backup},
		{`C:\Users\me\.gitconfig`, 0, Backup},
		{`C:\Users\me\AppData\Local\Temp\x.dat`, 0, Junk},
		{`C:\Users\me\AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data\f_000001`, 0, Junk},
		{`C:\Users\me\AppData\Local\Google\Chrome\User Data\Default\Bookmarks`, 0, Review},
		{`C:\Users\me\AppData\Roaming\Code\User\settings.json`, 0, Backup},
		{`C:\Users\me\AppData\Local\Microsoft\Outlook\me.ost`, 0, Safe},
		{`C:\Users\me\AppData\Local\Microsoft\Outlook\archive.pst`, 0, Backup},
		{`C:\Users\me\Documents\proj\node_modules\react\index.js`, 0, Reinstall},
		{`C:\Users\me\OneDrive\Documents\cv.docx`, AttrPinned, Safe},
		{`C:\Users\me\OneDrive\Documents\cv.docx`, AttrReparsePoint, Safe},
		{`C:\Users\me\OneDrive\Documents\cv.docx`, 0, Review},
		{`C:\Windows\System32\kernel32.dll`, 0, Reinstall},
		{`C:\Program Files\Git\bin\git.exe`, 0, Reinstall},
		{`C:\pagefile.sys`, AttrHidden, Junk},
		{`C:\$Recycle.Bin\S-1-5\$R123.docx`, 0, Junk},
		{`D:\Photos\2019\beach.heic`, 0, Backup},
		{`D:\SteamLibrary\steamapps\common\Game\data.pak`, 0, Reinstall},
		{`D:\stuff\backup.zip`, 0, Review},
		{`C:\Users\me\Saved Games\Game\save1.sav`, 0, Backup},
		{`C:\Users\me\Downloads\Win11.iso`, 0, Review},
		{`C:\Users\me\Documents\old-backup.zip`, 0, Review},
		{`C:\Windows.old\Users\me\Documents\letter.docx`, 0, Backup},
		{`C:\Windows.old\Users\me\AppData\Local\Temp\x.dat`, 0, Junk},
		{`C:\Users\me\AppData\LocalLow\Studio\Game\cache.bin`, 0, Review},
		{`C:\Windows.old\Windows\System32\x.dll`, 0, Junk},
	}
	for _, tc := range cases {
		// Split on "\" ourselves: filepath.Split only knows "\" on Windows,
		// and these tests must pass on the Linux CI runners too.
		i := strings.LastIndex(tc.path, `\`)
		dir, name := tc.path[:i+1], tc.path[i+1:]
		r := c.File(c.DirRule(dir), strings.ToLower(name), tc.attrs)
		if r.V != tc.want {
			t.Errorf("%s: got %s (%s), want %s", tc.path, VerdictNames[r.V], Reasons[r.Reason], VerdictNames[tc.want])
		}
	}
}
