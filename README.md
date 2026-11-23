# pcaudit

See what's on a computer before you wipe it.

pcaudit scans your drives and sorts every file into one of five verdicts:

| Verdict | Meaning |
|---|---|
| **Back up** | Only exists here. Copy it somewhere before you wipe. |
| **Already safe** | Already exists somewhere else, such as OneDrive or another sync client. |
| **Reinstallable** | Windows, programs, dependencies, games. You can download them again. |
| **Junk** | Caches, temp files and leftovers. Fine to lose. |
| **Review** | The tool couldn't decide. Have a quick look. |

It writes an offline **report.html** with an overview, a back-up checklist, a folder browser, file search, your git repositories and duplicate files. Next to it you get **files.csv**, which lists every file and opens in Excel, and **summary.json**.

It also checks two things that are easy to lose in a wipe:

- **Git repositories:** for every repo it finds, git is asked about uncommitted changes, unpushed commits, stashes, and repos with no remote. Committed and pushed files count as already safe. Unpushed work counts as back up.
- **Duplicates:** files of 1 MB or more that you'd back up or review are compared byte for byte. You'll see how much space extra copies take, and which folders are copies of each other.

pcaudit never changes, moves or uploads anything. Apart from the duplicate check, it only reads folder listings and file details. The report contains your file names, so keep it private.

## Use it

1. Download the zip for your system from [Releases](../../releases). On Windows that's `pcaudit_<version>_windows_amd64.zip`.
2. Unzip it and double-click `pcaudit.exe`, or run it from a terminal:

```powershell
.\pcaudit.exe                      # scan every fixed drive
.\pcaudit.exe C:\Users\me D:\      # scan only these folders
.\pcaudit.exe -out E:\audit        # put the report on a USB stick
```

| Flag | What it does |
|---|---|
| `-out <folder>` | Where to write the report |
| `-no-dupes` | Skip the duplicate check. It reads possible copies in full, which can take a few minutes. |
| `-no-git` | Don't ask git about repositories |
| `-rules <file>` | Use your own rules (see below) |
| `-print-rules` | Print the built-in rules |
| `-no-csv`, `-no-open`, `-workers`, `-version` | |

Windows SmartScreen may warn about an unsigned download. Choose **More info → Run anyway**.

## How files are sorted

The folder decides first. Known places settle most cases: `Program Files` and `Windows` are reinstallable, `Temp` and caches are junk, `.ssh` and editor settings get backed up, and OneDrive is already safe. The file type decides the rest. In your own folders, documents, photos and videos get backed up, installers count as reinstallable, and archives or ISOs go to Review.

### Your own rules

Put a `pcaudit-rules.json` next to `pcaudit.exe`, or pass `-rules file.json`. Your rules are checked before the built-in ones:

```json
{
  "rules": [
    { "where": "user", "pattern": "Documents/Clients", "verdict": "backup", "strong": true, "reason": "Client work" },
    { "where": "path", "pattern": "D:/Archive", "verdict": "safe", "reason": "Mirrored to my NAS" },
    { "where": "anywhere", "pattern": "renders", "verdict": "junk", "strong": true }
  ]
}
```

- `where`:
  - `anywhere`: a folder with that name on any drive
  - `drive`: a path from the root of any drive
  - `user`: a path inside any user profile
  - `path`: one exact folder
- `verdict`: `backup`, `safe`, `reinstall`, `junk` or `review`.
- `strong`: the rule beats the file type. A weak rule only applies when the file type doesn't already decide.

Run `pcaudit -print-rules` to see the built-in rules in the same format. They're also in [internal/classify/classify.go](internal/classify/classify.go).

## Build

```powershell
go test ./...
go build -o pcaudit.exe ./cmd/pcaudit
```

## Release

Push a tag and GitHub Actions builds Windows, macOS, Linux and Android binaries with GoReleaser:

```powershell
git tag v0.1.0
git push origin v0.1.0
```

## Roadmap

- [x] v0.1: parallel scan, verdict rules, HTML report, CSV export
- [x] v0.2: git repositories (uncommitted or unpushed work), duplicate files and folders, rules file you can edit
- [ ] v0.3: installed programs and winget list, select files in the report and export a backup script
- [ ] v0.5: Android via `adb` (the `android/arm64` build already scans `/sdcard`)
