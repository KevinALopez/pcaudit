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

It writes an offline **report.html** with an overview, a back-up checklist, a folder browser and file search. Next to it you get **files.csv**, which lists every file and opens in Excel, and **summary.json**.

pcaudit only reads folder listings and file details. It never reads file contents and never sends anything anywhere. The report contains your file names, so keep it private.

## Use it

1. Download the zip for your system from [Releases](../../releases). On Windows that's `pcaudit_<version>_windows_amd64.zip`.
2. Unzip it and double-click `pcaudit.exe`, or run it from a terminal:

```powershell
.\pcaudit.exe                      # scan every fixed drive
.\pcaudit.exe C:\Users\me D:\      # scan only these folders
.\pcaudit.exe -out E:\audit        # put the report on a USB stick
```

Flags: `-out`, `-workers`, `-no-csv`, `-no-open`, `-version`.

Windows SmartScreen may warn about an unsigned download. Choose **More info → Run anyway**.

## How files are sorted

The folder decides first. Known places settle most cases: `Program Files` and `Windows` are reinstallable, `Temp` and caches are junk, `.ssh` and editor settings get backed up, and OneDrive is already safe. The file type decides the rest. In your own folders, documents, photos and videos get backed up, installers count as reinstallable, and archives or ISOs go to Review.

The rules live in [internal/classify/classify.go](internal/classify/classify.go).

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
- [ ] v0.2: git repositories (uncommitted or unpushed work), duplicate files, rules file you can edit
- [ ] v0.3: installed programs and winget list, select files in the report and export a backup script
- [ ] v0.5: Android via `adb` (the `android/arm64` build already scans `/sdcard`)
