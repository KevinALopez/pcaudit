package classify

import (
	"path"
	"strings"
)

// Category is what kind of file something is, judged by its extension.
type Category uint8

const (
	Documents Category = iota
	Images
	Video
	Audio
	Archives
	DiskImages
	Code
	Programs
	Libraries
	Data
	Email
	Design
	Keys
	Config
	Fonts
	TempLogs
	Other
	NumCategories
)

var CategoryNames = [NumCategories]string{
	"Documents", "Images", "Video", "Audio", "Archives", "Disk images",
	"Code", "Programs & installers", "Libraries", "Data & databases",
	"Email", "Design & 3D", "Keys & secrets", "Config", "Fonts",
	"Temp & logs", "Other",
}

var extCategory = map[string]Category{}

func reg(c Category, exts ...string) {
	for _, e := range exts {
		extCategory["."+e] = c
	}
}

func init() {
	reg(Documents, "pdf", "doc", "docx", "docm", "dot", "dotx", "odt", "rtf", "txt", "md", "markdown",
		"tex", "epub", "mobi", "pages", "xls", "xlsx", "xlsm", "xlsb", "ods", "numbers", "ppt", "pptx",
		"pptm", "odp", "key", "one", "onetoc2", "vsd", "vsdx", "pub", "xps", "oxps", "djvu", "cbz", "cbr")
	reg(Images, "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "heic", "heif", "avif",
		"raw", "cr2", "cr3", "nef", "arw", "dng", "orf", "rw2", "ico", "svg", "jfif")
	reg(Video, "mp4", "mkv", "mov", "avi", "wmv", "webm", "flv", "m4v", "mpg", "mpeg", "3gp", "mts", "m2ts", "vob", "ts")
	reg(Audio, "mp3", "wav", "flac", "aac", "m4a", "ogg", "opus", "wma", "aiff", "aif", "mid", "midi", "amr")
	reg(Archives, "zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "zst", "lz", "cab", "jar", "apk", "xapk")
	reg(DiskImages, "iso", "img", "vhd", "vhdx", "vmdk", "vdi", "qcow2", "wim", "esd", "dmg", "ova", "ovf")
	reg(Code, "go", "py", "js", "mjs", "cjs", "ts", "tsx", "jsx", "java", "kt", "kts", "c", "h", "cpp",
		"hpp", "cc", "cs", "fs", "vb", "rs", "rb", "php", "swift", "m", "scala", "lua", "pl", "r", "dart",
		"sql", "sh", "bash", "ps1", "psm1", "bat", "cmd", "vbs", "ahk", "html", "htm", "css", "scss",
		"sass", "less", "vue", "svelte", "ipynb", "sln", "csproj", "vcxproj", "gradle", "asm", "zig", "nim", "ex", "exs", "erl", "hs", "clj", "groovy")
	reg(Programs, "exe", "msi", "msix", "msixbundle", "appx", "appxbundle", "com", "scr", "appimage", "deb", "rpm", "pkg")
	reg(Libraries, "dll", "sys", "so", "dylib", "lib", "a", "o", "obj", "pdb", "ocx", "drv", "mui", "node", "pyc", "pyd", "class", "winmd")
	reg(Data, "csv", "tsv", "db", "sqlite", "sqlite3", "mdb", "accdb", "parquet", "sav", "dta", "feather", "h5", "hdf5", "mat", "npy", "npz", "gpx", "kml", "kmz", "ldb")
	reg(Email, "pst", "ost", "eml", "msg", "mbox", "emlx", "vcf", "ics")
	reg(Design, "psd", "psb", "ai", "eps", "indd", "xd", "fig", "sketch", "afdesign", "afphoto", "kra",
		"xcf", "blend", "fbx", "obj3d", "stl", "3mf", "max", "ma", "mb", "c4d", "dwg", "dxf", "skp", "step", "stp", "iges", "prproj", "aep", "drp", "veg")
	reg(Keys, "pem", "key", "ppk", "pfx", "p12", "crt", "cer", "der", "gpg", "asc", "kdbx", "kdb", "ovpn", "keystore", "jks", "agilekeychain", "opvault", "1pux")
	reg(Config, "json", "xml", "yaml", "yml", "toml", "ini", "cfg", "conf", "config", "reg", "plist", "env", "properties", "editorconfig", "lnk", "url")
	reg(Fonts, "ttf", "otf", "woff", "woff2", "fon", "ttc")
	reg(TempLogs, "tmp", "temp", "log", "dmp", "mdmp", "crdownload", "part", "partial", "etl", "evtx", "old", "chk", "cache")
	// ".key" is both Keynote and a key file. A private key is the worse one to lose.
	extCategory[".key"] = Keys
}

// CategoryOf classifies a lowercased file name by its extension.
func CategoryOf(nameLower string) Category {
	if strings.HasPrefix(nameLower, "~$") {
		return TempLogs // Office lock files
	}
	switch nameLower {
	case "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "known_hosts", "authorized_keys", "credentials", ".npmrc", ".pypirc", ".netrc", ".git-credentials":
		return Keys
	case ".gitconfig", ".bashrc", ".zshrc", ".profile", ".vimrc", ".wslconfig":
		return Config
	}
	if c, ok := extCategory[path.Ext(nameLower)]; ok {
		return c
	}
	return Other
}
