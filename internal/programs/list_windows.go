//go:build windows

package programs

import (
	"regexp"
	"strings"
	"syscall"
	"unsafe"
)

const (
	keyWow64_64      = 0x0100 // KEY_WOW64_64KEY: read the 64-bit view even from a 32-bit build
	errNoMoreItems   = syscall.Errno(259)
	errMoreData      = syscall.Errno(234)
	maxValueBytes    = 64 << 10
	uninstallKeyPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	uninstall32Path  = `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
	scopeAllUsers    = "All users"
	scopeCurrentUser = "Current user"
)

var kbUpdate = regexp.MustCompile(`(?i)\(KB\d+\)|^KB\d+$|^Security Update for|^Update for `)

// List reads the uninstall entries Windows shows in "Installed apps".
func List() ([]Program, error) {
	roots := []struct {
		key   syscall.Handle
		path  string
		scope string
	}{
		{syscall.HKEY_LOCAL_MACHINE, uninstallKeyPath, scopeAllUsers},
		{syscall.HKEY_LOCAL_MACHINE, uninstall32Path, scopeAllUsers},
		{syscall.HKEY_CURRENT_USER, uninstallKeyPath, scopeCurrentUser},
	}
	var out []Program
	for _, r := range roots {
		h, err := openKey(r.key, r.path)
		if err != nil {
			continue // a missing view is normal (32-bit Windows, no per-user apps)
		}
		for _, sub := range subkeys(h) {
			sh, err := openKey(h, sub)
			if err != nil {
				continue
			}
			p, ok := readEntry(sh, sub, r.scope)
			syscall.RegCloseKey(sh)
			if ok {
				out = append(out, p)
			}
		}
		syscall.RegCloseKey(h)
	}
	return tidy(out), nil
}

func readEntry(h syscall.Handle, key, scope string) (Program, bool) {
	name := strings.TrimSpace(str(h, "DisplayName"))
	if name == "" || dword(h, "SystemComponent") == 1 || str(h, "ParentKeyName") != "" {
		return Program{}, false
	}
	switch str(h, "ReleaseType") {
	case "Update", "Hotfix", "Security Update", "Service Pack":
		return Program{}, false
	}
	if kbUpdate.MatchString(name) {
		return Program{}, false
	}
	p := Program{
		Name:      name,
		Version:   strings.TrimSpace(str(h, "DisplayVersion")),
		Publisher: strings.TrimSpace(str(h, "Publisher")),
		Installed: formatDate(str(h, "InstallDate")),
		SizeKB:    dword(h, "EstimatedSize"),
		Location:  strings.Trim(strings.TrimSpace(str(h, "InstallLocation")), `"`),
		Scope:     scope,
		Kind:      "Program",
		Source:    "registry",
	}
	if isGame(p, key) {
		p.Kind = "Game"
	}
	return p, true
}

func openKey(parent syscall.Handle, path string) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var h syscall.Handle
	err = syscall.RegOpenKeyEx(parent, p, 0, syscall.KEY_READ|keyWow64_64, &h)
	return h, err
}

func subkeys(h syscall.Handle) []string {
	var names []string
	buf := make([]uint16, 512)
	for i := uint32(0); ; i++ {
		n := uint32(len(buf))
		err := syscall.RegEnumKeyEx(h, i, &buf[0], &n, nil, nil, nil, nil)
		if err == errNoMoreItems {
			break
		}
		if err != nil {
			continue
		}
		names = append(names, syscall.UTF16ToString(buf[:n]))
	}
	return names
}

func query(h syscall.Handle, name string) (uint32, []byte) {
	np, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, nil
	}
	var typ uint32
	n := uint32(256)
	for n <= maxValueBytes {
		buf := make([]byte, n)
		err := syscall.RegQueryValueEx(h, np, nil, &typ, &buf[0], &n)
		if err == nil {
			return typ, buf[:n]
		}
		if err != errMoreData {
			return 0, nil
		}
	}
	return 0, nil
}

func str(h syscall.Handle, name string) string {
	typ, b := query(h, name)
	if (typ != syscall.REG_SZ && typ != syscall.REG_EXPAND_SZ) || len(b) < 2 {
		return ""
	}
	u := unsafe.Slice((*uint16)(unsafe.Pointer(&b[0])), len(b)/2)
	return syscall.UTF16ToString(u)
}

func dword(h syscall.Handle, name string) uint32 {
	typ, b := query(h, name)
	if typ != syscall.REG_DWORD || len(b) < 4 {
		return 0
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
