//go:build windows

package scan

import (
	"io/fs"
	"syscall"
	"unsafe"
)

func attrsOf(fi fs.FileInfo) uint32 {
	if d, ok := fi.Sys().(*syscall.Win32FileAttributeData); ok {
		return d.FileAttributes
	}
	return 0
}

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	getLogicalDrives       = kernel32.NewProc("GetLogicalDrives")
	getDriveTypeW          = kernel32.NewProc("GetDriveTypeW")
	getCompressedFileSizeW = kernel32.NewProc("GetCompressedFileSizeW")
)

const attrSparse = 0x200

// allocatedSize returns how much disk a sparse file really uses. Emulator
// and VM disks are often sparse: a "512 GB" image may hold a few GB.
func allocatedSize(path string, attrs uint32, size int64) (int64, bool) {
	if attrs&attrSparse == 0 {
		return size, false
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return size, false
	}
	var high uint32
	low, _, callErr := getCompressedFileSizeW.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&high)))
	if uint32(low) == 0xFFFFFFFF && callErr != syscall.Errno(0) {
		return size, false
	}
	return int64(high)<<32 | int64(uint32(low)), true
}

const driveFixed = 3

// DefaultRoots returns every fixed (non-removable, non-network) drive.
func DefaultRoots() []string {
	mask, _, _ := getLogicalDrives.Call()
	var roots []string
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		p, err := syscall.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		t, _, _ := getDriveTypeW.Call(uintptr(unsafe.Pointer(p)))
		if t == driveFixed {
			roots = append(roots, root)
		}
	}
	return roots
}
