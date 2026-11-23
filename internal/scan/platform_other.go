//go:build !windows

package scan

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"syscall"

	"github.com/KevinALopez/pcaudit/internal/classify"
)

func attrsOf(fi fs.FileInfo) uint32 {
	var a uint32
	if fi.IsDir() {
		a |= classify.AttrDirectory
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		a |= classify.AttrReparsePoint
	}
	if strings.HasPrefix(fi.Name(), ".") {
		a |= classify.AttrHidden
	}
	return a
}

func allocatedSize(path string, attrs uint32, size int64) (int64, bool) { return size, false }

func isDeviceError(err error) bool { return errors.Is(err, syscall.EIO) }

// LowPriority is Windows-only for now.
func LowPriority() {}

// DefaultRoots returns the home folder on non-Windows systems. On Android
// (later) this will be /sdcard.
func DefaultRoots() []string {
	if _, err := os.Stat("/sdcard"); err == nil {
		return []string{"/sdcard"}
	}
	if h, err := os.UserHomeDir(); err == nil {
		return []string{h}
	}
	return []string{"/"}
}
