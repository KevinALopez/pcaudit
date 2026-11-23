//go:build windows

package gitrepo

import (
	"os/exec"
	"syscall"
)

// hideWindow stops a console window flashing up for every git call when
// pcaudit was started by double-clicking.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}
