//go:build !windows

package gitrepo

import "os/exec"

func hideWindow(cmd *exec.Cmd) {}
