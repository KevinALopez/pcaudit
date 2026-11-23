//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// ownConsole reports whether pcaudit was started by double-clicking it: then
// it is the only process attached to its console window.
func ownConsole() bool {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleProcessList")
	var pids [4]uint32
	n, _, _ := proc.Call(uintptr(unsafe.Pointer(&pids[0])), 4)
	return n == 1
}

// interactive reports whether someone can answer questions on stdin.
func interactive() bool {
	var mode uint32
	return syscall.GetConsoleMode(syscall.Stdin, &mode) == nil
}

// pauseIfOwnConsole keeps the window open after a double-click, so the
// summary doesn't vanish.
func pauseIfOwnConsole() {
	if ownConsole() {
		fmt.Print("\nPress Enter to close...")
		stdin.ReadString('\n')
	}
}
