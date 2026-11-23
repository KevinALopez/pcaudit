//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// pauseIfOwnConsole keeps the window open when pcaudit was started by
// double-clicking it, so the summary doesn't vanish. When it runs from a
// terminal, that terminal is also attached to the console and nothing waits.
func pauseIfOwnConsole() {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleProcessList")
	var pids [4]uint32
	n, _, _ := proc.Call(uintptr(unsafe.Pointer(&pids[0])), 4)
	if n == 1 {
		fmt.Print("\nPress Enter to close...")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
}
