//go:build !windows

package main

import "os"

func ownConsole() bool { return false }

func interactive() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func pauseIfOwnConsole() {}
