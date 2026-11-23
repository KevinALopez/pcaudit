//go:build windows

package programs

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Winget runs `winget export` into outPath. It returns nil, nil when winget
// isn't installed. It never accepts source agreements on the user's behalf:
// if winget needs that, the export fails and the report says so.
func Winget(outPath string) (*WingetResult, error) {
	exe, err := exec.LookPath("winget")
	if err != nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "export", "-o", outPath, "--include-versions", "--disable-interactivity")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	runErr := cmd.Run()
	data, err := os.ReadFile(outPath)
	if err != nil {
		if runErr != nil {
			return nil, errors.New("winget export failed: " + runErr.Error())
		}
		return nil, err
	}
	return parseWinget(outPath, data, out.Bytes())
}
