//go:build !windows

package programs

// List isn't implemented outside Windows yet. Android (pm list packages)
// comes with the adb support.
func List() ([]Program, error) { return nil, nil }

// Winget only exists on Windows.
func Winget(outPath string) (*WingetResult, error) { return nil, nil }
