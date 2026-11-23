//go:build !windows

package diskhealth

// Check isn't implemented outside Windows yet.
func Check() *Report { return nil }
