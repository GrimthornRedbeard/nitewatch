//go:build !windows

package platform

// IsElevated reports whether the process has the privileges the live sensor
// needs. Only meaningful on Windows; elsewhere the live source is unavailable
// anyway, so report false.
func IsElevated() bool { return false }

// OpenBrowser is a no-op off Windows (dev uses --replay and opens the URL by hand).
func OpenBrowser(string) error { return nil }
