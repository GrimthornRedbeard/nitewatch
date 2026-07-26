//go:build !windows

package platform

// FileSigner is unavailable off Windows. Reporting "not signed" is the safe
// direction: rules that suppress on a trusted signature will simply not
// suppress, rather than trusting something unverified.
func FileSigner(string) (bool, string) { return false, "" }
