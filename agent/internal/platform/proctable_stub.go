//go:build !windows

package platform

// ProcInfo is one entry from the live process table.
type ProcInfo struct {
	PID      uint32
	PPID     uint32
	Image    string
	Services []string
}

// ProcessTable is unavailable off Windows; the replay source supplies lineage
// in test fixtures instead.
func ProcessTable() ([]ProcInfo, error) { return nil, nil }

// ServiceLabel renders a process for display.
func ServiceLabel(image string, _ []string) string { return image }
