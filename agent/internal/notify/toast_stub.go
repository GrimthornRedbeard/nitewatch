//go:build !windows

package notify

// NewWindowsToast returns a notifier that does nothing off Windows, so the
// gating logic above can be exercised on any platform.
func NewWindowsToast() Notifier { return noopNotifier{} }

type noopNotifier struct{}

func (noopNotifier) Notify(Alert) error { return nil }
