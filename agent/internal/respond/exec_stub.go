//go:build !windows

package respond

// NewWindowsExecutor returns an executor that refuses to act off Windows.
// Refusing is the right failure: silently "succeeding" at a remediation that
// did not happen would tell a user they are safe when they are not.
func NewWindowsExecutor(string) Executor { return unsupported{} }

type unsupported struct{}

func (unsupported) Execute(Action) Result {
	return Result{Message: "remediation is only available on Windows"}
}

func (unsupported) Undo(Action, map[string]string) Result {
	return Result{Message: "remediation is only available on Windows"}
}
