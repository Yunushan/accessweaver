//go:build !windows

package profile

// The desktop controller uses one process-wide OS identity. It does not expose
// per-thread credential impersonation on these supported native runtimes.
func canShareListRead() bool { return true }
