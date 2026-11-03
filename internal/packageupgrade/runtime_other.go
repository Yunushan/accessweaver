//go:build !darwin || (!amd64 && !arm64)

package packageupgrade

// Other targets retain their own lifecycle coordination. The new versioned
// deployment authority is currently supported only by native macOS packages.
func AcquireInstalledRuntime() (*RuntimeLease, error) { return nil, nil }
