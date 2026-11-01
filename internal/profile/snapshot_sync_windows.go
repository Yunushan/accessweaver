//go:build windows

package profile

// Windows publication uses MoveFileExW with MOVEFILE_WRITE_THROUGH; individual
// files use File.Sync. Unix directory fsync has no equivalent in this API.
// Reboot/power-loss qualification remains required for Windows metadata.
func syncSnapshotDirectory(string) error { return nil }
