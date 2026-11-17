//go:build !windows

package profile

import "os"

func syncSnapshotDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	return syncSnapshotOwned(file)
}
