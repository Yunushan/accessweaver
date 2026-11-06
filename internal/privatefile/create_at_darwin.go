//go:build darwin && (amd64 || arm64)

package privatefile

import (
	"os"
	"syscall"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
)

// CreateAt preserves Create's owner/ACL contract while using only the retained
// directory for name lookup. An existing object or permission is never repaired.
func CreateAt(parent *os.File, name string) (*os.File, error) {
	return createAtUnix(parent, name, func(file *os.File) error {
		if _, err := darwintrust.Check(file, false, uint32(os.Geteuid())); err != nil {
			return err
		}
		if err := darwintrust.CheckEmptyACL(file); err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Flags != 0 {
			return errPrivateCreateAt
		}
		return nil
	})
}
