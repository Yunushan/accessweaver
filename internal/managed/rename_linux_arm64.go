//go:build linux && arm64

package managed

import "syscall"

const linuxRenameat2 = syscall.SYS_RENAMEAT2
