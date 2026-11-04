//go:build linux || darwin || freebsd || openbsd

package audit

import (
	"os"
	"strconv"
)

func credentialSnapshot() [4]int { return [4]int{os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid()} }

// The execution principal is the effective UID, not SUDO_USER/USER, a home
// directory owner, or a password-database name. Refuse mixed/changed credentials.
func currentProcessPrincipal() (processPrincipal, error) {
	return principalFromCredentials(credentialSnapshot(), credentialSnapshot())
}
func principalFromCredentials(before, after [4]int) (processPrincipal, error) {
	if before != after || before[0] < 0 || before[1] < 0 || before[2] < 0 || before[3] < 0 || before[0] != before[1] || before[2] != before[3] {
		return processPrincipal{}, ErrProcessIdentity
	}
	class := "user"
	if before[1] == 0 {
		class = "administrator"
	}
	return processPrincipal{"uid", strconv.FormatUint(uint64(before[1]), 10), class}, nil
}
