//go:build !windows && !linux && !darwin && !freebsd && !openbsd

package audit

func currentProcessPrincipal() (processPrincipal, error) {
	return processPrincipal{}, ErrProcessIdentity
}
