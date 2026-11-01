// Package nativeargs enforces syntax shared by managed external-tool entry points.
package nativeargs

import (
	"errors"
	"strings"
)

// Abbreviates reports a non-exact long-option prefix. Exact protected names take
// precedence, matching getopt_long when one option is a prefix of another.
func Abbreviates(arg string, protected ...string) bool {
	name, _, _ := strings.Cut(arg, "=")
	if !strings.HasPrefix(name, "--") || name == "--" {
		return false
	}
	for _, option := range protected {
		if name == option {
			return false
		}
	}
	for _, option := range protected {
		if strings.HasPrefix(option, name) {
			return true
		}
	}
	return false
}

func ShortCluster(arg string) bool {
	return len(arg) > 2 && arg[0] == '-' && ((arg[1] >= 'a' && arg[1] <= 'z') || (arg[1] >= 'A' && arg[1] <= 'Z'))
}

// ValidateByeDPIInstall reserves listener and process ownership for the system
// installer. Unlike the foreground adapter, installation owns a fixed SOCKS port.
func ValidateByeDPIInstall(args []string) error {
	reserved := []string{"--ip", "--port", "--daemon", "--daemonize", "--service", "--transparent"}
	for _, arg := range args {
		name, _, _ := strings.Cut(arg, "=")
		blocked := name == "--" || strings.HasPrefix(arg, "@") || ShortCluster(arg) || Abbreviates(arg, reserved...)
		for _, option := range append([]string{"-i", "-p", "-D", "-E"}, reserved...) {
			if name == option {
				blocked = true
			}
		}
		if blocked {
			return errors.New("managed ByeDPI installation reserves listener/process options; use full strategy option names without option terminators or argument files")
		}
	}
	return nil
}
