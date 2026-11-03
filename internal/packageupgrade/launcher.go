package packageupgrade

import (
	"errors"
	"strings"
	"unicode/utf8"
)

func installedLaunchArguments(args []string) ([]string, error) {
	if len(args) == 0 {
		return []string{"ui"}, nil
	}
	if len(args) > 64 {
		return nil, errors.New("too many application arguments")
	}
	total := 0
	for _, arg := range args {
		total += len(arg)
		if len(arg) > 4096 || total > 32768 || !utf8.ValidString(arg) || strings.IndexByte(arg, 0) >= 0 {
			return nil, errors.New("invalid application argument extent or encoding")
		}
	}
	return append([]string{}, args...), nil
}
