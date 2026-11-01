//go:build !windows

package servicehost

import "errors"

func Run(string) error { return errors.New("Windows service hosting requires Windows") }
