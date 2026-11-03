package main

import "testing"

func TestDesktopPackageCLIHasNoPathOrSealOverride(t *testing.T) {
	for _, item := range []struct {
		name string
		args []string
	}{{"helper", nil}, {"helper", []string{"--root", "/tmp/other"}}, {"preinstall", []string{"p", "/Applications", "/tmp/other"}}, {"postinstall", []string{"p"}}, {"preinstall", []string{"x\x00y", "/Applications", "/"}}} {
		if e := execute(item.name, item.args); e == nil {
			t.Fatal("invalid desktop phase accepted", item)
		}
	}
}
