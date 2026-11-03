package main

import "testing"

func TestLauncherVersionRejectsUnexpectedArguments(t *testing.T) {
	if e := execute([]string{"launcher-version", "--invalid"}); e == nil {
		t.Fatal("unexpected version argument accepted")
	}
}
