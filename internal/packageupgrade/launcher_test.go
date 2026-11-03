package packageupgrade

import (
	"strings"
	"testing"
)

func TestInstalledLaunchArgumentsAreBoundedAndCopied(t *testing.T) {
	args, e := installedLaunchArguments(nil)
	if e != nil || len(args) != 1 || args[0] != "ui" {
		t.Fatal(args, e)
	}
	input := []string{"show", "discord-proxy"}
	args, e = installedLaunchArguments(input)
	if e != nil {
		t.Fatal(e)
	}
	input[0] = "changed"
	if args[0] != "show" {
		t.Fatal("argument alias")
	}
	for _, bad := range [][]string{{strings.Repeat("x", 4097)}, {"x\x00y"}, {string([]byte{0xff})}, make([]string, 65), {strings.Repeat("a", 4096), strings.Repeat("b", 4096), strings.Repeat("c", 4096), strings.Repeat("d", 4096), strings.Repeat("e", 4096), strings.Repeat("f", 4096), strings.Repeat("g", 4096), strings.Repeat("h", 4096), "extra"}} {
		if _, e := installedLaunchArguments(bad); e == nil {
			t.Fatal("unsafe arguments accepted")
		}
	}
}
