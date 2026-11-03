// accessweaver-desktop-installer verifies fixed public component paths without
// executing installed code or mutating the application/registration payloads.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"github.com/Yunushan/accessweaver/internal/packageupgrade"
)

func execute(name string, args []string) error {
	if len(args) == 2 && args[0] == "version" && args[1] == "--json" {
		return json.NewEncoder(os.Stdout).Encode(buildinfo.Current())
	}
	if name != "preinstall" && name != "postinstall" {
		return errors.New("usage: accessweaver-desktop-installer version --json; package phases require Apple's Installer")
	}
	if len(args) < 3 || len(args) > 8 || args[2] != "/" {
		return errors.New("desktop package phase requires the system root target")
	}
	for _, arg := range args {
		if len(arg) > 4096 || !utf8.ValidString(arg) || strings.IndexByte(arg, 0) >= 0 {
			return errors.New("desktop package argument exceeds encoding/size limit")
		}
	}
	result, e := packageupgrade.DesktopPackageOperation(name)
	if result.Phase != "" {
		e = errors.Join(e, json.NewEncoder(os.Stdout).Encode(result))
	}
	return e
}
func main() {
	if e := execute(filepath.Base(os.Args[0]), os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "desktop package refused:", e)
		os.Exit(1)
	}
}
