// accessweaver-installer is a separate native packaging tool. It never starts
// the UI, runs an installed executable or deletes retained deployment files.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"github.com/Yunushan/accessweaver/internal/packageupgrade"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

func execute(args []string) error {
	if len(args) == 2 && args[0] == "version" && args[1] == "--json" {
		return json.NewEncoder(os.Stdout).Encode(buildinfo.Current())
	}
	if len(args) == 1 && (args[0] == "prepare-deployment" || args[0] == "activate-deployment" || args[0] == "deactivate-deployment" || args[0] == "abandon-deployment") {
		result, err := packageupgrade.DeploymentOperation(args[0])
		if result.Operation != "" {
			err = errors.Join(err, json.NewEncoder(os.Stdout).Encode(result))
		}
		return err
	}
	if len(args) != 1 || args[0] != "preflight-upgrade" {
		return errors.New("usage: accessweaver-installer version --json | preflight-upgrade | prepare-deployment | activate-deployment | deactivate-deployment | abandon-deployment")
	}
	result, err := packageupgrade.Preflight(buildinfo.Current().Version)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

// PackageKit supplies package path, install location and target volume. Only
// the target-volume guard is interpreted; all filesystem authority stays fixed
// inside the compiled-seal API. Ordinary command routing remains available for
// explicit root recovery with a helper extracted from an authenticated package.
func executeForName(name string, args []string) error {
	if name != "preinstall" && name != "postinstall" {
		return execute(args)
	}
	if len(args) == 1 || len(args) == 2 {
		return execute(args)
	}
	if len(args) < 3 || len(args) > 8 || args[2] != "/" {
		return errors.New("package phase requires the system root target")
	}
	for _, arg := range args {
		if len(arg) > 4096 || !utf8.ValidString(arg) || strings.IndexByte(arg, 0) >= 0 {
			return errors.New("package argument exceeds encoding/size limits")
		}
	}
	result, err := packageupgrade.PackageOperation(name)
	if result.Operation != "" {
		err = errors.Join(err, json.NewEncoder(os.Stdout).Encode(result))
	}
	return err
}
func main() {
	if err := executeForName(filepath.Base(os.Args[0]), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "installer operation refused:", err)
		os.Exit(1)
	}
}
