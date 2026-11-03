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
func main() {
	if err := execute(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "installer operation refused:", err)
		os.Exit(1)
	}
}
