package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"github.com/Yunushan/accessweaver/internal/packageupgrade"
)

func main() {
	if e := execute(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "AccessWeaver:", e)
		os.Exit(1)
	}
}
func execute(args []string) error {
	if len(args) > 0 && args[0] == "launcher-version" {
		if len(args) == 2 && args[1] == "--json" {
			return json.NewEncoder(os.Stdout).Encode(buildinfo.Current())
		}
		if len(args) == 1 {
			fmt.Println("AccessWeaver launcher", buildinfo.Version)
			return nil
		}
		return errors.New("usage: accessweaver-launcher launcher-version [--json]")
	}
	return packageupgrade.LaunchInstalled(args)
}
