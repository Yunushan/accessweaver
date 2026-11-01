// Package buildinfo provides the common runtime and release identity.
package buildinfo

import (
	"runtime"
	"runtime/debug"
)

// Release builders can supply these values with Go linker -X settings.
// Unknown source identity must remain explicit rather than implying a clean build.
var Version = "0.1.0-alpha"
var Commit = "unknown"
var SourceState = "unknown"
var BuiltAt = "unknown"

type Info struct {
	Version     string `json:"version"`
	Commit      string `json:"commit"`
	SourceState string `json:"sourceState"`
	BuiltAt     string `json:"builtAt"`
	GoVersion   string `json:"goVersion"`
	Platform    string `json:"platform"`
	Arch        string `json:"arch"`
}

func Current() Info {
	info := Info{Version, Commit, SourceState, BuiltAt, runtime.Version(), runtime.GOOS, runtime.GOARCH}
	if build, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range build.Settings {
			switch setting.Key {
			case "vcs.revision":
				if info.Commit == "unknown" {
					info.Commit = setting.Value
				}
			case "vcs.modified":
				if info.SourceState == "unknown" {
					if setting.Value == "true" {
						info.SourceState = "modified"
					} else if setting.Value == "false" {
						info.SourceState = "clean"
					}
				}
			}
		}
	}
	return info
}
