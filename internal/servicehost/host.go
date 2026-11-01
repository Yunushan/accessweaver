// Package servicehost runs a foreground engine under the Windows SCM.
package servicehost

type Config struct {
	Name      string   `json:"name"`
	Binary    string   `json:"binary"`
	Args      []string `json:"args"`
	Directory string   `json:"directory"`
	LogPath   string   `json:"logPath"`
}
