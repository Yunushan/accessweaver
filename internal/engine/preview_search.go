package engine

import (
	"context"
	"strings"
)

// Search only absolute drive entries and native .exe names. In particular,
// neither implicit current-directory lookup nor remote PATH entries are probed.
// The Windows probe still performs native local-drive/reparse admission: drive
// syntax alone cannot establish local storage or protect a later open.
func searchWindowsPreviewExecutable(ctx context.Context, name string, directories []string, probe func(string) bool) string {
	if name == "" || strings.ContainsAny(name, `\/:"<>|?*`) || strings.ContainsAny(name, "\x00\r\n") {
		return ""
	}
	if !strings.HasSuffix(strings.ToLower(name), ".exe") {
		name += ".exe"
	}
	for _, dir := range directories {
		if ctx.Err() != nil {
			return ""
		}
		if !windowsPreviewDrivePath(dir) {
			continue
		}
		candidate := strings.TrimRight(strings.ReplaceAll(dir, "/", `\`), `\`) + `\` + name
		if probe(candidate) {
			return candidate
		}
	}
	return ""
}

// A lexical rejection before acquisition, not evidence of a local drive mapping.
// The native walker must still admit every drive and followed reparse target.
func windowsPreviewDrivePath(path string) bool {
	return len(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/') &&
		((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z'))
}
