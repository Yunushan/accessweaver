package engine

import (
	"fmt"
	"runtime"
	"sort"
)

// Descriptor describes this adapter's capabilities, not every feature of its upstream.
type Descriptor struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	Platforms    []string `json:"platforms"`
	Executables  []string `json:"executables"`
	Integration  string   `json:"integration"`
	License      string   `json:"license"`
	Includes     bool     `json:"includes"`
	Excludes     bool     `json:"excludes"`
	Applications bool     `json:"applications"`
	NativeMobile bool     `json:"nativeMobile"`
	Source       string   `json:"source"`
	Notes        string   `json:"notes"`
}

var catalog = map[string]Descriptor{
	"zapret":     {ID: "zapret", Name: "zapret · legacy", Kind: "packet", Platforms: []string{"windows", "linux", "freebsd", "openbsd", "darwin"}, Executables: []string{"winws", "nfqws", "tpws", "dvtws"}, Integration: "managed", License: "MIT", Includes: true, Excludes: true, Source: "https://github.com/bol-van/zapret", Notes: "Upstream EOL. Linux/BSD interception rules are external. macOS is limited to tpws in SOCKS mode; no macOS packet adapter."},
	"zapret2":    {ID: "zapret2", Name: "zapret2", Kind: "packet", Platforms: []string{"windows", "linux", "freebsd", "openbsd"}, Executables: []string{"winws2", "nfqws2", "dvtws2"}, Integration: "managed", License: "MIT", Includes: true, Excludes: true, Source: "https://github.com/bol-van/zapret2", Notes: "Lua-driven strategy engine. Supply a tested strategy, upstream Lua assets and OS interception setup. Upstream does not support macOS."},
	"byedpi":     {ID: "byedpi", Name: "ByeDPI", Kind: "proxy", Platforms: []string{"windows", "linux", "darwin", "freebsd", "openbsd"}, Executables: []string{"ciadpi"}, Integration: "managed", License: "MIT", Includes: true, Excludes: true, Source: "https://github.com/hufrea/byedpi", Notes: "Local SOCKS5 proxy with domain strategy groups. Configure each app's proxy separately. macOS/BSD require a compatible user-built binary; individual techniques differ by OS."},
	"goodbyedpi": {ID: "goodbyedpi", Name: "GoodbyeDPI", Kind: "packet", Platforms: []string{"windows"}, Executables: []string{"goodbyedpi"}, Integration: "managed", License: "Apache-2.0 (WinDivert has separate terms)", Includes: true, Source: "https://github.com/ValdikSS/GoodbyeDPI", Notes: "Windows administrator privileges and compatible WinDivert files required. Includes map to --blacklist. General domain exclusions and application filters are unsupported."},
	"wiresock":   {ID: "wiresock", Name: "WireSock SDK", Kind: "vpn", Platforms: []string{"windows"}, Executables: []string{"wiresock-client"}, Integration: "managed", License: "Proprietary SDK EULA; evaluation and commercial terms differ", Source: "https://wiresock.net/wiresock-sdk/", Notes: "Official SDK foreground client only. Supply a local WireGuard .conf file in configPath. Configure AllowedApps/DisallowedApps in that file. Vendor installation and driver required; never bundled."},
	"wireguard":  {ID: "wireguard", Name: "WireGuard", Kind: "vpn", Platforms: []string{"windows", "linux", "darwin", "freebsd", "openbsd"}, Executables: []string{"wg-quick", "wireguard", "wireguard-go"}, Integration: "external", License: "Varies by component; see upstream", Source: "https://www.wireguard.com/", Notes: "Reference integration only. Use the official OS client to manage tunnels. wg-quick exits while leaving a kernel tunnel, so it is deliberately not treated as a managed child process."},
	"spoofdpi":   {ID: "spoofdpi", Name: "SpoofDPI", Kind: "proxy", Platforms: []string{"windows", "linux", "darwin"}, Executables: []string{"spoofdpi"}, Integration: "managed", License: "Apache-2.0", Source: "https://github.com/xvzc/SpoofDPI", Notes: "Optional HTTP proxy. Supply flags for your installed version and inspect its system-proxy setting; some releases configure macOS proxies automatically."},
	"sing-box":   {ID: "sing-box", Name: "sing-box", Kind: "proxy", Platforms: []string{"windows", "linux", "darwin", "freebsd", "openbsd"}, Executables: []string{"sing-box"}, Integration: "managed", License: "GPL-3.0-or-later; external process only", Source: "https://sing-box.sagernet.org/", Notes: "Requires configPath to an existing configuration. Routing, credentials, proxy listeners and optional TUN changes are controlled by that configuration."},
	"xray":       {ID: "xray", Name: "Xray-core", Kind: "proxy", Platforms: []string{"windows", "linux", "darwin", "freebsd"}, Executables: []string{"xray"}, Integration: "managed", License: "MPL-2.0; external process only", Source: "https://github.com/XTLS/Xray-core", Notes: "Requires configPath to an existing local configuration. Remote config URLs are not accepted. This manager does not provision endpoints or credentials."},
}

func Catalog() []Descriptor {
	ids := make([]string, 0, len(catalog))
	for k := range catalog {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	out := make([]Descriptor, 0, len(ids))
	for _, k := range ids {
		d, _ := Lookup(k)
		out = append(out, d)
	}
	return out
}
func Lookup(id string) (Descriptor, error) {
	d, ok := catalog[id]
	if !ok {
		return d, fmt.Errorf("unknown engine %q", id)
	}
	// Callers cannot mutate the shared catalog through returned slices.
	d.Platforms = append([]string(nil), d.Platforms...)
	d.Executables = append([]string(nil), d.Executables...)
	return d, nil
}
func (d Descriptor) Supported(goos string) bool {
	for _, p := range d.Platforms {
		if p == goos {
			return true
		}
	}
	return false
}
func (d Descriptor) ExecutablesFor(goos string) []string {
	switch d.ID {
	case "zapret":
		switch goos {
		case "windows":
			return []string{"winws"}
		case "linux":
			return []string{"nfqws", "tpws"}
		case "freebsd", "openbsd":
			return []string{"dvtws", "tpws"}
		case "darwin":
			return []string{"tpws"}
		}
	case "zapret2":
		switch goos {
		case "windows":
			return []string{"winws2"}
		case "linux":
			return []string{"nfqws2"}
		case "freebsd", "openbsd":
			return []string{"dvtws2"}
		}
	}
	if d.Supported(goos) {
		return append([]string(nil), d.Executables...)
	}
	return nil
}
func Platform() string { return runtime.GOOS }
