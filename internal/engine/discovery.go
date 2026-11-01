package engine

import (
	"os"
	"path/filepath"
	"runtime"
)

func installedCandidates(id string) []string {
	if runtime.GOOS != "windows" {
		return nil
	}
	base := os.Getenv("ProgramFiles")
	data := os.Getenv("ProgramData")
	names := map[string]string{"byedpi": "byedpi/ciadpi.exe", "zapret": "zapret/zapret-winws/winws.exe", "zapret2": "zapret/zapret-winws2/winws2.exe", "goodbyedpi": "goodbyedpi/x86_64/goodbyedpi.exe"}
	binary := map[string]string{"byedpi": "ciadpi.exe", "zapret": "winws.exe", "zapret2": "winws2.exe", "goodbyedpi": "goodbyedpi.exe"}
	if name, ok := names[id]; ok {
		return []string{filepath.Join(data, "AccessWeaver", "components", id, binary[id]), filepath.Join(base, "SplitWire-Turkey", "res", filepath.FromSlash(name))}
	}
	if id == "wiresock" {
		return []string{filepath.Join(base, "WireSock Secure Connect", "bin", "wiresock-client.exe"), filepath.Join(base, "WireSock VPN Client", "bin", "wiresock-client.exe")}
	}
	return nil
}
