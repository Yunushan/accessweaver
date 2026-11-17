//go:build darwin && (amd64 || arm64)

package packageupgrade

import "os"

// Own the Applications descriptor through verification. A completed result is
// handed to the product coordinator only after every owned read has completed.
// This scope never writes public payloads or mutates the core installation.
func (r runtimeReadOps) withDesktopApplications(apps *os.File, verify func(*os.File) (DesktopPackageResult, error)) (result DesktopPackageResult, failure error) {
	defer func() {
		failure = r.finish(apps, failure)
		if failure != nil {
			result = DesktopPackageResult{}
		}
	}()
	return verify(apps)
}
