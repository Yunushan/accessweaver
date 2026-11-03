//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"strings"
	"syscall"
	"testing"
)

func TestInstalledPlistIdentityAndParserBounds(t *testing.T) {
	good := `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.github.yunushan.accessweaver</string><key>CFBundleExecutable</key><string>accessweaver</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>0.1.0</string><key>CFBundleShortVersionString</key><string>0.1.0</string><key>AccessWeaverReleaseVersion</key><string>0.1.0-alpha</string><key>LSUIElement</key><true/></dict></plist>`
	if e := checkPlist([]byte(good), "0.1.0-alpha"); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{good + good, strings.Replace(good, `<plist version="1.0">`, `<plist xmlns="urn:other" version="1.0">`, 1), strings.Replace(good, `<key>LSUIElement</key>`, `<key>CFBundleIdentifier</key>`, 1), strings.Replace(good, `<true/>`, `<false/>`, 1), strings.Replace(good, `<string>accessweaver</string>`, `<string>other</string>`, 1), `<plist><dict>` + strings.Repeat(`<dict>`, 20) + strings.Repeat(`</dict>`, 20) + `</dict></plist>`, strings.Replace(good, `<dict>`, `<!ENTITY secret SYSTEM "file:///private/secret"><dict>`, 1)} {
		if e := checkPlist([]byte(bad), "0.1.0-alpha"); e == nil {
			t.Fatal("malformed/ambiguous installed plist accepted")
		}
	}
}
func TestReadAccessTimeIsNotAnObjectMutation(t *testing.T) {
	a := syscall.Stat_t{}
	b := a
	b.Atimespec.Sec = 1
	if !sameState(a, b) {
		t.Fatal("ordinary read atime treated as mutation")
	}
	b.Ctimespec.Sec = 1
	if sameState(a, b) {
		t.Fatal("metadata mutation was ignored")
	}
	b = a
	b.Uid = 501
	if sameState(a, b) {
		t.Fatal("ownership change was ignored")
	}
}
