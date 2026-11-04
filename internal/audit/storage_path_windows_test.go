//go:build windows && (amd64 || arm64)

package audit

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// These cases exercise namespace admission only; no filesystem, account, token
// or security-descriptor API is called by this test.
func TestWindowsAuditPathAdmission(t *testing.T) {
	for _, tc := range []struct {
		name, path, root string
		parts            []string
	}{
		{"drive root", `C:\`, `C:\`, nil},
		{"private user path", `C:\Users\operator\.accessweaver-audit`, `C:\`, []string{"Users", "operator", ".accessweaver-audit"}},
		{"lowercase drive", `d:\Audit`, `d:\`, []string{"Audit"}},
		{"unicode component", `D:\監査\évidence`, `D:\`, []string{"監査", "évidence"}},
		{"non-device prefix", `D:\COM10\NUL-items`, `D:\`, []string{"COM10", "NUL-items"}},
		{"maximum component", `C:\` + strings.Repeat("a", 255), `C:\`, []string{strings.Repeat("a", 255)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, parts, err := parseWindowsAuditPath(tc.path)
			if err != nil || root != tc.root || len(parts) != len(tc.parts) {
				t.Fatalf("canonical path refused or changed: %v", err)
			}
			for index := range parts {
				if parts[index] != tc.parts[index] {
					t.Fatal("path component changed")
				}
			}
		})
	}
	invalid := []string{
		"", ".", "..", "relative", `C:relative`, `\rooted`, `C:/Audit`, `C:\Audit/child`,
		`\\server\share\Audit`, `\\?\C:\Audit`, `\\.\C:\Audit`, `\??\C:\Audit`, `1:\Audit`,
		`C:\Audit\`, `C:\\Audit`, `C:\Audit\.\child`, `C:\Audit\..\child`,
		`C:\Audit:stream`, `C:\Audit\events.journal:stream`, `C:\Audit.`, `C:\Audit `,
		`C:\Audit\CON`, `C:\Audit\nul.txt`, `C:\Audit\AUX.tar.gz`, `C:\Audit\COM1`,
		`C:\Audit\LPT9.log`, `C:\Audit\COM¹.log`, `C:\Audit\LPT²`, `C:\Audit\CONIN$`,
		`C:\Audit\CONOUT$`, `C:\Audit\CLOCK$`, `C:\Audit\wild*`, `C:\Audit\wild?`,
		`C:\Audit\a"b`, `C:\Audit\a<b`, `C:\Audit\a>b`, `C:\Audit\a|b`,
		"C:\\Audit\\line\nname", "C:\\Audit\\line\rname", "C:\\Audit\\tab\tname", "C:\\Audit\\zero\x00name",
		"C:\\Audit\\invalid" + string([]byte{0xff}), `C:\` + strings.Repeat("a", 256),
		`C:\` + strings.Repeat("😀", 128), `C:\` + strings.Repeat("a", 32760),
	}
	for index, path := range invalid {
		root, parts, err := parseWindowsAuditPath(path)
		if !errors.Is(err, ErrJournalStorage) || root != "" || parts != nil {
			t.Fatalf("unsafe namespace case %d admitted", index)
		}
		if strings.Contains(err.Error(), path) && path != "" {
			t.Fatalf("unsafe namespace case %d disclosed its path", index)
		}
	}
}

func TestWindowsAuditChildAdmission(t *testing.T) {
	for _, name := range []string{actorKeyName, journalName} {
		if !windowsAuditChild(name) {
			t.Fatal("fixed audit child refused")
		}
	}
	for _, name := range []string{"", ".", "..", ".ACTOR-KEY", "EVENTS.JOURNAL", ".actor-key:stream", "events.journal:stream", `sub\events.journal`, `..\events.journal`, `C:\events.journal`} {
		if windowsAuditChild(name) {
			t.Fatal("alternate child namespace admitted")
		}
	}
}

func TestWindowsAuditStorageErrorClassification(t *testing.T) {
	for _, err := range []error{windows.ERROR_SHARING_VIOLATION, windows.ERROR_LOCK_VIOLATION, windows.STATUS_SHARING_VIOLATION} {
		if !errors.Is(windowsAuditStorageError(err), ErrJournalBusy) {
			t.Fatal("contention lost")
		}
	}
	for _, err := range []error{windows.ERROR_ACCESS_DENIED, windows.ERROR_FILE_NOT_FOUND, windows.STATUS_OBJECT_NAME_NOT_FOUND, errors.New("private-path-detail")} {
		got := windowsAuditStorageError(err)
		if !errors.Is(got, ErrJournalStorage) || errors.Is(got, ErrJournalBusy) || strings.Contains(got.Error(), "private-path-detail") {
			t.Fatal("non-contention misclassified or disclosed")
		}
	}
	for _, err := range []error{windows.ERROR_FILE_NOT_FOUND, windows.STATUS_OBJECT_NAME_NOT_FOUND} {
		if !windowsAuditMissing(err) {
			t.Fatal("absent final child lost")
		}
	}
	for _, err := range []error{windows.ERROR_PATH_NOT_FOUND, windows.STATUS_OBJECT_PATH_NOT_FOUND, windows.ERROR_ACCESS_DENIED, ErrJournalStorage} {
		if windowsAuditMissing(err) {
			t.Fatal("broken ancestor or access refusal treated as an absent key")
		}
	}
}
