package engine

import (
	"context"
	"reflect"
	"testing"
)

func TestPreviewWindowsSearchAdmission(t *testing.T) {
	bad := []string{"", ".", `relative`, `C:relative`, `\rooted`, `\\preview.invalid\share`, `\\?\C:\tools`, `\??\C:\tools`, `\Device\HarddiskVolume1\tools`}
	dirs := append(append([]string{}, bad...), `C:\first`, `D:/second/`, `E:\unused`)
	var queried []string
	found := searchWindowsPreviewExecutable(context.Background(), "ciadpi", dirs, func(path string) bool {
		queried = append(queried, path)
		return path == `D:\second\ciadpi.exe`
	})
	if found != `D:\second\ciadpi.exe` || !reflect.DeepEqual(queried, []string{`C:\first\ciadpi.exe`, `D:\second\ciadpi.exe`}) {
		t.Fatal("search probed remote/current-directory entries, changed order, or continued after success")
	}
	for _, path := range bad {
		if windowsPreviewDrivePath(path) {
			t.Fatal("non-drive namespace passed lexical admission")
		}
	}
	for _, name := range []string{"", `\\preview.invalid\share\ciadpi.exe`, `C:\ciadpi.exe`, `sub/ciadpi`, "ciadpi\x00.exe", "ciadpi\n.exe"} {
		if searchWindowsPreviewExecutable(context.Background(), name, []string{`C:\local`}, func(string) bool { t.Fatal("invalid executable name reached a probe"); return false }) != "" {
			t.Fatal("invalid executable name was selected")
		}
	}
	if got := searchWindowsPreviewExecutable(context.Background(), "CIADPI.EXE", []string{`C:\`}, func(path string) bool { return path == `C:\CIADPI.EXE` }); got != `C:\CIADPI.EXE` {
		t.Fatal("native extension or drive-root search changed")
	}
}

func TestPreviewWindowsSearchCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queries := 0
	found := searchWindowsPreviewExecutable(ctx, "ciadpi", []string{`C:\first`, `D:\second`}, func(string) bool {
		queries++
		cancel()
		return false
	})
	if found != "" || queries != 1 {
		t.Fatal("cancellation allowed another filesystem probe")
	}
}
