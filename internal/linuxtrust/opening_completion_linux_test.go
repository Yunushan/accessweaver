//go:build linux

package linuxtrust

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type openingCompletionCase struct {
	name, kind, path, refusal string
	checks, closes            int
	failCheck, failClose      map[int]error
	changed                   bool
	success                   bool
}

func openingCompletionCases() []openingCompletionCase {
	primary, secondary, tertiary := errors.New("fixture inspection failure"), errors.New("fixture cleanup failure"), errors.New("fixture parent cleanup failure")
	return []openingCompletionCase{
		{name: "directory-handoff", kind: "directory", checks: 1, success: true},
		{name: "directory-check-close", kind: "directory", checks: 1, closes: 1, failCheck: map[int]error{1: primary}, failClose: map[int]error{1: secondary}},
		{name: "regular-handoff", kind: "regular", checks: 2, closes: 1, success: true},
		{name: "regular-probe-close", kind: "regular", checks: 1, closes: 1, failClose: map[int]error{1: secondary}},
		{name: "regular-probe-check-close", kind: "regular", checks: 1, closes: 1, failCheck: map[int]error{1: primary}, failClose: map[int]error{1: secondary}},
		{name: "regular-final-check-close", kind: "regular", checks: 2, closes: 2, failCheck: map[int]error{2: primary}, failClose: map[int]error{2: secondary}},
		{name: "regular-changed-close", kind: "regular", checks: 2, closes: 2, changed: true, refusal: "changed while opening", failClose: map[int]error{2: secondary}},
		{name: "root-handoff", kind: "root", path: "/", checks: 1, success: true},
		{name: "root-check-close", kind: "root", path: "/", checks: 1, closes: 1, failCheck: map[int]error{1: primary}, failClose: map[int]error{1: secondary}},
		{name: "walk-handoff", kind: "root", path: "/etc", checks: 2, closes: 1, success: true},
		{name: "walk-parent-close", kind: "root", path: "/etc", checks: 2, closes: 2, failClose: map[int]error{1: secondary}},
		{name: "walk-parent-child-close", kind: "root", path: "/etc", checks: 2, closes: 2, failClose: map[int]error{1: secondary, 2: tertiary}},
		{name: "walk-child-check-close-parent", kind: "root", path: "/etc", checks: 2, closes: 2, failCheck: map[int]error{2: primary}, failClose: map[int]error{1: secondary, 2: tertiary}},
		{name: "walk-open-parent-close", kind: "root", path: "/..", checks: 1, closes: 1, refusal: "expected one directory name", failClose: map[int]error{1: secondary}},
		{name: "walk-open-refusal", kind: "root", path: "/.", checks: 1, closes: 1, refusal: "expected one directory name"},
		{name: "relative-path-refusal", kind: "root", path: "relative", refusal: "must be absolute"},
	}
}

func TestLinuxTrustOpeningCompletion(t *testing.T) {
	records := []openingCompletionRecord{}
	for _, c := range openingCompletionCases() {
		record := openingCompletionRecord{Name: c.name}
		record.Passed = t.Run(c.name, func(t *testing.T) { record.CheckCalls, record.CloseCalls = exerciseOpeningCompletion(t, c) })
		records = append(records, record)
	}
	if err := writeOpeningCompletionEvidence(records); err != nil {
		t.Fatal("fixed opening completion evidence could not be retained")
	}
}

func exerciseOpeningCompletion(t *testing.T, c openingCompletionCase) (int, int) {
	t.Helper()
	owner := uint32(os.Geteuid())
	fixture := t.TempDir()
	if err := os.Mkdir(filepath.Join(fixture, "directory"), 0700); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(fixture, "payload")
	if err := os.WriteFile(payload, []byte("unchanged protected fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(fixture, "other")
	if err := os.WriteFile(other, []byte("different fixture inode"), 0600); err != nil {
		t.Fatal(err)
	}
	otherInfo, err := os.Stat(other)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := parent.Close(); err != nil {
			t.Error("caller parent close failed")
		}
	}()
	checkCalls, closeCalls := 0, 0
	checked := []*os.File{}
	closed := map[*os.File]int{}
	ops := openingOperations{
		check: func(f *os.File, directory bool, uid uint32) (os.FileInfo, error) {
			checked = append(checked, f)
			checkCalls++
			if err := c.failCheck[checkCalls]; err != nil {
				return nil, err
			}
			info, err := Check(f, directory, uid)
			if err == nil && c.changed && checkCalls == 2 {
				return otherInfo, nil
			}
			return info, err
		},
		close: func(f *os.File) error {
			closeCalls++
			closed[f]++
			if closed[f] != 1 {
				t.Error("owned descriptor close attempted more than once")
			}
			return errors.Join(f.Close(), c.failClose[closeCalls])
		},
	}
	var result *os.File
	switch c.kind {
	case "directory":
		result, err = openDirectoryAt(parent, "directory", owner, ops)
	case "regular":
		result, err = openRegularAt(parent, "payload", owner, ops)
	case "root":
		result, err = openRootDirectory(c.path, ops)
	default:
		t.Fatal("unknown fixture kind")
	}
	if result != nil {
		defer func() {
			if closeErr := result.Close(); closeErr != nil {
				t.Error("returned descriptor close failed")
			}
		}()
	}
	if c.success {
		if err != nil || result == nil {
			t.Errorf("handoff outcome differs: error=%v", err)
		}
	} else if err == nil || result != nil {
		t.Error("unconfirmed cleanup or inspection produced a handoff")
	}
	for _, cause := range c.failCheck {
		if !errors.Is(err, cause) {
			t.Error("inspection cause was lost")
		}
	}
	for _, cause := range c.failClose {
		if !errors.Is(err, cause) {
			t.Error("cleanup cause was lost")
		}
	}
	if c.refusal != "" && (err == nil || !strings.Contains(err.Error(), c.refusal)) {
		t.Error("original refusal cause was lost")
	}
	if checkCalls != c.checks || closeCalls != c.closes {
		t.Errorf("operation counts differ: checks=%d closes=%d; require %d/%d", checkCalls, closeCalls, c.checks, c.closes)
	}
	for _, f := range checked {
		_, statErr := f.Stat()
		if f == result {
			if closed[f] != 0 || statErr != nil {
				t.Error("returned descriptor was closed before caller handoff")
			}
		} else if closed[f] != 1 || !errors.Is(statErr, os.ErrClosed) {
			t.Error("temporary descriptor did not complete its single close")
		}
	}
	if _, err := parent.Stat(); err != nil {
		t.Error("callee closed the caller-owned parent")
	}
	data, err := os.ReadFile(payload)
	if err != nil || string(data) != "unchanged protected fixture" {
		t.Error("protected source bytes changed")
	}
	return checkCalls, closeCalls
}
