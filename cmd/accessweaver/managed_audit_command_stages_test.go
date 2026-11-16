// Fixed receipt/protocol labels only. This file has no native operations so
// every platform can check the one-byte command-failure projection.
package main

import (
	"errors"
	"testing"
)

// The worker may publish only these fixed labels for a failed desktop assertion.
type windowsDesktopStage byte

const (
	windowsDesktopNoFailure windowsDesktopStage = iota
	windowsDesktopStream
	windowsDesktopStartup
	windowsDesktopLaunchPath
	windowsDesktopLaunchFileACL
	windowsDesktopLaunchDirectoryACL
	windowsDesktopLaunchContents
	windowsDesktopHTTPAdmission
	windowsDesktopHTTPMutation
	windowsDesktopHTTPDenials
	windowsDesktopShutdown
	windowsDesktopCleanup
	windowsDesktopJournal
	windowsDesktopExport
	windowsDesktopReopen
)

var windowsDesktopStageNames = [...]string{
	windowsDesktopNoFailure:          "none",
	windowsDesktopStream:             "stream",
	windowsDesktopStartup:            "startup",
	windowsDesktopLaunchPath:         "launch-path",
	windowsDesktopLaunchFileACL:      "launch-file-acl",
	windowsDesktopLaunchDirectoryACL: "launch-directory-acl",
	windowsDesktopLaunchContents:     "launch-contents",
	windowsDesktopHTTPAdmission:      "http-admission",
	windowsDesktopHTTPMutation:       "http-mutation",
	windowsDesktopHTTPDenials:        "http-denials",
	windowsDesktopShutdown:           "shutdown",
	windowsDesktopCleanup:            "cleanup",
	windowsDesktopJournal:            "journal",
	windowsDesktopExport:             "export",
	windowsDesktopReopen:             "reopen",
}

type windowsAliasFailure byte

var windowsAliasVariants = [...]string{"none", "direct", "case", "hardlink", "ads", "pairwise"}
var windowsAliasPhases = [...]string{"none", "prepare", "source-snapshot", "destination-open", "invoke", "watchdog", "refusal", "input-preservation", "product-inventory", "source-readback", "profile-inventory", "destination-cleanup", "budget", "refusal-input", "refusal-error", "refusal-output"}

// Classify only source-known categories; never publish command errors or output.
func windowsAliasRefusalPhase(commandErr, expected error, out, notice []byte) string {
	if !errors.Is(commandErr, expected) {
		if commandErr != nil && commandErr.Error() == "audit input must be an unchanged bounded regular file" {
			return "refusal-input"
		}
		return "refusal-error"
	}
	if len(out) != 0 || len(notice) != 0 {
		return "refusal-output"
	}
	return ""
}

func makeWindowsAliasFailure(variant, phase string) windowsAliasFailure {
	for kind, name := range windowsAliasVariants {
		if variant != name {
			continue
		}
		for step, label := range windowsAliasPhases {
			if step > 0 && phase == label {
				return windowsAliasFailure(kind<<4 | step)
			}
		}
	}
	return 127 // invalid; the parent must reject an unknown category
}
func windowsAliasFailureValid(value windowsAliasFailure) bool {
	return value != 0 && int(value>>4) < len(windowsAliasVariants) && int(value&15) > 0 && int(value&15) < len(windowsAliasPhases)
}
func windowsAliasFailureNames(value windowsAliasFailure) (string, string) {
	if value == 0 {
		return "none", "none"
	}
	if !windowsAliasFailureValid(value) {
		return "unavailable", "unavailable"
	}
	return windowsAliasVariants[value>>4], windowsAliasPhases[value&15]
}
func encodeWindowsCommandFailure(desktop windowsDesktopStage, alias windowsAliasFailure) byte {
	if int(desktop) >= len(windowsDesktopStageNames) || (alias != 0 && (!windowsAliasFailureValid(alias) || desktop != windowsDesktopNoFailure)) {
		return 255
	}
	if alias != 0 {
		return 128 | byte(alias)
	}
	return byte(desktop)
}
func decodeWindowsCommandFailure(value byte, failed uint64) (windowsDesktopStage, windowsAliasFailure, bool) {
	const desktopCase = uint64(1) << (5 + 2)
	const capacityCase = uint64(1) << (5 + 6)
	const aliasCase = uint64(1) << (5 + 5)
	observed := failed & (desktopCase | capacityCase | aliasCase)
	if value&128 != 0 {
		alias := windowsAliasFailure(value & 127)
		if !windowsAliasFailureValid(alias) || observed != aliasCase {
			return 0, 0, false
		}
		return 0, alias, true
	}
	desktop := windowsDesktopStage(value)
	if int(desktop) >= len(windowsDesktopStageNames) ||
		(desktop == windowsDesktopNoFailure && observed&(desktopCase|aliasCase) != 0) ||
		(desktop != windowsDesktopNoFailure && observed != desktopCase && observed != capacityCase) {
		return 0, 0, false
	}
	return desktop, 0, true
}

func TestWindowsCommandFailureStageRoundTripAndCaseBinding(t *testing.T) {
	if len(windowsAliasPhases) > 16 || len(windowsAliasVariants) > 8 {
		t.Fatal("fixed alias labels exceed the one-byte transport capacity")
	}
	const desktopCase = uint64(1) << (5 + 2)
	const capacityCase = uint64(1) << (5 + 6)
	const aliasCase = uint64(1) << (5 + 5)
	for stage := range windowsDesktopStageNames {
		failed := uint64(0)
		if stage != 0 {
			failed = desktopCase
		}
		encoded := encodeWindowsCommandFailure(windowsDesktopStage(stage), 0)
		desktop, alias, ok := decodeWindowsCommandFailure(encoded, failed)
		if !ok || desktop != windowsDesktopStage(stage) || alias != 0 {
			t.Fatal("desktop failure category changed in transport")
		}
		if stage != 0 {
			if _, _, ok := decodeWindowsCommandFailure(encoded, capacityCase); !ok {
				t.Fatal("capacity desktop phase was lost")
			}
			for _, wrong := range []uint64{0, aliasCase, desktopCase | aliasCase} {
				if _, _, ok := decodeWindowsCommandFailure(encoded, wrong); ok {
					t.Fatal("desktop phase admitted a different failed case")
				}
			}
		}
	}
	for _, variant := range windowsAliasVariants {
		for _, phase := range windowsAliasPhases[1:] {
			code := makeWindowsAliasFailure(variant, phase)
			if !windowsAliasFailureValid(code) {
				t.Fatal("fixed alias category unavailable")
			}
			encoded := encodeWindowsCommandFailure(windowsDesktopNoFailure, code)
			desktop, alias, ok := decodeWindowsCommandFailure(encoded, aliasCase)
			gotVariant, gotPhase := windowsAliasFailureNames(alias)
			if !ok || desktop != windowsDesktopNoFailure || alias != code || gotVariant != variant || gotPhase != phase {
				t.Fatal("fixed alias category changed in transport")
			}
			for _, wrong := range []uint64{0, desktopCase, capacityCase, aliasCase | desktopCase, aliasCase | capacityCase} {
				if _, _, ok := decodeWindowsCommandFailure(encoded, wrong); ok {
					t.Fatal("alias phase admitted a different failed case")
				}
			}
			if encodeWindowsCommandFailure(windowsDesktopStream, code) != 255 {
				t.Fatal("two failure categories shared one scalar")
			}
		}
	}
	if _, _, ok := decodeWindowsCommandFailure(0, uint64(1)<<14); !ok {
		t.Fatal("independent cleanup failure acquired a fabricated phase")
	}
	if _, _, ok := decodeWindowsCommandFailure(0, capacityCase); !ok {
		t.Fatal("capacity setup failure without a desktop phase was discarded")
	}
	for _, failed := range []uint64{desktopCase, aliasCase} {
		if _, _, ok := decodeWindowsCommandFailure(0, failed); ok {
			t.Fatal("missing phase admitted a failed categorized case")
		}
	}
}

func TestWindowsAliasFailureProjectionRejectsUnknownAndPrivateLabels(t *testing.T) {
	for _, item := range [][2]string{{"PRIVATE_ACCOUNT_PATH", "prepare"}, {"ads", "PRIVATE_NATIVE_ERROR"}, {"ads", "none"}, {"", ""}} {
		code := makeWindowsAliasFailure(item[0], item[1])
		variant, phase := windowsAliasFailureNames(code)
		if code != 127 || windowsAliasFailureValid(code) || variant != "unavailable" || phase != "unavailable" {
			t.Fatal("unknown alias metadata escaped fixed labels")
		}
	}
	const aliasCase = uint64(1) << (5 + 5)
	for scalar := 0; scalar < 256; scalar++ {
		desktop, alias, ok := decodeWindowsCommandFailure(byte(scalar), aliasCase)
		expected := scalar&128 != 0 && windowsAliasFailureValid(windowsAliasFailure(scalar&127))
		if ok != expected {
			t.Fatal("unknown or reserved command scalar was accepted")
		}
		if ok && (desktop != 0 || encodeWindowsCommandFailure(desktop, alias) != byte(scalar)) {
			t.Fatal("decoded scalar did not retain its original fixed category")
		}
	}
	for _, scalar := range []byte{16, 127, 128, 255} {
		if _, _, ok := decodeWindowsCommandFailure(scalar, 0); ok {
			t.Fatal("invalid scalar was accepted without a matching failure")
		}
	}
}

// These statuses belong only to the source-test worker wire protocol. A
// status never authenticates a reply or authorizes a command.
type darwinOrdinaryWorkerExit int

const (
	darwinOrdinaryExitRequestDescriptor darwinOrdinaryWorkerExit = 71 + iota
	darwinOrdinaryExitReplyDescriptor
	darwinOrdinaryExitWireFiles
	darwinOrdinaryExitRequestRead
	darwinOrdinaryExitRequestClose
	darwinOrdinaryExitReplyWrite
	darwinOrdinaryExitReplyClose
)

func (code darwinOrdinaryWorkerExit) label() string {
	switch code {
	case darwinOrdinaryExitRequestDescriptor:
		return "request-descriptor"
	case darwinOrdinaryExitReplyDescriptor:
		return "reply-descriptor"
	case darwinOrdinaryExitWireFiles:
		return "wire-files"
	case darwinOrdinaryExitRequestRead:
		return "request-read"
	case darwinOrdinaryExitRequestClose:
		return "request-close"
	case darwinOrdinaryExitReplyWrite:
		return "reply-write"
	case darwinOrdinaryExitReplyClose:
		return "reply-close"
	default:
		return ""
	}
}

func TestDarwinOrdinaryWorkerExitProjectionIsClosed(t *testing.T) {
	known := map[int]string{
		71: "request-descriptor", 72: "reply-descriptor", 73: "wire-files",
		74: "request-read", 75: "request-close", 76: "reply-write", 77: "reply-close",
	}
	// Include signal/timeout, ordinary validation and every other process status.
	for code := -1; code <= 255; code++ {
		if got := darwinOrdinaryWorkerExit(code).label(); got != known[code] {
			t.Fatalf("worker diagnostic escaped its fixed vocabulary for status %d", code)
		}
	}
}

func TestWindowsAliasRefusalProjectionDropsPrivateDiagnostics(t *testing.T) {
	expected := errors.New("expected admission refusal")
	private := errors.New("PRIVATE_ACCOUNT_PATH_NATIVE_ERROR")
	for _, check := range []struct {
		err         error
		out, notice []byte
		phase       string
	}{
		{err: expected},
		{err: errors.Join(expected, private)},
		{err: nil, phase: "refusal-error"},
		{err: private, phase: "refusal-error"},
		{err: errors.New("audit input must be an unchanged bounded regular file"), phase: "refusal-input"},
		{err: expected, out: []byte("PRIVATE_PROFILE"), phase: "refusal-output"},
		{err: expected, notice: []byte("PRIVATE_ACCOUNT"), phase: "refusal-output"},
	} {
		got := windowsAliasRefusalPhase(check.err, expected, check.out, check.notice)
		if got != check.phase {
			t.Fatal("private diagnostic did not reduce to its fixed refusal category")
		}
		if got != "" && !windowsAliasFailureValid(makeWindowsAliasFailure("direct", got)) {
			t.Fatal("fixed refusal category cannot cross the existing protocol")
		}
	}
}
