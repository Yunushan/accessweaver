// Fixed receipt/protocol labels only. This file has no native operations so
// every platform can check the one-byte command-failure projection.
package main

import (
	"errors"
	"math/bits"
	"syscall"
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

// Detail cases reuse unused bits in the existing executed/passed fields.
const windowsAliasDetailCaseOffset = 10

var windowsAliasDetailCaseNames = [...]string{
	"alias-action-import", "alias-action-ui", "alias-action-export-recorded", "alias-action-run",
	"alias-source-genesis", "alias-source-head", "alias-source-key", "alias-source-journal",
	"alias-source-profile", "alias-source-executable", "alias-source-pairwise",
	"alias-role-stdout", "alias-role-stderr", "alias-role-pairwise",
}

// Foreground assertions reuse the remaining bits without carrying native output.
const windowsRunDetailCaseOffset = windowsAliasDetailCaseOffset + len(windowsAliasDetailCaseNames)

var windowsRunDetailCaseNames = [...]string{
	"run-stream", "run-input-snapshot", "run-command-return",
	"run-error-preview-absent", "run-error-admission-absent", "run-error-recorder-absent",
	"run-error-uncertain-absent", "run-error-context-absent",
	"run-error-engine-exit-absent", "run-error-output-absent", "run-error-profile-absent",
	"run-error-input-absent", "run-error-journal-absent",
	"run-error-inert-args-absent", "run-error-inert-token-absent", "run-error-inert-security-absent",
	"run-error-inert-event-absent", "run-error-inert-existing-absent", "run-error-inert-close-absent",
	"run-error-ready-access-absent", "run-error-ready-handle-absent", "run-error-ready-parameter-absent",
	"run-error-ready-security-absent", "run-error-ready-owner-absent",
	"run-error-ready-privilege-absent", "run-error-ready-path-absent",
	"run-launch-notice", "run-observed-journal", "run-notice-private",
	"run-preserved-inputs", "run-released-resources", "run-stale-head-refusal",
	"run-retained-head-export", "run-unapproved-profile", "run-unapproved-refusal",
}

func windowsRunDetailBit(label string) (uint64, bool) {
	for index, name := range windowsRunDetailCaseNames {
		if label == name {
			return 1 << index, true
		}
	}
	return 0, false
}

func windowsAliasDetailBits(action, source, role string) (uint64, bool) {
	var mask uint64
	for index, name := range windowsAliasDetailCaseNames {
		if name == "alias-action-"+action || name == "alias-source-"+source || name == "alias-role-"+role {
			mask |= 1 << index
		}
	}
	if bits.OnesCount64(mask) != 3 {
		return 0, false
	}
	return mask, true
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
	aliasDetails := failed & (((uint64(1) << len(windowsAliasDetailCaseNames)) - 1) << (5 + windowsAliasDetailCaseOffset))
	if aliasDetails != 0 && failed&aliasCase == 0 {
		return 0, 0, false
	}
	const runCase = uint64(1) << (5 + 7)
	runDetails := failed & (((uint64(1) << len(windowsRunDetailCaseNames)) - 1) << (5 + windowsRunDetailCaseOffset))
	if runDetails != 0 && failed&runCase == 0 {
		return 0, 0, false
	}
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

func TestWindowsAliasDetailProjectionDropsPrivateLabels(t *testing.T) {
	const aliasCase = uint64(1) << (5 + 5)
	if 5+windowsAliasDetailCaseOffset+len(windowsAliasDetailCaseNames) > 64 {
		t.Fatal("alias detail cases exceed the existing reply fields")
	}
	var observed uint64
	for _, action := range []string{"import", "ui", "export-recorded", "run"} {
		for _, source := range []string{"genesis", "head", "key", "journal", "profile", "executable", "pairwise"} {
			for _, role := range []string{"stdout", "stderr", "pairwise"} {
				mask, ok := windowsAliasDetailBits(action, source, role)
				if !ok || bits.OnesCount64(mask) != 3 {
					t.Fatal("fixed detail case lost its command, input or output role")
				}
				observed |= mask
				failed := mask << (5 + windowsAliasDetailCaseOffset)
				code := encodeWindowsCommandFailure(0, makeWindowsAliasFailure("direct", "refusal-error"))
				if _, _, ok := decodeWindowsCommandFailure(code, aliasCase|failed); !ok {
					t.Fatal("detail cases lost the bound alias failure")
				}
				if _, _, ok := decodeWindowsCommandFailure(0, failed); ok {
					t.Fatal("detail failure was accepted without its umbrella alias failure")
				}
			}
		}
	}
	if observed != (uint64(1)<<len(windowsAliasDetailCaseNames))-1 {
		t.Fatal("detail case labels are duplicate or unreachable")
	}
	for _, labels := range [][3]string{
		{"PRIVATE_ACCOUNT_PATH", "genesis", "stdout"},
		{"import", "PRIVATE_NATIVE_PATH", "stdout"},
		{"ui", "head", "PRIVATE_STDERR"},
		{"", "", ""},
	} {
		if mask, ok := windowsAliasDetailBits(labels[0], labels[1], labels[2]); ok || mask != 0 {
			t.Fatal("private or unknown labels escaped the fixed detail projection")
		}
	}
}

func TestWindowsRunDetailProjectionIsClosedAndCaseBound(t *testing.T) {
	if 5+windowsRunDetailCaseOffset+len(windowsRunDetailCaseNames) > 64 {
		t.Fatal("foreground details exceed the existing reply fields")
	}
	const runCase = uint64(1) << (5 + 7)
	var observed uint64
	for index, label := range windowsRunDetailCaseNames {
		mask, ok := windowsRunDetailBit(label)
		if !ok || mask != uint64(1)<<index || observed&mask != 0 {
			t.Fatal("foreground detail is duplicate or unreachable")
		}
		observed |= mask
		failed := mask << (5 + windowsRunDetailCaseOffset)
		if _, _, ok := decodeWindowsCommandFailure(0, runCase|failed); !ok {
			t.Fatal("foreground detail lost its umbrella failure")
		}
		if _, _, ok := decodeWindowsCommandFailure(0, failed); ok {
			t.Fatal("foreground detail escaped its umbrella failure")
		}
	}
	for _, label := range []string{"PRIVATE_ACCOUNT_PATH", "PRIVATE_NATIVE_ERROR", ""} {
		if mask, ok := windowsRunDetailBit(label); ok || mask != 0 {
			t.Fatal("unknown or private foreground detail escaped its fixed vocabulary")
		}
	}
}

// Public Win32 codes only; native error strings and object names never cross
// the worker protocol. Unknown errors retain the existing generic exit.
func windowsInertReadyFailureExit(err error) int {
	if errors.Is(err, syscall.Errno(2)) { // an existing named readiness endpoint was not found
		return 110
	}
	for index, code := range []syscall.Errno{5, 6, 87, 1338, 1307, 1314, 3} {
		if errors.Is(err, code) {
			return 104 + index
		}
	}
	return 101
}

func TestWindowsInertReadyErrorProjectionDropsPrivateText(t *testing.T) {
	if windowsInertReadyFailureExit(errors.Join(syscall.Errno(2), errors.New("PRIVATE_ACCOUNT_PATH"))) != 110 {
		t.Fatal("missing readiness endpoint was not reduced to the fixed path category")
	}
	for index, code := range []syscall.Errno{5, 6, 87, 1338, 1307, 1314, 3} {
		if windowsInertReadyFailureExit(errors.Join(code, errors.New("PRIVATE_ACCOUNT_PATH"))) != 104+index {
			t.Fatal("fixed readiness error category was lost")
		}
	}
	for _, err := range []error{nil, errors.New("PRIVATE_NATIVE_ERROR"), syscall.Errno(9999)} {
		if windowsInertReadyFailureExit(err) != 101 {
			t.Fatal("unknown readiness error escaped the fixed projection")
		}
	}
}

// Fixed source stages for the native release probe. One additional command
// reply byte avoids overflowing the already full executed/passed bit fields.
type windowsRunReleaseStage byte

var windowsRunReleaseNames = [...]string{
	"none", "profiles-read", "profiles-not-empty", "presets-present-or-unreadable",
	"generated-present-or-unreadable", "controller-record-before", "controller-name",
	"controller-open", "controller-lock", "controller-close", "controller-record-after",
	"journal-record-before", "journal-name", "journal-open", "journal-lock", "journal-close",
	"journal-record-after", "profile-lock-record", "profile-lock-inspect",
	"job-accounting-query", "job-child-remains",
	"job-active-zero", "job-active-overflow", "job-list-query", "job-list-inconsistent",
	"job-worker-missing", "job-live-engine", "job-terminated-engine", "job-live-worker-peer",
	"job-live-other", "job-terminated-other", "job-peer-probe", "job-worker-only-list",
	"job-live-system-console-path", "job-live-system-powershell-path", "job-live-system-cmd-path",
	"console-window-binding", "console-process-binding", "console-process-open", "console-image-provenance", "console-initial-job-members",
}

func windowsRunReleaseValid(stage windowsRunReleaseStage, failed uint64) bool {
	if int(stage) >= len(windowsRunReleaseNames) {
		return false
	}
	const runCase = uint64(1) << (5 + 7)
	const drainCase = uint64(1) << (5 + 8)
	if stage >= 36 {
		stream, known := windowsRunDetailBit("run-stream")
		return known && failed&runCase != 0 && failed&(stream<<(5+windowsRunDetailCaseOffset)) != 0
	}
	released, known := windowsRunDetailBit("run-released-resources")
	if !known {
		return false
	}
	released <<= 5 + windowsRunDetailCaseOffset
	if failed&released != 0 {
		return stage != 0 && failed&runCase != 0
	}
	return stage == 0 || failed&drainCase != 0
}

func TestWindowsRunReleaseProjectionIsClosedAndCaseBound(t *testing.T) {
	released, _ := windowsRunDetailBit("run-released-resources")
	released <<= 5 + windowsRunDetailCaseOffset
	const runCase = uint64(1) << (5 + 7)
	const drainCase = uint64(1) << (5 + 8)
	for value := 0; value < 256; value++ {
		stage := windowsRunReleaseStage(value)
		stream, _ := windowsRunDetailBit("run-stream")
		if value >= 36 && windowsRunReleaseValid(stage, runCase|stream<<(5+windowsRunDetailCaseOffset)) != (value < len(windowsRunReleaseNames)) {
			t.Fatal("console binding diagnostic escaped its owning assertion")
		}
		known := value > 0 && value < 36
		if windowsRunReleaseValid(stage, runCase|released) != known ||
			windowsRunReleaseValid(stage, released) ||
			windowsRunReleaseValid(stage, drainCase) != (value < 36) ||
			windowsRunReleaseValid(stage, 0) != (value == 0) {
			t.Fatal("release stage escaped its fixed vocabulary or owning assertion")
		}
	}
}

// A held console host is part of the fixture baseline, never an engine child.
// Require an exact, duplicate-free set, not a larger allowed process count.
func windowsJobMembersValid(worker, console, child uint32, consoleInJob bool, assigned uint32, ids []uint32) bool {
	if worker == 0 || (consoleInJob && (console == 0 || console == worker)) || (child != 0 && (child == worker || child == console)) {
		return false
	}
	expected := map[uint32]bool{worker: true}
	if consoleInJob {
		expected[console] = true
	}
	if child != 0 {
		expected[child] = true
	}
	if assigned != uint32(len(ids)) || len(ids) != len(expected) {
		return false
	}
	for _, pid := range ids {
		if !expected[pid] {
			return false
		}
		delete(expected, pid)
	}
	return len(expected) == 0
}

func TestWindowsJobMembersRejectUnknownAndDuplicateProcesses(t *testing.T) {
	cases := []struct {
		consoleInJob    bool
		child, assigned uint32
		ids             []uint32
		want            bool
	}{
		{false, 0, 1, []uint32{10}, true}, {true, 0, 2, []uint32{20, 10}, true},
		{false, 30, 2, []uint32{30, 10}, true}, {true, 30, 3, []uint32{30, 20, 10}, true},
		{true, 0, 2, []uint32{10, 10}, false}, {true, 0, 2, []uint32{10, 99}, false},
		{false, 0, 1, []uint32{99}, false}, {true, 30, 3, []uint32{10, 20}, false},
		{false, 0, 2, []uint32{10}, false}, {true, 30, 3, []uint32{10, 20, 20}, false},
		{false, 0, 2, []uint32{10, 20}, false}, {true, 0, 3, []uint32{10, 20, 99}, false},
	}
	for _, c := range cases {
		if windowsJobMembersValid(10, 20, c.child, c.consoleInJob, c.assigned, c.ids) != c.want {
			t.Fatal("job membership escaped the held fixture baseline")
		}
	}
	for _, values := range [][3]uint32{{0, 20, 30}, {10, 10, 30}, {10, 0, 30}, {10, 20, 10}, {10, 20, 20}} {
		if windowsJobMembersValid(values[0], values[1], values[2], true, 3, []uint32{10, 20, 30}) {
			t.Fatal("invalid process binding accepted")
		}
	}
}
