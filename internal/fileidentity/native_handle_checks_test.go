package fileidentity

import "testing"

const (
	windowsIdentityEventHandle     = 4
	windowsIdentityFileHandle      = 7
	windowsIdentityTokenHandle     = 8
	windowsIdentityHandleTypeCount = 9
)

type windowsIdentityHandleWindow struct {
	SnapshotComplete bool                                   `json:"snapshotComplete"`
	CountsMatch      bool                                   `json:"countsMatch"`
	KindsBefore      [windowsIdentityHandleTypeCount]uint32 `json:"kindsBefore"`
	KindsAfter       [windowsIdentityHandleTypeCount]uint32 `json:"kindsAfter"`
	NewHandleKinds   [windowsIdentityHandleTypeCount]uint32 `json:"newHandleKinds"`
}

func windowsIdentityMetadataHandlesClosed(before, after uint32, types *windowsIdentityHandleWindow) bool {
	complete := types != nil && types.SnapshotComplete && types.CountsMatch
	if complete && (types.NewHandleKinds[windowsIdentityFileHandle] != 0 ||
		types.NewHandleKinds[windowsIdentityTokenHandle] != 0) {
		return false
	}
	if after <= before || after-before == 1 {
		return true
	}
	// This fixture owns files and tokens. Windows can also allocate an
	// event pair while the Go scheduler parks an existing thread. Accept
	// only a complete census that accounts for the entire two-handle rise.
	if !complete || after-before != 2 {
		return false
	}
	for kind, previous := range types.KindsBefore {
		added := uint32(0)
		if kind == windowsIdentityEventHandle {
			added = 2
		}
		if types.KindsAfter[kind] != previous+added || types.NewHandleKinds[kind] != added {
			return false
		}
	}
	return true
}

func TestWindowsIdentityHandleAdmission(t *testing.T) {
	eventPair := windowsIdentityHandleWindow{
		SnapshotComplete: true, CountsMatch: true,
		KindsBefore:    [windowsIdentityHandleTypeCount]uint32{77, 0, 8, 2, 20, 0, 2, 9, 0},
		KindsAfter:     [windowsIdentityHandleTypeCount]uint32{77, 0, 8, 2, 22, 0, 2, 9, 0},
		NewHandleKinds: [windowsIdentityHandleTypeCount]uint32{0, 0, 0, 0, 2, 0, 0, 0, 0},
	}
	tests := []struct {
		name     string
		after    uint32
		change   func(*windowsIdentityHandleWindow)
		accepted bool
	}{
		{"measured-event-pair", 120, func(*windowsIdentityHandleWindow) {}, true},
		{"incomplete-census", 120, func(w *windowsIdentityHandleWindow) { w.SnapshotComplete = false }, false},
		{"mismatched-totals", 120, func(w *windowsIdentityHandleWindow) { w.CountsMatch = false }, false},
		{"file-replaces-event", 120, func(w *windowsIdentityHandleWindow) {
			w.KindsAfter[windowsIdentityEventHandle]--
			w.NewHandleKinds[windowsIdentityEventHandle]--
			w.KindsAfter[windowsIdentityFileHandle]++
			w.NewHandleKinds[windowsIdentityFileHandle]++
		}, false},
		{"token-within-original-threshold", 119, func(w *windowsIdentityHandleWindow) {
			w.KindsAfter[windowsIdentityEventHandle] -= 2
			w.NewHandleKinds[windowsIdentityEventHandle] = 0
			w.KindsAfter[windowsIdentityTokenHandle]++
			w.NewHandleKinds[windowsIdentityTokenHandle]++
		}, false},
		{"unknown-handle-replaced", 120, func(w *windowsIdentityHandleWindow) { w.NewHandleKinds[0] = 1 }, false},
		{"more-than-one-event-pair", 122, func(w *windowsIdentityHandleWindow) {
			w.KindsAfter[windowsIdentityEventHandle] += 2
			w.NewHandleKinds[windowsIdentityEventHandle] += 2
		}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			window := eventPair
			test.change(&window)
			if got := windowsIdentityMetadataHandlesClosed(118, test.after, &window); got != test.accepted {
				t.Fatalf("handle admission = %t, want %t", got, test.accepted)
			}
		})
	}
	if !windowsIdentityMetadataHandlesClosed(118, 119, nil) || windowsIdentityMetadataHandlesClosed(118, 120, nil) {
		t.Fatal("missing attribution changed the original aggregate guard")
	}
}
