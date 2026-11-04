package packageupgrade

import (
	"bytes"
	"strings"
	"testing"
)

func TestRemovalJournalEveryInterruptedByte(t *testing.T) {
	seed := strings.Repeat("e", 64)
	raw := []byte{}
	for entry := 0; entry < 4; entry++ {
		before, e := decodeRemovalJournal(raw, seed, 2)
		if e != nil {
			t.Fatal(e)
		}
		next, e := nextRemovalJournalLine(seed, before)
		if e != nil {
			t.Fatal(e)
		}
		for cut := 0; cut < len(next); cut++ {
			partial := append(append([]byte{}, raw...), next[:cut]...)
			got, e := decodeRemovalJournal(partial, seed, 2)
			if e != nil || got.entries != entry || got.completed != entry/2 || got.pending != (entry%2 != 0) || got.validBytes != len(raw) || !bytes.Equal(got.tail, next[:cut]) {
				t.Fatalf("entry %d byte %d incorrectly advanced: %+v %v", entry, cut, got, e)
			}
			// Truncating only the recognized suffix preserves the exact chain.
			repaired := append(append([]byte{}, partial[:got.validBytes]...), next...)
			finished, e := decodeRemovalJournal(repaired, seed, 2)
			if e != nil || finished.entries != entry+1 {
				t.Fatal(finished, e)
			}
		}
		raw = append(raw, next...)
		after, e := decodeRemovalJournal(raw, seed, 2)
		if e != nil || after.entries != entry+1 || after.completed != (entry+1)/2 || after.pending != ((entry+1)%2 != 0) {
			t.Fatal(after, e)
		}
	}
	for _, bad := range [][]byte{append(append([]byte{}, raw...), 'x'), append(append([]byte{}, raw...), '\n'), raw[1:], append([]byte{' '}, raw...), bytes.Replace(raw, []byte("intent"), []byte("done"), 1), bytes.Replace(raw, []byte("\"action\":0"), []byte("\"action\":1"), 1), bytes.Replace(raw, []byte("\"sequence\":1"), []byte("\"sequence\":2"), 1)} {
		if got, e := decodeRemovalJournal(bad, seed, 2); e == nil || got.entries != 0 || got.completed != 0 || got.pending || got.validBytes != 0 || got.lastSHA256 != "" || got.tail != nil {
			t.Fatal("invalid log accepted or nonzero failure", got, e)
		}
	}
	if _, e := decodeRemovalJournal(raw, strings.Repeat("a", 64), 2); e == nil {
		t.Fatal("different intent accepted")
	}
}
func TestRemovalJournalCorruptPartialAndExtent(t *testing.T) {
	seed := strings.Repeat("e", 64)
	for _, raw := range [][]byte{[]byte("{bad"), []byte("\n"), []byte("{}\n"), bytes.Repeat([]byte("x"), maxRemovalJournalBytes+1)} {
		if _, e := decodeRemovalJournal(raw, seed, 2); e == nil {
			t.Fatal("bad journal accepted")
		}
	}
	for _, count := range []int{-1, 0, maxRemovalPlanObjects + 1} {
		if _, e := decodeRemovalJournal(nil, seed, count); e == nil {
			t.Fatal("invalid action count accepted")
		}
	}
	if _, e := decodeRemovalJournal(nil, "bad", 2); e == nil {
		t.Fatal("invalid binding accepted")
	}
}
func TestRemovalJournalOnlyProtectedRegularFiles(t *testing.T) {
	plan := removalPlanFixture()
	actions, e := removalFileActions(plan)
	if e != nil || len(actions) != 2 {
		t.Fatal(actions, e)
	}
	for _, action := range actions {
		root := plan.Roots[action.root]
		if root.Kind != "core" && root.Kind != "incoming" || root.Objects[action.object].Kind != "file" {
			t.Fatal("unsafe action", action)
		}
	}
	plan.Roots[0].Objects[1].Path = "../private-profile"
	if _, e := removalFileActions(plan); e == nil {
		t.Fatal("invalid plan accepted")
	}
}
