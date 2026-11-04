package packageupgrade

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestRemovalAppActionsPreserveProtectedPrefixAndUseOnlyRecordedPublicObjects(t *testing.T) {
	plan := removalPlanFixture()
	protected, e := removalProtectedActions(plan)
	if e != nil {
		t.Fatal(e)
	}
	all, e := removalAllActions(plan)
	if e != nil {
		t.Fatal(e)
	}
	if len(all) <= len(protected) || !reflect.DeepEqual(protected, all[:len(protected)]) {
		t.Fatal("protected action prefix changed", all)
	}
	seen := map[removalFileAction]bool{}
	for _, action := range all[len(protected):] {
		root := plan.Roots[action.root]
		object := root.Objects[action.object]
		if root.Kind != "public" || seen[action] {
			t.Fatal("ineligible or duplicate app action", action)
		}
		if object.Kind == "directory" {
			for j, child := range root.Objects {
				if j != action.object && (object.Path == "." || strings.HasPrefix(child.Path, object.Path+"/")) && !seen[removalFileAction{action.root, j}] {
					t.Fatal("app directory before child", object.Path, child.Path)
				}
			}
		}
		seen[action] = true
	}
	last := all[len(all)-1]
	if plan.Roots[last.root].Kind != "public" || last.object != 0 {
		t.Fatal("public root is not last")
	}
	again, e := removalAllActions(plan)
	if e != nil || !reflect.DeepEqual(all, again) {
		t.Fatal("nondeterministic app actions", e)
	}
	seed := strings.Repeat("a", 64)
	raw := []byte{}
	for i := 0; i < 2*len(protected); i++ {
		j, _ := decodeRemovalJournal(raw, seed, len(all))
		line, _ := nextRemovalJournalLine(seed, j)
		raw = append(raw, line...)
	}
	old, e := decodeRemovalJournal(raw, seed, len(protected))
	if e != nil || old.completed != len(protected) {
		t.Fatal("old protected completion changed", old, e)
	}
	for entry := 2 * len(protected); entry < 2*len(all); entry++ {
		before, e := decodeRemovalJournal(raw, seed, len(all))
		if e != nil {
			t.Fatal(e)
		}
		line, e := nextRemovalJournalLine(seed, before)
		if e != nil {
			t.Fatal(e)
		}
		for cut := 0; cut < len(line); cut++ {
			got, e := decodeRemovalJournal(append(append([]byte{}, raw...), line[:cut]...), seed, len(all))
			if e != nil || got.entries != entry || got.completed != entry/2 || got.pending != (entry%2 == 1) || !bytes.Equal(got.tail, line[:cut]) {
				t.Fatal(entry, cut, got, e)
			}
		}
		raw = append(raw, line...)
	}
	final, e := decodeRemovalJournal(raw, seed, len(all))
	if e != nil || final.completed != len(all) {
		t.Fatal(final, e)
	}
}
func TestRemovalQuarantinedRootAbsenceNeedsItsExactFullIntent(t *testing.T) {
	plan := removalPlanFixture()
	all, e := removalAllActions(plan)
	if e != nil {
		t.Fatal(e)
	}
	protected, _ := removalProtectedActions(plan)
	seed := strings.Repeat("e", 64)
	raw := []byte{}
	for entry := 0; entry <= 2*len(all); entry++ {
		journal, e := decodeRemovalJournal(raw, seed, len(all))
		if e != nil {
			t.Fatal(e)
		}
		started, absence, done, e := removalQuarantinedRootState(plan, journal)
		if e != nil || started != (entry > 2*len(protected)) || absence != (entry >= 2*len(all)-1) || done != (entry == 2*len(all)) {
			t.Fatal(entry, started, absence, done, e)
		}
		if entry == 2*len(all) {
			break
		}
		line, _ := nextRemovalJournalLine(seed, journal)
		partial, _ := decodeRemovalJournal(append(append([]byte{}, raw...), line[:len(line)/2]...), seed, len(all))
		_, partialAbsence, _, e := removalQuarantinedRootState(plan, partial)
		if e != nil || partialAbsence != absence {
			t.Fatal("partial record granted root absence", entry, e)
		}
		raw = append(raw, line...)
	}
}
