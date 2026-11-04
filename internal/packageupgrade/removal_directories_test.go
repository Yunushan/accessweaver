package packageupgrade

import (
	"reflect"
	"strings"
	"testing"
)

func TestRemovalProtectedActionsPreserveFilePrefixAndDirectoryPostorder(t *testing.T) {
	plan := removalPlanFixture()
	files, e := removalFileActions(plan)
	if e != nil {
		t.Fatal(e)
	}
	actions, e := removalProtectedActions(plan)
	if e != nil {
		t.Fatal(e)
	}
	if len(actions) != 6 || !reflect.DeepEqual(files, actions[:len(files)]) {
		t.Fatal("file prefix changed", actions, files)
	}
	seen := map[removalFileAction]bool{}
	for index, action := range actions {
		root := plan.Roots[action.root]
		object := root.Objects[action.object]
		if root.Kind != "core" && root.Kind != "incoming" || seen[action] {
			t.Fatal("ineligible/duplicate action", action)
		}
		if index >= len(files) && object.Kind != "directory" {
			t.Fatal("file after directory phase")
		}
		if object.Kind == "directory" {
			for j, child := range root.Objects {
				if j == action.object {
					continue
				}
				if object.Path == "." || strings.HasPrefix(child.Path, object.Path+"/") {
					if !seen[removalFileAction{action.root, j}] {
						t.Fatal("parent scheduled before child", object.Path, child.Path)
					}
				}
			}
		}
		seen[action] = true
	}
	again, e := removalProtectedActions(plan)
	if e != nil || !reflect.DeepEqual(actions, again) {
		t.Fatal("nondeterministic actions", e)
	}
}
func TestRemovalCompletedFileJournalIsOnlyProtectedActionPrefix(t *testing.T) {
	seed := strings.Repeat("a", 64)
	raw := []byte{}
	for i := 0; i < 4; i++ {
		j, e := decodeRemovalJournal(raw, seed, 6)
		if e != nil {
			t.Fatal(e)
		}
		line, e := nextRemovalJournalLine(seed, j)
		if e != nil {
			t.Fatal(e)
		}
		raw = append(raw, line...)
	}
	old, e := decodeRemovalJournal(raw, seed, 2)
	if e != nil || old.completed != 2 || old.pending {
		t.Fatal("file journal changed", old, e)
	}
	current, e := decodeRemovalJournal(raw, seed, 6)
	if e != nil || current.completed != 2 || current.pending {
		t.Fatal("file prefix lost", current, e)
	}
	line, e := nextRemovalJournalLine(seed, current)
	if e != nil {
		t.Fatal(e)
	}
	current, e = decodeRemovalJournal(append(raw, line...), seed, 6)
	if e != nil || current.completed != 2 || !current.pending {
		t.Fatal("directory intent not bound", current, e)
	}
}
