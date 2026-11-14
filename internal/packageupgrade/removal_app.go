package packageupgrade

import (
	"errors"
	"sort"
	"strings"
)

// Keep the already qualified protected-object sequence byte-for-byte compatible
// as a prefix. The public app follows at its protected quarantine binding.
func removalPayloadActions(plan removalPlan) ([]removalFileAction, error) {
	actions, e := removalProtectedActions(plan)
	if e != nil {
		return nil, e
	}
	for i, root := range plan.Roots {
		if root.Kind != "public" {
			continue
		}
		directories := []removalFileAction{}
		for j, object := range root.Objects {
			if object.Kind == "file" {
				actions = append(actions, removalFileAction{i, j})
			} else {
				directories = append(directories, removalFileAction{i, j})
			}
		}
		depth := func(name string) int {
			if name == "." {
				return -1
			}
			return strings.Count(name, "/")
		}
		sort.Slice(directories, func(a, b int) bool {
			left, right := root.Objects[directories[a].object].Path, root.Objects[directories[b].object].Path
			if depth(left) != depth(right) {
				return depth(left) > depth(right)
			}
			return left < right
		})
		actions = append(actions, directories...)
	}
	if len(actions) > maxRemovalPlanObjects {
		return nil, errors.New("removal object action budget exceeded")
	}
	return actions, nil
}

// Registration records follow all payload actions. The registration directory
// remains in place, and Installer receipts stay outside this journal.
func removalAllActions(plan removalPlan) ([]removalFileAction, error) {
	actions, e := removalPayloadActions(plan)
	if e != nil {
		return nil, e
	}
	for i, root := range plan.Roots {
		if root.Kind != "registrations" {
			continue
		}
		for j, object := range root.Objects {
			if object.Kind == "file" {
				actions = append(actions, removalFileAction{i, j})
			}
		}
	}
	return actions, nil
}

func removalQuarantinedRootState(plan removalPlan, journal removalJournal) (started, mayBeAbsent, completed bool, err error) {
	all, e := removalAllActions(plan)
	if e != nil {
		return false, false, false, e
	}
	protected, e := removalProtectedActions(plan)
	if e != nil {
		return false, false, false, e
	}
	started = journal.completed > len(protected) || journal.completed == len(protected) && (journal.pending || len(journal.tail) > 0)
	for index, action := range all {
		if plan.Roots[action.root].Kind == "public" && action.object == 0 {
			completed = journal.completed > index
			mayBeAbsent = completed || journal.pending && journal.completed == index
			return started, mayBeAbsent, completed, nil
		}
	}
	return false, false, false, errors.New("quarantined root action is absent")
}
