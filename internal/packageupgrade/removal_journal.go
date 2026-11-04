package packageupgrade

import (
	"bytes"
	"encoding/json"
	"errors"
)

const removalJournalName = "progress.jsonl"
const maxRemovalJournalLine = 512
const maxRemovalJournalBytes = (2*maxRemovalPlanObjects + 1) * maxRemovalJournalLine

// Only regular files inside protected core/incoming roots are eligible.
// Public apps, registrations, receipts and every directory remain untouched.
type removalFileAction struct{ root, object int }

func removalFileActions(plan removalPlan) ([]removalFileAction, error) {
	if e := plan.validate(); e != nil {
		return nil, e
	}
	actions := []removalFileAction{}
	for i, root := range plan.Roots {
		if root.Kind != "core" && root.Kind != "incoming" {
			continue
		}
		for j, object := range root.Objects {
			if object.Kind == "file" {
				actions = append(actions, removalFileAction{i, j})
			}
		}
	}
	if len(actions) == 0 {
		return nil, errors.New("removal journal has no protected file actions")
	}
	return actions, nil
}

type removalJournalEntry struct {
	SchemaVersion  int    `json:"schemaVersion"`
	FenceSHA256    string `json:"fenceSHA256"`
	Sequence       int    `json:"sequence"`
	Action         int    `json:"action"`
	Phase          string `json:"phase"`
	PreviousSHA256 string `json:"previousSHA256"`
}
type removalJournal struct {
	completed, entries, validBytes int
	pending                        bool
	lastSHA256                     string
	tail                           []byte
}

func removalJournalSeed(f removalFence) string {
	raw, _ := json.Marshal(f)
	return removalDigest(raw)
}

func nextRemovalJournalLine(seed string, journal removalJournal) ([]byte, error) {
	if !hash.MatchString(seed) || !hash.MatchString(journal.lastSHA256) || journal.entries < 0 || journal.entries >= 2*maxRemovalPlanObjects {
		return nil, errors.New("invalid removal journal continuation")
	}
	phase := "intent"
	if journal.entries%2 == 1 {
		phase = "done"
	}
	raw, e := json.Marshal(removalJournalEntry{1, seed, journal.entries + 1, journal.entries / 2, phase, journal.lastSHA256})
	if e != nil || len(raw)+1 > maxRemovalJournalLine {
		return nil, errors.New("removal journal line exceeds budget")
	}
	return append(raw, '\n'), nil
}

// A complete canonical intent permits only its one corresponding absence.
// An incomplete tail authorizes nothing. It may only be a prefix of the exact
// next record; a writer can discard it after revalidating all remaining data.
// This is a protected progress log, not cryptographic publisher authentication.
func decodeRemovalJournal(raw []byte, seed string, actions int) (removalJournal, error) {
	zero := removalJournal{}
	if !hash.MatchString(seed) || actions <= 0 || actions > maxRemovalPlanObjects || len(raw) > maxRemovalJournalBytes {
		return zero, errors.New("invalid removal journal binding or extent")
	}
	result := removalJournal{lastSHA256: seed}
	remaining := raw
	for len(remaining) > 0 {
		if result.entries >= 2*actions {
			return zero, errors.New("removal journal extends beyond planned actions")
		}
		want, e := nextRemovalJournalLine(seed, result)
		if e != nil {
			return zero, e
		}
		end := bytes.IndexByte(remaining, '\n')
		if end < 0 {
			if len(remaining) >= len(want) || !bytes.Equal(remaining, want[:len(remaining)]) {
				return zero, errors.New("noncanonical partial removal journal record")
			}
			result.tail = append([]byte{}, remaining...)
			break
		}
		line := remaining[:end+1]
		if !bytes.Equal(line, want) {
			return zero, errors.New("removal journal chain, action or phase differs")
		}
		result.lastSHA256 = removalDigest(line)
		result.entries++
		result.completed = result.entries / 2
		result.pending = result.entries%2 != 0
		result.validBytes += len(line)
		remaining = remaining[len(line):]
	}
	return result, nil
}
