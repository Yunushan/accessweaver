//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDarwinRemovalFencePublicationPreservesOldStateUntilAtomicPair(t *testing.T) {
	for _, phase := range []string{"removal-record-reserved", "removal-state-durable", "removal-marker-durable", "removal-directory-durable", "removal-published", "removal-parent-durable", "complete"} {
		t.Run(phase, func(t *testing.T) {
			parent := t.TempDir()
			s := deploymentFixtureStore(t, parent, nil)
			before := removalFenceState()
			if _, e := s.commit(before); e != nil {
				t.Fatal(e)
			}
			original := append([]byte{}, s.encoded...)
			fence, _, e := newRemovalFence(before, strings.Repeat("d", 64), strings.Repeat("e", 64))
			if e != nil {
				t.Fatal(e)
			}
			s.observe = func(observed string) error {
				if observed == phase {
					return errors.New("injected removal boundary")
				}
				return nil
			}
			published, e := s.publishRemovalFence(fence)
			expected := phase == "removal-published" || phase == "removal-parent-durable" || phase == "complete"
			if published != expected || (e == nil) != (phase == "complete") {
				t.Fatal("publication outcome lost", published, e)
			}
			if expected {
				if _, e = s.readRecord(s.current); e == nil {
					t.Fatal("legacy single-file reader accepted removal intent pair")
				}
				read, raw, e := readRemovalFencePair(s.current, s.owner)
				if e != nil || read != fence || !bytes.Equal(raw, s.encoded) || s.state.Generation != 8 || s.state.Active != (deploymentSlot{}) {
					t.Fatal("published pair cannot be reconciled", e)
				}
				if again, e := s.publishRemovalFence(fence); again || e == nil {
					t.Fatal("old active barrier could publish again")
				}
			} else {
				actual, e := s.readRecord(s.current)
				if e != nil || !bytes.Equal(actual, original) {
					t.Fatal("unpublished barrier changed active state", e)
				}
			}
			entries, e := os.ReadDir(filepath.Join(parent, deploymentRoot))
			if e != nil {
				t.Fatal(e)
			}
			foundOld := false
			for _, entry := range entries {
				if !recordName.MatchString(entry.Name()) {
					continue
				}
				dir, e := os.Open(filepath.Join(parent, deploymentRoot, entry.Name()))
				if e != nil {
					t.Fatal(e)
				}
				raw, e := s.readRecord(dir)
				dir.Close()
				if e == nil && bytes.Equal(raw, original) {
					foundOld = true
				}
			}
			if expected && !foundOld {
				t.Fatal("displaced active record was removed")
			}
		})
	}
}
func TestDarwinRemovalFenceChangedPreimageRefusesBeforeReservation(t *testing.T) {
	parent := t.TempDir()
	s := deploymentFixtureStore(t, parent, nil)
	if _, e := s.commit(removalFenceState()); e != nil {
		t.Fatal(e)
	}
	fence, _, e := newRemovalFence(s.state, strings.Repeat("d", 64), strings.Repeat("e", 64))
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(parent, deploymentRoot, "state", deploymentRecord)
	changed := append(append([]byte{}, s.encoded...), ' ')
	if e = os.WriteFile(path, changed, 0644); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadDir(filepath.Join(parent, deploymentRoot))
	if e != nil {
		t.Fatal(e)
	}
	if published, e := s.publishRemovalFence(fence); published || e == nil {
		t.Fatal("changed preimage published")
	}
	after, e := os.ReadDir(filepath.Join(parent, deploymentRoot))
	if e != nil || len(before) != len(after) {
		t.Fatal("refusal reserved another object", e)
	}
	raw, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(raw, changed) {
		t.Fatal("refusal repaired changed data", e)
	}
}

func TestDarwinRemovalFenceReaderRefusesChangedIncompleteAndAliasedPairs(t *testing.T) {
	for _, kind := range []string{"marker-mode", "marker-hardlink", "marker-alias", "marker-noncanonical", "marker-oversize", "state-truncated", "unknown-entry", "missing-marker"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			s := deploymentFixtureStore(t, parent, nil)
			if _, e := s.commit(removalFenceState()); e != nil {
				t.Fatal(e)
			}
			fence, _, e := newRemovalFence(s.state, strings.Repeat("d", 64), strings.Repeat("e", 64))
			if e != nil {
				t.Fatal(e)
			}
			if published, e := s.publishRemovalFence(fence); !published || e != nil {
				t.Fatal(e)
			}
			state := filepath.Join(parent, deploymentRoot, "state")
			marker := filepath.Join(state, removalFenceName)
			switch kind {
			case "marker-mode":
				e = os.Chmod(marker, 0664)
			case "marker-hardlink":
				e = os.Link(marker, filepath.Join(parent, "owned-marker-link"))
			case "marker-alias":
				backup := filepath.Join(parent, "owned-marker-backup")
				if e = os.Rename(marker, backup); e == nil {
					e = os.Symlink(backup, marker)
				}
			case "marker-noncanonical":
				var raw []byte
				if raw, e = os.ReadFile(marker); e == nil {
					e = os.WriteFile(marker, append(raw, ' '), 0644)
				}
			case "marker-oversize":
				e = os.WriteFile(marker, bytes.Repeat([]byte(" "), maxDeploymentRecord+1), 0644)
			case "state-truncated":
				e = os.WriteFile(filepath.Join(state, deploymentRecord), []byte("{"), 0644)
			case "unknown-entry":
				e = os.WriteFile(filepath.Join(state, "unknown"), []byte("preserve"), 0644)
			case "missing-marker":
				e = os.Remove(marker) // Exact file created by this owned fixture.
			}
			if e != nil {
				t.Fatal(e)
			}
			before, e := os.Lstat(state)
			if e != nil {
				t.Fatal(e)
			}
			if _, _, e := readRemovalFencePair(s.current, s.owner); e == nil {
				t.Fatal("unsafe removal pair accepted")
			}
			after, e := os.Lstat(state)
			if e != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
				t.Fatal("pair refusal changed directory", e)
			}
		})
	}
}
