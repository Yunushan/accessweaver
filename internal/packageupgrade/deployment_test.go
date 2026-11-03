package packageupgrade

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
)

func deploymentFixtureSlot(n int, v string) deploymentSlot {
	return deploymentSlot{ID: fmt.Sprintf("%032x", n), Device: 1, Inode: uint64(n), Identity: deploymentIdentity{v, strings.Repeat("a", 64), strings.Repeat("b", 64)}}
}
func mustDeployment(t *testing.T, s deploymentState, e error) deploymentState {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestDeploymentGenerationFencesRemovalAndConcurrentPrepares(t *testing.T) {
	a, b, c := deploymentFixtureSlot(1, "0.1.0-alpha"), deploymentFixtureSlot(2, "0.1.1-alpha"), deploymentFixtureSlot(3, "0.1.2-alpha")
	s, e := emptyDeployment().prepare(a)
	s = mustDeployment(t, s, e)
	s, e = s.activate(a)
	s = mustDeployment(t, s, e)
	s, e = s.prepare(b)
	s = mustDeployment(t, s, e)
	s, e = s.prepare(c)
	s = mustDeployment(t, s, e)
	s, e = s.deactivate()
	s = mustDeployment(t, s, e)
	if s.Generation != 2 || s.Active != (deploymentSlot{}) || s.HighWaterVersion != a.Identity.Version {
		t.Fatal("removal lost tombstone/history")
	}
	before, _ := encodeDeployment(s)
	for _, slot := range []deploymentSlot{a, b, c} {
		if _, e = s.activate(slot); e == nil {
			t.Fatal("stale transaction reactivated after removal")
		}
	}
	after, _ := encodeDeployment(s)
	if !bytes.Equal(before, after) {
		t.Fatal("refusal mutated state")
	}
	old := deploymentFixtureSlot(4, "0.0.9")
	if _, e = s.prepare(old); e == nil {
		t.Fatal("removal permitted downgrade")
	}
	s, e = s.abandon(b.ID)
	s = mustDeployment(t, s, e)
	b = deploymentFixtureSlot(5, "0.1.1-alpha")
	s, e = s.prepare(b)
	s = mustDeployment(t, s, e)
	s, e = s.activate(b)
	s = mustDeployment(t, s, e)
	if s.Generation != 3 || s.Active != b {
		t.Fatal("new preparation after removal did not activate")
	}
	if _, e = s.activate(c); e == nil {
		t.Fatal("concurrent stale prepare accepted")
	}
}
func TestDeploymentRecordRejectsAmbiguityAndCapacityOverflow(t *testing.T) {
	s := emptyDeployment()
	good, e := encodeDeployment(s)
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{
		append(append([]byte{}, good...), '\n'),
		[]byte(strings.Replace(string(good), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1)),
		[]byte(strings.Replace(string(good), `"schemaVersion":1,`, "", 1)),
		[]byte(strings.Replace(string(good), `"generation":0`, `"generation":null`, 1)),
		[]byte(strings.Replace(string(good), `"pending":[]`, `"pending":null`, 1)),
		[]byte(strings.Replace(string(good), `"generation":0`, `"Generation":0`, 1)),
		[]byte(strings.Replace(string(good), `"generation":0`, `"generation":1`, 1)),
		[]byte(strings.Repeat(" ", maxDeploymentRecord+1)),
	} {
		if _, e := decodeDeployment(bad); e == nil {
			t.Fatal("ambiguous/invalid deployment record accepted")
		}
	}
	for i := 1; i <= maxDeploymentPending; i++ {
		s, e = s.prepare(deploymentFixtureSlot(i, "0.1.0"))
		s = mustDeployment(t, s, e)
	}
	if _, e = s.prepare(deploymentFixtureSlot(99, "0.1.0")); e == nil {
		t.Fatal("pending bound ignored")
	}
	raw, e := encodeDeployment(s)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = decodeDeployment(raw); e != nil {
		t.Fatal(e)
	}
	s = emptyDeployment()
	a := deploymentFixtureSlot(1, "0.1.0")
	s, e = s.prepare(a)
	s = mustDeployment(t, s, e)
	s, e = s.activate(a)
	s = mustDeployment(t, s, e)
	s.Generation = math.MaxUint64
	if _, e = s.prepare(deploymentFixtureSlot(2, "0.1.1")); e == nil {
		t.Fatal("generation wrapped on prepare")
	}
	if _, e = s.deactivate(); e == nil {
		t.Fatal("generation wrapped on removal")
	}
	s.Pending = []deploymentPending{{math.MaxUint64, deploymentFixtureSlot(2, "0.1.1")}}
	if _, e = s.activate(s.Pending[0].Slot); e == nil {
		t.Fatal("generation wrapped on activation")
	}
}
func TestDeploymentSlotIdentityIsExactAndTransitionsDoNotAlias(t *testing.T) {
	slot := deploymentFixtureSlot(1, "0.1.0")
	s, e := emptyDeployment().prepare(slot)
	s = mustDeployment(t, s, e)
	before, _ := json.Marshal(s)
	for _, change := range []func(*deploymentSlot){func(v *deploymentSlot) { v.Inode++ }, func(v *deploymentSlot) { v.Device++ }, func(v *deploymentSlot) { v.Identity.PayloadSHA256 = strings.Repeat("c", 64) }, func(v *deploymentSlot) { v.Identity.Version = "0.1.1" }, func(v *deploymentSlot) { v.ID = "../escape" }} {
		changed := slot
		change(&changed)
		if _, e = s.activate(changed); e == nil {
			t.Fatal("changed reserved identity accepted")
		}
	}
	next, e := s.prepare(deploymentFixtureSlot(2, "0.1.1"))
	next = mustDeployment(t, next, e)
	next.Pending[0].Slot.Inode++
	after, _ := json.Marshal(s)
	if !bytes.Equal(before, after) {
		t.Fatal("transition shares mutable pending storage")
	}
}
