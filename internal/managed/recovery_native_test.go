package managed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// Called only inside the existing guarded fresh-hosted-machine acceptance cases.
// The caller owns the protected source and its validated cleanup procedure.
func exerciseNativeRecovery(t *testing.T, minimum uint64, damage func([]byte), abandon func([]byte)) {
	t.Helper()
	damaged := []byte("AccessWeaver disposable damaged source fixture\n")
	damage(damaged)
	if _, err := Current(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("damaged source became usable/unmanaged", err)
	}
	exported, err := ExportMachineSource()
	if err != nil || !bytes.Equal(exported, damaged) {
		t.Fatal("damaged protected source export failed", err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	p := Policy{SchemaVersion: 1, Revision: minimum + 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	payload, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	next, err := Sign(payload, private, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Update(next); err == nil {
		t.Fatal("ordinary update trusted damaged prior state")
	}
	recovery, err := SignRecovery(damaged, next, private, minimum, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, candidate, err := recoveryTransition(damaged, recovery, public, minimum, now)
	if err != nil {
		t.Fatal(err)
	}
	abandon(candidate)
	if _, err := Current(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("abandoned recovery became usable/unmanaged", err)
	}
	exported, err = ExportMachineSource()
	if err != nil || !bytes.Equal(exported, damaged) {
		t.Fatal("abandoned repair changed source", err)
	}
	wrong, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(recovery, wrong, minimum); err == nil {
		t.Fatal("wrong recovery key authorized native repair")
	}
	if _, err := Recover(recovery, public, minimum+1); err == nil {
		t.Fatal("wrong independent floor authorized native repair")
	}
	result, err := Recover(recovery, public, minimum)
	if err != nil || !result.Committed || result.Revision != minimum+1 || result.Operation != "recover" || result.PreviousSourceSHA256 == "" || result.RecoveryPayloadSHA256 == "" {
		t.Fatal("native signed repair failed", result, err)
	}
	status, err := MachineStatus()
	if err != nil || !status.Valid || status.Revision != minimum+1 || status.KeyID != KeyID(public) {
		t.Fatal("native repaired policy not active", status, err)
	}
	if err := NewGuard(nil).Diagnostics(); !errors.Is(err, ErrDenied) {
		t.Fatal("repair failed to enforce new deny policy", err)
	}
	if _, err := Recover(recovery, public, minimum); err == nil {
		t.Fatal("native repair replay accepted")
	}
}
