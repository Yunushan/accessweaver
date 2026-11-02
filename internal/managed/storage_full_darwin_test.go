//go:build darwin && (amd64 || arm64)

package managed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

type darwinStorageReceipt struct {
	SchemaVersion      int    `json:"schemaVersion"`
	SourceCommit       string `json:"sourceCommit"`
	Capsule            string `json:"capsule"`
	Mount              string `json:"mount"`
	VolumeDevice       string `json:"volumeDevice"`
	Image              string `json:"image"`
	ImageDev           uint64 `json:"imageDev"`
	ImageIno           uint64 `json:"imageIno"`
	MaximumVolumeBytes uint64 `json:"maximumVolumeBytes"`
	Report             string `json:"report"`
}

func darwinFSString[T ~int8 | ~uint8](input []T) string {
	value := make([]byte, 0, len(input))
	for _, b := range input {
		if b == 0 {
			break
		}
		value = append(value, byte(b))
	}
	return string(value)
}

func TestDisposableDarwinAPFSExhaustion(t *testing.T) {
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_DARWIN_STORAGE_TEST") != "1" {
		t.Skip("explicit disposable hosted image only")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "macOS" || os.Geteuid() != 0 {
		t.Fatal("refusing pressure outside a root disposable hosted fixture")
	}
	var receipt darwinStorageReceipt
	path := os.Getenv("ACCESSWEAVER_DARWIN_STORAGE_RECEIPT")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 16385))
	if err := errors.Join(readErr, file.Close()); err != nil {
		t.Fatal(err)
	}
	if len(data) > 16384 || strictJSON(data, 16384, &receipt) != nil {
		t.Fatal("invalid bounded storage receipt")
	}
	workspace := os.Getenv("GITHUB_WORKSPACE")
	if !filepath.IsAbs(workspace) || filepath.Clean(workspace) != workspace || receipt.SourceCommit != os.Getenv("GITHUB_SHA") || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(receipt.SourceCommit) || receipt.SchemaVersion != 1 {
		t.Fatal("unexpected fixture source/workspace")
	}
	if filepath.Dir(receipt.Capsule) != filepath.Join(workspace, "build", "storage-capsules") || !strings.HasPrefix(filepath.Base(receipt.Capsule), "apfs-full-") || path != filepath.Join(receipt.Capsule, "receipt.json") || receipt.Mount != filepath.Join(receipt.Capsule, "mount") || receipt.Image != filepath.Join(receipt.Capsule, "pressure.sparseimage") || receipt.Report != filepath.Join(workspace, "build", "darwin-storage-checks", "apfs-exhaustion-"+runtime.GOARCH+".json") {
		t.Fatal("refusing non-capsule paths")
	}
	for _, target := range []string{receipt.Capsule, receipt.Mount, receipt.Image, path} {
		resolved, err := filepath.EvalSymlinks(target)
		if err != nil || resolved != target {
			t.Fatal("fixture path alias refused", err)
		}
	}
	imageInfo, err := os.Lstat(receipt.Image)
	if err != nil {
		t.Fatal(err)
	}
	imageStat, ok := imageInfo.Sys().(*syscall.Stat_t)
	if !ok || !imageInfo.Mode().IsRegular() || imageStat.Nlink != 1 || uint64(imageStat.Dev) != receipt.ImageDev || imageStat.Ino != receipt.ImageIno || imageInfo.Size() > int64(1<<30) {
		t.Fatal("unverified bounded image")
	}
	volume, err := os.Open(receipt.Mount)
	if err != nil {
		t.Fatal(err)
	}
	defer volume.Close()
	if _, err := darwintrust.Check(volume, true, 0); err != nil {
		t.Fatal(err)
	}
	var fs, host unix.Statfs_t
	if err := unix.Fstatfs(int(volume.Fd()), &fs); err != nil {
		t.Fatal(err)
	}
	if err := unix.Statfs(receipt.Capsule, &host); err != nil {
		t.Fatal(err)
	}
	if receipt.MaximumVolumeBytes != 1<<30 || fs.Bsize <= 0 || uint64(fs.Bsize) > 1<<20 || fs.Blocks == 0 || fs.Blocks > receipt.MaximumVolumeBytes/uint64(fs.Bsize) || fs.Fsid == host.Fsid || darwinFSString(fs.Mntfromname[:]) != receipt.VolumeDevice || !regexp.MustCompile(`^/dev/disk[0-9]+s[0-9]+$`).MatchString(receipt.VolumeDevice) || fs.Flags&unix.MNT_RDONLY != 0 {
		t.Fatal("refusing pressure on an unbounded, host, unassociated or read-only volume")
	}
	cases := []map[string]any{}
	for _, operation := range []string{"install", "update", "rotate", "recover"} {
		for _, record := range []string{darwinPolicyFile, darwinAcceptanceFile} {
			t.Run("operation="+operation+"/record="+record, func(t *testing.T) {
				result := exerciseDarwinExhaustion(t, receipt, operation, record)
				cases = append(cases, result)
			})
			if t.Failed() {
				t.Fatal("stopping pressure after the first failed native case")
			}
		}
	}
	report := map[string]any{"schemaVersion": 1, "sourceCommit": receipt.SourceCommit, "arch": runtime.GOARCH, "platform": "darwin", "goVersion": runtime.Version(), "effectiveUID": os.Geteuid(), "filesystem": "apfs", "mountFlags": fs.Flags, "volumeBytes": fs.Blocks * uint64(fs.Bsize), "deviceDiffersFromHost": true, "cases": cases, "rootMachinePolicyChanged": false, "powerLossQualified": false, "fullStorageFaultQualificationComplete": false, "productionQualificationComplete": false}
	data, err = json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(receipt.Report, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := output.Write(append(data, '\n'))
	if err := errors.Join(writeErr, output.Close()); err != nil {
		t.Fatal(err)
	}
}

func exhaustionEnvelope(t *testing.T, revision uint64, key ed25519.PrivateKey, now time.Time) []byte {
	t.Helper()
	data, err := json.Marshal(Policy{SchemaVersion: 1, Revision: revision, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	// Large valid signed payloads require new data blocks even if metadata retains
	// an emergency reserve; no invalid or over-limit policy is used as the fault.
	data = append(data, bytes.Repeat([]byte{' '}, 48<<10)...)
	signed, err := Sign(data, key, now)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func exerciseDarwinExhaustion(t *testing.T, receipt darwinStorageReceipt, operation, record string) map[string]any {
	t.Helper()
	parent, err := os.MkdirTemp(receipt.Mount, "policy-case-")
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	prior, err := PrepareInstallation(exhaustionEnvelope(t, 2, private, now), public, now, 1)
	if err != nil {
		t.Fatal(err)
	}
	before := machineSnapshot{}
	input := prior
	expectedKey := KeyID(public)
	if operation != "install" {
		darwinFixtureInstall(t, parent, prior, now)
		before = darwinStoredPair(t, parent)
		input = exhaustionEnvelope(t, 3, private, now)
		if operation == "rotate" || operation == "recover" {
			nextPublic, nextPrivate, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			next := exhaustionEnvelope(t, 3, nextPrivate, now)
			expectedKey = KeyID(nextPublic)
			if operation == "rotate" {
				input, err = SignRotation(before.source, next, nextPublic, private, now)
			} else {
				damaged := []byte("damaged primary is never restored as active permissions")
				if err := os.WriteFile(filepath.Join(parent, darwinPolicyDirectory, darwinPolicyFile), damaged, 0644); err != nil {
					t.Fatal(err)
				}
				before = darwinStoredPair(t, parent)
				input, err = SignRecovery(damaged, next, nextPrivate, 2, now, time.Hour)
				public = nextPublic
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	fillerPath := filepath.Join(parent, "owned-filler")
	filler, err := os.OpenFile(fillerPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	fillerInfo, err := filler.Stat()
	if err != nil {
		filler.Close()
		t.Fatal(err)
	}
	released := false
	release := func() error {
		if released {
			return nil
		}
		released = true
		closeErr := filler.Close()
		if errors.Is(closeErr, unix.ENOSPC) {
			closeErr = nil
		} // Expected full-volume writeback; removal must still succeed.
		info, statErr := os.Lstat(fillerPath)
		if statErr != nil || !os.SameFile(info, fillerInfo) || !info.Mode().IsRegular() {
			return errors.Join(closeErr, statErr, errors.New("refusing changed filler cleanup"))
		}
		return errors.Join(closeErr, os.Remove(fillerPath))
	}
	defer func() {
		if err := release(); err != nil {
			t.Error(err)
		}
	}()
	apply := func(observe func(*darwinInstallationTransaction, string)) (InstallResult, error) {
		dir, err := os.Open(parent)
		if err != nil {
			return InstallResult{}, err
		}
		tx, err := beginDarwinInstallationObserved(dir, operation == "install", 0, observe)
		if err != nil {
			return InstallResult{}, err
		}
		if operation == "recover" {
			return commitRecovery(tx, input, public, 2, time.Now)
		}
		change := changeUpdate
		if operation == "install" {
			change = changeInstall
		} else if operation == "rotate" {
			change = changeRotate
		}
		return commitInstallation(tx, input, public, change, time.Now)
	}
	fired := false
	var filled int64
	var beforeCleanup map[string][]byte
	cleanupEligible := false
	result, mutationErr := apply(func(tx *darwinInstallationTransaction, phase string) {
		if phase == record+".closed" {
			beforeCleanup = readDarwinAbandonedFixture(t, filepath.Join(parent, tx.pair.name))
			cleanupEligible = true
			for name, value := range beforeCleanup {
				expected := tx.pair.candidate.source
				if name == darwinAcceptanceFile {
					expected = tx.pair.candidate.acceptance
				}
				if !bytes.Equal(value, expected) {
					cleanupEligible = false
				}
			}
		}
		if phase != record+".created" {
			return
		}
		if fired {
			t.Fatal("pressure boundary repeated")
		}
		fired = true
		filled = fillDarwinImage(t, filler)
	})
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if !fired || mutationErr == nil || !errors.Is(mutationErr, unix.ENOSPC) || result.Committed {
		t.Fatal("expected actual ENOSPC without publication", fired, result, mutationErr)
	}
	dir, err := os.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	actual, readErr := readDarwinSnapshotAt(dir, 0)
	if err := errors.Join(readErr, dir.Close()); err != nil {
		t.Fatal(err)
	}
	if actual.present != before.present || !equalDarwinPair(actual, before) {
		t.Fatal("exhaustion changed active policy or accepted history")
	}
	if operation == "recover" {
		if _, _, err := decodeMachineSnapshot(actual, time.Now()); err == nil {
			t.Fatal("exhaustion enabled damaged policy")
		}
	}
	stages, err := filepath.Glob(filepath.Join(parent, darwinStagePrefix+"*"))
	if err != nil || len(stages) > 1 {
		t.Fatal("unexpected failed-generation namespace", err)
	}
	if len(stages) == 0 && !cleanupEligible {
		t.Fatal("unverified or partial failed writes were removed")
	}
	var stageInfo os.FileInfo
	var retained map[string][]byte
	if len(stages) == 1 {
		stageInfo, err = os.Lstat(stages[0])
		if err != nil {
			t.Fatal(err)
		}
		retained = readDarwinAbandonedFixture(t, stages[0])
		if !cleanupEligible && beforeCleanup != nil {
			if len(retained) != len(beforeCleanup) {
				t.Fatal("partial failed-write layout changed during abort")
			}
			for name, value := range beforeCleanup {
				if !bytes.Equal(retained[name], value) {
					t.Fatal("partial failed-write bytes changed during abort", name)
				}
			}
		}
	}
	// APFS may release blocks asynchronously. Wait only for bounded reclamation;
	// never grow the image, alter mount flags or relax the required write outcome.
	deadline := time.Now().Add(15 * time.Second)
	for {
		var available unix.Statfs_t
		if err := unix.Statfs(parent, &available); err != nil {
			t.Fatal(err)
		}
		if available.Bavail*uint64(available.Bsize) >= 4<<20 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owned filler removal did not reclaim bounded space")
		}
		time.Sleep(50 * time.Millisecond)
	}
	retried, retryErr := apply(nil)
	if retryErr != nil || !retried.Committed {
		t.Fatal("explicit retry failed after restoring image capacity", retried, retryErr)
	}
	authority, history, err := decodeMachineSnapshot(darwinStoredPair(t, parent), time.Now())
	if err != nil || authority == nil || history == nil || authority.verified.KeyID != expectedKey || history.revision != retried.Revision {
		t.Fatal("retry lost signature or accepted history", err)
	}
	afterStages, err := filepath.Glob(filepath.Join(parent, darwinStagePrefix+"*"))
	if err != nil || len(afterStages) != len(stages) {
		t.Fatal("retry changed retained namespace", err)
	}
	if len(stages) == 1 {
		current, err := os.Lstat(stages[0])
		if err != nil || !os.SameFile(current, stageInfo) {
			t.Fatal("retry replaced retained failed-write stage", err)
		}
		after := readDarwinAbandonedFixture(t, stages[0])
		if len(after) != len(retained) {
			t.Fatal("retry changed retained layout")
		}
		for name, value := range retained {
			if !bytes.Equal(after[name], value) {
				t.Fatal("retry changed retained bytes", name)
			}
		}
	}

	return map[string]any{"operation": operation, "record": record, "fillerBytes": filled, "nativeENOSPCObserved": true, "unpublished": true, "priorPairUnchanged": true, "explicitSignedRetryCommitted": true, "retainedStagePreserved": true, "retainedStagePresent": len(stages) == 1, "knownAbortCleaned": len(stages) == 0}
}

func fillDarwinImage(t *testing.T, file *os.File) int64 {
	t.Helper()
	buffer := make([]byte, 1<<20)
	if _, err := rand.Read(buffer); err != nil {
		t.Fatal(err)
	}
	var total int64
	deadline := time.Now().Add(90 * time.Second)
	for _, size := range []int{1 << 20, 64 << 10, 4096, 1} {
		for {
			if total+int64(size) > 1<<30 || time.Now().After(deadline) {
				t.Fatal("bounded image pressure did not reach ENOSPC")
			}
			count, err := file.Write(buffer[:size])
			total += int64(count)
			if errors.Is(err, unix.ENOSPC) {
				break
			}
			if err != nil || count != size {
				t.Fatal("unexpected filler write outcome", count, err)
			}
		}
	}
	if err := file.Sync(); err != nil && !errors.Is(err, unix.ENOSPC) {
		t.Fatal(fmt.Errorf("filler sync: %w", err))
	}
	return total
}
