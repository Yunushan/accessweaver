//go:build windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/Yunushan/accessweaver/internal/api"
	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/fileidentity"
	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
	"github.com/Yunushan/accessweaver/internal/wintrust"
	"golang.org/x/sys/windows"
)

const ordinaryCommandWorkerArgument = "--accessweaver-audit-commands-native-worker-v1"

var ordinaryCommandCaseNames = []string{
	"signed-required-audit-admission", "initialize-import-retained-head",
	"audited-private-http-desktop", "read-only-export-verify",
	"current-recorded-export-key-boundary", "actual-output-alias-admission",
	"full-journal-reservation-refusal", "approved-recorded-foreground-run",
	"recorded-foreground-output-cancellation-drain",
}

func windowsCommandReadSource(w *windowsCommandWorker, path string) ([]byte, error) {
	if strings.EqualFold(path, w.engine) {
		return windowsCommandRead(path, 128<<20)
	}
	return windowsCommandRead(path, audit.MaxJournalBytes)
}
func windowsCommandReadDefault(path string) ([]byte, error) {
	return windowsCommandRead(path, audit.MaxJournalBytes)
}
func windowsCommandRead(path string, limit int64) (data []byte, failure error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errOrdinary
	}
	defer func() {
		if file.Close() != nil {
			ordinaryCloseFailure = true
			clear(data)
			data = nil
			failure = errOrdinary
		}
	}()
	data, err = io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		clear(data)
		return nil, errOrdinary
	}
	return data, nil
}

type ordinaryPolicyFixture struct {
	installation, acceptance []byte
	descriptor               string
	installed                bool
}

func ordinaryPolicyBytes(key windows.Handle, name string) ([]byte, error) {
	value, _ := windows.UTF16PtrFromString(name)
	var kind, size uint32
	if windows.RegQueryValueEx(key, value, nil, &kind, nil, &size) != nil || kind != windows.REG_BINARY || size == 0 || size > 1<<20 {
		return nil, errOrdinary
	}
	data := make([]byte, size)
	if windows.RegQueryValueEx(key, value, nil, &kind, &data[0], &size) != nil || kind != windows.REG_BINARY || size == 0 || size > uint32(len(data)) {
		clear(data)
		return nil, errOrdinary
	}
	return data[:size], nil
}
func ordinaryOpenPolicy(access uint32) (windows.Handle, error) {
	path, _ := windows.UTF16PtrFromString(nativePolicyTestKey)
	var key windows.Handle
	if windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, path, 0, access|windows.KEY_WOW64_64KEY, &key) != nil {
		return 0, errOrdinary
	}
	if winErr := wintrustPolicy(key); winErr != nil {
		_ = windows.RegCloseKey(key)
		return 0, errOrdinary
	}
	return key, nil
}
func wintrustPolicy(key windows.Handle) error {
	// MachineStatus rechecks the signed fixed source; this separately checks
	// native owner/DACL while this exact 64-bit registry handle is held.
	return checkNativePolicyHandle(syscall.Handle(key))
}
func checkNativePolicyHandle(key syscall.Handle) error {
	return wintrust.CheckHandle(key, 4, wintrust.RegistryMutationRights)
}
func ordinaryPolicySnapshot() (installation, acceptance []byte, descriptor string, failure error) {
	key, err := ordinaryOpenPolicy(windows.KEY_READ)
	if err != nil {
		return nil, nil, "", err
	}
	defer func() {
		if windows.RegCloseKey(key) != nil {
			ordinaryCloseFailure = true
			failure = errOrdinary
		}
	}()
	var subkeys, values uint32
	if windows.RegQueryInfoKey(key, nil, nil, nil, &subkeys, nil, nil, &values, nil, nil, nil, nil) != nil || subkeys != 0 || values != 2 {
		return nil, nil, "", errOrdinary
	}
	installation, err = ordinaryPolicyBytes(key, "Installation")
	if err != nil {
		return nil, nil, "", err
	}
	acceptance, err = ordinaryPolicyBytes(key, "Acceptance")
	if err != nil {
		clear(installation)
		return nil, nil, "", err
	}
	sd, err := windows.GetSecurityInfo(key, windows.SE_REGISTRY_KEY, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil || !sd.IsValid() {
		return nil, nil, "", errOrdinary
	}
	return installation, acceptance, sd.String(), nil
}
func (p *ordinaryPolicyFixture) Close() error {
	if !p.installed {
		if !ordinaryRegistryAbsent(windows.HKEY_LOCAL_MACHINE, nativePolicyTestKey) {
			return errOrdinary
		}
		return nil
	}
	source, accepted, descriptor, err := ordinaryPolicySnapshot()
	defer clear(source)
	defer clear(accepted)
	if err != nil || !bytes.Equal(source, p.installation) || !bytes.Equal(accepted, p.acceptance) || descriptor != p.descriptor {
		return errOrdinary
	}
	path, _ := windows.UTF16PtrFromString(nativePolicyTestKey)
	code, _, _ := ordinaryAdvapi.NewProc("RegDeleteKeyExW").Call(uintptr(windows.HKEY_LOCAL_MACHINE), uintptr(unsafe.Pointer(path)), uintptr(windows.KEY_WOW64_64KEY), 0)
	if code != 0 || !ordinaryRegistryAbsent(windows.HKEY_LOCAL_MACHINE, nativePolicyTestKey) {
		return errOrdinary
	}
	p.installed = false
	clear(p.installation)
	clear(p.acceptance)
	return nil
}
func ordinaryStageFile(f *ordinaryFixture, path string, data []byte) error {
	sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FRFX;;;" + f.sid + ")")
	if err != nil {
		return errOrdinary
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, windows.FILE_SHARE_READ, &sa, windows.CREATE_NEW, windows.FILE_FLAG_WRITE_THROUGH|windows.FILE_ATTRIBUTE_NORMAL, 0)
	runtime.KeepAlive(sd)
	if err != nil {
		return errOrdinary
	}
	file := os.NewFile(uintptr(h), path)
	recordErr := f.record(path)
	n, writeErr := file.Write(data)
	syncErr, closeErr := file.Sync(), file.Close()
	if closeErr != nil {
		ordinaryCloseFailure = true
	}
	if recordErr != nil || writeErr != nil || syncErr != nil || closeErr != nil || n != len(data) {
		return errOrdinary
	}
	return nil
}
func stageRequiredWindowsPolicy(f *ordinaryFixture) (*ordinaryPolicyFixture, error) {
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_WINDOWS_AUDIT_COMMANDS_TEST") != "1" || !ordinaryRegistryAbsent(windows.HKEY_LOCAL_MACHINE, nativePolicyTestKey) {
		return nil, errOrdinary
	}
	for _, ancestor := range []string{"SOFTWARE", "SOFTWARE\\Policies"} {
		name, _ := windows.UTF16PtrFromString(ancestor)
		var key windows.Handle
		if windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, name, 0, windows.KEY_READ|windows.KEY_WOW64_64KEY, &key) != nil {
			return nil, errOrdinary
		}
		valid := checkNativePolicyHandle(syscall.Handle(key)) == nil
		closed := windows.RegCloseKey(key) == nil
		if !closed {
			ordinaryCloseFailure = true
		}
		if !valid || !closed {
			return nil, errOrdinary
		}
	}
	p := &ordinaryPolicyFixture{}
	f.cleanupPolicy = p.Close
	var recorded ordinaryObject
	found := false
	for _, object := range f.objects {
		if strings.EqualFold(object.path, f.image) {
			recorded = object
			found = true
			break
		}
	}
	if !found {
		return p, errOrdinary
	}
	handle, err := ordinarySameObject(recorded, windows.GENERIC_READ)
	if err != nil {
		return p, errOrdinary
	}
	imageFile := os.NewFile(uintptr(handle), f.image)
	source, readErr := io.ReadAll(io.LimitReader(imageFile, (128<<20)+1))
	closeErr := imageFile.Close()
	if closeErr != nil {
		ordinaryCloseFailure = true
	}
	if readErr != nil || closeErr != nil || len(source) == 0 || len(source) > 128<<20 || sha256.Sum256(source) != f.imageHash {
		clear(source)
		return p, errOrdinary
	}
	enginePath := filepath.Join(f.root, "ciadpi.exe")
	if ordinaryStageFile(f, enginePath, source) != nil {
		clear(source)
		return p, errOrdinary
	}
	clear(source)
	reviewed := profile.New("ordinary-native", "PRIVATE_ORDINARY_NATIVE_PROFILE", "byedpi")
	reviewed.Binary = enginePath
	reviewed.Probe.Host = "127.0.0.1"
	reviewed.Args = nil
	input, err := json.Marshal(reviewed)
	if err != nil {
		return p, errOrdinary
	}
	if ordinaryStageFile(f, filepath.Join(f.root, "reviewed-profile.json"), input) != nil {
		clear(input)
		return p, errOrdinary
	}
	clear(input)
	slot := filepath.Join(f.root, "child-slot")
	sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x001200a5;;;" + f.sid + ")")
	if err != nil {
		return p, errOrdinary
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, _ := windows.UTF16PtrFromString(slot)
	if windows.CreateDirectory(name, &sa) != nil {
		return p, errOrdinary
	}
	runtime.KeepAlive(sd)
	if f.record(slot) != nil {
		return p, errOrdinary
	}
	f.childSlot = slot
	digest, err := reviewed.ExecutionDigest()
	if err != nil {
		return p, errOrdinary
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return p, errOrdinary
	}
	defer clear(private)
	now := time.Now().UTC()
	policy := managed.Policy{SchemaVersion: 1, Revision: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), AllowProfileChanges: true, RequireProfileAudit: true, Launches: []managed.LaunchRule{{Engine: "byedpi", InputSHA256: digest, BinarySHA256: hex.EncodeToString(f.imageHash[:])}}}
	payload, err := json.Marshal(policy)
	if err != nil {
		return p, errOrdinary
	}
	signed, err := managed.Sign(payload, private, now)
	if err != nil {
		return p, errOrdinary
	}
	installation, err := managed.PrepareInstallation(signed, public, now, 0)
	if err != nil {
		return p, errOrdinary
	}
	result, err := managed.Install(installation, public)
	if result.Committed {
		p.installed = true
		f.policyInstalled = true
	}
	if err != nil || !result.Committed || result.Revision != 1 {
		return p, errOrdinary
	}
	p.installation, p.acceptance, p.descriptor, err = ordinaryPolicySnapshot()
	if err != nil {
		return p, err
	}
	return p, nil
}

type windowsCommandWorker struct {
	base, directory, state, profilePath, engine, sid string
	start, head                                      audit.Checkpoint
	p                                                profile.Profile
	owner                                            *windowsCommandWorker
	objects                                          []ordinaryObject
	ctx                                              context.Context
	cancel                                           context.CancelFunc
	counter                                          uint32
}

func (w *windowsCommandWorker) manifest() *windowsCommandWorker {
	if w.owner != nil {
		return w.owner
	}
	return w
}
func (w *windowsCommandWorker) record(path string) error {
	owner := w.manifest()
	h, err := ordinaryOpen(path, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL)
	if err != nil {
		return err
	}
	state, stateErr := ordinaryState(path, h)
	sd, securityErr := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	closed := ordinaryClose(&h)
	if stateErr != nil || securityErr != nil || !closed || state.owner != w.sid || !ordinaryDescriptor(sd, w.sid, false) {
		return errOrdinary
	}
	for _, prior := range owner.objects {
		if strings.EqualFold(prior.path, path) {
			if prior.id != state.id || prior.owner != state.owner {
				return errOrdinary
			}
			return nil
		}
	}
	owner.objects = append(owner.objects, state)
	return nil
}
func (w *windowsCommandWorker) forget(path string) error {
	_, err := fileidentity.FromPath(path, false)
	if !errors.Is(err, os.ErrNotExist) {
		return errOrdinary
	}
	owner := w.manifest()
	for i, object := range owner.objects {
		if strings.EqualFold(object.path, path) {
			owner.objects = append(owner.objects[:i], owner.objects[i+1:]...)
			return nil
		}
	}
	return errOrdinary
}
func (w *windowsCommandWorker) mkdirPrivate(path string) error {
	sd, err := windows.SecurityDescriptorFromString("O:" + w.sid + "D:P(A;OICI;FA;;;" + w.sid + ")(A;OICI;FA;;;SY)")
	if err != nil {
		return errOrdinary
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, _ := windows.UTF16PtrFromString(path)
	if windows.CreateDirectory(name, &sa) != nil {
		return errOrdinary
	}
	runtime.KeepAlive(sd)
	return w.record(path)
}
func (w *windowsCommandWorker) ownFile(path string, data []byte) error {
	sd, err := windows.SecurityDescriptorFromString("O:" + w.sid + "D:P(A;;FA;;;" + w.sid + ")(A;;FA;;;SY)")
	if err != nil {
		return errOrdinary
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, &sa, windows.CREATE_NEW, windows.FILE_FLAG_WRITE_THROUGH|windows.FILE_ATTRIBUTE_NORMAL, 0)
	runtime.KeepAlive(sd)
	if err != nil {
		return errOrdinary
	}
	file := os.NewFile(uintptr(h), path)
	recordErr := w.record(path)
	n, writeErr := file.Write(data)
	syncErr, closeErr := file.Sync(), file.Close()
	if closeErr != nil {
		ordinaryCloseFailure = true
	}
	if recordErr != nil || writeErr != nil || syncErr != nil || closeErr != nil || n != len(data) {
		return errOrdinary
	}
	return nil
}
func (w *windowsCommandWorker) put(path string, data []byte) error {
	owner := w.manifest()
	for _, object := range owner.objects {
		if strings.EqualFold(object.path, path) {
			h, err := ordinarySameObject(object, windows.GENERIC_READ|windows.GENERIC_WRITE)
			if err != nil {
				return err
			}
			file := os.NewFile(uintptr(h), path)
			n, writeErr := file.WriteAt(data, 0)
			truncateErr := file.Truncate(int64(len(data)))
			syncErr, closeErr := file.Sync(), file.Close()
			if closeErr != nil {
				ordinaryCloseFailure = true
			}
			if writeErr != nil || truncateErr != nil || syncErr != nil || closeErr != nil || n != len(data) {
				return errOrdinary
			}
			return nil
		}
	}
	return w.ownFile(path, data)
}
func (w *windowsCommandWorker) privateCapture() (*os.File, error) {
	root := w.manifest()
	root.counter++
	path := filepath.Join(root.base, "capture-"+strconv.FormatUint(uint64(root.counter), 10)+".bin")
	if err := w.ownFile(path, nil); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, errOrdinary
	}
	return file, nil
}
func (w *windowsCommandWorker) command(args []string, stdout, stderr *os.File) (out, notice []byte, failure error) {
	if w.ctx.Err() != nil {
		return nil, nil, errOrdinary
	}
	if w.state != "" {
		os.Setenv("ACCESSWEAVER_HOME", w.state)
	}
	var ownOut, ownErr bool
	var err error
	if stdout == nil {
		stdout, err = w.privateCapture()
		if err != nil {
			return nil, nil, err
		}
		ownOut = true
	}
	if stderr == nil {
		stderr, err = w.privateCapture()
		if err != nil {
			if ownOut {
				if stdout.Close() != nil {
					ordinaryCloseFailure = true
				}
			}
			return nil, nil, err
		}
		ownErr = true
	}
	previousOut, previousErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdout, stderr
	commandErr := execute(args)
	os.Stdout, os.Stderr = previousOut, previousErr
	read := func(file *os.File) ([]byte, error) {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return nil, errOrdinary
		}
		data, err := io.ReadAll(io.LimitReader(file, audit.MaxJournalBytes+1))
		if err != nil || len(data) > audit.MaxJournalBytes {
			clear(data)
			return nil, errOrdinary
		}
		return data, nil
	}
	if ownOut {
		out, err = read(stdout)
		if stdout.Close() != nil {
			ordinaryCloseFailure = true
			failure = errOrdinary
		}
		if err != nil {
			failure = errOrdinary
		}
	}
	if ownErr {
		notice, err = read(stderr)
		if stderr.Close() != nil {
			ordinaryCloseFailure = true
			failure = errOrdinary
		}
		if err != nil {
			failure = errOrdinary
		}
	}
	if failure != nil {
		return out, notice, failure
	}
	return out, notice, commandErr
}
func windowsCommandCheckpoints(data []byte) ([]audit.Checkpoint, error) {
	if len(data) == 0 {
		return nil, errOrdinary
	}
	var result []audit.Checkpoint
	for _, line := range bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'}) {
		checkpoint, err := audit.DecodeCheckpoint(append(append([]byte(nil), line...), '\n'))
		if err != nil || len(result) > 16 {
			return nil, errOrdinary
		}
		result = append(result, checkpoint)
	}
	return result, nil
}
func (w *windowsCommandWorker) newStream(label string) (*windowsCommandWorker, error) {
	root := w.manifest()
	child := &windowsCommandWorker{base: filepath.Join(root.base, label), sid: w.sid, engine: w.engine, p: w.p, owner: root, ctx: w.ctx}
	child.directory = filepath.Join(child.base, "journal")
	child.state = filepath.Join(child.base, "state")
	child.profilePath = filepath.Join(child.base, "profile.json")
	for _, path := range []string{child.base, child.directory, child.state, filepath.Join(child.state, "profiles")} {
		if child.directoryCreate(path) != nil {
			return nil, errOrdinary
		}
	}
	input, err := json.Marshal(child.p)
	if err != nil {
		return nil, errOrdinary
	}
	if child.ownFile(child.profilePath, input) != nil {
		clear(input)
		return nil, errOrdinary
	}
	clear(input)
	os.Setenv("ACCESSWEAVER_HOME", child.state)
	output, _, err := child.command([]string{"audit", "initialize", "--directory", child.directory}, nil, nil)
	if err != nil {
		return nil, errOrdinary
	}
	checkpoints, err := windowsCommandCheckpoints(output)
	if err != nil || len(checkpoints) != 1 || checkpoints[0].Sequence != 0 || checkpoints[0].Producer.ActorClass != "user" || checkpoints[0].Producer.SourceCommit != buildinfo.Current().Commit || checkpoints[0].Producer.SourceState != "clean" {
		return nil, errOrdinary
	}
	child.start, child.head = checkpoints[0], checkpoints[0]
	for _, name := range []string{".actor-key", "events.journal"} {
		if child.record(filepath.Join(child.directory, name)) != nil {
			return nil, errOrdinary
		}
	}
	genesis, _ := audit.EncodeCheckpoint(child.start)
	if child.ownFile(filepath.Join(child.base, "genesis.json"), genesis) != nil || child.ownFile(filepath.Join(child.base, "head.json"), genesis) != nil {
		return nil, errOrdinary
	}
	return child, nil
}
func (w *windowsCommandWorker) directoryCreate(path string) error { return w.mkdirPrivate(path) }
func (w *windowsCommandWorker) writeHead() error {
	data, err := audit.EncodeCheckpoint(w.head)
	if err != nil {
		return errOrdinary
	}
	return w.put(filepath.Join(w.base, "head.json"), data)
}
func (w *windowsCommandWorker) importArgs() []string {
	return []string{"audit", "import", "--directory", w.directory, "--from", filepath.Join(w.base, "genesis.json"), "--to", filepath.Join(w.base, "head.json"), "--profile", w.profilePath}
}
func (w *windowsCommandWorker) exportArgs(recorded bool) []string {
	action := "export"
	if recorded {
		action = "export-recorded"
	}
	return []string{"audit", action, "--directory", w.directory, "--from", filepath.Join(w.base, "genesis.json"), "--to", filepath.Join(w.base, "head.json"), "--consent", "metadata-only"}
}
func (w *windowsCommandWorker) readSegment() ([]audit.Event, []byte, audit.Checkpoint, error) {
	raw, err := windowsCommandReadDefault(filepath.Join(w.directory, "events.journal"))
	if err != nil || len(raw) > audit.MaxJournalBytes {
		return nil, nil, audit.Checkpoint{}, errOrdinary
	}
	end := bytes.IndexByte(raw, '\n')
	if end < 0 {
		return nil, nil, audit.Checkpoint{}, errOrdinary
	}
	// Journal's first line is the retained genesis; remaining lines are JSONL.
	genesis, err := audit.DecodeCheckpoint(raw[:end+1])
	if err != nil || genesis != w.start {
		return nil, nil, audit.Checkpoint{}, errOrdinary
	}
	current := w.start
	var events []audit.Event
	for _, line := range bytes.Split(bytes.TrimSuffix(raw[end+1:], []byte{'\n'}), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var record struct {
			Event audit.Event `json:"event"`
		}
		if json.Unmarshal(line, &record) != nil {
			return nil, nil, audit.Checkpoint{}, errOrdinary
		}
		expected, next, err := audit.Append(current, record.Event)
		if err != nil || !bytes.Equal(expected, append(append([]byte(nil), line...), '\n')) {
			return nil, nil, audit.Checkpoint{}, errOrdinary
		}
		events = append(events, record.Event)
		current = next
	}
	if _, err := audit.VerifySegment(w.ctx, bytes.NewReader(raw[end+1:]), w.start, current); err != nil {
		return nil, nil, audit.Checkpoint{}, errOrdinary
	}
	return events, raw, current, nil
}

func windowsCommandMetadata(w *windowsCommandWorker, outputs ...[]byte) bool {
	private := [][]byte{[]byte(w.sid), []byte(w.manifest().base), []byte(w.p.ID), []byte(w.p.Name), []byte(w.engine)}
	keyPath := filepath.Join(w.directory, ".actor-key")
	key, err := windowsCommandRead(keyPath, 4096)
	if err == nil {
		defer clear(key)
		private = append(private, key)
		if len(key) >= 32 {
			private = append(private, key[len(key)-32:])
		}
	} else if _, probe := fileidentity.FromPath(keyPath, false); !errors.Is(probe, os.ErrNotExist) {
		return false
	}
	for _, output := range outputs {
		for _, value := range private {
			if len(value) > 0 && bytes.Contains(output, value) {
				return false
			}
		}
	}
	return true
}
func (w *windowsCommandWorker) exportVerify(expected uint64) error {
	if w.writeHead() != nil {
		return errOrdinary
	}
	output, _, err := w.command(w.exportArgs(false), nil, nil)
	if err != nil {
		return errOrdinary
	}
	if !windowsCommandMetadata(w, output) {
		return errOrdinary
	}
	result, err := audit.VerifySegment(w.ctx, bytes.NewReader(output), w.start, w.head)
	if err != nil || result.Records != int(expected) {
		return errOrdinary
	}
	path := filepath.Join(w.base, "export.jsonl")
	if w.put(path, output) != nil {
		return errOrdinary
	}
	verified, _, err := w.command([]string{"audit", "verify", "--events", path, "--from", filepath.Join(w.base, "genesis.json"), "--to", filepath.Join(w.base, "head.json")}, nil, nil)
	if err != nil {
		return errOrdinary
	}
	var actual audit.Verification
	if json.Unmarshal(verified, &actual) != nil || actual.Records != int(expected) {
		return errOrdinary
	}
	return nil
}
func (w *windowsCommandWorker) sources() map[string][]byte {
	result := map[string][]byte{}
	for _, path := range []string{w.profilePath, filepath.Join(w.directory, "events.journal"), filepath.Join(w.directory, ".actor-key"), filepath.Join(w.base, "genesis.json"), filepath.Join(w.base, "head.json")} {
		data, err := windowsCommandReadDefault(path)
		if err != nil {
			return nil
		}
		result[path] = data
	}
	source, acceptance, _, err := ordinaryPolicySnapshot()
	if err != nil {
		return nil
	}
	result["registry-installation"] = source
	result["registry-acceptance"] = acceptance
	return result
}
func (w *windowsCommandWorker) preserved(before map[string][]byte) bool {
	if before == nil {
		return false
	}
	after := w.sources()
	if after == nil {
		return false
	}
	for path, data := range before {
		actual, present := after[path]
		if !present {
			var err error
			actual, err = windowsCommandReadSource(w, path)
			if err != nil {
				return false
			}
		}
		if !bytes.Equal(data, actual) {
			return false
		}
	}
	return true
}
func (w *windowsCommandWorker) recordProducts() error {
	for _, path := range []string{filepath.Join(w.state, ".controller.lock"), filepath.Join(w.state, ".profiles.lock")} {
		_, err := fileidentity.FromPath(path, false)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || w.record(path) != nil {
			return errOrdinary
		}
	}
	for _, path := range []string{filepath.Join(w.state, "presets-initialized"), filepath.Join(w.state, "generated")} {
		if _, err := fileidentity.FromPath(path, false); !errors.Is(err, os.ErrNotExist) {
			return errOrdinary
		}
	}
	return nil
}
func (w *windowsCommandWorker) close() error {
	root := w.manifest()
	var failure error
	for i := len(root.objects) - 1; i >= 0; i-- {
		object := root.objects[i]
		if object.owner != w.sid || (object.path != root.base && !strings.HasPrefix(strings.ToLower(object.path), strings.ToLower(root.base)+"\\")) {
			failure = errOrdinary
			continue
		}
		h, err := ordinarySameObject(object, windows.DELETE)
		if err != nil {
			failure = errOrdinary
			continue
		}
		remove := byte(1)
		if windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &remove, 1) != nil {
			failure = errOrdinary
		}
		if !ordinaryClose(&h) {
			failure = errOrdinary
		}
		if _, err := fileidentity.FromPath(object.path, false); !errors.Is(err, os.ErrNotExist) {
			failure = errOrdinary
		}
	}
	return failure
}

func (w *windowsCommandWorker) requiredAdmission() error {
	s, err := w.newStream("required")
	if err != nil {
		return err
	}
	status, err := managed.MachineStatus()
	if err != nil || !status.Valid || status.Revision != 1 {
		return errOrdinary
	}
	source, err := managed.ExportInstallation()
	if err != nil {
		return errOrdinary
	}
	var installation managed.Installation
	if json.Unmarshal(source, &installation) != nil {
		return errOrdinary
	}
	public, err := managed.PublicKey(installation.PublicKey)
	envelope, _ := json.Marshal(installation.Envelope)
	verified, err := managed.Verify(envelope, public, time.Now(), 0)
	if err != nil || !verified.Policy.AllowProfileChanges || !verified.Policy.RequireProfileAudit || verified.Policy.Revision != 1 {
		return errOrdinary
	}
	before := s.sources()
	out, notice, err := s.command([]string{"import", s.profilePath}, nil, nil)
	if !errors.Is(err, managed.ErrDenied) || len(out) != 0 || len(notice) != 0 || !s.preserved(before) {
		return errOrdinary
	}
	store, err := profile.NewStore(s.state)
	if err != nil {
		return errOrdinary
	}
	for _, operation := range []func() error{
		func() error { return store.Save(s.p) },
		func() error { return store.SaveIfUnchangedContext(s.ctx, s.p) },
		func() error { return store.Delete(s.p.ID) },
		func() error { return store.DeleteIfUnchangedContext(s.ctx, s.p.ID, time.Now()) },
		func() error {
			return profile.RestoreSnapshot(s.ctx, filepath.Join(s.base, "must-remain-absent"), []profile.Profile{s.p}, false, managed.NewGuard(nil))
		},
	} {
		if !errors.Is(operation(), managed.ErrDenied) {
			return errOrdinary
		}
	}
	server, err := api.New(store, engine.NewManager(s.state), nil)
	if err != nil {
		return errOrdinary
	}
	body, _ := json.Marshal(s.p)
	request := httptest.NewRequest(http.MethodPut, "http://127.0.0.1/api/v1/profiles/"+s.p.ID, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-AccessWeaver-Token", server.Token)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		return errOrdinary
	}
	entries, err := os.ReadDir(filepath.Join(s.state, "profiles"))
	if err != nil || len(entries) != 0 || !s.preserved(before) || s.recordProducts() != nil {
		return errOrdinary
	}
	if _, err := fileidentity.FromPath(filepath.Join(s.base, "must-remain-absent"), false); !errors.Is(err, os.ErrNotExist) {
		return errOrdinary
	}
	policyName, _ := windows.UTF16PtrFromString(nativePolicyTestKey)
	var denied windows.Handle
	deniedErr := windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, policyName, 0, windows.KEY_SET_VALUE|windows.KEY_WOW64_64KEY, &denied)
	if deniedErr == nil {
		if windows.RegCloseKey(denied) != nil {
			ordinaryCloseFailure = true
		}
		return errOrdinary
	}
	if !errors.Is(deniedErr, windows.ERROR_ACCESS_DENIED) {
		return errOrdinary
	}
	binaryName, _ := windows.UTF16PtrFromString(s.engine)
	forbidden, binaryErr := windows.CreateFile(binaryName, windows.GENERIC_WRITE, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if binaryErr == nil {
		_ = ordinaryClose(&forbidden)
		return errOrdinary
	}
	if !errors.Is(binaryErr, windows.ERROR_ACCESS_DENIED) {
		return errOrdinary
	}
	if _, err := managed.Update([]byte("{}")); !errors.Is(err, managed.ErrDenied) {
		return errOrdinary
	}
	return nil
}
func (w *windowsCommandWorker) adoptProfile(saved profile.Profile) error {
	path := filepath.Join(w.state, "profiles", saved.ID+".json")
	data, err := windowsCommandReadDefault(path)
	if err != nil {
		return errOrdinary
	}
	actual, err := profile.Decode(bytes.NewReader(data))
	if err != nil || !reflect.DeepEqual(actual, saved) || actual.UpdatedAt.IsZero() {
		return errOrdinary
	}
	owner := w.manifest()
	for i := len(owner.objects) - 1; i >= 0; i-- {
		if strings.EqualFold(owner.objects[i].path, path) {
			owner.objects = append(owner.objects[:i], owner.objects[i+1:]...)
			break
		}
	}
	return w.record(path)
}
func (w *windowsCommandWorker) importRoundTrip() error {
	s, err := w.newStream("import")
	if err != nil {
		return err
	}
	output, notice, err := s.command(s.importArgs(), nil, nil)
	if err != nil || len(notice) != 0 {
		return errOrdinary
	}
	checkpoints, err := windowsCommandCheckpoints(output)
	if err != nil || len(checkpoints) != 2 || checkpoints[0].Sequence != 1 || checkpoints[1].Sequence != 2 {
		return errOrdinary
	}
	s.head = checkpoints[1]
	store, err := profile.NewStore(s.state)
	if err != nil {
		return errOrdinary
	}
	saved, err := store.Get(s.p.ID)
	expected := s.p
	expected.UpdatedAt = saved.UpdatedAt
	if err != nil || !reflect.DeepEqual(saved, expected) || s.adoptProfile(saved) != nil || s.recordProducts() != nil {
		return errOrdinary
	}
	before := s.sources()
	originalProfile, err := windowsCommandReadDefault(filepath.Join(s.state, "profiles", saved.ID+".json"))
	if err != nil {
		return errOrdinary
	}
	output, notice, err = s.command(s.importArgs(), nil, nil) // Retained head is still genesis.
	if err == nil || len(output) != 0 || len(notice) != 0 || !s.preserved(before) {
		return errOrdinary
	}
	afterProfile, err := windowsCommandReadDefault(filepath.Join(s.state, "profiles", saved.ID+".json"))
	if err != nil || !bytes.Equal(originalProfile, afterProfile) {
		return errOrdinary
	}
	if s.writeHead() != nil {
		return errOrdinary
	}
	output, _, err = s.command(s.importArgs(), nil, nil) // Zero reviewed revision now conflicts.
	if !errors.Is(err, errAuditImportRefused) {
		return errOrdinary
	}
	observations, err := windowsCommandCheckpoints(output)
	if err != nil || len(observations) != 2 || observations[1].Sequence != 4 {
		return errOrdinary
	}
	s.head = observations[1]
	afterProfile, err = windowsCommandReadDefault(filepath.Join(s.state, "profiles", saved.ID+".json"))
	if err != nil || !bytes.Equal(originalProfile, afterProfile) {
		return errOrdinary
	}
	importEvents, _, importHead, importErr := s.readSegment()
	if importErr != nil || importHead != s.head || len(importEvents) != 4 {
		return errOrdinary
	}
	for i, event := range importEvents {
		expected := []string{"intent", "completed", "intent", "refused"}[i]
		if event.Action != "profile.import" || event.Outcome != expected || (i%2 == 1 && event.OperationID != importEvents[i-1].OperationID) {
			return errOrdinary
		}
	}
	if s.exportVerify(4) != nil {
		return errOrdinary
	}
	// A failed observation after initialization preserves both created files.
	failed := &windowsCommandWorker{base: filepath.Join(w.base, "initialize-output"), sid: w.sid, owner: w.manifest(), ctx: w.ctx}
	if failed.mkdirPrivate(failed.base) != nil {
		return errOrdinary
	}
	failed.directory = filepath.Join(failed.base, "journal")
	if failed.mkdirPrivate(failed.directory) != nil {
		return errOrdinary
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return errOrdinary
	}
	_ = reader.Close()
	_, _, commandErr := s.command([]string{"audit", "initialize", "--directory", failed.directory}, writer, nil)
	closeErr := writer.Close()
	if commandErr == nil || closeErr != nil {
		return errOrdinary
	}
	for _, name := range []string{".actor-key", "events.journal"} {
		if failed.record(filepath.Join(failed.directory, name)) != nil {
			return errOrdinary
		}
	}
	journal, err := windowsCommandReadDefault(filepath.Join(failed.directory, "events.journal"))
	keyBytes, keyErr := windowsCommandReadDefault(filepath.Join(failed.directory, ".actor-key"))
	if err != nil || keyErr != nil {
		return errOrdinary
	}
	_, _, commandErr = s.command([]string{"audit", "initialize", "--directory", failed.directory}, nil, nil)
	afterJournal, _ := windowsCommandReadDefault(filepath.Join(failed.directory, "events.journal"))
	afterKey, _ := windowsCommandReadDefault(filepath.Join(failed.directory, ".actor-key"))
	if commandErr == nil || !bytes.Equal(journal, afterJournal) || !bytes.Equal(keyBytes, afterKey) {
		return errOrdinary
	}
	return nil
}
func (w *windowsCommandWorker) historicalRoundTrip() error {
	s, err := w.newStream("readonly")
	if err != nil {
		return err
	}
	output, _, err := s.command(s.importArgs(), nil, nil)
	if err != nil {
		return errOrdinary
	}
	observations, err := windowsCommandCheckpoints(output)
	if err != nil || len(observations) != 2 {
		return errOrdinary
	}
	s.head = observations[1]
	store, err := profile.NewStore(s.state)
	if err != nil {
		return errOrdinary
	}
	saved, err := store.Get(s.p.ID)
	if err != nil || s.adoptProfile(saved) != nil || s.recordProducts() != nil || s.writeHead() != nil {
		return errOrdinary
	}
	before := s.sources()
	if s.exportVerify(2) != nil || !s.preserved(before) {
		return errOrdinary
	}
	absent := filepath.Join(s.base, "verify-must-not-create")
	os.Setenv("ACCESSWEAVER_HOME", absent)
	_, _, err = s.command([]string{"audit", "verify", "--events", filepath.Join(s.base, "export.jsonl"), "--from", filepath.Join(s.base, "genesis.json"), "--to", filepath.Join(s.base, "head.json")}, nil, nil)
	os.Setenv("ACCESSWEAVER_HOME", s.state)
	if err != nil || !s.preserved(before) {
		return errOrdinary
	}
	if _, err := fileidentity.FromPath(absent, false); !errors.Is(err, os.ErrNotExist) {
		return errOrdinary
	}
	return nil
}
func (w *windowsCommandWorker) currentExport() error {
	s, err := w.newStream("current-export")
	if err != nil {
		return err
	}
	output, notice, err := s.command(s.exportArgs(true), nil, nil)
	if err != nil || len(output) != 0 {
		return errOrdinary
	}
	observations, err := windowsCommandCheckpoints(notice)
	if err != nil || len(observations) != 2 || observations[0].Sequence != 1 || observations[1].Sequence != 2 {
		return errOrdinary
	}
	s.head = observations[1]
	accessEvents, _, accessHead, accessErr := s.readSegment()
	if accessErr != nil || accessHead != s.head || len(accessEvents) != 2 || accessEvents[0].Action != "audit.export" || accessEvents[1].Action != "audit.export" || accessEvents[0].Outcome != "intent" || accessEvents[1].Outcome != "completed" || accessEvents[0].OperationID != accessEvents[1].OperationID {
		return errOrdinary
	}
	if s.exportVerify(2) != nil {
		return errOrdinary
	}
	before := s.sources()
	_, _, err = s.command(append(append([]string{}, s.exportArgs(true)[:len(s.exportArgs(true))-1]...), "rejected-consent"), nil, nil)
	if !errors.Is(err, errAuditExportConsent) || !s.preserved(before) {
		return errOrdinary
	}
	keyPath := filepath.Join(s.directory, ".actor-key")
	key, err := windowsCommandReadDefault(keyPath)
	if err != nil {
		return errOrdinary
	}
	changed := append([]byte(nil), key...)
	changed[len(changed)-1] ^= 1
	if s.put(keyPath, changed) != nil {
		return errOrdinary
	}
	before = s.sources()
	output, notice, err = s.command(s.exportArgs(true), nil, nil)
	if err == nil || len(output) != 0 || len(notice) != 0 || !s.preserved(before) {
		return errOrdinary
	}
	// Historical export uses retained genesis, not the current key.
	if s.exportVerify(2) != nil {
		return errOrdinary
	}
	if s.put(keyPath, key) != nil {
		return errOrdinary
	}
	clear(key)
	clear(changed)
	// Delete only this checked owned key; recording must never recreate it.
	var object ordinaryObject
	found := false
	for _, candidate := range w.manifest().objects {
		if candidate.path == keyPath {
			object = candidate
			found = true
			break
		}
	}
	if !found {
		return errOrdinary
	}
	handle, err := ordinarySameObject(object, windows.DELETE)
	if err != nil {
		return errOrdinary
	}
	remove := byte(1)
	deleteErr := windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo, &remove, 1)
	closed := ordinaryClose(&handle)
	if deleteErr != nil || !closed || s.forget(keyPath) != nil {
		return errOrdinary
	}
	journalBefore, _ := windowsCommandReadDefault(filepath.Join(s.directory, "events.journal"))
	output, notice, err = s.command(s.exportArgs(true), nil, nil)
	journalAfter, _ := windowsCommandReadDefault(filepath.Join(s.directory, "events.journal"))
	if err == nil || len(output) != 0 || len(notice) != 0 || !bytes.Equal(journalBefore, journalAfter) {
		return errOrdinary
	}
	if s.exportVerify(2) != nil {
		return errOrdinary
	}
	if _, err := fileidentity.FromPath(keyPath, false); !errors.Is(err, os.ErrNotExist) {
		return errOrdinary
	}
	return nil
}
func windowsHTTP(client *http.Client, method, address, token string, input any) (int, []byte, error) {
	var body []byte
	if input != nil {
		var err error
		body, err = json.Marshal(input)
		if err != nil {
			return 0, nil, errOrdinary
		}
	}
	request, err := http.NewRequest(method, address, bytes.NewReader(body))
	if err != nil {
		return 0, nil, errOrdinary
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("X-AccessWeaver-Token", token)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, errOrdinary
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(data) >= 1<<20 {
		return 0, nil, errOrdinary
	}
	return response.StatusCode, data, nil
}
func (w *windowsCommandWorker) desktop(full bool) error {
	label := "desktop"
	if full {
		label = "full-desktop"
	}
	s, err := w.newStream(label)
	if err != nil {
		return err
	}
	if full && s.seedCapacity() != nil {
		return errOrdinary
	}
	os.Setenv("ACCESSWEAVER_NO_BROWSER", "1")
	reader, writer, err := os.Pipe()
	if err != nil {
		return errOrdinary
	}
	defer reader.Close()
	type desktopResult struct {
		output []byte
		err    error
	}
	done := make(chan desktopResult, 1)
	var uiOutput []byte
	go func() {
		output, _, err := s.command([]string{"audit", "ui", "--directory", s.directory, "--from", filepath.Join(s.base, "genesis.json"), "--to", filepath.Join(s.base, "head.json")}, nil, writer)
		if writer.Close() != nil {
			ordinaryCloseFailure = true
			err = errOrdinary
		}
		done <- desktopResult{output, err}
	}()
	startup := make(chan string, 1)
	go func() {
		scan := bufio.NewScanner(io.LimitReader(reader, 16385))
		scan.Buffer(make([]byte, 1024), 16384)
		for scan.Scan() {
			line := scan.Text()
			const prefix = "Open this private launch file in your browser: "
			if strings.HasPrefix(line, prefix) {
				startup <- strings.TrimPrefix(line, prefix)
				return
			}
		}
		startup <- ""
	}()
	var launch string
	select {
	case launch = <-startup:
	case <-time.After(15 * time.Second):
		_ = windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, 0)
		<-done
		return errOrdinary
	}
	stop := func() error {
		if windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, 0) != nil {
			return errOrdinary
		}
		select {
		case result := <-done:
			uiOutput = result.output
			return result.err
		case <-time.After(15 * time.Second):
			return errOrdinary
		}
	}
	if launch == "" {
		_ = stop()
		return errOrdinary
	}
	parsed, err := url.Parse(launch)
	if err != nil || parsed.Scheme != "file" || parsed.Host != "" {
		_ = stop()
		return errOrdinary
	}
	path := filepath.FromSlash(strings.TrimPrefix(parsed.Path, "/"))
	cache, err := os.UserCacheDir()
	if err != nil || !strings.EqualFold(filepath.Dir(filepath.Dir(path)), cache) || !strings.HasPrefix(filepath.Base(filepath.Dir(path)), "accessweaver-ui-") || filepath.Base(path) != "start.html" {
		_ = stop()
		return errOrdinary
	}
	launchHandle, err := ordinaryOpen(path, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL)
	if err != nil {
		_ = stop()
		return errOrdinary
	}
	launchObject, stateErr := ordinaryState(path, launchHandle)
	launchSD, launchSDErr := windows.GetSecurityInfo(launchHandle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	launchPrivate := launchSDErr == nil && ordinaryDescriptor(launchSD, w.sid, true)
	if !ordinaryClose(&launchHandle) || stateErr != nil || launchObject.owner != w.sid || !launchPrivate {
		_ = stop()
		return errOrdinary
	}
	directoryHandle, err := ordinaryOpen(filepath.Dir(path), windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL)
	if err != nil {
		_ = stop()
		return errOrdinary
	}
	directoryObject, directoryStateErr := ordinaryState(filepath.Dir(path), directoryHandle)
	directorySD, directorySDErr := windows.GetSecurityInfo(directoryHandle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	directoryPrivate := directorySDErr == nil && ordinaryDescriptor(directorySD, w.sid, true)
	if !ordinaryClose(&directoryHandle) || directoryStateErr != nil || directoryObject.owner != w.sid || !directoryPrivate {
		_ = stop()
		return errOrdinary
	}
	page, err := windowsCommandReadDefault(path)
	if err != nil || len(page) > 8192 {
		_ = stop()
		return errOrdinary
	}
	text := html.UnescapeString(string(page))
	start := strings.Index(text, "http://127.0.0.1:")
	if start < 0 {
		_ = stop()
		return errOrdinary
	}
	tail := text[start:]
	end := strings.IndexAny(tail, "\"<> \r\n")
	if end < 0 {
		_ = stop()
		return errOrdinary
	}
	target, err := url.Parse(tail[:end])
	if err != nil || target.Scheme != "http" || target.Hostname() != "127.0.0.1" || target.Port() == "" || !strings.HasPrefix(target.Fragment, "accessweaver-session=") {
		_ = stop()
		return errOrdinary
	}
	token := strings.TrimPrefix(target.Fragment, "accessweaver-session=")
	target.Fragment = ""
	if len(token) != 43 {
		_ = stop()
		return errOrdinary
	}
	address := strings.TrimSuffix(target.String(), "/")
	client := &http.Client{Timeout: 5 * time.Second}
	call := func(method, route, credential string, input any, expected int) ([]byte, error) {
		status, data, err := windowsHTTP(client, method, address+route, credential, input)
		if err != nil || status != expected {
			clear(data)
			return nil, errOrdinary
		}
		return data, nil
	}
	if _, err := call("GET", "/api/bootstrap", token, nil, 200); err != nil {
		_ = stop()
		return errOrdinary
	}
	if _, err := call("PUT", "/api/v1/profiles/"+s.p.ID, "", s.p, 403); err != nil {
		_ = stop()
		return errOrdinary
	}
	if full {
		if _, err := call("PUT", "/api/v1/profiles/"+s.p.ID, token, s.p, 503); err != nil {
			_ = stop()
			return errOrdinary
		}
	} else {
		data, err := call("PUT", "/api/v1/profiles/"+s.p.ID, token, s.p, 200)
		var saved profile.Profile
		if err != nil || json.Unmarshal(data, &saved) != nil || s.adoptProfile(saved) != nil {
			_ = stop()
			return errOrdinary
		}
		if _, err := call("PUT", "/api/v1/profiles/"+s.p.ID, token, s.p, 409); err != nil {
			_ = stop()
			return errOrdinary
		}
		saved.Name = "PRIVATE_UPDATED_ORDINARY_PROFILE"
		data, err = call("PUT", "/api/v1/profiles/"+s.p.ID, token, saved, 200)
		if err != nil || json.Unmarshal(data, &saved) != nil || s.adoptProfile(saved) != nil {
			_ = stop()
			return errOrdinary
		}
		if _, err := call("DELETE", "/api/v1/profiles/"+s.p.ID, token, map[string]any{"expectedUpdatedAt": saved.UpdatedAt}, 200); err != nil {
			_ = stop()
			return errOrdinary
		}
		if s.forget(filepath.Join(s.state, "profiles", saved.ID+".json")) != nil {
			_ = stop()
			return errOrdinary
		}
	}
	for _, route := range []string{"/api/v1/start", "/api/v1/stop", "/api/v1/diagnose", "/api/v1/system/start", "/api/v1/support"} {
		method := "POST"
		if route == "/api/v1/support" {
			method = "GET"
		}
		if _, err := call(method, route, token, map[string]any{}, 403); err != nil {
			_ = stop()
			return errOrdinary
		}
	}
	if stop() != nil || s.recordProducts() != nil {
		return errOrdinary
	}
	if _, err := fileidentity.FromPath(path, false); !errors.Is(err, os.ErrNotExist) {
		return errOrdinary
	}
	if _, err := fileidentity.FromPath(filepath.Dir(path), false); !errors.Is(err, os.ErrNotExist) {
		return errOrdinary
	}
	events, _, head, err := s.readSegment()
	expected := 8
	if full {
		expected = 4095
	}
	if err != nil || len(events) != expected {
		return errOrdinary
	}
	if full {
		if len(uiOutput) != 0 || head != s.head {
			return errOrdinary
		}
	} else {
		observed, err := windowsCommandCheckpoints(uiOutput)
		if err != nil || len(observed) != 8 || observed[len(observed)-1] != head {
			return errOrdinary
		}
		current := s.start
		actions := []string{"profile.write", "profile.write", "profile.write", "profile.write", "profile.write", "profile.write", "profile.delete", "profile.delete"}
		outcomes := []string{"intent", "completed", "intent", "refused", "intent", "completed", "intent", "completed"}
		for i, checkpoint := range observed {
			_, expected, appendErr := audit.Append(current, events[i])
			if appendErr != nil || checkpoint != expected || events[i].Action != actions[i] || events[i].Outcome != outcomes[i] {
				return errOrdinary
			}
			if i%2 == 1 && events[i].OperationID != events[i-1].OperationID {
				return errOrdinary
			}
			current = expected
		}
		s.head = observed[len(observed)-1]
	}
	if !full && s.exportVerify(8) != nil {
		return errOrdinary
	}
	reopened, err := audit.OpenLocalJournal(s.ctx, s.directory, s.start, s.head)
	if err != nil {
		return errOrdinary
	}
	if reopened.Close() != nil {
		return errOrdinary
	}
	lock, err := filelock.TryAcquire(filepath.Join(s.state, ".controller.lock"))
	if err != nil || lock.Close() != nil {
		return errOrdinary
	}
	return nil
}

func runWindowsCommandCases(nonce []byte) (executed, passed uint64) {
	executable, err := os.Executable()
	if err != nil || len(nonce) != 32 {
		return 0, 0
	}
	stage := filepath.Dir(executable)
	input, err := os.Open(filepath.Join(stage, "reviewed-profile.json"))
	if err != nil {
		return 0, 0
	}
	data, readErr := io.ReadAll(io.LimitReader(input, (1<<20)+1))
	closeErr := input.Close()
	if readErr != nil || closeErr != nil || len(data) > 1<<20 {
		clear(data)
		return 0, 0
	}
	reviewed, err := profile.Decode(bytes.NewReader(data))
	clear(data)
	if err != nil || !strings.EqualFold(reviewed.Binary, filepath.Join(stage, "ciadpi.exe")) || len(reviewed.Args) != 0 {
		return 0, 0
	}
	var token windows.Token
	if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token) != nil {
		return 0, 0
	}
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		_ = token.Close()
		return 0, 0
	}
	sid := user.User.Sid.String()
	if token.Close() != nil {
		ordinaryCloseFailure = true
		return 0, 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	root := &windowsCommandWorker{base: filepath.Join(stage, "child-slot", "work-"+hex.EncodeToString(nonce[:8])), sid: sid, engine: reviewed.Binary, p: reviewed, ctx: ctx}
	if root.mkdirPrivate(root.base) != nil {
		return 0, 0
	}
	operations := []func() error{
		root.requiredAdmission, root.importRoundTrip, func() error { return root.desktop(false) },
		root.historicalRoundTrip, root.currentExport, root.aliasAdmission, root.capacityRefusal,
		root.runApprovedAndRefusals, root.runFailuresAndCancellation,
	}
	for index, operation := range operations {
		if ctx.Err() != nil {
			break
		}
		executed |= 1 << index
		if operation() != nil {
			break
		}
		passed |= 1 << index
	}
	// No arbitrary enumeration is adopted for deletion. Unexpected operation
	// outputs remain in their private directory and make exact cleanup fail.
	if root.close() != nil {
		passed = 0
	}
	return executed, passed
}
func windowsInertReadyName(parent, pid uint32) string {
	return "Local\\AccessWeaverOrdinaryReady-" + strconv.FormatUint(uint64(parent), 10) + "-" + strconv.FormatUint(uint64(pid), 10)
}
func ordinaryInertWindowsEngine() bool {
	if !strings.EqualFold(filepath.Base(os.Args[0]), "ciadpi.exe") {
		return false
	}
	if len(os.Args) != 3 || os.Args[1] != "--ip" || os.Args[2] != "127.0.0.1" {
		os.Exit(98)
	}
	// Consume BREAK through Notify: Windows' runtime default handler does not
	// treat signal.Ignore as a delivered SIGINT. Readiness is signaled only after
	// this subscription exists, so the real manager owns the cancellation kill.
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		os.Exit(98)
	}
	sid := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;GA;;;" + sid + ")(A;;GA;;;SY)")
	if err != nil {
		os.Exit(98)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, _ := windows.UTF16PtrFromString(windowsInertReadyName(uint32(os.Getppid()), uint32(os.Getpid())))
	handle, _, lastErr := ordinaryKernel.NewProc("CreateEventW").Call(uintptr(unsafe.Pointer(&sa)), 1, 1, uintptr(unsafe.Pointer(name)))
	runtime.KeepAlive(sd)
	if handle == 0 {
		os.Exit(98)
	}
	ready := windows.Handle(handle)
	if errors.Is(lastErr, windows.ERROR_ALREADY_EXISTS) {
		_ = ordinaryClose(&ready)
		os.Exit(98)
	}
	time.Sleep(3 * time.Second)
	signal.Stop(interrupts)
	if !ordinaryClose(&ready) {
		os.Exit(98)
	}
	os.Exit(0)
	return true
}
func windowsRunWaitReady(w *windowsCommandWorker) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var processes struct {
			Assigned, Count uint32
			IDs             [4]uintptr
		}
		if windows.QueryInformationJobObject(0, windows.JobObjectBasicProcessIdList, uintptr(unsafe.Pointer(&processes)), uint32(unsafe.Sizeof(processes)), nil) != nil || processes.Count > 4 {
			return false
		}
		if processes.Count == 2 {
			var childPID uint32
			for _, pid := range processes.IDs[:processes.Count] {
				if uint32(pid) != uint32(os.Getpid()) {
					childPID = uint32(pid)
				}
			}
			if childPID == 0 {
				return false
			}
			process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, childPID)
			if err != nil {
				return false
			}
			var image [32768]uint16
			length := uint32(len(image))
			imageErr := windows.QueryFullProcessImageName(process, 0, &image[0], &length)
			closed := ordinaryClose(&process)
			if imageErr != nil || !closed || length == 0 || length >= uint32(len(image)) || !strings.EqualFold(windows.UTF16ToString(image[:length]), w.engine) {
				return false
			}
			name, _ := windows.UTF16PtrFromString(windowsInertReadyName(uint32(os.Getpid()), childPID))
			event, err := windows.OpenEvent(windows.SYNCHRONIZE|windows.READ_CONTROL, false, name)
			if err == nil {
				sd, securityErr := windows.GetSecurityInfo(event, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
				status, waitErr := windows.WaitForSingleObject(event, 0)
				closed := ordinaryClose(&event)
				return securityErr == nil && ordinaryDescriptor(sd, w.sid, true) && waitErr == nil && status == windows.WAIT_OBJECT_0 && closed
			}
			if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
				return false
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
func TestDisposableWindowsAuditCommands(t *testing.T) {
	if _, present := os.LookupEnv("ACCESSWEAVER_DISPOSABLE_WINDOWS_AUDIT_COMMANDS_TEST"); !present {
		t.Skip("explicit disposable hosted Windows command fixture only")
	}
	f := &ordinaryFixture{cleanupOK: true, commands: true}
	for _, id := range ordinaryCaseNames {
		f.cases = append(f.cases, ordinaryCase{ID: id})
	}
	for _, id := range ordinaryCommandCaseNames {
		f.cases = append(f.cases, ordinaryCase{ID: id})
	}
	t.Cleanup(func() { f.finish(); f.report(t) })
	if f.prepare() != nil {
		t.Fatal("ordinary Windows command fixture preparation failed")
	}
	if _, err := stageRequiredWindowsPolicy(f); err != nil {
		t.Fatal("ordinary Windows command policy setup failed")
	}
	if f.launch() != nil {
		t.Fatal("ordinary Windows command worker launch failed")
	}
	if f.exchange() != nil {
		t.Fatal("ordinary Windows command acceptance failed")
	}
}

// This fragment uses bytes/errors/io/os/path/filepath/time/unsafe,
// encoding/json, audit/profile, and golang.org/x/sys/windows imports.
const windowsRunLaunchNotice = "Process launched. This does not guarantee functional routing or connection.\n"

func windowsRunArguments(w *windowsCommandWorker, input string) []string {
	return []string{"run", "--directory", w.directory,
		"--from", filepath.Join(w.base, "genesis.json"), "--to", filepath.Join(w.base, "head.json"),
		"--profile", input, "--consent", "metadata-only"}
}

// Never adopt a disk-derived head. Only complete, emitted stdout observations
// below authorize updating w.head or retaining a successor checkpoint file.
func windowsRunObserved(w *windowsCommandWorker, data []byte, outcomes ...string) error {
	checkpoints, err := windowsCommandCheckpoints(data)
	if err != nil || len(checkpoints) != len(outcomes) {
		return errOrdinary
	}
	events, raw, end, err := w.readSegment()
	if err != nil || len(events) != len(outcomes) {
		return errOrdinary
	}
	operation := ""
	current := w.start
	for index, outcome := range outcomes {
		_, expected, appendErr := audit.Append(current, events[index])
		if appendErr != nil || checkpoints[index] != expected {
			return errOrdinary
		}
		current = expected
		if checkpoints[index].Sequence != w.start.Sequence+uint64(index)+1 ||
			events[index].Action != "engine.start" || events[index].Outcome != outcome ||
			len(events[index].OperationID) != 32 {
			return errOrdinary
		}
		if index == 0 {
			operation = events[index].OperationID
		} else if events[index].OperationID != operation {
			return errOrdinary
		}
	}
	if len(checkpoints) == 0 || checkpoints[len(checkpoints)-1] != end {
		return errOrdinary
	}
	if !windowsRunPrivateMetadata(w, data, raw) {
		return errOrdinary
	}
	w.head = checkpoints[len(checkpoints)-1]
	return nil
}

func windowsRunPrivateMetadata(w *windowsCommandWorker, outputs ...[]byte) bool {
	input, err := windowsCommandReadDefault(w.profilePath)
	if err != nil {
		return false
	}
	p, err := profile.Decode(bytes.NewReader(input))
	if err != nil {
		return false
	}
	key, err := windowsCommandReadDefault(filepath.Join(w.directory, ".actor-key"))
	if err != nil || len(key) < 32 {
		return false
	}
	defer clear(key)
	private := [][]byte{input, []byte(p.ID), []byte(p.Name), []byte(p.Binary), []byte(w.base), []byte(w.profilePath), key, key[len(key)-32:]}
	for _, output := range outputs {
		for _, value := range private {
			if len(value) != 0 && bytes.Contains(output, value) {
				return false
			}
		}
	}
	return true
}

// Exclude only the journal that this explicit operation is expected to append.
// Inputs, key, independently retained checkpoint files and the fixed HKLM pair
// remain in the snapshot. The staged approved engine is protected separately.
func windowsRunPreservedInputs(w *windowsCommandWorker) (map[string][]byte, error) {
	before := w.sources()
	if len(before) == 0 {
		return nil, errOrdinary
	}
	delete(before, filepath.Join(w.directory, "events.journal"))
	engine, err := windowsCommandRead(w.engine, 128<<20)
	if err != nil || len(engine) == 0 {
		return nil, errOrdinary
	}
	before[w.engine] = engine
	return before, nil
}

// Test native exclusion directly, including a failed intent observation whose
// disk-derived terminal checkpoint must never be reused as retained authority.
// Opening existing lock-bearing files does not recreate or truncate anything.
func windowsRunReleased(w *windowsCommandWorker) error {
	entries, err := os.ReadDir(filepath.Join(w.state, "profiles"))
	if err != nil || len(entries) != 0 {
		return errOrdinary
	}
	if _, err := os.Lstat(filepath.Join(w.state, "presets-initialized")); !os.IsNotExist(err) {
		return errOrdinary
	}
	if _, err := os.Lstat(filepath.Join(w.state, "generated")); !os.IsNotExist(err) {
		return errOrdinary
	}
	for _, path := range []string{filepath.Join(w.state, ".controller.lock"), filepath.Join(w.directory, "events.journal")} {
		if w.record(path) != nil {
			return errOrdinary
		}
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return errOrdinary
		}
		handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
			windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return errOrdinary
		}
		var overlap windows.Overlapped
		lockErr := windows.LockFileEx(handle, windows.LOCKFILE_FAIL_IMMEDIATELY|windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlap)
		closeErr := windows.CloseHandle(handle) // Final close releases the lock.
		if lockErr != nil || closeErr != nil || w.record(path) != nil {
			return errOrdinary
		}
	}
	// The real command may create this coordination object in some paths.
	profileLock := filepath.Join(w.state, ".profiles.lock")
	if _, err := os.Lstat(profileLock); err == nil {
		if w.record(profileLock) != nil {
			return errOrdinary
		}
	} else if !os.IsNotExist(err) {
		return errOrdinary
	}
	var accounting ordinaryAccounting
	if windows.QueryInformationJobObject(0, windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil) != nil ||
		accounting.Active != 1 {
		return errOrdinary
	}
	return nil
}

func (w *windowsCommandWorker) runApprovedAndRefusals() error {
	child, err := w.newStream("run-approved")
	if err != nil {
		return errOrdinary
	}
	before, err := windowsRunPreservedInputs(child)
	if err != nil {
		return errOrdinary
	}
	command := windowsRunArguments(child, child.profilePath)
	observed, notice, err := child.command(command, nil, nil)
	if err != nil || string(notice) != windowsRunLaunchNotice ||
		windowsRunObserved(child, observed, "intent", "accepted", "completed") != nil ||
		!windowsRunPrivateMetadata(child, notice) || !child.preserved(before) ||
		windowsRunReleased(child) != nil {
		return errOrdinary
	}
	// The retained file still contains genesis. The in-memory head above came
	// from stdout, but is deliberately not retained until after this retry.
	stale := child.sources()
	retry, retryNotice, err := child.command(command, nil, nil)
	if err == nil || len(retry) != 0 || len(retryNotice) != 0 || !child.preserved(stale) ||
		windowsRunReleased(child) != nil {
		return errOrdinary
	}
	if child.writeHead() != nil || child.exportVerify(3) != nil {
		return errOrdinary
	}
	input, err := windowsCommandReadDefault(child.profilePath)
	if err != nil {
		return errOrdinary
	}
	unapproved, err := profile.Decode(bytes.NewReader(input))
	if err != nil {
		return errOrdinary
	}
	unapproved.Routing.IncludeDomains = []string{"unapproved-native-fixture.invalid"}
	unapprovedBytes, err := json.Marshal(unapproved)
	if err != nil {
		return errOrdinary
	}
	unapprovedPath := filepath.Join(child.base, "unapproved-run-profile.json")
	if child.ownFile(unapprovedPath, unapprovedBytes) != nil {
		return errOrdinary
	}
	preserved := child.sources()
	preserved[unapprovedPath] = bytes.Clone(unapprovedBytes)
	preserved[child.engine] = bytes.Clone(before[child.engine])
	refused, refusedNotice, err := child.command(windowsRunArguments(child, unapprovedPath), nil, nil)
	if !errors.Is(err, errAuditRunPreview) || len(refused) != 0 || len(refusedNotice) != 0 ||
		!child.preserved(preserved) || windowsRunReleased(child) != nil {
		return errOrdinary
	}
	return nil
}

func windowsRunClosedOutput() (*os.File, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, errOrdinary
	}
	if reader.Close() != nil {
		_ = writer.Close()
		return nil, errOrdinary
	}
	return writer, nil
}

func windowsRunOutputFailure(w *windowsCommandWorker, intent bool) (failure error) {
	label := "run-notice-output-failure"
	if intent {
		label = "run-intent-output-failure"
	}
	child, err := w.newStream(label)
	if err != nil {
		return errOrdinary
	}
	before, err := windowsRunPreservedInputs(child)
	if err != nil {
		return errOrdinary
	}
	broken, err := windowsRunClosedOutput()
	if err != nil {
		return errOrdinary
	}
	defer func() {
		if broken.Close() != nil {
			failure = errOrdinary
		}
	}()
	var observed, notice []byte
	if intent {
		observed, notice, err = child.command(windowsRunArguments(child, child.profilePath), broken, nil)
	} else {
		observed, notice, err = child.command(windowsRunArguments(child, child.profilePath), nil, broken)
	}
	if intent {
		if !errors.Is(err, audit.ErrRecorderUnavailable) || len(observed) != 0 || len(notice) != 0 {
			return errOrdinary
		}
		events, raw, _, segmentErr := child.readSegment()
		if segmentErr != nil || len(events) != 2 || events[0].Action != "engine.start" ||
			events[1].Action != "engine.start" || events[0].Outcome != "intent" ||
			events[1].Outcome != "refused" || len(events[0].OperationID) != 32 ||
			events[0].OperationID != events[1].OperationID || !windowsRunPrivateMetadata(child, raw) {
			return errOrdinary
		}
		// No stdout successor was observed: leave child.head at genesis and
		// do not open another audit writer or export with a disk-derived head.
	} else {
		if !errors.Is(err, audit.ErrRecordedUncertain) ||
			windowsRunObserved(child, observed, "intent", "accepted", "failed") != nil ||
			len(notice) != 0 || child.writeHead() != nil || child.exportVerify(3) != nil {
			return errOrdinary
		}
		// writeHead intentionally changed only the separately retained head.
		delete(before, filepath.Join(child.base, "head.json"))
	}
	if !child.preserved(before) || windowsRunReleased(child) != nil {
		return errOrdinary
	}
	return nil
}

func windowsRunCancellation(w *windowsCommandWorker) (failure error) {
	child, err := w.newStream("run-cancellation")
	if err != nil {
		return errOrdinary
	}
	before, err := windowsRunPreservedInputs(child)
	if err != nil {
		return errOrdinary
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return errOrdinary
	}
	defer func() {
		if reader.Close() != nil {
			failure = errOrdinary
		}
		if writer != nil && writer.Close() != nil {
			failure = errOrdinary
		}
	}()
	signalResult := make(chan bool, 1)
	go func() {
		// A direct pipe receives only the fixed notice, after observed intent
		// and acceptance. The source-only ciadpi branch ignores Interrupt;
		// the real controller Stop path must kill and drain its held process.
		line := make([]byte, len(windowsRunLaunchNotice))
		_, readErr := io.ReadFull(reader, line)
		if readErr != nil || string(line) != windowsRunLaunchNotice {
			signalResult <- false
			return
		}
		signalResult <- windowsRunWaitReady(child) && windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, 0) == nil
	}()
	observed, _, commandErr := child.command(windowsRunArguments(child, child.profilePath), nil, writer)
	// A failed startup emits no notice. Close the writer so its reader cannot
	// outlive this case; a normal notice was already consumed in full.
	if writer.Close() != nil {
		return errOrdinary
	}
	writer = nil
	var signaled bool
	select {
	case signaled = <-signalResult:
	case <-time.After(5 * time.Second):
		return errOrdinary
	}
	if !signaled || commandErr != nil ||
		windowsRunObserved(child, observed, "intent", "accepted", "failed") != nil ||
		!child.preserved(before) || windowsRunReleased(child) != nil {
		return errOrdinary
	}
	if child.writeHead() != nil || child.exportVerify(3) != nil {
		return errOrdinary
	}
	return nil
}

func (w *windowsCommandWorker) runFailuresAndCancellation() error {
	if windowsRunOutputFailure(w, true) != nil || windowsRunOutputFailure(w, false) != nil ||
		windowsRunCancellation(w) != nil {
		return errOrdinary
	}
	return nil
}

// This fragment uses bytes/crypto-rand/encoding-hex/errors/os/filepath/strings/
// strconv/time/unsafe plus audit/fileidentity and golang.org/x/sys/windows.

func (w *windowsCommandWorker) seedCapacity() error {
	if w.start.Sequence != 0 || w.head != w.start {
		return errOrdinary
	}
	genesis, err := audit.EncodeCheckpoint(w.start)
	if err != nil {
		return errOrdinary
	}
	current, err := windowsCommandReadDefault(filepath.Join(w.directory, "events.journal"))
	if err != nil || !bytes.Equal(current, genesis) {
		return errOrdinary
	}
	full := bytes.Clone(genesis)
	head := w.start
	for index := uint64(0); index < audit.MaxSegmentRecords-1; index++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return errOrdinary
		}
		line, next, err := audit.Append(head, audit.Event{
			OccurredAt: time.Now().UTC(), OperationID: hex.EncodeToString(random[:]),
			Action: "profile.write", Outcome: "completed",
		})
		clear(random[:])
		if err != nil || len(full)+len(line) > audit.MaxJournalBytes {
			return errOrdinary
		}
		full = append(full, line...)
		head = next
	}
	verified, err := audit.VerifySegment(w.ctx, bytes.NewReader(full[len(genesis):]), w.start, head)
	if err != nil || uint64(verified.Records) != audit.MaxSegmentRecords-1 ||
		w.put(filepath.Join(w.directory, "events.journal"), full) != nil {
		return errOrdinary
	}
	w.head = head
	if w.writeHead() != nil {
		return errOrdinary
	}
	events, raw, observed, err := w.readSegment()
	if err != nil || uint64(len(events)) != audit.MaxSegmentRecords-1 ||
		observed != head || !bytes.Equal(raw, full) {
		return errOrdinary
	}
	return nil
}

func windowsAliasArguments(w *windowsCommandWorker, action string) []string {
	switch action {
	case "import":
		return w.importArgs()
	case "export-recorded":
		return w.exportArgs(true)
	case "ui":
		return []string{"audit", "ui", "--directory", w.directory,
			"--from", filepath.Join(w.base, "genesis.json"), "--to", filepath.Join(w.base, "head.json")}
	case "run":
		return []string{"audit", "run", "--directory", w.directory,
			"--from", filepath.Join(w.base, "genesis.json"), "--to", filepath.Join(w.base, "head.json"),
			"--profile", w.profilePath, "--consent", "metadata-only"}
	}
	return nil
}

func (w *windowsCommandWorker) capacityRefusal() error {
	child, err := w.newStream("capacity")
	if err != nil || child.seedCapacity() != nil {
		return errOrdinary
	}
	before := child.sources()
	if before == nil {
		return errOrdinary
	}
	for _, action := range []string{"import", "export-recorded", "run"} {
		out, notice, commandErr := child.command(windowsAliasArguments(child, action), nil, nil)
		expected := audit.ErrRecorderUnavailable
		if action == "import" {
			expected = errAuditImportAdmission
		}
		if !errors.Is(commandErr, expected) || len(out) != 0 || len(notice) != 0 ||
			!child.preserved(before) || child.recordProducts() != nil {
			return errOrdinary
		}
		entries, err := os.ReadDir(filepath.Join(child.state, "profiles"))
		if err != nil || len(entries) != 0 {
			return errOrdinary
		}
	}
	events, _, head, err := child.readSegment()
	if err != nil || uint64(len(events)) != audit.MaxSegmentRecords-1 || head != child.head {
		return errOrdinary
	}
	// Exercise the real private launcher/HTTP mutation path at the same
	// reservation boundary; the main desktop helper owns signal/HTTP cleanup.
	return w.desktop(true)
}

type windowsAliasDestination struct {
	worker       *windowsCommandWorker
	file         *os.File
	source, path string
	variant      string
	object       ordinaryObject
	linked       bool
	stream       bool
}

func windowsAliasOpenedPath(handle windows.Handle) (string, error) {
	var buffer [32768]uint16
	length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0x8) // FILE_NAME_OPENED
	if err != nil || length == 0 || length >= uint32(len(buffer)) {
		return "", errOrdinary
	}
	name := windows.UTF16ToString(buffer[:length])
	return strings.TrimPrefix(name, "\\\\?\\"), nil
}

// Withdraw deletion authority after ambiguous stream cleanup. Nonrecursive
// directory removal then fails naturally, retaining the uncertain base object.
func windowsAliasPreserveBase(w *windowsCommandWorker, path string) {
	root := w.manifest()
	for index := len(root.objects) - 1; index >= 0; index-- {
		if strings.EqualFold(root.objects[index].path, path) {
			root.objects = append(root.objects[:index], root.objects[index+1:]...)
		}
	}
}

func windowsAliasNew(w *windowsCommandWorker, source, variant string, readonly bool) (*windowsAliasDestination, error) {
	destination := &windowsAliasDestination{worker: w, source: source, path: source, variant: variant}
	handle, err := ordinaryOpen(source, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL)
	if err != nil {
		return destination, errOrdinary
	}
	original, stateErr := ordinaryState(source, handle)
	closeOK := ordinaryClose(&handle)
	if stateErr != nil || !closeOK {
		return destination, errOrdinary
	}
	destination.object = original
	access := uint32(windows.GENERIC_READ | windows.FILE_APPEND_DATA)
	if readonly {
		access = windows.GENERIC_READ
	}
	disposition := uint32(windows.OPEN_EXISTING)
	switch variant {
	case "direct":
	case "case":
		destination.path = strings.ToUpper(source)
	case "hardlink":
		root := w.manifest()
		root.counter++
		destination.path = filepath.Join(w.base, "alias-link-"+strconv.FormatUint(uint64(root.counter), 10)+".bin")
		if os.Link(source, destination.path) != nil {
			return destination, errOrdinary
		}
		destination.linked = true
		destination.object.path = destination.path
		if w.record(destination.path) != nil {
			return destination, errOrdinary
		}
	case "ads":
		// CREATE_NEW refuses a preexisting unknown stream, without truncation.
		destination.path = source + ":accessweaver-native-output"
		disposition = windows.CREATE_NEW
	default:
		return destination, errOrdinary
	}
	name, err := windows.UTF16PtrFromString(destination.path)
	if err != nil {
		return destination, errOrdinary
	}
	handle, err = windows.CreateFile(name, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, disposition, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if variant == "ads" {
			windowsAliasPreserveBase(w, source)
		}
		return destination, errOrdinary
	}
	destination.file = os.NewFile(uintptr(handle), destination.path)
	destination.stream = variant == "ads"
	state, stateErr := fileidentity.FromFile(destination.file)
	if stateErr != nil || state.Kind != fileidentity.Regular || state.ID != original.id {
		return destination, errOrdinary
	}
	if destination.stream {
		opened, err := windowsAliasOpenedPath(handle)
		if err != nil {
			return destination, errOrdinary
		}
		opened = strings.TrimSuffix(strings.ToLower(opened), ":$data")
		if !strings.EqualFold(opened, destination.path) {
			return destination, errOrdinary
		}
	}
	return destination, nil
}

func (destination *windowsAliasDestination) close() error {
	if destination == nil {
		return nil
	}
	var failure error
	// The checked stream handle remains open (with share-delete) while the
	// fixed exact stream name is removed; no default-stream delete is used.
	if destination.stream {
		valid := destination.file != nil
		if valid {
			state, err := fileidentity.FromFile(destination.file)
			opened, nameErr := windowsAliasOpenedPath(windows.Handle(destination.file.Fd()))
			opened = strings.TrimSuffix(strings.ToLower(opened), ":$data")
			valid = err == nil && nameErr == nil && state.Kind == fileidentity.Regular &&
				state.ID == destination.object.id && strings.EqualFold(opened, destination.path)
		}
		base, err := ordinarySameObject(ordinaryObject{path: destination.source, owner: destination.object.owner, id: destination.object.id}, windows.FILE_READ_ATTRIBUTES)
		if err != nil || !ordinaryClose(&base) {
			valid = false
		}
		if valid {
			name, _ := windows.UTF16PtrFromString(destination.path)
			if windows.DeleteFile(name) != nil {
				valid = false
			}
		}
		if !valid {
			windowsAliasPreserveBase(destination.worker, destination.source)
			failure = errOrdinary
		}
	}
	if destination.file != nil {
		if destination.file.Close() != nil {
			ordinaryCloseFailure = true
			failure = errOrdinary
		}
		destination.file = nil
	}
	if destination.stream {
		_, absence := fileidentity.FromPath(destination.path, false)
		if !errors.Is(absence, os.ErrNotExist) {
			windowsAliasPreserveBase(destination.worker, destination.source)
			failure = errOrdinary
		}
	}
	if destination.linked {
		handle, err := ordinarySameObject(destination.object, windows.DELETE)
		if err != nil {
			return errOrdinary
		}
		opened, nameErr := windowsAliasOpenedPath(handle)
		if nameErr != nil || !strings.EqualFold(opened, destination.path) {
			_ = ordinaryClose(&handle)
			return errOrdinary
		}
		remove := byte(1)
		removeErr := windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo, &remove, 1)
		closeOK := ordinaryClose(&handle)
		if removeErr != nil || !closeOK || destination.worker.forget(destination.path) != nil {
			return errOrdinary
		}
	}
	return failure
}

func windowsAliasInvoke(w *windowsCommandWorker, action string, stdout, stderr *os.File) ([]byte, []byte, error, bool) {
	if action != "ui" {
		out, notice, err := w.command(windowsAliasArguments(w, action), stdout, stderr)
		return out, notice, err, false
	}
	done := make(chan struct{})
	stopped := make(chan bool, 1)
	go func() {
		select {
		case <-done:
			stopped <- false
		case <-time.After(2 * time.Second):
			// A regressed alias guard must not leave a real UI listener alive.
			_ = windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, 0)
			stopped <- true
		}
	}()
	out, notice, err := w.command(windowsAliasArguments(w, action), stdout, stderr)
	close(done)
	return out, notice, err, <-stopped
}

func windowsAliasAttempt(w *windowsCommandWorker, action, source, variant string, role int, readonly bool) (failure error) {
	before := w.sources()
	if before == nil {
		return errOrdinary
	}
	original, err := windowsCommandReadSource(w, source)
	if err != nil {
		return errOrdinary
	}
	sourceState, err := fileidentity.FromPath(source, false)
	if err != nil || sourceState.Kind != fileidentity.Regular {
		return errOrdinary
	}
	destination, err := windowsAliasNew(w, source, variant, readonly)
	defer func() {
		if destination.close() != nil {
			failure = errOrdinary
		}
	}()
	if err != nil || destination == nil || destination.file == nil {
		return errOrdinary
	}
	var stdout, stderr *os.File
	if role == 0 {
		stdout = destination.file
	} else {
		stderr = destination.file
	}
	out, notice, commandErr, watchdog := windowsAliasInvoke(w, action, stdout, stderr)
	expected := errAuditOutputAlias
	switch action {
	case "import":
		expected = errAuditImportAdmission
	case "export-recorded":
		expected = audit.ErrExportDestination
	case "run":
		expected = errAuditRunOutput
	}
	if watchdog || !errors.Is(commandErr, expected) || len(out) != 0 || len(notice) != 0 ||
		!w.preserved(before) || w.recordProducts() != nil {
		return errOrdinary
	}
	current, err := windowsCommandReadSource(w, source)
	afterState, stateErr := fileidentity.FromPath(source, false)
	if err != nil || stateErr != nil || !bytes.Equal(original, current) ||
		afterState.Kind != sourceState.Kind || afterState.ID != sourceState.ID {
		return errOrdinary
	}
	entries, err := os.ReadDir(filepath.Join(w.state, "profiles"))
	if err != nil || len(entries) != 0 {
		return errOrdinary
	}
	return nil
}

func (w *windowsCommandWorker) aliasAdmission() error {
	child, err := w.newStream("aliases")
	if err != nil {
		return errOrdinary
	}
	deadline := time.Now().Add(35 * time.Second)
	common := []string{filepath.Join(child.base, "genesis.json"), filepath.Join(child.base, "head.json"),
		filepath.Join(child.directory, ".actor-key"), filepath.Join(child.directory, "events.journal")}
	for _, action := range []string{"import", "ui", "export-recorded", "run"} {
		sources := append([]string(nil), common...)
		roles := 2
		if action == "import" {
			roles = 1
		}
		if action == "import" || action == "run" {
			sources = append(sources, child.profilePath)
		}
		for _, source := range sources {
			for _, variant := range []string{"direct", "case", "hardlink", "ads"} {
				for role := 0; role < roles; role++ {
					if time.Now().After(deadline) || child.ctx.Err() != nil ||
						windowsAliasAttempt(child, action, source, variant, role, false) != nil {
						return errOrdinary
					}
				}
			}
		}
	}
	// The approved executable is administrator-owned/read-only to this child.
	// Its actual resolved identity is protected by run's second admission pass.
	for role := 0; role < 2; role++ {
		if windowsAliasAttempt(child, "run", child.engine, "direct", role, true) != nil {
			return errOrdinary
		}
	}
	for _, action := range []string{"ui", "export-recorded", "run"} {
		root := child.manifest()
		root.counter++
		path := filepath.Join(child.base, "pairwise-output-"+strconv.FormatUint(uint64(root.counter), 10)+".bin")
		if child.ownFile(path, nil) != nil {
			return errOrdinary
		}
		destination, err := windowsAliasNew(child, path, "direct", false)
		if err != nil {
			if destination != nil {
				_ = destination.close()
			}
			return errOrdinary
		}
		before := child.sources()
		out, notice, commandErr, watchdog := windowsAliasInvoke(child, action, destination.file, destination.file)
		closeErr := destination.close()
		content, readErr := windowsCommandReadDefault(path)
		expected := errAuditOutputAlias
		if action == "export-recorded" {
			expected = audit.ErrExportDestination
		} else if action == "run" {
			expected = errAuditRunOutput
		}
		if watchdog || closeErr != nil || readErr != nil || len(content) != 0 ||
			!errors.Is(commandErr, expected) || len(out) != 0 || len(notice) != 0 ||
			!child.preserved(before) || child.recordProducts() != nil {
			return errOrdinary
		}
	}
	return nil
}
