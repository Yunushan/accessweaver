//go:build darwin && (amd64 || arm64)

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"debug/macho"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
	"golang.org/x/sys/unix"
)

var errDarwinOrdinary = errors.New("ordinary Darwin audit fixture unavailable")

const darwinOrdinaryUID = 65534
const darwinOrdinaryWireLimit = 32 << 10
const darwinOrdinaryImageLimit = 128 << 20
const darwinOrdinaryWorkerArg = "--accessweaver-ordinary-darwin-worker"

type darwinOrdinaryCheck uint8

const (
	darwinOrdinaryCheckUnknown darwinOrdinaryCheck = iota
	darwinOrdinaryCheckHost
	darwinOrdinaryCheckSource
	darwinOrdinaryCheckAncestry
	darwinOrdinaryCheckStaging
	darwinOrdinaryCheckHome
	darwinOrdinaryCheckPreflight
	darwinOrdinaryCheckPolicyInstall
	darwinOrdinaryCheckPolicyBinding
	darwinOrdinaryCheckLaunch
	darwinOrdinaryCheckIPC
	darwinOrdinaryCheckGate
	darwinOrdinaryCheckDrain
	darwinOrdinaryCheckCleanup
)

func (check darwinOrdinaryCheck) label() string {
	switch check {
	case darwinOrdinaryCheckHost:
		return "host-context"
	case darwinOrdinaryCheckSource:
		return "source-binding"
	case darwinOrdinaryCheckAncestry:
		return "protected-ancestry"
	case darwinOrdinaryCheckStaging:
		return "protected-source-staging"
	case darwinOrdinaryCheckHome:
		return "private-home"
	case darwinOrdinaryCheckPreflight:
		return "policy-preflight"
	case darwinOrdinaryCheckPolicyInstall:
		return "required-policy-install"
	case darwinOrdinaryCheckPolicyBinding:
		return "required-policy-bindings"
	case darwinOrdinaryCheckLaunch:
		return "worker-launch"
	case darwinOrdinaryCheckIPC:
		return "worker-ipc"
	case darwinOrdinaryCheckGate:
		return "signal-lifetime-gate"
	case darwinOrdinaryCheckDrain:
		return "worker-drain"
	case darwinOrdinaryCheckCleanup:
		return "owned-cleanup"
	default:
		return "unknown-bootstrap"
	}
}

// Private inputs remain exclusively on inherited anonymous pipes. These are
// source-test controls, never a production backend or machine-authority selector.
type darwinOrdinaryRequest struct {
	Version           int
	Nonce             string
	SourceCommit      string
	TestImageSHA256   string
	WorkerImageSHA256 string
	WorkerPID         int
	GateDev           int64
	GateIno           uint64
	Stage             string
	Home              string
	State             string
	Workspace         string
	Engine            string
	Profile           profile.Profile
	HoldEngine        string
	HoldProfile       profile.Profile
}
type darwinOrdinaryReply struct {
	Version       int
	Nonce         string
	PID           int
	Executed      uint64
	Passed        uint64
	Identity      bool
	Home          bool
	Image         bool
	Backend       bool
	Lifecycle     bool
	Authenticated bool `json:"-"`
}

var darwinOrdinaryReady = make(chan os.Signal, 8)
var darwinOrdinaryHoldReady = make(chan os.Signal, 8)

func darwinOrdinaryDrainReady() {
	for {
		select {
		case <-darwinOrdinaryReady:
		case <-darwinOrdinaryHoldReady:
		default:
			return
		}
	}
}
func darwinOrdinaryWaitReady(ctx context.Context) bool {
	select {
	case <-darwinOrdinaryReady:
		return true
	case <-ctx.Done():
		return false
	}
}

func darwinOrdinaryWaitHoldReady(ctx context.Context) bool {
	select {
	case <-darwinOrdinaryHoldReady:
		return true
	case <-ctx.Done():
		return false
	}
}

// A fixture-only readiness notification carries no path, profile or key. The
// manager still owns the actual engine process/group and its sole Wait call.
func ordinaryDarwinInertEngine() (handled bool, exitCode int) {
	executable, err := os.Executable()
	if err != nil || filepath.Base(executable) != "ciadpi" {
		return false, 0
	}
	stage := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(executable))))
	name := filepath.Base(stage)
	if !strings.HasPrefix(name, "aw-audit-") || len(name) != len("aw-audit-")+32 {
		return false, 0
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(name, "aw-audit-")); err != nil {
		return true, 97
	}
	if len(os.Args) != 3 || os.Args[1] != "--ip" || os.Args[2] != "127.0.0.1" || os.Getuid() != darwinOrdinaryUID || os.Geteuid() != darwinOrdinaryUID {
		return true, 97
	}
	gate, err := darwinOrdinaryOpenGate(stage)
	if err != nil {
		return true, 97
	}
	defer func() {
		if gate.Close() != nil {
			handled, exitCode = true, 97
		}
	}()
	parentPID := os.Getppid()
	if parentPID <= 1 {
		return true, 97
	}
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(signals)
	hold := executable == filepath.Join(stage, "Hold.app", "Contents", "MacOS", "ciadpi")
	readySignal := syscall.SIGUSR1
	if hold {
		readySignal = syscall.SIGUSR2
	}
	if syscall.Kill(parentPID, readySignal) != nil {
		return true, 97
	}
	duration := 2 * time.Second
	if hold {
		duration = 30 * time.Second
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-signals:
		return true, 0
	case <-timer.C:
		if hold {
			return true, 97
		}
		return true, 0
	}
}

func darwinOrdinaryOpenGate(stage string) (file *os.File, failure error) {
	parent, err := darwintrust.OpenRootDirectory(stage)
	if err != nil {
		return nil, errDarwinOrdinary
	}
	defer func() {
		if parent.Close() != nil {
			if file != nil {
				file.Close()
			}
			file, failure = nil, errDarwinOrdinary
		}
	}()
	file, err = darwintrust.OpenRegularAt(parent, "lifetime.gate", 0)
	if err != nil {
		return nil, errDarwinOrdinary
	}
	info, err := file.Stat()
	if err != nil || info.Size() != 0 || info.Mode().Perm() != 0644 || info.Sys().(*syscall.Stat_t).Flags != 0 || darwintrust.CheckEmptyACL(file) != nil || unix.Flock(int(file.Fd()), unix.LOCK_SH|unix.LOCK_NB) != nil {
		file.Close()
		return nil, errDarwinOrdinary
	}
	return file, nil
}

var darwinOrdinaryRetainedGates []*os.File

type darwinOrdinaryDiscard struct {
	mu        sync.Mutex
	remaining int
	exceeded  bool
}

func (d *darwinOrdinaryDiscard) Write(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(data) > d.remaining {
		d.exceeded = true
		d.remaining = 0
	} else {
		d.remaining -= len(data)
	}
	return len(data), nil
}
func (d *darwinOrdinaryDiscard) clean() bool { d.mu.Lock(); defer d.mu.Unlock(); return !d.exceeded }

// Reject duplicate keys as well as unknown fields; DisallowUnknownFields alone
// does not reject repeated keys. The protocol has no arrays of unbounded data.
func darwinOrdinaryJSON(data []byte, output any) error {
	if len(data) == 0 || len(data) > darwinOrdinaryWireLimit {
		return errDarwinOrdinary
	}
	scan := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := scan.Token()
		if err != nil {
			return errDarwinOrdinary
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for scan.More() {
				key, err := scan.Token()
				name, ok := key.(string)
				if err != nil || !ok || keys[strings.ToLower(name)] {
					return errDarwinOrdinary
				}
				keys[strings.ToLower(name)] = true
				if walk() != nil {
					return errDarwinOrdinary
				}
			}
			token, err = scan.Token()
			if err != nil || token != json.Delim('}') {
				return errDarwinOrdinary
			}
		case '[':
			for scan.More() {
				if walk() != nil {
					return errDarwinOrdinary
				}
			}
			token, err = scan.Token()
			if err != nil || token != json.Delim(']') {
				return errDarwinOrdinary
			}
		default:
			return errDarwinOrdinary
		}
		return nil
	}
	if walk() != nil {
		return errDarwinOrdinary
	}
	if _, err := scan.Token(); !errors.Is(err, io.EOF) {
		return errDarwinOrdinary
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(output) != nil {
		return errDarwinOrdinary
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errDarwinOrdinary
	}
	return nil
}
func darwinOrdinaryReadWire(file *os.File, output any, budget time.Duration) error {
	if file.SetReadDeadline(time.Now().Add(budget)) != nil {
		return errDarwinOrdinary
	}
	data, err := io.ReadAll(io.LimitReader(file, darwinOrdinaryWireLimit+1))
	defer clear(data)
	if err != nil {
		return errDarwinOrdinary
	}
	return darwinOrdinaryJSON(data, output)
}
func darwinOrdinaryWriteWire(file *os.File, value any) error {
	data, err := json.Marshal(value)
	defer clear(data)
	if err != nil || len(data) > darwinOrdinaryWireLimit || file.SetWriteDeadline(time.Now().Add(10*time.Second)) != nil {
		return errDarwinOrdinary
	}
	n, err := file.Write(data)
	if err != nil || n != len(data) {
		return errDarwinOrdinary
	}
	return nil
}
func darwinOrdinaryCredentials() bool {
	groups, err := os.Getgroups()
	return err == nil && len(groups) == 1 && groups[0] == darwinOrdinaryUID && os.Getuid() == darwinOrdinaryUID && os.Geteuid() == darwinOrdinaryUID && os.Getgid() == darwinOrdinaryUID && os.Getegid() == darwinOrdinaryUID
}
func darwinOrdinaryHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value) && value != strings.Repeat("0", 64)
}
func darwinOrdinaryCanonical(path string) bool {
	return len(path) > 0 && len(path) <= 1023 && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path, 0)
}

func darwinOrdinaryRead(path string, limit int64) (data []byte, failure error) {
	if !darwinOrdinaryCanonical(path) || limit <= 0 {
		return nil, errDarwinOrdinary
	}
	var before unix.Stat_t
	if unix.Lstat(path, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Flags != 0 {
		return nil, errDarwinOrdinary
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errDarwinOrdinary
	}
	file := os.NewFile(uintptr(fd), "ordinary-read")
	defer func() {
		if file.Close() != nil {
			clear(data)
			data, failure = nil, errDarwinOrdinary
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errDarwinOrdinary
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Dev) != int64(before.Dev) || stat.Ino != before.Ino || darwintrust.CheckReadOnlyACL(file) != nil {
		return nil, errDarwinOrdinary
	}
	data, err = io.ReadAll(io.LimitReader(file, limit+1))
	after, statErr := file.Stat()
	var named unix.Stat_t
	if err != nil || int64(len(data)) > limit || statErr != nil || unix.Lstat(path, &named) != nil || !darwinOrdinarySameInfo(info, after) || int64(named.Dev) != int64(stat.Dev) || named.Ino != stat.Ino || named.Flags != stat.Flags {
		clear(data)
		return nil, errDarwinOrdinary
	}
	return data, nil
}
func darwinOrdinarySameInfo(a, b os.FileInfo) bool {
	if a == nil || b == nil || !os.SameFile(a, b) || a.Mode() != b.Mode() || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	x, ok := a.Sys().(*syscall.Stat_t)
	y, other := b.Sys().(*syscall.Stat_t)
	return ok && other && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Flags == y.Flags && x.Ctimespec == y.Ctimespec
}
func darwinOrdinaryImage(path string) (string, error) {
	data, err := darwinOrdinaryRead(path, darwinOrdinaryImageLimit)
	if err != nil {
		return "", err
	}
	defer clear(data)
	image, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return "", errDarwinOrdinary
	}
	expected := macho.CpuAmd64
	if runtime.GOARCH == "arm64" {
		expected = macho.CpuArm64
	}
	if image.Cpu != expected || image.Type != macho.TypeExec || image.Close() != nil {
		return "", errDarwinOrdinary
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}
func darwinOrdinaryPrivate(path string, directory bool, owner uint32) (os.FileInfo, error) {
	if !darwinOrdinaryCanonical(path) {
		return nil, errDarwinOrdinary
	}
	var before unix.Stat_t
	if unix.Lstat(path, &before) != nil || before.Uid != owner || before.Flags != 0 {
		return nil, errDarwinOrdinary
	}
	if directory {
		if before.Mode&unix.S_IFMT != unix.S_IFDIR || before.Mode&07777 != 0700 {
			return nil, errDarwinOrdinary
		}
	} else {
		if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Mode&07777 != 0600 {
			return nil, errDarwinOrdinary
		}
	}
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, errDarwinOrdinary
	}
	file := os.NewFile(uintptr(fd), "ordinary-private")
	info, err := darwintrust.Check(file, directory, owner)
	if err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		mode := os.FileMode(0600)
		if directory {
			mode = 0700
		}
		if !ok || stat.Flags != 0 || info.Mode().Perm() != mode || darwintrust.CheckEmptyACL(file) != nil {
			err = errDarwinOrdinary
		}
	}
	if err == nil {
		stat := info.Sys().(*syscall.Stat_t)
		var after unix.Stat_t
		var fs unix.Statfs_t
		if int64(stat.Dev) != int64(before.Dev) || stat.Ino != before.Ino || unix.Lstat(path, &after) != nil || int64(after.Dev) != int64(stat.Dev) || after.Ino != stat.Ino || unix.Fstatfs(int(file.Fd()), &fs) != nil || fs.Flags&unix.MNT_AUTOMOUNTED != 0 {
			err = errDarwinOrdinary
		}
	}
	if file.Close() != nil {
		err = errDarwinOrdinary
	}
	if err != nil {
		return nil, errDarwinOrdinary
	}
	return info, nil
}

func ordinaryDarwinWorker() int {
	for descriptor, direction := range map[int]int{3: unix.O_RDONLY, 4: unix.O_WRONLY} {
		var stat unix.Stat_t
		flags, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFL, 0)
		if unix.Fstat(descriptor, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFIFO || err != nil || flags&unix.O_ACCMODE != direction || unix.SetNonblock(descriptor, true) != nil {
			return 91
		}
	}
	requestFile := os.NewFile(3, "ordinary-request")
	replyFile := os.NewFile(4, "ordinary-reply")
	var request darwinOrdinaryRequest
	if requestFile == nil || replyFile == nil || darwinOrdinaryReadWire(requestFile, &request, 15*time.Second) != nil || requestFile.Close() != nil {
		return 91
	}
	reply := darwinOrdinaryReply{Version: 1, Nonce: request.Nonce, PID: os.Getpid()}
	valid := request.Version == 1 && len(request.Nonce) == 32 && request.WorkerPID == os.Getpid() && len(request.SourceCommit) == 40 && darwinOrdinaryHash(request.TestImageSHA256) && request.TestImageSHA256 == request.WorkerImageSHA256
	nonce, err := hex.DecodeString(request.Nonce)
	clear(nonce)
	valid = valid && err == nil && filepath.Dir(request.Stage) == "/Library/Preferences" && filepath.Base(request.Stage) == "aw-audit-"+request.Nonce
	for _, path := range []string{request.Stage, request.Home, request.State, request.Workspace, request.Engine, request.HoldEngine} {
		valid = valid && darwinOrdinaryCanonical(path)
	}
	valid = valid && request.Home == filepath.Join(request.Stage, "home") && request.State == filepath.Join(request.Home, "state") && request.Workspace == filepath.Join(request.Home, "work") && request.Engine == filepath.Join(request.Stage, "Approved.app", "Contents", "MacOS", "ciadpi") && request.HoldEngine == filepath.Join(request.Stage, "Hold.app", "Contents", "MacOS", "ciadpi")
	linked := buildinfo.Current()
	valid = valid && linked.Commit == request.SourceCommit && linked.SourceState == "clean" && linked.Platform == "darwin" && linked.Arch == runtime.GOARCH
	reply.Identity = valid && darwinOrdinaryCredentials()
	if reply.Identity {
		_, homeErr := darwinOrdinaryPrivate(request.Home, true, darwinOrdinaryUID)
		_, stateErr := darwinOrdinaryPrivate(request.State, true, darwinOrdinaryUID)
		_, cacheErr := darwinOrdinaryPrivate(filepath.Join(request.Home, "Library", "Caches"), true, darwinOrdinaryUID)
		reply.Home = homeErr == nil && stateErr == nil && cacheErr == nil
		executable, imageErr := os.Executable()
		hash, hashErr := darwinOrdinaryImage(executable)
		engineHash, engineErr := darwinOrdinaryImage(request.Engine)
		holdHash, holdErr := darwinOrdinaryImage(request.HoldEngine)
		reply.Image = imageErr == nil && hashErr == nil && engineErr == nil && hash == request.TestImageSHA256 && engineHash == hash && holdErr == nil && holdHash == hash && executable == filepath.Join(request.Stage, "ordinary-worker")
		reply.Backend = audit.LocalRecordingSupported()
	}
	var lifetime *os.File
	if reply.Identity && reply.Home && reply.Image && reply.Backend {
		lifetime, err = darwinOrdinaryOpenGate(request.Stage)
		if err == nil {
			info, statErr := lifetime.Stat()
			if statErr == nil {
				st := info.Sys().(*syscall.Stat_t)
				reply.Lifecycle = int64(st.Dev) == request.GateDev && st.Ino == request.GateIno
			}
		}
	}
	if reply.Identity && reply.Home && reply.Image && reply.Backend && reply.Lifecycle {
		valid = os.Setenv("HOME", request.Home) == nil && os.Setenv("ACCESSWEAVER_HOME", request.State) == nil && os.Setenv("ACCESSWEAVER_NO_BROWSER", "1") == nil
		if valid {
			terminalGuard := make(chan os.Signal, 8)
			signal.Notify(terminalGuard, syscall.SIGTERM, os.Interrupt)
			defer signal.Stop(terminalGuard)
			signal.Notify(darwinOrdinaryReady, syscall.SIGUSR1)
			defer signal.Stop(darwinOrdinaryReady)
			signal.Notify(darwinOrdinaryHoldReady, syscall.SIGUSR2)
			defer signal.Stop(darwinOrdinaryHoldReady)
			reply.Executed, reply.Passed = runDarwinCommandCases(request)
		}
	}
	if lifetime != nil && lifetime.Close() != nil {
		reply.Lifecycle = false
	}
	writeErr := darwinOrdinaryWriteWire(replyFile, reply)
	closeErr := replyFile.Close()
	mask := uint64(1)<<uint(len(darwinCommandCaseIDs)) - 1
	if writeErr != nil || closeErr != nil || !reply.Identity || !reply.Home || !reply.Image || !reply.Backend || !reply.Lifecycle || reply.Executed != mask || reply.Passed != mask {
		return 92
	}
	return 0
}

type darwinOrdinaryScope struct {
	files []*os.File
	names []string
	infos []os.FileInfo
}

func openDarwinOrdinaryScope() (*darwinOrdinaryScope, error) {
	scope := &darwinOrdinaryScope{}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errDarwinOrdinary
	}
	scope.files = append(scope.files, os.NewFile(uintptr(fd), "/"))
	scope.names = append(scope.names, "")
	for _, name := range []string{"Library", "Preferences"} {
		next, err := darwintrust.OpenDirectoryAt(scope.files[len(scope.files)-1], name, 0)
		if err != nil {
			scope.close()
			return nil, errDarwinOrdinary
		}
		scope.files = append(scope.files, next)
		scope.names = append(scope.names, name)
	}
	for _, file := range scope.files {
		info, err := darwintrust.Check(file, true, 0)
		if err != nil {
			scope.close()
			return nil, errDarwinOrdinary
		}
		scope.infos = append(scope.infos, info)
	}
	if scope.check() != nil {
		scope.close()
		return nil, errDarwinOrdinary
	}
	return scope, nil
}
func (s *darwinOrdinaryScope) check() error {
	for i, file := range s.files {
		info, err := darwintrust.Check(file, true, 0)
		if err != nil || !darwinOrdinaryTrustInfo(s.infos[i], info) {
			return errDarwinOrdinary
		}
		stat := info.Sys().(*syscall.Stat_t)
		const allowed = unix.UF_NODUMP | unix.UF_HIDDEN | unix.SF_RESTRICTED | unix.SF_FIRMLINK | unix.SF_NOUNLINK
		if stat.Flags & ^uint32(allowed) != 0 || stat.Flags&unix.SF_FIRMLINK != 0 && stat.Uid != 0 {
			return errDarwinOrdinary
		}
		var fs unix.Statfs_t
		if unix.Fstatfs(int(file.Fd()), &fs) != nil || fs.Flags&unix.MNT_AUTOMOUNTED != 0 {
			return errDarwinOrdinary
		}
		if i > 0 {
			var named unix.Stat_t
			stat := info.Sys().(*syscall.Stat_t)
			if unix.Fstatat(int(s.files[i-1].Fd()), s.names[i], &named, unix.AT_SYMLINK_NOFOLLOW) != nil || int64(named.Dev) != int64(stat.Dev) || named.Ino != stat.Ino {
				return errDarwinOrdinary
			}
		}
	}
	return nil
}
func darwinOrdinaryTrustInfo(a, b os.FileInfo) bool {
	if a == nil || b == nil || !os.SameFile(a, b) || a.Mode() != b.Mode() {
		return false
	}
	x, ok := a.Sys().(*syscall.Stat_t)
	y, other := b.Sys().(*syscall.Stat_t)
	return ok && other && x.Uid == y.Uid && x.Gid == y.Gid && x.Flags == y.Flags
}
func (s *darwinOrdinaryScope) close() error {
	var result error
	for i := len(s.files) - 1; i >= 0; i-- {
		if s.files[i].Close() != nil {
			result = errDarwinOrdinary
		}
	}
	return result
}

type darwinOrdinaryOwned struct {
	parent *os.File
	name   string
	info   os.FileInfo
	held   *os.File
	digest string
}
type ordinaryDarwinFixture struct {
	scope      *darwinOrdinaryScope
	owned      []darwinOrdinaryOwned
	request    darwinOrdinaryRequest
	preserve   bool
	gate       *os.File
	retainGate bool
	phase      darwinOrdinaryCheck
}

func (f *ordinaryDarwinFixture) parent() *os.File { return f.scope.files[len(f.scope.files)-1] }
func (f *ordinaryDarwinFixture) remember(parent *os.File, name string, held *os.File) error {
	info, err := held.Stat()
	if err != nil {
		return errDarwinOrdinary
	}
	var named unix.Stat_t
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || unix.Fstatat(int(parent.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || int64(named.Dev) != int64(stat.Dev) || named.Ino != stat.Ino {
		return errDarwinOrdinary
	}
	digest := ""
	if info.Mode().IsRegular() {
		flags, err := unix.FcntlInt(held.Fd(), unix.F_GETFL, 0)
		if err != nil {
			return errDarwinOrdinary
		}
		if flags&unix.O_ACCMODE != unix.O_WRONLY {
			digest, err = darwinOrdinaryHeldHash(held)
			if err != nil {
				return errDarwinOrdinary
			}
		}
	}
	if stat.Flags != 0 || darwintrust.CheckEmptyACL(held) != nil {
		return errDarwinOrdinary
	}
	f.owned = append(f.owned, darwinOrdinaryOwned{parent: parent, name: name, info: info, held: held, digest: digest})
	return nil
}
func darwinOrdinaryHeldHash(file *os.File) (string, error) {
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > darwinOrdinaryImageLimit {
		return "", errDarwinOrdinary
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.NewSectionReader(file, 0, before.Size()))
	after, statErr := file.Stat()
	if err != nil || count != before.Size() || statErr != nil || !darwinOrdinarySameInfo(before, after) {
		return "", errDarwinOrdinary
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func (f *ordinaryDarwinFixture) freezeCapture(parent *os.File, name string) error {
	index := len(f.owned) - 1
	if index < 0 || f.owned[index].parent != parent || f.owned[index].name != name {
		return errDarwinOrdinary
	}
	before, err := f.owned[index].held.Stat()
	if err != nil {
		return errDarwinOrdinary
	}
	if f.owned[index].held.Close() != nil {
		return errDarwinOrdinary
	}
	reader, err := darwintrust.OpenRegularAt(parent, name, 0)
	if err != nil {
		return errDarwinOrdinary
	}
	after, err := reader.Stat()
	if err != nil || !os.SameFile(before, after) {
		reader.Close()
		return errDarwinOrdinary
	}
	digest, err := darwinOrdinaryHeldHash(reader)
	if err != nil {
		reader.Close()
		return errDarwinOrdinary
	}
	f.owned[index].held, f.owned[index].info, f.owned[index].digest = reader, after, digest
	return nil
}
func (f *ordinaryDarwinFixture) authorityAbsent() error {
	if !f.absent("AccessWeaver") || !f.absent(".accessweaver-policy.lock") {
		return errDarwinOrdinary
	}
	fd, err := unix.Openat(int(f.parent().Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errDarwinOrdinary
	}
	directory := os.NewFile(uintptr(fd), "ordinary-authority-inventory")
	before, statErr := f.parent().Stat()
	opened, openErr := directory.Stat()
	if statErr != nil || openErr != nil || !os.SameFile(before, opened) {
		directory.Close()
		return errDarwinOrdinary
	}
	entries, readErr := directory.ReadDir(513)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) > 512 {
		return errDarwinOrdinary
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".accessweaver-policy-stage-") {
			return errDarwinOrdinary
		}
	}
	return nil
}

func (f *ordinaryDarwinFixture) mkdir(parent *os.File, name string, owner uint32, mode os.FileMode) (*os.File, error) {
	if f.scope.check() != nil {
		return nil, errDarwinOrdinary
	}
	file, err := darwintrust.CreateDirectoryAt(parent, name, 0)
	if err != nil {
		return nil, errDarwinOrdinary
	}
	if owner != 0 {
		err = file.Chown(int(owner), int(owner))
	}
	if err == nil {
		err = file.Chmod(mode)
	}
	if err == nil {
		_, err = darwintrust.Check(file, true, owner)
	}
	if err == nil {
		err = darwintrust.CheckEmptyACL(file)
	}
	if err == nil {
		err = f.remember(parent, name, file)
	}
	if err != nil {
		file.Close()
		return nil, errDarwinOrdinary
	}
	return file, nil
}
func (f *ordinaryDarwinFixture) create(parent *os.File, name string, data []byte, mode os.FileMode) error {
	writer, err := darwintrust.CreateRegularAt(parent, name, 0)
	if err != nil {
		return errDarwinOrdinary
	}
	before, statErr := writer.Stat()
	n, writeErr := writer.Write(data)
	modeErr := writer.Chmod(mode)
	closeErr := writer.Close()
	if statErr != nil || writeErr != nil || n != len(data) || modeErr != nil || closeErr != nil {
		return errDarwinOrdinary
	}
	// Executable staging never retains a writable descriptor across exec.
	reader, err := darwintrust.OpenRegularAt(parent, name, 0)
	if err != nil {
		return errDarwinOrdinary
	}
	after, statErr := reader.Stat()
	if statErr != nil || !os.SameFile(before, after) || darwintrust.CheckEmptyACL(reader) != nil {
		reader.Close()
		return errDarwinOrdinary
	}
	if f.remember(parent, name, reader) != nil {
		reader.Close()
		return errDarwinOrdinary
	}
	return nil
}

func (f *ordinaryDarwinFixture) absent(name string) bool {
	var st unix.Stat_t
	return errors.Is(unix.Fstatat(int(f.parent().Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT)
}
func (f *ordinaryDarwinFixture) enroll(stage *os.File) error {
	f.phase = darwinOrdinaryCheckPreflight
	if f.authorityAbsent() != nil {
		return errDarwinOrdinary
	}
	f.phase = darwinOrdinaryCheckPolicyInstall
	p := f.request.Profile
	input, err := p.ExecutionDigest()
	if err != nil {
		return errDarwinOrdinary
	}
	now := time.Now().UTC()
	holdInput, err := f.request.HoldProfile.ExecutionDigest()
	if err != nil {
		return errDarwinOrdinary
	}
	policy := managed.Policy{SchemaVersion: 1, Revision: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), AllowProfileChanges: true, RequireProfileAudit: true, Launches: []managed.LaunchRule{{Engine: p.Engine, InputSHA256: input, BinarySHA256: f.request.TestImageSHA256}, {Engine: p.Engine, InputSHA256: holdInput, BinarySHA256: f.request.TestImageSHA256}}}
	payload, err := json.Marshal(policy)
	if err != nil {
		return errDarwinOrdinary
	}
	defer clear(payload)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errDarwinOrdinary
	}
	defer clear(private)
	envelope, err := managed.Sign(payload, private, now)
	if err != nil {
		return errDarwinOrdinary
	}
	defer clear(envelope)
	installation, err := managed.PrepareInstallation(envelope, public, now, 0)
	if err != nil {
		return errDarwinOrdinary
	}
	defer clear(installation)
	if f.create(stage, "installation.json", installation, 0600) != nil {
		return errDarwinOrdinary
	}
	capture, err := darwintrust.CreateRegularAt(stage, "setup-output", 0)
	if err != nil {
		return errDarwinOrdinary
	}
	if f.remember(stage, "setup-output", capture) != nil {
		capture.Close()
		return errDarwinOrdinary
	}
	previousOut, previousErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = capture, capture
	f.preserve = true // An interrupted/partial install must never be guessed away.
	callErr := execute([]string{"managed", "install", filepath.Join(f.request.Stage, "installation.json"), "--public-key", base64.StdEncoding.EncodeToString(public)})
	os.Stdout, os.Stderr = previousOut, previousErr
	info, statErr := capture.Stat()
	if callErr != nil || statErr != nil || info.Size() > 32<<10 {
		return errDarwinOrdinary
	}
	// Created files were opened write-only: read with a distinct checked descriptor.
	data, err := darwinOrdinaryRead(filepath.Join(f.request.Stage, "setup-output"), 32<<10)
	if err != nil {
		return errDarwinOrdinary
	}
	defer clear(data)
	if f.freezeCapture(stage, "setup-output") != nil {
		return errDarwinOrdinary
	}
	var result managed.InstallResult
	if json.Unmarshal(data, &result) != nil || !result.Committed {
		return errDarwinOrdinary
	}
	f.phase = darwinOrdinaryCheckPolicyBinding
	policyDir, err := darwintrust.OpenDirectoryAt(f.parent(), "AccessWeaver", 0)
	if err != nil {
		return errDarwinOrdinary
	}
	if f.remember(f.parent(), "AccessWeaver", policyDir) != nil {
		policyDir.Close()
		return errDarwinOrdinary
	}
	for _, name := range []string{"installation.json", "acceptance.json"} {
		file, err := darwintrust.OpenRegularAt(policyDir, name, 0)
		if err != nil {
			return errDarwinOrdinary
		}
		if f.remember(policyDir, name, file) != nil {
			file.Close()
			return errDarwinOrdinary
		}
	}
	lock, err := darwintrust.OpenRegularAt(f.parent(), ".accessweaver-policy.lock", 0)
	if err != nil {
		return errDarwinOrdinary
	}
	if f.remember(f.parent(), ".accessweaver-policy.lock", lock) != nil {
		lock.Close()
		return errDarwinOrdinary
	}
	status, err := managed.MachineStatus()
	if err != nil || !status.Valid || status.Revision != 1 || status.KeyID != managed.KeyID(public) {
		return errDarwinOrdinary
	}
	return nil
}

func newOrdinaryDarwinFixture() (*ordinaryDarwinFixture, error) {
	f := &ordinaryDarwinFixture{phase: darwinOrdinaryCheckAncestry}
	scope, err := openDarwinOrdinaryScope()
	if err != nil {
		return f, err
	}
	f.scope = scope
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return f, errDarwinOrdinary
	}
	f.request = darwinOrdinaryRequest{Version: 1, Nonce: hex.EncodeToString(nonce), SourceCommit: buildinfo.Current().Commit}
	clear(nonce)
	f.request.Stage = filepath.Join("/Library/Preferences", "aw-audit-"+f.request.Nonce)
	f.phase = darwinOrdinaryCheckPreflight
	// Refuse authority before creating any fixture, including reserved partial stages.
	if f.authorityAbsent() != nil {
		return f, errDarwinOrdinary
	}
	f.phase = darwinOrdinaryCheckStaging
	stage, err := f.mkdir(f.parent(), filepath.Base(f.request.Stage), 0, 0755)
	if err != nil {
		return f, err
	}
	executable, err := os.Executable()
	if err != nil {
		return f, errDarwinOrdinary
	}
	bytes, err := darwinOrdinaryRead(executable, darwinOrdinaryImageLimit)
	if err != nil {
		return f, err
	}
	defer clear(bytes)
	digest, err := darwinOrdinaryImage(executable)
	if err != nil {
		return f, err
	}
	f.request.TestImageSHA256, f.request.WorkerImageSHA256 = digest, digest
	if f.create(stage, "ordinary-worker", bytes, 0755) != nil {
		return f, errDarwinOrdinary
	}
	app, err := f.mkdir(stage, "Approved.app", 0, 0755)
	if err != nil {
		return f, err
	}
	contents, err := f.mkdir(app, "Contents", 0, 0755)
	if err != nil {
		return f, err
	}
	macos, err := f.mkdir(contents, "MacOS", 0, 0755)
	if err != nil {
		return f, err
	}
	if f.create(macos, "ciadpi", bytes, 0755) != nil {
		return f, errDarwinOrdinary
	}
	holdApp, err := f.mkdir(stage, "Hold.app", 0, 0755)
	if err != nil {
		return f, err
	}
	holdContents, err := f.mkdir(holdApp, "Contents", 0, 0755)
	if err != nil {
		return f, err
	}
	holdMacOS, err := f.mkdir(holdContents, "MacOS", 0, 0755)
	if err != nil {
		return f, err
	}
	if f.create(holdMacOS, "ciadpi", bytes, 0755) != nil {
		return f, errDarwinOrdinary
	}
	if f.create(stage, "lifetime.gate", nil, 0644) != nil {
		return f, errDarwinOrdinary
	}
	f.gate = f.owned[len(f.owned)-1].held
	gateInfo, err := f.gate.Stat()
	if err != nil {
		return f, errDarwinOrdinary
	}
	gateStat := gateInfo.Sys().(*syscall.Stat_t)
	f.request.GateDev = int64(gateStat.Dev)
	f.request.GateIno = gateStat.Ino
	f.request.Engine = filepath.Join(f.request.Stage, "Approved.app", "Contents", "MacOS", "ciadpi")
	f.request.HoldEngine = filepath.Join(f.request.Stage, "Hold.app", "Contents", "MacOS", "ciadpi")
	f.phase = darwinOrdinaryCheckHome
	home, err := f.mkdir(stage, "home", darwinOrdinaryUID, 0700)
	if err != nil {
		return f, err
	}
	f.request.Home = filepath.Join(f.request.Stage, "home")
	f.request.State = filepath.Join(f.request.Home, "state")
	f.request.Workspace = filepath.Join(f.request.Home, "work")
	if _, err := f.mkdir(home, "state", darwinOrdinaryUID, 0700); err != nil {
		return f, err
	}
	library, err := f.mkdir(home, "Library", darwinOrdinaryUID, 0700)
	if err != nil {
		return f, err
	}
	if _, err := f.mkdir(library, "Caches", darwinOrdinaryUID, 0700); err != nil {
		return f, err
	}
	p := profile.New("darwin-audit-fixture", "Approved Darwin audit fixture", "byedpi")
	p.Binary = f.request.Engine
	p.Probe.Host = "127.0.0.1"
	f.request.Profile = p
	f.request.HoldProfile = p
	f.request.HoldProfile.Binary = f.request.HoldEngine
	if f.enroll(stage) != nil {
		return f, errDarwinOrdinary
	}
	return f, nil
}
func (f *ordinaryDarwinFixture) checkOwned() error {
	if f.scope.check() != nil {
		return errDarwinOrdinary
	}
	for _, owned := range f.owned {
		info, err := owned.held.Stat()
		if err != nil || !darwinOrdinaryTrustInfo(owned.info, info) {
			return errDarwinOrdinary
		}
		stat := info.Sys().(*syscall.Stat_t)
		var named unix.Stat_t
		if unix.Fstatat(int(owned.parent.Fd()), owned.name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || int64(named.Dev) != int64(stat.Dev) || named.Ino != stat.Ino || named.Uid != stat.Uid || named.Gid != stat.Gid || named.Flags != stat.Flags {
			return errDarwinOrdinary
		}
		if darwintrust.CheckEmptyACL(owned.held) != nil {
			return errDarwinOrdinary
		}
		if info.Mode().IsRegular() {
			digest, err := darwinOrdinaryHeldHash(owned.held)
			if err != nil || owned.digest == "" || digest != owned.digest || !darwinOrdinarySameInfo(owned.info, info) {
				return errDarwinOrdinary
			}
		}
	}
	return nil
}
func (f *ordinaryDarwinFixture) close() error {
	if f == nil || f.scope == nil {
		return nil
	}
	result := error(nil)
	safe := !f.preserve && f.checkOwned() == nil
	if !safe {
		result = errDarwinOrdinary
	}
	for i := len(f.owned) - 1; i >= 0; i-- {
		owned := f.owned[i]
		if safe {
			var named unix.Stat_t
			stat := owned.info.Sys().(*syscall.Stat_t)
			if unix.Fstatat(int(owned.parent.Fd()), owned.name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || int64(named.Dev) != int64(stat.Dev) || named.Ino != stat.Ino {
				safe = false
				result = errDarwinOrdinary
			} else {
				flags := 0
				if owned.info.IsDir() {
					flags = unix.AT_REMOVEDIR
				}
				if unix.Unlinkat(int(owned.parent.Fd()), owned.name, flags) != nil {
					safe = false
					result = errDarwinOrdinary
				}
			}
		}
		if owned.held == f.gate && f.retainGate {
			darwinOrdinaryRetainedGates = append(darwinOrdinaryRetainedGates, owned.held)
			continue
		}
		if owned.held.Close() != nil {
			result = errDarwinOrdinary
		}
	}
	if f.scope.close() != nil {
		result = errDarwinOrdinary
	}
	return result
}
func (f *ordinaryDarwinFixture) run() (reply darwinOrdinaryReply, failure error) {
	f.phase = darwinOrdinaryCheckStaging
	if f.checkOwned() != nil {
		return reply, errDarwinOrdinary
	}
	workerHash, workerErr := darwinOrdinaryImage(filepath.Join(f.request.Stage, "ordinary-worker"))
	engineHash, engineErr := darwinOrdinaryImage(f.request.Engine)
	holdHash, holdErr := darwinOrdinaryImage(f.request.HoldEngine)
	if workerErr != nil || engineErr != nil || workerHash != f.request.TestImageSHA256 || engineHash != workerHash || holdErr != nil || holdHash != workerHash {
		return reply, errDarwinOrdinary
	}
	requestRead, requestWrite, err := os.Pipe()
	if err != nil {
		return reply, errDarwinOrdinary
	}
	replyRead, replyWrite, err := os.Pipe()
	if err != nil {
		requestRead.Close()
		requestWrite.Close()
		return reply, errDarwinOrdinary
	}
	closeAll := func() error {
		var result error
		for _, file := range []*os.File{requestRead, requestWrite, replyRead, replyWrite} {
			if file != nil && file.Close() != nil {
				result = errDarwinOrdinary
			}
		}
		return result
	}
	f.phase = darwinOrdinaryCheckLaunch
	child := exec.Command(filepath.Join(f.request.Stage, "ordinary-worker"), darwinOrdinaryWorkerArg)
	child.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", "TZ=UTC"}
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: darwinOrdinaryUID, Gid: darwinOrdinaryUID, Groups: []uint32{}}, Setpgid: true}
	child.ExtraFiles = []*os.File{requestRead, replyWrite}
	stdout, stderr := &darwinOrdinaryDiscard{remaining: 1 << 20}, &darwinOrdinaryDiscard{remaining: 1 << 20}
	child.Stdout, child.Stderr = stdout, stderr
	if child.Start() != nil {
		closeAll()
		return reply, errDarwinOrdinary
	}
	f.phase = darwinOrdinaryCheckIPC
	f.request.WorkerPID = child.Process.Pid
	endpointErr := requestRead.Close()
	if replyWrite.Close() != nil {
		endpointErr = errDarwinOrdinary
	}
	writeErr := darwinOrdinaryWriteWire(requestWrite, f.request)
	if requestWrite.Close() != nil {
		writeErr = errDarwinOrdinary
	}
	readErr := darwinOrdinaryReadWire(replyRead, &reply, 125*time.Second)
	if replyRead.Close() != nil {
		readErr = errDarwinOrdinary
	}
	mask := uint64(1)<<uint(len(darwinCommandCaseIDs)) - 1
	validReply := reply.Version == 1 && reply.Nonce == f.request.Nonce && reply.PID == f.request.WorkerPID && reply.Executed & ^mask == 0 && reply.Passed & ^reply.Executed == 0
	if writeErr != nil || readErr != nil || endpointErr != nil || !validReply {
		// Kill is issued before the sole Wait begins; no released/reused PID race.
		_ = child.Process.Kill()
		if f.holdGateExclusive() == nil {
			_ = f.waitChild(child)
		}
		return reply, errDarwinOrdinary
	}
	reply.Authenticated = true
	f.phase = darwinOrdinaryCheckGate
	if f.holdGateExclusive() != nil {
		return reply, errDarwinOrdinary
	}
	f.phase = darwinOrdinaryCheckDrain
	waitErr := f.waitChild(child)
	if waitErr != nil || !stdout.clean() || !stderr.clean() || reply.Version != 1 || reply.Nonce != f.request.Nonce || reply.PID != f.request.WorkerPID || !reply.Identity || !reply.Home || !reply.Image || !reply.Backend || !reply.Lifecycle || reply.Executed != mask || reply.Passed != mask || f.checkOwned() != nil {
		return reply, errDarwinOrdinary
	}
	f.preserve = false
	return reply, nil
}

func (f *ordinaryDarwinFixture) holdGateExclusive() error {
	if f.gate == nil || f.scope.check() != nil {
		return errDarwinOrdinary
	}
	info, err := f.gate.Stat()
	if err != nil {
		return errDarwinOrdinary
	}
	stat := info.Sys().(*syscall.Stat_t)
	if int64(stat.Dev) != f.request.GateDev || stat.Ino != f.request.GateIno || info.Size() != 0 || info.Mode().Perm() != 0644 || stat.Uid != 0 || stat.Flags != 0 || darwintrust.CheckEmptyACL(f.gate) != nil {
		return errDarwinOrdinary
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		err := unix.Flock(int(f.gate.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return errDarwinOrdinary
		}
		select {
		case <-deadline.C:
			return errDarwinOrdinary
		case <-tick.C:
		}
	}
}
func (f *ordinaryDarwinFixture) waitChild(child *exec.Cmd) error {
	f.retainGate = true
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		f.retainGate = false
		return err
	case <-timer.C:
		return errDarwinOrdinary
	}
}

func TestDisposableDarwinAuditCommands(t *testing.T) {
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_DARWIN_AUDIT_COMMANDS_TEST") != "1" {
		t.Skip("disposable ordinary Darwin audit source fixture only")
	}
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_DARWIN_POLICY_TEST") != "1" {
		t.Fatalf("ordinary Darwin audit bootstrap failed: %s", darwinOrdinaryCheckHost.label())
	}
	darwinNativeContext(t)
	linked := buildinfo.Current()
	expected := os.Getenv("GITHUB_SHA")
	arch := map[string]string{"amd64": "X64", "arm64": "ARM64"}[runtime.GOARCH]
	if os.Getuid() != 0 || os.Geteuid() != 0 || runtime.GOOS != "darwin" || arch == "" || os.Getenv("RUNNER_ARCH") != arch || runtime.Version() != "go"+os.Getenv("GO_VERSION") || os.Getenv("GOTOOLCHAIN") != "local" {
		t.Fatalf("ordinary Darwin audit bootstrap failed: %s", darwinOrdinaryCheckHost.label())
	}
	if len(expected) != 40 || expected != strings.ToLower(expected) || linked.Commit != expected || linked.SourceState != "clean" {
		t.Fatalf("ordinary Darwin audit bootstrap failed: %s", darwinOrdinaryCheckSource.label())
	}
	if _, err := hex.DecodeString(expected); err != nil {
		t.Fatalf("ordinary Darwin audit bootstrap failed: %s", darwinOrdinaryCheckSource.label())
	}
	fixture, err := newOrdinaryDarwinFixture()
	if fixture != nil {
		defer func() {
			if fixture.close() != nil {
				t.Errorf("ordinary Darwin audit bootstrap failed: %s", darwinOrdinaryCheckCleanup.label())
			}
		}()
	}
	if err != nil {
		check := darwinOrdinaryCheckUnknown
		if fixture != nil {
			check = fixture.phase
		}
		t.Fatalf("ordinary Darwin audit bootstrap failed: %s", check.label())
	}
	reply, runErr := fixture.run()
	if reply.Authenticated {
		if !reply.Identity {
			t.Error("ordinary Darwin audit worker identity unavailable")
		}
		if !reply.Home {
			t.Error("ordinary Darwin audit worker home binding unavailable")
		}
		if !reply.Image {
			t.Error("ordinary Darwin audit worker image binding unavailable")
		}
		if !reply.Backend {
			t.Error("ordinary Darwin audit worker public backend unavailable")
		}
		if !reply.Lifecycle {
			t.Error("ordinary Darwin audit worker lifecycle binding unavailable")
		}
		for index, name := range darwinCommandCaseIDs {
			bit := uint64(1) << uint(index)
			if reply.Executed&bit == 0 {
				t.Errorf("ordinary Darwin audit command case not executed: %s", name)
			} else if reply.Passed&bit == 0 {
				t.Errorf("ordinary Darwin audit command case failed: %s", name)
			}
		}
	} else {
		t.Error("ordinary Darwin audit worker protocol unavailable")
	}
	if runErr != nil {
		t.Errorf("ordinary Darwin audit bootstrap failed: %s", fixture.phase.label())
	}
}

func TestDarwinOrdinaryProtocolRejectsAmbiguity(t *testing.T) {
	for _, data := range []string{`{}`, `{"Version":1,"Version":1}`, `{"Version":1,"extra":1}`, `{"Version":1} {}`, strings.Repeat(" ", darwinOrdinaryWireLimit+1)} {
		var out struct{ Version int }
		err := darwinOrdinaryJSON([]byte(data), &out)
		if data == `{}` {
			if err != nil {
				t.Fatal("ordinary Darwin empty protocol object parser changed")
			}
			continue
		}
		if err == nil {
			t.Fatal("ordinary Darwin ambiguous protocol admitted")
		}
	}
	var out struct{ Version int }
	if darwinOrdinaryJSON([]byte(`{"Version":1}`), &out) != nil || out.Version != 1 {
		t.Fatal("ordinary Darwin exact protocol refused")
	}
	discard := &darwinOrdinaryDiscard{remaining: 3}
	if n, err := discard.Write([]byte("1234")); n != 4 || err != nil || discard.clean() {
		t.Fatal("ordinary Darwin subprocess output bound lost")
	}
}
