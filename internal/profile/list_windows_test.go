//go:build windows

package profile

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestImpersonatedListCannotJoinProcessIdentityRead(t *testing.T) {
	// Isolate thread-token manipulation and Windows error-formatting side
	// effects from other tests in a bounded child test process.
	if os.Getenv("ACCESSWEAVER_PROFILE_IMPERSONATION_PROBE") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestImpersonatedListCannotJoinProcessIdentityRead$", "-test.timeout=10s")
		command.Env = append(os.Environ(), "ACCESSWEAVER_PROFILE_IMPERSONATION_PROBE=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("isolated impersonation probe failed: %v\n%s", err, output)
		}
		return
	}
	s, p := listingFixture(t)
	hold, err := s.lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan listed, 1)
	go func() { rows, err := s.ListContext(ctx); result <- listed{rows, err} }()
	pending := waitListing(t, s, 1)
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		t.Fatal(err)
	}
	var token syscall.Token
	if err := syscall.OpenProcessToken(process, syscall.TOKEN_QUERY|syscall.TOKEN_DUPLICATE|syscall.TOKEN_IMPERSONATE, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	restrictedSID, err := syscall.StringToSid("S-1-5-12")
	if err != nil {
		t.Fatal(err)
	}
	restriction := struct {
		SID        *syscall.SID
		Attributes uint32
	}{SID: restrictedSID}
	var limited syscall.Token
	dll := syscall.NewLazyDLL("advapi32.dll")
	ok, _, callErr := dll.NewProc("CreateRestrictedToken").Call(uintptr(token), 1, 0, 0, 0, 0, 1, uintptr(unsafe.Pointer(&restriction)), uintptr(unsafe.Pointer(&limited)))
	if ok == 0 {
		t.Fatal(callErr)
	}
	defer limited.Close()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if !canShareListRead() {
		t.Fatal("probe must begin under the process identity")
	}
	ok, _, callErr = dll.NewProc("ImpersonateLoggedOnUser").Call(uintptr(limited))
	if ok == 0 {
		t.Fatal(callErr)
	}
	reverted := false
	revert := func() {
		if reverted {
			return
		}
		ok, _, _ := dll.NewProc("RevertToSelf").Call()
		if ok == 0 {
			panic("cannot restore profile-test token")
		}
		reverted = true
	}
	defer revert()
	// Independently establish that this effective token cannot read the fixture.
	f, openErr := os.Open(filepath.Join(s.Root, "profiles", p.ID+".json"))
	if f != nil {
		f.Close()
	}
	if !errors.Is(openErr, os.ErrPermission) {
		t.Fatalf("fixture must deny the effective token: %v", openErr)
	}
	if canShareListRead() {
		t.Fatal("impersonated read was eligible for sharing")
	}
	short, cancelShort := context.WithTimeout(context.Background(), 150*time.Millisecond)
	rows, err := s.ListContext(short)
	cancelShort()
	if rows != nil || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("impersonated caller inherited a different principal's read: %v", err)
	}
	s.listMu.Lock()
	stillPending := s.listing == pending && pending.waiters == 1
	s.listMu.Unlock()
	if !stillPending {
		t.Fatal("impersonated caller altered the process-identity transaction")
	}
	revert()
	if err := hold.Close(); err != nil {
		t.Fatal(err)
	}
	if got := <-result; got.err != nil || len(got.profiles) != 1 {
		t.Fatal("original process-identity reader failed", got.err)
	}
}
