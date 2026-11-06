package diagnostics

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// An inert Close witness models a connection whose first Close still owns
// cleanup while subsequent Close calls return immediately. It performs no I/O.
type cancellationCloseConn struct {
	entered  chan struct{}
	release  chan struct{}
	finished chan struct{}
	unblock  sync.Once
	calls    atomic.Int32
	closeErr error
}

func newCancellationCloseConn(t *testing.T) *cancellationCloseConn {
	t.Helper()
	return &cancellationCloseConn{entered: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
}
func (c *cancellationCloseConn) Close() error {
	if c.calls.Add(1) != 1 {
		return nil
	}
	close(c.entered)
	<-c.release
	close(c.finished)
	return c.closeErr
}
func (c *cancellationCloseConn) open()                          { c.unblock.Do(func() { close(c.release) }) }
func (*cancellationCloseConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (*cancellationCloseConn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (*cancellationCloseConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*cancellationCloseConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*cancellationCloseConn) SetDeadline(time.Time) error      { return nil }
func (*cancellationCloseConn) SetReadDeadline(time.Time) error  { return nil }
func (*cancellationCloseConn) SetWriteDeadline(time.Time) error { return nil }

func awaitCancellationClose(t *testing.T, done <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal(message)
	}
}

func TestCloseOnCancelRetainsTheActualClosingOwner(t *testing.T) {
	for _, phase := range []string{"callback-running", "stop-before-cancel", "already-canceled"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			if phase == "already-canceled" {
				cancel()
			}
			conn := newCancellationCloseConn(t)
			conn.closeErr = errors.New("PRIVATE_SOURCE_CLOSE_FAILURE")
			var releaseErr error
			release := closeOnCancel(ctx, conn)
			returned := make(chan struct{})
			started := false
			t.Cleanup(func() {
				cancel()
				conn.open()
				if !started {
					go func() { releaseErr = release(); close(returned) }()
				}
				select {
				case <-returned:
				case <-time.After(3 * time.Second):
					t.Error("owned connection release did not join")
				}
				select {
				case <-conn.finished:
				case <-time.After(3 * time.Second):
					t.Error("actual connection Close did not finish")
				}
			})
			if phase == "callback-running" {
				cancel()
				awaitCancellationClose(t, conn.entered, "cancellation callback did not enter its owned Close")
			}
			started = true
			go func() { releaseErr = release(); close(returned) }()
			awaitCancellationClose(t, conn.entered, "owned release did not enter connection Close")
			if phase == "stop-before-cancel" {
				cancel()
			}
			// Close is still blocked in this fixture. A later idempotent Close
			// cannot substitute for joining that original cleanup operation.
			select {
			case <-returned:
				t.Fatal("release abandoned an already-running connection Close")
			default:
			}
			if conn.calls.Load() != 1 {
				t.Fatal("connection cleanup was reclosed instead of retaining its owner")
			}
			conn.open()
			awaitCancellationClose(t, returned, "release did not join actual connection Close")
			awaitCancellationClose(t, conn.finished, "connection Close did not finish before release")
			if conn.calls.Load() != 1 || releaseErr != conn.closeErr {
				t.Fatal("normal or canceled release lost the single actual Close outcome")
			}
		})
	}
}

func TestDiagnosticCleanupFailurePreservesTransportCofailureWithoutPrivateText(t *testing.T) {
	report := Report{Checks: []Check{{Name: "TLS", Status: "failed", Detail: "fixed transport failure"}}}
	cause := errors.New("PRIVATE_CONNECTION_CLOSE_FAILURE")
	calls := 0
	recordConnectionCleanup(&report, func() error { calls++; return cause })
	if calls != 1 || len(report.Checks) != 2 || report.Checks[0].Name != "TLS" || report.Checks[0].Detail != "fixed transport failure" || report.Checks[1].Name != "Cleanup" || report.Checks[1].Status != "failed" || report.Passed() {
		t.Fatal("connection cleanup masked a transport failure or became a successful report")
	}
	if strings.Contains(report.Checks[1].Detail, "PRIVATE") || len(report.Checks[1].Detail) > 128 {
		t.Fatal("connection cleanup published private Close detail")
	}
	successful := Report{Checks: []Check{{Name: "TCP", Status: "ok", Detail: "fixed success"}}}
	recordConnectionCleanup(&successful, func() error { return nil })
	if !successful.Passed() || len(successful.Checks) != 1 {
		t.Fatal("successful cleanup changed the diagnostic result")
	}
}

type diagnosticTLSCloseConn struct {
	net.Conn
	entered  chan struct{}
	allow    chan struct{}
	finished chan struct{}
	unblock  sync.Once
	calls    atomic.Int32
	closeErr error
}

func (c *diagnosticTLSCloseConn) Close() error {
	if c.calls.Add(1) != 1 {
		return nil
	}
	// Unblock the actual TLS read before retaining this original Close. A
	// second Close may return nil while this cleanup operation still owns it.
	_ = c.Conn.Close()
	close(c.entered)
	<-c.allow
	close(c.finished)
	return c.closeErr
}
func (c *diagnosticTLSCloseConn) open() { c.unblock.Do(func() { close(c.allow) }) }

func TestTLSHandshakeCancellationSharesTheActualRawCloser(t *testing.T) {
	client, peer := net.Pipe()
	cause := errors.New("PRIVATE_ACTUAL_TLS_CLOSE_FAILURE")
	raw := &diagnosticTLSCloseConn{Conn: client, entered: make(chan struct{}), allow: make(chan struct{}), finished: make(chan struct{}), closeErr: cause}
	ctx, cancel := context.WithCancel(context.Background())
	// Force the TLS library's cancellation callback to be the first actor. The
	// normal raw owner is intentionally not canceled in this fixture; TLS must
	// use that same positive release instead of a separate raw Close path.
	release := closeOnCancel(context.Background(), raw)
	returned := make(chan struct{})
	var handshakeErr, releaseErr error
	t.Cleanup(func() {
		cancel()
		raw.open()
		_ = peer.Close()
		_ = client.Close()
		select {
		case <-returned:
		case <-time.After(3 * time.Second):
			t.Error("actual TLS handshake and release did not join")
		}
		select {
		case <-raw.finished:
		case <-time.After(3 * time.Second):
			t.Error("original TLS cancellation Close did not finish")
		}
	})
	go func() {
		_, handshakeErr = handshakeDiagnosticTLS(ctx, raw, release, &tls.Config{ServerName: "source-fixture.invalid", MinVersion: tls.VersionTLS12})
		releaseErr = release()
		close(returned)
	}()
	if peer.SetReadDeadline(time.Now().Add(3*time.Second)) != nil {
		t.Fatal("inert TLS peer deadline is unavailable")
	}
	var header [5]byte
	if _, err := io.ReadFull(peer, header[:]); err != nil || header[0] != 22 {
		t.Fatal("actual TLS helper did not emit its ClientHello record")
	}
	length := int(binary.BigEndian.Uint16(header[3:]))
	if length < 1 || length > 65535 {
		t.Fatal("actual TLS helper emitted an invalid record length")
	}
	if _, err := io.CopyN(io.Discard, peer, int64(length)); err != nil {
		t.Fatal("actual TLS helper ClientHello did not complete")
	}
	cancel()
	awaitCancellationClose(t, raw.entered, "TLS cancellation did not enter its first raw Close")
	select {
	case <-returned:
		t.Fatal("TLS cancellation abandoned the original raw Close")
	default:
	}
	if raw.calls.Load() != 1 {
		t.Fatal("TLS and diagnostic cancellation used separate raw closers")
	}
	raw.open()
	awaitCancellationClose(t, returned, "TLS helper did not join the shared raw closer")
	awaitCancellationClose(t, raw.finished, "TLS original raw Close did not complete")
	if !errors.Is(handshakeErr, context.Canceled) || releaseErr != cause || raw.calls.Load() != 1 {
		t.Fatal("TLS cancellation erased the original context or exact single-Close outcome")
	}
}
