package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/diagnostics"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

type diagnosticHTTPCall struct {
	cancel      context.CancelFunc
	clientDone  chan struct{}
	handlerDone chan struct{}
	status      int
	header      http.Header
	body        []byte
	err         error
}
type diagnosticHTTPFixture struct {
	t         *testing.T
	server    *Server
	http      *httptest.Server
	client    *http.Client
	transport *http.Transport
	root      string
	rootInfo  os.FileInfo
	mu        sync.Mutex
	calls     []*diagnosticHTTPCall
	peers     []func() bool
}

func newDiagnosticHTTPFixture(t *testing.T, guard *managed.Guard) *diagnosticHTTPFixture {
	t.Helper()
	root, err := os.MkdirTemp("", "accessweaver-diagnostic-http-")
	if err != nil {
		t.Fatal("diagnostic fixture root is unavailable")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("diagnostic fixture root binding is unavailable")
	}
	if guard == nil {
		guard = managed.NewGuard(func() (*managed.Authority, error) { return nil, nil })
	}
	store, err := profile.NewStoreWithGuard(root, guard)
	if err != nil {
		t.Fatal("diagnostic fixture store is unavailable")
	}
	server, err := New(store, engine.NewManagerWithGuard(root, guard), nil)
	if err != nil {
		t.Fatal("diagnostic fixture server is unavailable")
	}
	server.Policy = guard
	server.Workflows = workflow.NewWithGuard(root, guard)
	f := &diagnosticHTTPFixture{t: t, server: server, root: root, rootInfo: info}
	handler := server.Handler()
	f.http = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		index, parseErr := strconv.Atoi(r.Header.Get("X-AccessWeaver-Fixture-Request"))
		f.mu.Lock()
		var call *diagnosticHTTPCall
		if parseErr == nil && index >= 0 && index < len(f.calls) {
			call = f.calls[index]
		}
		f.mu.Unlock()
		if call != nil {
			defer close(call.handlerDone)
		}
		handler.ServeHTTP(w, r)
	}))
	// No environment proxy is consulted; every HTTP and diagnostic endpoint in
	// these tests is an owned loopback listener.
	f.transport = &http.Transport{Proxy: nil, MaxConnsPerHost: 4, MaxIdleConnsPerHost: 4}
	f.client = &http.Client{Transport: f.transport, Timeout: 10 * time.Second}
	t.Cleanup(f.close)
	return f
}
func (f *diagnosticHTTPFixture) start(method, path string, input any, token string) *diagnosticHTTPCall {
	f.t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		f.t.Fatal("diagnostic HTTP fixture input could not be encoded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(ctx, method, f.http.URL+path, bytes.NewReader(data))
	if err != nil {
		cancel()
		f.t.Fatal("diagnostic HTTP fixture request is unavailable")
	}
	call := &diagnosticHTTPCall{cancel: cancel, clientDone: make(chan struct{}), handlerDone: make(chan struct{})}
	f.mu.Lock()
	index := len(f.calls)
	f.calls = append(f.calls, call)
	f.mu.Unlock()
	request.Header.Set("X-AccessWeaver-Fixture-Request", strconv.Itoa(index))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-AccessWeaver-Token", token)
	go func() {
		defer close(call.clientDone)
		response, err := f.client.Do(request)
		if err != nil {
			call.err = err
			return
		}
		call.status = response.StatusCode
		call.header = response.Header.Clone()
		call.body, err = io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
		call.err = errors.Join(err, response.Body.Close())
		if len(call.body) > 64<<10 {
			call.err = errors.New("diagnostic HTTP fixture response exceeded its bound")
		}
	}()
	return call
}
func diagnosticAwait(t *testing.T, done <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal(message)
	}
}
func (f *diagnosticHTTPFixture) complete(call *diagnosticHTTPCall) {
	f.t.Helper()
	diagnosticAwait(f.t, call.clientDone, "diagnostic HTTP client did not finish")
	diagnosticAwait(f.t, call.handlerDone, "diagnostic HTTP handler did not actually return")
}
func (f *diagnosticHTTPFixture) close() {
	f.mu.Lock()
	calls := append([]*diagnosticHTTPCall(nil), f.calls...)
	f.mu.Unlock()
	for _, call := range calls {
		call.cancel()
	}
	f.transport.CloseIdleConnections()
	f.http.CloseClientConnections()
	confirmed := true
	for _, stop := range f.peers {
		if !stop() {
			confirmed = false
		}
	}
	closed := make(chan struct{})
	go func() { f.http.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(8 * time.Second):
		confirmed = false
		f.t.Error("diagnostic HTTP server did not join; fixture preserved")
	}
	for _, call := range calls {
		select {
		case <-call.clientDone:
		case <-time.After(4 * time.Second):
			confirmed = false
			f.t.Error("diagnostic HTTP client did not join; fixture preserved")
		}
	}
	if !confirmed {
		return
	}
	current, err := os.Lstat(f.root)
	if err != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(f.rootInfo, current) {
		f.t.Error("changed diagnostic fixture root was preserved")
		return
	}
	if os.RemoveAll(f.root) != nil {
		f.t.Error("diagnostic fixture root cleanup failed")
	}
}

type diagnosticTCPPeer struct {
	listener   *net.TCPListener
	ready      chan struct{}
	done       chan struct{}
	mu         sync.Mutex
	connection net.Conn
	stopping   bool
	err        error
}

func newDiagnosticTCPPeer(f *diagnosticHTTPFixture, serve func(net.Conn, chan<- struct{}) error) *diagnosticTCPPeer {
	f.t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		f.t.Fatal("diagnostic TCP fixture listener is unavailable")
	}
	p := &diagnosticTCPPeer{listener: listener, ready: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(p.done)
		connection, err := listener.Accept()
		if err != nil {
			p.err = err
			return
		}
		defer connection.Close()
		p.mu.Lock()
		p.connection = connection
		stopping := p.stopping
		p.mu.Unlock()
		if stopping {
			p.err = net.ErrClosed
			return
		}
		if connection.SetDeadline(time.Now().Add(10*time.Second)) != nil {
			p.err = errors.New("diagnostic TCP fixture deadline failed")
			return
		}
		p.err = serve(connection, p.ready)
	}()
	f.peers = append(f.peers, func() bool {
		p.mu.Lock()
		p.stopping = true
		connection := p.connection
		p.mu.Unlock()
		_ = listener.Close()
		if connection != nil {
			_ = connection.Close()
		}
		select {
		case <-p.done:
			return true
		case <-time.After(4 * time.Second):
			f.t.Error("diagnostic TCP fixture did not join")
			return false
		}
	})
	return p
}
func diagnosticReadClosure(connection net.Conn) error {
	if _, err := io.Copy(io.Discard, connection); err != nil {
		return errors.New("diagnostic owned TCP socket did not close cleanly")
	}
	return nil
}
func diagnosticTLSStall(connection net.Conn, ready chan<- struct{}) error {
	var header [5]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil || header[0] != 22 {
		return errors.New("diagnostic TLS fixture did not receive a ClientHello record")
	}
	length := int(binary.BigEndian.Uint16(header[3:]))
	if length < 1 || length > 65535 {
		return errors.New("diagnostic TLS fixture record length is invalid")
	}
	if _, err := io.CopyN(io.Discard, connection, int64(length)); err != nil {
		return errors.New("diagnostic TLS fixture record is incomplete")
	}
	close(ready)
	return diagnosticReadClosure(connection)
}
func diagnosticSOCKSStall(connection net.Conn, ready chan<- struct{}) error {
	var greeting [3]byte
	if _, err := io.ReadFull(connection, greeting[:]); err != nil || greeting != [3]byte{5, 1, 0} {
		return errors.New("diagnostic SOCKS fixture greeting is invalid")
	}
	close(ready)
	return diagnosticReadClosure(connection)
}
func diagnosticConnectStall(connection net.Conn, ready chan<- struct{}) error {
	request, err := http.ReadRequest(bufio.NewReader(io.LimitReader(connection, 4096)))
	if err != nil || request.Method != http.MethodConnect {
		return errors.New("diagnostic CONNECT fixture request is invalid")
	}
	if request.Body != nil {
		_ = request.Body.Close()
	}
	close(ready)
	return diagnosticReadClosure(connection)
}
func diagnosticAssertIdleControls(f *diagnosticHTTPFixture) {
	f.t.Helper()
	for _, route := range []struct{ method, path string }{{http.MethodGet, "/api/v1/runtime"}, {http.MethodPost, "/api/v1/system/cancel"}} {
		call := f.start(route.method, route.path, map[string]any{}, f.server.Token)
		f.complete(call)
		if call.err != nil || call.status != http.StatusOK {
			f.t.Fatal("active diagnostic blocked independent status or workflow cancellation")
		}
	}
}
func diagnosticAssertBusyAndAuth(f *diagnosticHTTPFixture, input diagnostics.Request) {
	f.t.Helper()
	busy := f.start(http.MethodPost, "/api/v1/diagnose", input, f.server.Token)
	f.complete(busy)
	var body struct {
		Code string `json:"code"`
	}
	if busy.err != nil || busy.status != http.StatusServiceUnavailable || busy.header.Get("Retry-After") != "1" || json.Unmarshal(busy.body, &body) != nil || body.Code != "diagnostic-busy" {
		f.t.Fatal("active diagnostic did not retain its separate bounded admission slot")
	}
	denied := f.start(http.MethodPost, "/api/v1/diagnose", input, "invalid-fixture-token")
	f.complete(denied)
	if denied.err != nil || denied.status != http.StatusForbidden {
		f.t.Fatal("diagnostic busy state bypassed session authorization")
	}
	diagnosticAssertIdleControls(f)
}
func diagnosticAssertFreshRequest(f *diagnosticHTTPFixture) {
	f.t.Helper()
	peer := newDiagnosticTCPPeer(f, func(connection net.Conn, ready chan<- struct{}) error { close(ready); return nil })
	input := diagnostics.Request{Probe: profile.Probe{Host: "127.0.0.1", Port: peer.listener.Addr().(*net.TCPAddr).Port, TimeoutSeconds: 2}}
	call := f.start(http.MethodPost, "/api/v1/diagnose", input, f.server.Token)
	f.complete(call)
	var report diagnostics.Report
	if call.err != nil || call.status != http.StatusOK || json.Unmarshal(call.body, &report) != nil || !report.Passed() || report.Path != "direct" || report.Transport != "tcp" {
		f.t.Fatal("completed diagnostic cancellation retained capacity or corrupted the next request")
	}
	diagnosticAwait(f.t, peer.done, "fresh diagnostic TCP peer did not join")
	if peer.err != nil {
		f.t.Fatal("fresh diagnostic TCP fixture failed")
	}
}

func TestDiagnosticAPIClientCancellationClosesOwnedTCPAndReleasesCapacity(t *testing.T) {
	for _, mode := range []string{"tls", "socks5", "http-connect"} {
		t.Run(mode, func(t *testing.T) {
			f := newDiagnosticHTTPFixture(t, nil)
			serve := diagnosticTLSStall
			if mode == "socks5" {
				serve = diagnosticSOCKSStall
			}
			if mode == "http-connect" {
				serve = diagnosticConnectStall
			}
			peer := newDiagnosticTCPPeer(f, serve)
			// A selected proxy must never connect directly to its target, even
			// when cancellation interrupts its incomplete handshake.
			target, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal("diagnostic fallback canary is unavailable")
			}
			defer target.Close()
			input := diagnostics.Request{Probe: profile.Probe{Host: "127.0.0.1", Port: peer.listener.Addr().(*net.TCPAddr).Port, TLS: true, TimeoutSeconds: 30}}
			if mode != "tls" {
				input.TLS = false
				input.Port = target.Addr().(*net.TCPAddr).Port
				input.Path = mode
				input.Proxy = peer.listener.Addr().String()
			}
			active := f.start(http.MethodPost, "/api/v1/diagnose", input, f.server.Token)
			diagnosticAwait(t, peer.ready, "real diagnostic did not reach its owned stalled transport")
			diagnosticAssertBusyAndAuth(f, input)
			active.cancel()
			f.complete(active)
			if !errors.Is(active.err, context.Canceled) {
				t.Fatal("canceled real HTTP client reported diagnostic success")
			}
			diagnosticAwait(t, peer.done, "HTTP cancellation did not close the real diagnostic TCP socket")
			if peer.err != nil {
				t.Fatal("HTTP cancellation did not produce owned socket closure")
			}
			if mode != "tls" {
				if target.SetDeadline(time.Now().Add(100*time.Millisecond)) != nil {
					t.Fatal("diagnostic fallback canary deadline failed")
				}
				connection, err := target.Accept()
				if connection != nil {
					connection.Close()
					t.Fatal("canceled proxy diagnostic fell back to a direct target")
				}
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Fatal("diagnostic fallback canary did not confirm an unused target")
				}
			}
			diagnosticAssertFreshRequest(f)
		})
	}
}

func TestDiagnosticAPIHTTPPolicyRevocationClosesSocketAndPreservesDenial(t *testing.T) {
	authority := apiPolicy(t, managed.Policy{AllowDiagnostics: true})
	var revoked atomic.Bool
	guard := managed.NewGuard(func() (*managed.Authority, error) {
		if revoked.Load() {
			return nil, managed.ErrUnavailable
		}
		return authority, nil
	})
	f := newDiagnosticHTTPFixture(t, guard)
	peer := newDiagnosticTCPPeer(f, diagnosticSOCKSStall)
	target, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal("managed diagnostic fallback canary is unavailable")
	}
	defer target.Close()
	input := diagnostics.Request{Probe: profile.Probe{Host: "127.0.0.1", Port: target.Addr().(*net.TCPAddr).Port, TimeoutSeconds: 30}, Path: "socks5", Proxy: peer.listener.Addr().String()}
	active := f.start(http.MethodPost, "/api/v1/diagnose", input, f.server.Token)
	diagnosticAwait(t, peer.ready, "managed diagnostic did not reach its real proxy")
	revoked.Store(true)
	f.complete(active)
	diagnosticAwait(t, peer.done, "policy revocation did not close the actual diagnostic socket")
	if active.err != nil || active.status != http.StatusForbidden || peer.err != nil {
		t.Fatal("active policy revocation was replaced by success or a generic cancellation response")
	}
	if target.SetDeadline(time.Now().Add(100*time.Millisecond)) != nil {
		t.Fatal("managed diagnostic fallback canary deadline failed")
	}
	connection, err := target.Accept()
	if connection != nil {
		connection.Close()
		t.Fatal("revoked proxy diagnostic fell back to a direct target")
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatal("managed diagnostic fallback canary did not confirm an unused target")
	}
	revoked.Store(false)
	diagnosticAssertFreshRequest(f)
}

// UDP has no peer EOF. On Linux, demonstrate that the exact observed source
// endpoint is occupied before cancellation and bindable after owned handler
// completion. This is a socket-lifetime witness, not a server-authentication or
// packet-delivery claim. Other hosts still verify the SOCKS control TCP closure.
func diagnosticUDPPortHeld(t *testing.T, address *net.UDPAddr) {
	t.Helper()
	if runtime.GOOS != "linux" {
		return
	}
	connection, err := net.ListenUDP("udp4", address)
	if connection != nil {
		connection.Close()
		t.Fatal("UDP endpoint was not exclusively held before cancellation")
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatal("UDP ownership witness did not establish an occupied endpoint")
	}
}
func diagnosticUDPPortReleased(t *testing.T, address *net.UDPAddr) {
	t.Helper()
	if runtime.GOOS != "linux" {
		return
	}
	connection, err := net.ListenUDP("udp4", address)
	if err != nil {
		t.Fatal("canceled diagnostic retained its actual UDP socket")
	}
	if connection.Close() != nil {
		t.Fatal("UDP closure witness did not release its owned socket")
	}
}

type diagnosticUDPObservation struct {
	connection *net.UDPConn
	received   chan struct{}
	address    *net.UDPAddr
	packet     []byte
	err        error
}

func newDiagnosticUDPObservation(f *diagnosticHTTPFixture) *diagnosticUDPObservation {
	f.t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		f.t.Fatal("diagnostic UDP fixture is unavailable")
	}
	observation := &diagnosticUDPObservation{connection: connection, received: make(chan struct{})}
	go func() {
		defer close(observation.received)
		if connection.SetReadDeadline(time.Now().Add(10*time.Second)) != nil {
			observation.err = errors.New("diagnostic UDP fixture deadline failed")
			return
		}
		packet := make([]byte, 1024)
		count, address, err := connection.ReadFromUDP(packet)
		observation.packet = packet[:count]
		observation.address = address
		observation.err = err
	}()
	f.peers = append(f.peers, func() bool {
		_ = connection.Close()
		select {
		case <-observation.received:
			return true
		case <-time.After(4 * time.Second):
			f.t.Error("diagnostic UDP observer did not join")
			return false
		}
	})
	return observation
}
func TestDiagnosticAPIClientCancellationClosesUDPAndSOCKSAssociation(t *testing.T) {
	for _, path := range []string{"direct", "socks5"} {
		t.Run(path, func(t *testing.T) {
			f := newDiagnosticHTTPFixture(t, nil)
			relay := newDiagnosticUDPObservation(f)
			input := diagnostics.Request{Probe: profile.Probe{Host: "127.0.0.1", Port: relay.connection.LocalAddr().(*net.UDPAddr).Port, TimeoutSeconds: 30}, Transport: "stun"}
			var control *diagnosticTCPPeer
			var canary *net.UDPConn
			if path == "socks5" {
				var err error
				canary, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal("diagnostic UDP fallback canary is unavailable")
				}
				defer canary.Close()
				input.Port = canary.LocalAddr().(*net.UDPAddr).Port
				input.Path = "socks5"
				control = newDiagnosticTCPPeer(f, func(connection net.Conn, ready chan<- struct{}) error {
					var greeting [3]byte
					if _, err := io.ReadFull(connection, greeting[:]); err != nil || greeting != [3]byte{5, 1, 0} {
						return errors.New("UDP association greeting is invalid")
					}
					if _, err := connection.Write([]byte{5, 0}); err != nil {
						return errors.New("UDP association authentication reply failed")
					}
					var command [10]byte
					if _, err := io.ReadFull(connection, command[:]); err != nil || command != [10]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0} {
						return errors.New("UDP association command changed its fixed bind request")
					}
					reply := []byte{5, 0, 0, 1, 127, 0, 0, 1}
					reply = binary.BigEndian.AppendUint16(reply, uint16(relay.connection.LocalAddr().(*net.UDPAddr).Port))
					if _, err := connection.Write(reply); err != nil {
						return errors.New("UDP association relay reply failed")
					}
					close(ready)
					return diagnosticReadClosure(connection)
				})
				input.Proxy = control.listener.Addr().String()
			}
			active := f.start(http.MethodPost, "/api/v1/diagnose", input, f.server.Token)
			diagnosticAwait(t, relay.received, "actual diagnostic did not send its loopback STUN datagram")
			if relay.err != nil || relay.address == nil {
				t.Fatal("diagnostic UDP ownership observation failed")
			}
			packet := relay.packet
			if path == "socks5" {
				if len(packet) != 30 || !bytes.Equal(packet[:8], []byte{0, 0, 0, 1, 127, 0, 0, 1}) || binary.BigEndian.Uint16(packet[8:10]) != uint16(input.Port) {
					t.Fatal("selected UDP proxy did not receive the exact target envelope")
				}
				packet = packet[10:]
				diagnosticAwait(t, control.ready, "actual SOCKS association did not become ready")
			}
			if len(packet) != 20 || binary.BigEndian.Uint16(packet) != 1 || binary.BigEndian.Uint32(packet[4:8]) != 0x2112a442 {
				t.Fatal("diagnostic fixture did not receive the bounded STUN binding request")
			}
			diagnosticUDPPortHeld(t, relay.address)
			diagnosticAssertBusyAndAuth(f, input)
			active.cancel()
			f.complete(active)
			if !errors.Is(active.err, context.Canceled) {
				t.Fatal("canceled UDP diagnostic returned a successful HTTP client result")
			}
			diagnosticUDPPortReleased(t, relay.address)
			if control != nil {
				diagnosticAwait(t, control.done, "HTTP cancellation retained its SOCKS UDP control connection")
				if control.err != nil {
					t.Fatal("SOCKS UDP control socket did not close cleanly")
				}
				if canary.SetReadDeadline(time.Now().Add(100*time.Millisecond)) != nil {
					t.Fatal("UDP fallback canary deadline failed")
				}
				var packet [64]byte
				_, _, err := canary.ReadFromUDP(packet[:])
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Fatal("canceled SOCKS UDP diagnostic sent directly to the target")
				}
			}
			diagnosticAssertFreshRequest(f)
		})
	}
}
