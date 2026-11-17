package diagnostics

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

type Check struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	DurationMs int64  `json:"durationMs"`
	Detail     string `json:"detail"`
}
type Report struct {
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Path      string    `json:"path"`
	Transport string    `json:"transport"`
	Proxy     string    `json:"proxy,omitempty"`
	Checks    []Check   `json:"checks"`
	At        time.Time `json:"at"`
}

// Request extends the original flat probe JSON without changing saved profiles.
type Request struct {
	profile.Probe
	Path      string `json:"path,omitempty"`
	Transport string `json:"transport,omitempty"`
	Proxy     string `json:"proxy,omitempty"`
}

func (r Report) Passed() bool {
	if len(r.Checks) == 0 {
		return false
	}
	for _, c := range r.Checks {
		if c.Status != "ok" {
			return false
		}
	}
	return true
}
func (r *Request) normalize() error {
	if r.Path == "" {
		r.Path = "direct"
	}
	if r.Transport == "" {
		r.Transport = "tcp"
	}
	if r.TimeoutSeconds == 0 {
		r.TimeoutSeconds = 5
	}
	if r.Host == "" {
		return errors.New("probe host is required")
	}
	if err := profile.ValidateHost(r.Host); err != nil {
		return err
	}
	if r.Port < 1 || r.Port > 65535 {
		return errors.New("invalid port")
	}
	if r.TimeoutSeconds < 1 || r.TimeoutSeconds > 60 {
		return errors.New("probe timeout must be 1-60 seconds")
	}
	if r.Path != "direct" && r.Path != "socks5" && r.Path != "http-connect" {
		return errors.New("unsupported diagnostic path")
	}
	if r.Transport != "tcp" && r.Transport != "stun" {
		return errors.New("unsupported diagnostic transport")
	}
	if r.Transport == "stun" && (r.TLS || r.Path == "http-connect") {
		return errors.New("UDP/STUN requires TLS disabled and a direct or SOCKS5 path")
	}
	if r.Path == "direct" {
		if r.Proxy != "" {
			return errors.New("direct diagnostics cannot specify a proxy")
		}
	} else {
		host, port, err := net.SplitHostPort(r.Proxy)
		if err != nil || host == "" {
			return errors.New("proxy must be a host:port authority without credentials or a URL")
		}
		if err := profile.ValidateHost(host); err != nil {
			return errors.New("invalid proxy host")
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("invalid proxy port")
		}
		r.Proxy = net.JoinHostPort(host, strconv.Itoa(n))
	}
	return nil
}

// Run preserves the original direct-probe interface; runtime entry points use
// Diagnose so policy errors can retain their HTTP/CLI outcome independently.
func Run(ctx context.Context, p profile.Probe) Report {
	report, err := Diagnose(ctx, Request{Probe: p}, nil)
	if err != nil {
		report.Checks = append(report.Checks, Check{Name: "policy", Status: "failed", Detail: err.Error()})
	}
	return report
}
func Diagnose(ctx context.Context, input Request, guard *managed.Guard) (Report, error) {
	return (runner{}).diagnose(ctx, input, guard)
}

type runner struct {
	lookup   func(context.Context, string) ([]net.IPAddr, error)
	tlsRoots *x509.CertPool // In-process test trust only; never request-controlled.
}

func (d runner) diagnose(ctx context.Context, input Request, guard *managed.Guard) (Report, error) {
	r := Report{Host: input.Host, Port: input.Port, Checks: []Check{}, At: time.Now().UTC()}
	authorization, err := guard.AuthorizeDiagnostics()
	if err != nil {
		return r, err
	}
	monitored, stop, err := authorization.Context(ctx)
	if err != nil {
		return r, err
	}
	defer stop()
	validationErr := input.normalize()
	r.Path, r.Transport = input.Path, input.Transport
	if validationErr != nil {
		r.Checks = append(r.Checks, Check{Name: "input", Status: "failed", Detail: validationErr.Error()})
		return r, nil
	}
	r.Proxy = input.Proxy
	deadline, cancel := context.WithTimeout(monitored, time.Duration(input.TimeoutSeconds)*time.Second)
	defer cancel()
	if input.Transport == "stun" {
		d.stun(deadline, input, &r)
	} else {
		d.tcp(deadline, input, &r)
	}
	if err := authorization.Check(); err != nil {
		return r, err
	}
	if cause := context.Cause(monitored); managed.IsPolicyError(cause) {
		return r, cause
	}
	if err := deadline.Err(); err != nil && r.Passed() {
		r.Checks = append(r.Checks, Check{Name: "Cancellation", Status: "failed", Detail: err.Error()})
	}
	return r, nil
}
func (d runner) resolve(ctx context.Context, host string) ([]net.IPAddr, error) {
	resolver := d.lookup
	if resolver == nil {
		resolver = net.DefaultResolver.LookupIPAddr
	}
	addresses, err := resolver(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 || len(addresses) > 64 {
		return nil, errors.New("resolver returned an empty or excessive address list")
	}
	return addresses, nil
}
func (d runner) dial(ctx context.Context, network, host string, port int) (net.Conn, error) {
	addresses, err := d.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	return dialAddresses(ctx, network, addresses, port)
}
func dialAddresses(ctx context.Context, network string, addresses []net.IPAddr, port int) (net.Conn, error) {
	return dialAddressSet(ctx, network, addresses, port, (&net.Dialer{}).DialContext, 300*time.Millisecond)
}

// The deferred owner joins an already-running cancellation Close. A second
// Close may return immediately while the first still owns actual cleanup, so
// it cannot substitute for observing that callback's completion.
func closeOnCancel(ctx context.Context, c net.Conn) func() error {
	done := make(chan struct{})
	var closeErr error
	closeConnection := func() {
		defer close(done)
		closeErr = c.Close()
	}
	stop := context.AfterFunc(ctx, closeConnection)
	return func() error {
		if stop() {
			closeConnection()
		} else {
			<-done
		}
		return closeErr
	}
}

func recordConnectionCleanup(report *Report, release func() error) {
	if release() != nil {
		// Reports are private, but a native Close cause still need not expose
		// arbitrary implementation text. Preserve the earlier transport checks.
		report.Checks = append(report.Checks, Check{Name: "Cleanup", Status: "failed", Detail: "connection cleanup reported an error"})
	}
}

// TLS can start its own asynchronous Close when its handshake context ends.
// Delegate that Close to the same retained owner as every other cancellation
// path, including when the current I/O connection wraps buffered proxy bytes.
// No TLS-library callback can substitute a second raw Close for the first one.
type diagnosticTLSConnection struct {
	net.Conn
	release func() error
}

func (c *diagnosticTLSConnection) Close() error { return c.release() }

func handshakeDiagnosticTLS(ctx context.Context, connection net.Conn, release func() error, config *tls.Config) (tls.ConnectionState, error) {
	secured := tls.Client(&diagnosticTLSConnection{Conn: connection, release: release}, config)
	if err := secured.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, err
	}
	return secured.ConnectionState(), nil
}

func (d runner) tcp(ctx context.Context, input Request, r *Report) {
	start := time.Now()
	var connection net.Conn
	var release func() error
	var err error
	if input.Path == "direct" {
		// Resolve once, report that stage independently, and dial only those IPs.
		addresses, resolveErr := d.resolve(ctx, input.Host)
		if resolveErr != nil {
			r.Checks = append(r.Checks, check("DNS", "failed", start, resolveErr.Error()))
			return
		}
		r.Checks = append(r.Checks, check("DNS", "ok", start, fmt.Sprintf("resolved %d target address(es)", len(addresses))))
		start = time.Now()
		connection, err = dialAddresses(ctx, "tcp", addresses, input.Port)
		if err != nil {
			r.Checks = append(r.Checks, check("TCP", "failed", start, err.Error()))
			return
		}
		release = closeOnCancel(ctx, connection)
		defer recordConnectionCleanup(r, release)
		r.Checks = append(r.Checks, check("TCP", "ok", start, "direct connection established"))
	} else {
		host, port, _ := net.SplitHostPort(input.Proxy)
		n, _ := strconv.Atoi(port)
		connection, err = d.dial(ctx, "tcp", host, n)
		if err != nil {
			r.Checks = append(r.Checks, check("Proxy", "failed", start, err.Error()))
			return
		}
		release = closeOnCancel(ctx, connection)
		defer recordConnectionCleanup(r, release)
		if input.Path == "socks5" {
			_, err = socksCommand(connection, 1, input.Host, input.Port)
		} else {
			connection, err = httpConnect(connection, input.Host, input.Port)
		}
		if err != nil {
			r.Checks = append(r.Checks, check("Proxy", "failed", start, err.Error()))
			return
		}
		r.Checks = append(r.Checks, check("Proxy", "ok", start, input.Path+" tunnel accepted; destination DNS is delegated to the proxy"))
		r.Checks = append(r.Checks, check("TCP", "ok", start, "connection through the selected proxy established"))
	}
	if !input.TLS {
		return
	}
	start = time.Now()
	state, err := handshakeDiagnosticTLS(ctx, connection, release, &tls.Config{ServerName: input.Host, MinVersion: tls.VersionTLS12, RootCAs: d.tlsRoots})
	if err != nil {
		r.Checks = append(r.Checks, check("TLS", "failed", start, err.Error()))
		return
	}
	if len(state.VerifiedChains) == 0 {
		r.Checks = append(r.Checks, check("TLS", "failed", start, "server certificate chain was not verified"))
		return
	}
	r.Checks = append(r.Checks, check("TLS", "ok", start, fmt.Sprintf("TLS %x; target certificate and name verified", state.Version)))
	// The registered raw-connection owner closes after the handshake; no
	// second TLS closer can race or outlive the cancellation owner.
}
func check(name, status string, started time.Time, detail string) Check {
	return Check{Name: name, Status: status, DurationMs: time.Since(started).Milliseconds(), Detail: detail}
}
