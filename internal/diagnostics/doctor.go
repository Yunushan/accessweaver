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
	if err := input.normalize(); err != nil {
		r.Checks = append(r.Checks, Check{Name: "input", Status: "failed", Detail: err.Error()})
		return r, nil
	}
	r.Path, r.Transport, r.Proxy = input.Path, input.Transport, input.Proxy
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
	var last error
	for _, address := range addresses {
		target := net.JoinHostPort(address.String(), strconv.Itoa(port))
		connection, err := (&net.Dialer{}).DialContext(ctx, network, target)
		if err == nil {
			if limit, ok := ctx.Deadline(); ok {
				_ = connection.SetDeadline(limit)
			}
			return connection, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}
func closeOnCancel(ctx context.Context, c net.Conn) func() {
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	return func() { stop(); _ = c.Close() }
}
func (d runner) tcp(ctx context.Context, input Request, r *Report) {
	start := time.Now()
	var connection net.Conn
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
		r.Checks = append(r.Checks, check("TCP", "ok", start, "direct connection established"))
	} else {
		host, port, _ := net.SplitHostPort(input.Proxy)
		n, _ := strconv.Atoi(port)
		connection, err = d.dial(ctx, "tcp", host, n)
		if err != nil {
			r.Checks = append(r.Checks, check("Proxy", "failed", start, err.Error()))
			return
		}
		defer closeOnCancel(ctx, connection)()
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
	defer closeOnCancel(ctx, connection)()
	if !input.TLS {
		return
	}
	start = time.Now()
	secured := tls.Client(connection, &tls.Config{ServerName: input.Host, MinVersion: tls.VersionTLS12, RootCAs: d.tlsRoots})
	if err := secured.HandshakeContext(ctx); err != nil {
		r.Checks = append(r.Checks, check("TLS", "failed", start, err.Error()))
		return
	}
	state := secured.ConnectionState()
	if len(state.VerifiedChains) == 0 {
		r.Checks = append(r.Checks, check("TLS", "failed", start, "server certificate chain was not verified"))
		return
	}
	r.Checks = append(r.Checks, check("TLS", "ok", start, fmt.Sprintf("TLS %x; target certificate and name verified", state.Version)))
	_ = secured.Close()
}
func check(name, status string, started time.Time, detail string) Check {
	return Check{Name: name, Status: status, DurationMs: time.Since(started).Milliseconds(), Detail: detail}
}
