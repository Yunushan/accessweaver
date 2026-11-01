package diagnostics

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/Yunushan/accessweaver/internal/profile"
)

type Check struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	DurationMs int64  `json:"durationMs"`
	Detail     string `json:"detail"`
}
type Report struct {
	Host   string    `json:"host"`
	Port   int       `json:"port"`
	Checks []Check   `json:"checks"`
	At     time.Time `json:"at"`
}

func Run(ctx context.Context, p profile.Probe) Report {
	r := Report{Host: p.Host, Port: p.Port, At: time.Now().UTC(), Checks: []Check{}}
	if err := profile.ValidateHost(p.Host); err != nil || p.Host == "" {
		if err == nil {
			err = errors.New("probe host is required")
		}
		r.Checks = append(r.Checks, Check{Name: "input", Status: "failed", Detail: err.Error()})
		return r
	}
	if p.Port < 1 || p.Port > 65535 {
		r.Checks = append(r.Checks, Check{Name: "input", Status: "failed", Detail: "invalid port"})
		return r
	}
	timeout := p.TimeoutSeconds
	if timeout < 1 || timeout > 60 {
		timeout = 5
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	start := time.Now()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, p.Host)
	if err != nil {
		r.Checks = append(r.Checks, check("DNS", "failed", start, err.Error()))
		return r
	}
	if len(ips) == 0 {
		r.Checks = append(r.Checks, check("DNS", "failed", start, "no addresses returned"))
		return r
	}
	r.Checks = append(r.Checks, check("DNS", "ok", start, fmt.Sprintf("resolved %d address(es); first %s", len(ips), ips[0].IP)))
	start = time.Now()
	addr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	c, err := (&net.Dialer{Timeout: time.Duration(timeout) * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		r.Checks = append(r.Checks, check("TCP", "failed", start, err.Error()))
		return r
	}
	r.Checks = append(r.Checks, check("TCP", "ok", start, "connection established"))
	if !p.TLS {
		c.Close()
		return r
	}
	start = time.Now()
	tlsConn := tls.Client(c, &tls.Config{ServerName: p.Host, MinVersion: tls.VersionTLS12})
	deadline, _ := ctx.Deadline()
	_ = tlsConn.SetDeadline(deadline)
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		r.Checks = append(r.Checks, check("TLS", "failed", start, err.Error()))
		tlsConn.Close()
		return r
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		err = errors.New("no peer certificate")
	}
	detail := fmt.Sprintf("TLS %x; certificate verified: %v", state.Version, len(state.VerifiedChains) > 0)
	if err != nil {
		r.Checks = append(r.Checks, check("TLS", "failed", start, err.Error()))
	} else {
		r.Checks = append(r.Checks, check("TLS", "ok", start, detail))
	}
	tlsConn.Close()
	return r
}
func check(name, status string, started time.Time, detail string) Check {
	return Check{Name: name, Status: status, DurationMs: time.Since(started).Milliseconds(), Detail: detail}
}
