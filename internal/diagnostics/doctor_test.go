package diagnostics

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/Yunushan/accessweaver/internal/profile"
)

func TestRejectInvalidInputs(t *testing.T) {
	for _, host := range []string{"", "example.org;bad", "^example.com", "https://example.com", "1:::2"} {
		report := Run(context.Background(), profile.Probe{Host: host, Port: 443})
		if len(report.Checks) != 1 || report.Checks[0].Name != "input" || report.Checks[0].Status != "failed" {
			t.Fatalf("invalid host %q was not rejected: %+v", host, report)
		}
	}
}

func TestLocalIPv4AndIPv6TCP(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
			if err != nil {
				if host == "::1" {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				c, e := listener.Accept()
				if e == nil {
					c.Close()
				}
			}()
			r := Run(context.Background(), profile.Probe{Host: host, Port: listener.Addr().(*net.TCPAddr).Port, TimeoutSeconds: 2})
			if len(r.Checks) != 2 || r.Checks[1].Status != "ok" {
				t.Fatalf("TCP probe: %+v", r)
			}
		})
	}
}

func TestTLSRejectsUntrustedCertificate(t *testing.T) {
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	s.StartTLS()
	defer s.Close()
	host, port, _ := net.SplitHostPort(s.Listener.Addr().String())
	n, _ := strconv.Atoi(port)
	r := Run(context.Background(), profile.Probe{Host: host, Port: n, TLS: true, TimeoutSeconds: 2})
	if len(r.Checks) != 3 || r.Checks[2].Name != "TLS" || r.Checks[2].Status != "failed" {
		t.Fatalf("untrusted certificate accepted: %+v", r)
	}
}
