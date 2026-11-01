package api

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/diagnostics"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

func TestDiagnosticAPIKeepsFlatProbeCompatibility(t *testing.T) {
	server := makeServer(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := listener.Accept()
		if e == nil {
			c.Close()
		}
	}()
	response := request(t, server, "POST", "/api/v1/diagnose", profile.Probe{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, TimeoutSeconds: 2}, server.Token, "127.0.0.1:54321")
	var report diagnostics.Report
	if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil || response.Code != 200 || !report.Passed() || report.Path != "direct" || report.Transport != "tcp" {
		t.Fatalf("legacy flat probe: %d %s %v", response.Code, response.Body.String(), err)
	}
	listener.Close()
	<-done
}
func TestDiagnosticAPIHonorsInjectedGuardDuringProbe(t *testing.T) {
	server := makeServer(t)
	authority := apiPolicy(t, managed.Policy{AllowDiagnostics: true})
	var revoked atomic.Bool
	server.Policy = managed.NewGuard(func() (*managed.Authority, error) {
		if revoked.Load() {
			return nil, managed.ErrUnavailable
		}
		return authority, nil
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		c, e := listener.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		var greeting [3]byte
		if _, e = io.ReadFull(c, greeting[:]); e != nil {
			done <- e
			return
		}
		revoked.Store(true)
		var b [1]byte
		_, e = c.Read(b[:])
		done <- e
	}()
	response := request(t, server, "POST", "/api/v1/diagnose", diagnostics.Request{Probe: profile.Probe{Host: "remote.invalid", Port: 443, TimeoutSeconds: 5}, Path: "socks5", Proxy: listener.Addr().String()}, server.Token, "127.0.0.1:54321")
	if response.Code != http.StatusForbidden {
		t.Fatalf("policy revocation returned %d %s", response.Code, response.Body.String())
	}
	if e := <-done; e != io.EOF {
		t.Fatalf("active probe socket did not close: %v", e)
	}
}
