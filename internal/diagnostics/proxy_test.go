package diagnostics

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

func tcpFixture(t *testing.T, serve func(net.Conn) error) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(8 * time.Second))
			err = serve(c)
		}
		done <- err
	}()
	t.Cleanup(func() {
		listener.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
		case <-time.After(9 * time.Second):
			t.Error("fixture did not terminate")
		}
	})
	return listener.Addr().String()
}
func socksFixtureRequest(c net.Conn, command byte, target string, port int) error {
	var greeting [3]byte
	if _, err := io.ReadFull(c, greeting[:]); err != nil {
		return err
	}
	if greeting != [3]byte{5, 1, 0} {
		return fmt.Errorf("unexpected greeting %v", greeting)
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return err
	}
	var header [3]byte
	if _, err := io.ReadFull(c, header[:]); err != nil {
		return err
	}
	host, n, err := readSocksAddress(c)
	if err != nil {
		return err
	}
	if header != [3]byte{5, command, 0} || host != target || n != port {
		return fmt.Errorf("unexpected SOCKS request %v %s:%d", header, host, n)
	}
	return nil
}
func proxyOnlyResolver(ctx context.Context, host string) ([]net.IPAddr, error) {
	if host != "127.0.0.1" {
		return nil, fmt.Errorf("destination DNS must remain at proxy: %s", host)
	}
	return []net.IPAddr{{IP: net.ParseIP(host)}}, nil
}
func trustedTLSFixture(t *testing.T) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "AccessWeaver local test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"example.com"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}}, MinVersion: tls.VersionTLS12}
	target.StartTLS()
	t.Cleanup(target.Close)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	c, err := tls.Dial("tcp", target.Listener.Addr().String(), &tls.Config{ServerName: "example.com", RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err != nil {
		var verify *tls.CertificateVerificationError
		if errors.As(err, &verify) && len(verify.UnverifiedCertificates) > 0 {
			t.Fatalf("local TLS fixture rejected: %v; received issuer=%s; expected issuer=%s", err, verify.UnverifiedCertificates[0].Issuer, ca.Subject)
		}
		t.Fatal(err)
	}
	c.Close()
	return target, roots
}
func TestProxyTLSChecksTargetWithoutLocalDestinationDNS(t *testing.T) {
	target, roots := trustedTLSFixture(t)
	defer target.Close()
	for _, mode := range []string{"socks5", "http-connect"} {
		t.Run(mode, func(t *testing.T) {
			proxy := tcpFixture(t, func(c net.Conn) error {
				if mode == "socks5" {
					if err := socksFixtureRequest(c, 1, "example.com", 443); err != nil {
						return err
					}
					if _, err := c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1}); err != nil {
						return err
					}
				} else {
					req, err := http.ReadRequest(bufio.NewReader(c))
					if err != nil {
						return err
					}
					if req.Method != "CONNECT" || req.Host != "example.com:443" {
						return fmt.Errorf("unexpected CONNECT %v", req)
					}
					if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
						return err
					}
				}
				upstream, err := net.Dial("tcp", target.Listener.Addr().String())
				if err != nil {
					return err
				}
				defer upstream.Close()
				done := make(chan struct{})
				go func() { io.Copy(upstream, c); upstream.Close(); close(done) }()
				io.Copy(c, upstream)
				c.Close()
				<-done
				return nil
			})
			input := Request{Probe: profile.Probe{Host: "example.com", Port: 443, TLS: true, TimeoutSeconds: 3}, Path: mode, Proxy: proxy}
			r, err := (runner{lookup: proxyOnlyResolver, tlsRoots: roots}).diagnose(context.Background(), input, nil)
			if err != nil || !r.Passed() || len(r.Checks) != 3 || r.Path != mode || r.Checks[2].Name != "TLS" {
				t.Fatalf("probe: %+v %v", r, err)
			}
		})
	}
}
func TestHTTPConnectRetainsEarlyAndLargeTunnelPayload(t *testing.T) {
	for _, status := range []string{"200 OK", "201 Created"} {
		t.Run(status, func(t *testing.T) {
			payload := bytes.Repeat([]byte("payload"), 10000)
			proxy := tcpFixture(t, func(c net.Conn) error {
				if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
					return err
				}
				_, err := c.Write(append([]byte("HTTP/1.1 "+status+"\r\nContent-Length: 1\r\n\r\n"), payload...))
				return err
			})
			c, err := net.Dial("tcp", proxy)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			tunnel, err := httpConnect(c, "example.com", 443)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(tunnel)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("tunnel lost bytes: %d %v", len(got), err)
			}
		})
	}
}
func TestProxyProtocolFailuresDoNotFallBack(t *testing.T) {
	cases := []struct{ name, path, response string }{
		{"auth", "http-connect", "HTTP/1.1 407 Authentication Required\r\n\r\n"},
		{"denied", "http-connect", "HTTP/1.1 403 Forbidden\r\n\r\n"},
		{"malformed", "http-connect", "not HTTP\r\n\r\n"},
		{"oversized", "http-connect", "HTTP/1.1 200 OK\r\nX: " + strings.Repeat("a", 17000) + "\r\n\r\n"},
		{"socks auth", "socks5", string([]byte{5, 2})},
		{"socks version", "socks5", string([]byte{4, 0})},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			proxy := tcpFixture(t, func(c net.Conn) error {
				if tt.path == "http-connect" {
					if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
						return err
					}
				} else {
					var greeting [3]byte
					if _, err := io.ReadFull(c, greeting[:]); err != nil {
						return err
					}
				}
				_, _ = io.WriteString(c, tt.response)
				return nil
			})
			r, err := (runner{lookup: proxyOnlyResolver}).diagnose(context.Background(), Request{Probe: profile.Probe{Host: "remote.invalid", Port: 443, TimeoutSeconds: 2}, Path: tt.path, Proxy: proxy}, nil)
			if err != nil || r.Passed() || len(r.Checks) != 1 || r.Checks[0].Name != "Proxy" {
				t.Fatalf("unexpected result %+v %v", r, err)
			}
		})
	}
}
func TestActiveDiagnosticPolicyFailureClosesSocket(t *testing.T) {
	var unavailable atomic.Bool
	guard := managed.NewGuard(func() (*managed.Authority, error) {
		if unavailable.Load() {
			return nil, managed.ErrUnavailable
		}
		return nil, nil
	})
	proxy := tcpFixture(t, func(c net.Conn) error {
		var greeting [3]byte
		if _, err := io.ReadFull(c, greeting[:]); err != nil {
			return err
		}
		unavailable.Store(true)
		var b [1]byte
		_, err := c.Read(b[:])
		if err != io.EOF {
			return fmt.Errorf("probe connection remained open: %v", err)
		}
		return nil
	})
	started := time.Now()
	r, err := Diagnose(context.Background(), Request{Probe: profile.Probe{Host: "remote.invalid", Port: 443, TimeoutSeconds: 5}, Path: "socks5", Proxy: proxy}, guard)
	if !managed.IsPolicyError(err) || r.Passed() || time.Since(started) > 3*time.Second {
		t.Fatalf("policy failure did not cancel probe: %+v %v", r, err)
	}
}
func TestDiagnosticInputMatrix(t *testing.T) {
	for _, tt := range []Request{
		{Probe: profile.Probe{Host: "example.com", Port: 0}},
		{Probe: profile.Probe{Host: "example.com", Port: 443, TimeoutSeconds: 61}},
		{Probe: profile.Probe{Host: "example.com", Port: 443}, Path: "unknown"},
		{Probe: profile.Probe{Host: "example.com", Port: 443}, Transport: "udp"},
		{Probe: profile.Probe{Host: "example.com", Port: 443}, Proxy: "localhost:1080"},
		{Probe: profile.Probe{Host: "example.com", Port: 443}, Path: "socks5", Proxy: "http://localhost:1080"},
		{Probe: profile.Probe{Host: "example.com", Port: 443}, Path: "socks5", Proxy: "user:password@localhost:1080"},
		{Probe: profile.Probe{Host: "example.com", Port: 443, TLS: true}, Transport: "stun"},
		{Probe: profile.Probe{Host: "example.com", Port: 443}, Transport: "stun", Path: "http-connect", Proxy: "localhost:8080"},
	} {
		r, err := Diagnose(context.Background(), tt, nil)
		if err != nil || r.Passed() || len(r.Checks) != 1 || r.Checks[0].Name != "input" {
			t.Fatalf("input accepted: %+v %+v %v", tt, r, err)
		}
	}
}
func TestSocksAddressRoundTrip(t *testing.T) {
	for _, host := range []string{"example.com", "127.0.0.1", "2001:db8::1"} {
		b, err := socksAddress(host, 65535)
		if err != nil {
			t.Fatal(err)
		}
		got, port, err := readSocksAddress(bytes.NewReader(b))
		if err != nil || got != host || port != 65535 {
			t.Fatal(got, port, err)
		}
	}
	for _, packet := range [][]byte{{}, {0}, {3, 0}, {1, 127}, {4, 0}} {
		if _, _, err := readSocksAddress(bytes.NewReader(packet)); err == nil {
			t.Fatal("accepted malformed address")
		}
	}
}
func portOf(t *testing.T, address string) int {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
