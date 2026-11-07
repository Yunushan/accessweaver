package diagnostics

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

func stunReply(request []byte, ip net.IP, port int, fingerprint bool) []byte {
	p := append([]byte(nil), request...)
	binary.BigEndian.PutUint16(p, 0x0101)
	address := ip.To4()
	family := byte(1)
	if address == nil {
		address = ip.To16()
		family = 2
	}
	v := []byte{0, family, 0, 0}
	binary.BigEndian.PutUint16(v[2:], uint16(port)^uint16(stunCookie>>16))
	for i, b := range address {
		v = append(v, b^request[4+i])
	}
	p = binary.BigEndian.AppendUint16(p, 0x0020)
	p = binary.BigEndian.AppendUint16(p, uint16(len(v)))
	p = append(p, v...)
	if fingerprint {
		binary.BigEndian.PutUint16(p[2:], uint16(len(p)-20+8))
		sum := crc32.ChecksumIEEE(p) ^ 0x5354554e
		p = append(p, 0x80, 0x28, 0, 4)
		p = binary.BigEndian.AppendUint32(p, sum)
	} else {
		binary.BigEndian.PutUint16(p[2:], uint16(len(p)-20))
	}
	return p
}
func TestBindingResponseValidation(t *testing.T) {
	request, err := bindingRequest()
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"203.0.113.7", "2001:db8::123"} {
		for _, fingerprint := range []bool{true, false} {
			got, err := bindingResponse(stunReply(request, net.ParseIP(ip), 49152, fingerprint), request)
			if err != nil || got != net.JoinHostPort(ip, "49152") {
				t.Fatal(got, err)
			}
		}
	}
	valid := stunReply(request, net.ParseIP("203.0.113.7"), 49152, true)
	for _, mutate := range []func([]byte) []byte{
		func(p []byte) []byte { return p[:19] },
		func(p []byte) []byte { p[8] ^= 1; return p },
		func(p []byte) []byte { p[4] ^= 1; return p },
		func(p []byte) []byte { p[0] = 0; return p },
		func(p []byte) []byte { p[2] = 1; return p },
		func(p []byte) []byte { p[len(p)-1] ^= 1; return p },
		func(p []byte) []byte { p[20] = 0; p[21] = 0x7f; return p },
		func(p []byte) []byte { p[23] = 255; return p },
		func(p []byte) []byte { p[25] = 3; return p },
		func(p []byte) []byte { return append(p, make([]byte, 4096)...) },
	} {
		if _, err := bindingResponse(mutate(bytes.Clone(valid)), request); err == nil {
			t.Fatal("accepted invalid binding response")
		}
	}
	// No mapped address, duplicate mapped address, or unsupported mandatory data.
	for _, attrs := range [][]byte{{}, append(bytes.Clone(valid[20:32]), valid[20:32]...), append(bytes.Clone(valid[20:32]), 0, 0x7f, 0, 0)} {
		p := append(bytes.Clone(request), attrs...)
		binary.BigEndian.PutUint16(p, 0x0101)
		binary.BigEndian.PutUint16(p[2:], uint16(len(attrs)))
		if _, err := bindingResponse(p, request); err == nil {
			t.Fatal("accepted missing, duplicate or unknown mandatory attribute")
		}
	}
}
func FuzzBindingResponse(f *testing.F) {
	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request, 1)
	binary.BigEndian.PutUint32(request[4:], stunCookie)
	for _, ip := range []string{"203.0.113.7", "2001:db8::123"} {
		for _, fingerprint := range []bool{false, true} {
			f.Add(stunReply(request, net.ParseIP(ip), 49152, fingerprint))
		}
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, p []byte) {
		before := bytes.Clone(p)
		mapped, err := bindingResponse(p, request)
		if !bytes.Equal(before, p) {
			t.Fatal("STUN parser changed input bytes")
		}
		if err == nil {
			host, port, e := net.SplitHostPort(mapped)
			n, _ := strconv.Atoi(port)
			if e != nil || net.ParseIP(host) == nil || n < 1 || n > 65535 {
				t.Fatalf("invalid mapped endpoint %q", mapped)
			}
		}
	})
}
func udpFixture(t *testing.T, serve func([]byte) ([]byte, error)) string {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		buffer := make([]byte, 8192)
		n, addr, err := c.ReadFromUDP(buffer)
		if err == nil {
			var reply []byte
			reply, err = serve(buffer[:n])
			if err == nil {
				_, err = c.WriteToUDP(reply, addr)
			}
		}
		done <- err
	}()
	t.Cleanup(func() {
		c.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(6 * time.Second):
			t.Error("UDP fixture did not terminate")
		}
	})
	return c.LocalAddr().String()
}
func TestDirectSTUNExchange(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprint(malformed), func(t *testing.T) {
			endpoint := udpFixture(t, func(request []byte) ([]byte, error) {
				if len(request) != 20 || binary.BigEndian.Uint16(request) != 1 {
					return nil, fmt.Errorf("unexpected request %x", request)
				}
				response := stunReply(request, net.ParseIP("203.0.113.7"), 49152, true)
				if malformed {
					response[8] ^= 1
				}
				return response, nil
			})
			r, err := Diagnose(context.Background(), Request{Probe: profile.Probe{Host: "127.0.0.1", Port: portOf(t, endpoint), TimeoutSeconds: 2}, Transport: "stun"}, nil)
			if err != nil || r.Passed() == malformed || len(r.Checks) != 1 || r.Transport != "stun" {
				t.Fatalf("STUN %+v %v", r, err)
			}
		})
	}
}
func TestSocksUDPExchangeDelegatesTargetDNS(t *testing.T) {
	for _, wrongSource := range []bool{false, true} {
		t.Run(fmt.Sprint(wrongSource), func(t *testing.T) {
			endpoint := udpFixture(t, func(packet []byte) ([]byte, error) {
				if len(packet) < 4 || !bytes.Equal(packet[:3], []byte{0, 0, 0}) {
					return nil, fmt.Errorf("invalid UDP encapsulation")
				}
				reader := bytes.NewReader(packet[3:])
				host, port, err := readSocksAddress(reader)
				if err != nil {
					return nil, err
				}
				if host != "remote.invalid" || port != 3478 {
					return nil, fmt.Errorf("destination changed %s:%d", host, port)
				}
				request := packet[len(packet)-reader.Len():]
				if len(request) != 20 {
					return nil, fmt.Errorf("invalid binding request")
				}
				if wrongSource {
					port++
				}
				source, _ := socksAddress("192.0.2.10", port)
				return append(append([]byte{0, 0, 0}, source...), stunReply(request, net.ParseIP("203.0.113.7"), 49152, true)...), nil
			})
			proxy := tcpFixture(t, func(c net.Conn) error {
				if err := socksFixtureRequest(c, 3, "0.0.0.0", 0); err != nil {
					return err
				}
				bound, _ := socksAddress("0.0.0.0", portOf(t, endpoint))
				if _, err := c.Write(append([]byte{5, 0, 0}, bound...)); err != nil {
					return err
				}
				_, err := io.Copy(io.Discard, c)
				return err
			})
			r, err := (runner{lookup: proxyOnlyResolver}).diagnose(context.Background(), Request{Probe: profile.Probe{Host: "remote.invalid", Port: 3478, TimeoutSeconds: 2}, Transport: "stun", Path: "socks5", Proxy: proxy}, nil)
			if err != nil || r.Passed() == wrongSource || len(r.Checks) != 2 {
				t.Fatalf("SOCKS UDP %+v %v", r, err)
			}
		})
	}
}
func TestSTUNTimeout(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	r, err := Diagnose(context.Background(), Request{Probe: profile.Probe{Host: "127.0.0.1", Port: c.LocalAddr().(*net.UDPAddr).Port, TimeoutSeconds: 1}, Transport: "stun"}, nil)
	if err != nil || r.Passed() || time.Since(start) > 3*time.Second {
		t.Fatalf("STUN timeout %+v %v", r, err)
	}
}

func TestActiveUDPDiagnosticPolicyFailureInterruptsRead(t *testing.T) {
	var unavailable atomic.Bool
	guard := managed.NewGuard(func() (*managed.Authority, error) {
		if unavailable.Load() {
			return nil, managed.ErrUnavailable
		}
		return nil, nil
	})
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan error, 1)
	go func() {
		_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
		b := make([]byte, 1024)
		_, _, err := c.ReadFromUDP(b)
		unavailable.Store(true)
		done <- err
	}()
	started := time.Now()
	r, err := Diagnose(context.Background(), Request{Probe: profile.Probe{Host: "127.0.0.1", Port: c.LocalAddr().(*net.UDPAddr).Port, TimeoutSeconds: 5}, Transport: "stun"}, guard)
	if !managed.IsPolicyError(err) || r.Passed() || time.Since(started) > 3*time.Second {
		t.Fatalf("UDP policy failure did not interrupt read: %+v %v", r, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
