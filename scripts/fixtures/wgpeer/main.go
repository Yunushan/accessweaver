// Test-only userspace WireGuard endpoint. Never installs an OS tunnel or driver.
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const reply = "accessweaver-wireguard-fixture"
const server4 = "198.51.100.1"
const server6 = "fd42:6177::1"
const client4 = "192.0.2.2"
const client6 = "fd42:6177::2"

// Keep only whether a WireGuard initiation reached the UDP socket, before
// the device authenticates it. Never retain datagrams or endpoint addresses.
type observedBind struct {
	conn.Bind
	initiation atomic.Bool
}

func (b *observedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	receivers, boundPort, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	observed := make([]conn.ReceiveFunc, len(receivers))
	for i, receive := range receivers {
		observed[i] = func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
			count, err := receive(packets, sizes, endpoints)
			if err == nil && !b.initiation.Load() {
				for j, packet := range packets[:count] {
					if sizes[j] == device.MessageInitiationSize &&
						binary.LittleEndian.Uint32(packet[:4]) == device.MessageInitiationType {
						b.initiation.Store(true)
						break
					}
				}
			}
			return count, err
		}
	}
	return observed, boundPort, nil
}

type endpoint struct {
	dev   *device.Device
	stack *netstack.Net
	port  int
	bind  *observedBind
}

func key() (*ecdh.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) }
func start(private *ecdh.PrivateKey, peer []byte, addresses []string, allowed []string, remote string) (*endpoint, error) {
	ips := []netip.Addr{}
	for _, address := range addresses {
		ips = append(ips, netip.MustParseAddr(address))
	}
	tun, stack, err := netstack.CreateNetTUN(ips, nil, 1420)
	if err != nil {
		return nil, err
	}
	bind := &observedBind{Bind: conn.NewDefaultBind()}
	dev := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelError, "fixture: "))
	config := "private_key=" + hex.EncodeToString(private.Bytes()) + "\nlisten_port=0\npublic_key=" + hex.EncodeToString(peer) + "\n"
	for _, prefix := range allowed {
		config += "allowed_ip=" + prefix + "\n"
	}
	if remote != "" {
		config += "endpoint=" + remote + "\npersistent_keepalive_interval=5\n"
	}
	if err = dev.IpcSet(config); err != nil {
		dev.Close()
		return nil, err
	}
	if err = dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	state, err := dev.IpcGet()
	if err != nil {
		dev.Close()
		return nil, err
	}
	port := 0
	for _, line := range strings.Split(state, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			port, _ = strconv.Atoi(strings.TrimPrefix(line, "listen_port="))
		}
	}
	if port == 0 {
		dev.Close()
		return nil, errors.New("endpoint did not bind a UDP port")
	}
	return &endpoint{dev: dev, stack: stack, port: port, bind: bind}, nil
}
func (e *endpoint) serve() error {
	for _, address := range []string{server4, server6} {
		listener, err := e.stack.ListenTCP(&net.TCPAddr{IP: net.ParseIP(address), Port: 8080})
		if err != nil {
			return err
		}
		go http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, reply) }))
		socket, err := e.stack.ListenUDP(&net.UDPAddr{IP: net.ParseIP(address), Port: 7000})
		if err != nil {
			return err
		}
		go func() {
			defer socket.Close()
			buf := make([]byte, 4096)
			for {
				n, from, err := socket.ReadFrom(buf)
				if err != nil {
					return
				}
				_, _ = socket.WriteTo(buf[:n], from)
			}
		}()
	}
	return nil
}
func (e *endpoint) stats() map[string]any {
	result := map[string]any{"initiation_received": e.bind.initiation.Load()}
	state, err := e.dev.IpcGet()
	if err != nil {
		return result
	}
	for _, line := range strings.Split(state, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok && (k == "last_handshake_time_sec" || k == "rx_bytes" || k == "tx_bytes") {
			result[k] = v
		}
	}
	return result
}
func save(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}
func run() error {
	if os.Getenv("ACCESSWEAVER_TEST_VM") != "1" {
		return errors.New("run this test fixture only in a disposable guest with ACCESSWEAVER_TEST_VM=1")
	}
	if len(os.Args) != 3 || (os.Args[1] != "serve" && os.Args[1] != "self-test") {
		return errors.New("usage: wgpeer serve|self-test PRIVATE_GUEST_DIRECTORY")
	}
	dir, err := filepath.Abs(os.Args[2])
	if err != nil {
		return err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	serverKey, err := key()
	if err != nil {
		return err
	}
	clientKey, err := key()
	if err != nil {
		return err
	}
	server, err := start(serverKey, clientKey.PublicKey().Bytes(), []string{server4, server6}, []string{client4 + "/32", client6 + "/128"}, "")
	if err != nil {
		return err
	}
	defer server.dev.Close()
	if err = server.serve(); err != nil {
		return err
	}
	if os.Args[1] == "self-test" {
		client, err := start(clientKey, serverKey.PublicKey().Bytes(), []string{client4, client6}, []string{server4 + "/32", server6 + "/128"}, net.JoinHostPort("127.0.0.1", strconv.Itoa(server.port)))
		if err != nil {
			return err
		}
		defer client.dev.Close()
		for _, address := range []string{server4, server6} {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			connection, err := client.stack.DialContextTCP(ctx, &net.TCPAddr{IP: net.ParseIP(address), Port: 8080})
			cancel()
			if err != nil {
				return err
			}
			_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
			_, err = fmt.Fprintf(connection, "GET / HTTP/1.0\r\nHost: fixture\r\n\r\n")
			if err != nil {
				return err
			}
			body, err := io.ReadAll(connection)
			_ = connection.Close()
			if err != nil || !strings.Contains(string(body), reply) {
				return fmt.Errorf("TCP fixture round trip failed: %v", err)
			}
			udp, err := client.stack.DialUDP(nil, &net.UDPAddr{IP: net.ParseIP(address), Port: 7000})
			if err != nil {
				return err
			}
			_ = udp.SetDeadline(time.Now().Add(10 * time.Second))
			_, err = udp.Write([]byte(reply))
			if err != nil {
				return err
			}
			buffer := make([]byte, 100)
			n, err := udp.Read(buffer)
			_ = udp.Close()
			if err != nil || string(buffer[:n]) != reply {
				return fmt.Errorf("UDP fixture round trip failed: %v", err)
			}
		}
		return save(filepath.Join(dir, "self-test.json"), map[string]any{"passed": true, "tcpIPv4": true, "udpIPv4": true, "tcpIPv6": true, "udpIPv6": true, "peer": server.stats()})
	}
	config := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32, %s/128\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\nAllowedIPs = %s/32, %s/128\nPersistentKeepalive = 5\n", base64.StdEncoding.EncodeToString(clientKey.Bytes()), client4, client6, base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes()), server.port, server4, server6)
	if err = os.WriteFile(filepath.Join(dir, "client.conf"), []byte(config), 0600); err != nil {
		return err
	}
	if err = save(filepath.Join(dir, "ready.json"), map[string]any{"endpoint": "127.0.0.1", "port": server.port}); err != nil {
		return err
	}
	for range time.NewTicker(time.Second).C {
		if err = save(filepath.Join(dir, "traffic.json"), server.stats()); err != nil {
			return err
		}
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
