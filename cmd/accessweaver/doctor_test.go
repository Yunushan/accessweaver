package main

import (
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestDoctorOptions(t *testing.T) {
	for _, args := range [][]string{{"--transport", "stun"}, {"--unknown"}, {"one", "two"}, {"example.com", "--path", "socks5"}} {
		if _, err := doctorRequest(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	input, err := doctorRequest([]string{"--path", "socks5", "--proxy", "127.0.0.1:1080", "--transport", "stun", "stun.example.com"})
	if err != nil || input.TLS || input.Port != 3478 || input.Host != "stun.example.com" || input.Path != "socks5" {
		t.Fatal(input, err)
	}
	input, err = doctorRequest([]string{"--transport", "stun", "--port", "5000", "--tls=true", "stun.example.com"})
	if err != nil || !input.TLS || input.Port != 5000 {
		t.Fatal(input, err)
	}
	input, err = doctorRequest(nil)
	if err != nil || !input.TLS || input.Port != 443 || input.Path != "direct" {
		t.Fatal(input, err)
	}
}
func TestDoctorFailureStatusAndJSON(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	output, err := os.CreateTemp(t.TempDir(), "doctor")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	previous := os.Stdout
	os.Stdout = output
	defer func() { os.Stdout = previous }()
	err = doctorCommand([]string{"--tls=false", "--port", strconv.Itoa(port), "127.0.0.1"})
	if err == nil {
		t.Fatal("failed TCP probe returned success")
	}
	if _, err := output.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(output)
	if err != nil || !strings.Contains(string(data), `"status": "failed"`) || !strings.Contains(string(data), `"path": "direct"`) {
		t.Fatalf("missing failure report %s %v", data, err)
	}
}
