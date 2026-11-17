package api

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDesktopHTTPKeepAliveIdleBudget(t *testing.T) {
	server := makeServer(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("owned loopback listener unavailable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	address, err := server.serveListener(ctx, listener)
	if err != nil {
		cancel()
		t.Fatal("owned desktop listener failed")
	}
	t.Cleanup(func() {
		cancel()
		if server.Wait() != nil {
			t.Error("desktop server did not confirm cleanup")
		}
	})
	authority := strings.TrimPrefix(address, "http://")
	connect := func(t *testing.T) net.Conn {
		t.Helper()
		connection, err := net.DialTimeout("tcp", authority, 2*time.Second)
		if err != nil {
			t.Fatal("owned connection unavailable")
		}
		t.Cleanup(func() {
			if connection.Close() != nil {
				t.Error("owned client close unconfirmed")
			}
		})
		if connection.SetDeadline(time.Now().Add(12*time.Second)) != nil {
			t.Fatal("client deadline unavailable")
		}
		return connection
	}
	response := func(t *testing.T, connection net.Conn, method string, status int) {
		t.Helper()
		result, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: method})
		if err != nil {
			t.Fatal("owned HTTP response unavailable")
		}
		content, readErr := io.ReadAll(io.LimitReader(result.Body, (64<<10)+1))
		closeErr := result.Body.Close()
		if readErr != nil || closeErr != nil || len(content) > 64<<10 || result.StatusCode != status || result.Close {
			t.Fatal("owned response did not complete as a keep-alive exchange")
		}
	}
	t.Run("unused-connection-expires", func(t *testing.T) {
		t.Parallel()
		connection := connect(t)
		if _, err := fmt.Fprintf(connection, "GET /api/v1/runtime HTTP/1.1\r\nHost: %s\r\nX-AccessWeaver-Token: %s\r\n\r\n", authority, server.Token); err != nil {
			t.Fatal("owned request failed")
		}
		response(t, connection, http.MethodGet, http.StatusOK)
		if connection.SetReadDeadline(time.Now().Add(time.Second)) != nil {
			t.Fatal("short observation deadline failed")
		}
		var one [1]byte
		n, err := connection.Read(one[:])
		var timeout net.Error
		if n != 0 || !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatal("keep-alive connection was not reusable during its idle allowance")
		}
		if connection.SetReadDeadline(time.Now().Add(2*time.Second)) != nil {
			t.Fatal("reuse response deadline failed")
		}
		if _, err := fmt.Fprintf(connection, "GET /api/v1/runtime HTTP/1.1\r\nHost: %s\r\nX-AccessWeaver-Token: %s\r\n\r\n", authority, server.Token); err != nil {
			t.Fatal("idle connection could not be reused")
		}
		response(t, connection, http.MethodGet, http.StatusOK)
		if connection.SetReadDeadline(time.Now().Add(7*time.Second)) != nil {
			t.Fatal("idle completion deadline failed")
		}
		n, err = connection.Read(one[:])
		if n != 0 || !errors.Is(err, io.EOF) {
			t.Fatal("unused desktop keep-alive connection exceeded its idle budget")
		}
	})
	t.Run("active-request-outlives-idle-allowance", func(t *testing.T) {
		t.Parallel()
		connection := connect(t)
		if _, err := fmt.Fprintf(connection, "POST /api/v1/preview HTTP/1.1\r\nHost: %s\r\nX-AccessWeaver-Token: %s\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{", authority, server.Token); err != nil {
			t.Fatal("partial owned request failed")
		}
		// The request is active and remains within the existing twenty-second read
		// allowance. Only an idle connection should expire at five seconds.
		time.Sleep(6 * time.Second)
		if _, err := connection.Write([]byte{'!'}); err != nil {
			t.Fatal("idle policy interrupted an active request")
		}
		response(t, connection, http.MethodPost, http.StatusBadRequest)
	})
}
