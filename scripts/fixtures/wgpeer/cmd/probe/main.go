// A small named-process probe for application-routing tests in a disposable VM.
package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

var errNoResponse = errors.New("no network response")

func probeNetworkError(err error) error {
	var op *net.OpError
	var timeout net.Error
	if errors.As(err, &op) || (errors.As(err, &timeout) && timeout.Timeout()) {
		return fmt.Errorf("%w: %v", errNoResponse, err)
	}
	return err
}

func run() error {
	if len(os.Args) != 3 {
		return errors.New("usage: probe http URL | udp ADDRESS")
	}
	switch os.Args[1] {
	case "http":
		client := &http.Client{
			Timeout:   8 * time.Second,
			Transport: &http.Transport{Proxy: nil},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		response, err := client.Get(os.Args[2])
		if err != nil {
			return probeNetworkError(err)
		}
		defer response.Body.Close()
		b, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil {
			return err
		}
		if response.StatusCode != 200 || string(b) != "accessweaver-wireguard-fixture" {
			return errors.New("unexpected HTTP fixture response")
		}
		return nil
	case "udp":
		connection, err := net.DialTimeout("udp", os.Args[2], 5*time.Second)
		if err != nil {
			return probeNetworkError(err)
		}
		defer connection.Close()
		if err = connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		payload := make([]byte, 32)
		if _, err = rand.Read(payload); err != nil {
			return err
		}
		if _, err = connection.Write(payload); err != nil {
			return err
		}
		buffer := make([]byte, 100)
		n, err := connection.Read(buffer)
		if err != nil {
			return probeNetworkError(err)
		}
		if !bytes.Equal(payload, buffer[:n]) {
			return errors.New("UDP echo differs")
		}
		return nil
	default:
		return errors.New("unknown probe protocol")
	}
}
func main() {
	if err := run(); err != nil {
		if errors.Is(err, errNoResponse) {
			fmt.Println("NO_RESPONSE")
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("PASS")
}
