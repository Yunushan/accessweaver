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

func run() error {
	if len(os.Args) != 3 {
		return errors.New("usage: probe http URL | udp ADDRESS")
	}
	switch os.Args[1] {
	case "http":
		client := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{Proxy: nil}}
		response, err := client.Get(os.Args[2])
		if err != nil {
			return err
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
			return err
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
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
			return err
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
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("PASS")
}
