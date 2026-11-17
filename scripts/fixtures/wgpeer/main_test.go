package main

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

type fixtureBind struct {
	conn.Bind
	receive conn.ReceiveFunc
}

func (b fixtureBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{b.receive}, 12345, nil
}

func TestPeerHost(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "default loopback", want: "127.0.0.1"},
		{name: "private address", args: []string{"172.31.4.5"}, want: "172.31.4.5"},
		{name: "loopback argument", args: []string{"127.0.0.1"}},
		{name: "public address", args: []string{"198.51.100.5"}},
		{name: "IPv6", args: []string{"fd42::1"}},
		{name: "hostname", args: []string{"fixture.invalid"}},
		{name: "extra address", args: []string{"10.0.0.1", "10.0.0.2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := peerHost(tc.args)
			if got != tc.want || (err == nil) != (tc.want != "") {
				t.Fatalf("peerHost() = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestObservedBind(t *testing.T) {
	packet := make([]byte, device.MessageInitiationSize)
	for _, test := range []struct {
		name string
		kind uint32
		size int
		err  error
		want bool
	}{
		{name: "initiation", kind: device.MessageInitiationType, size: len(packet), want: true},
		{name: "short", kind: device.MessageInitiationType, size: 4},
		{name: "wrong type", kind: device.MessageResponseType, size: len(packet)},
		{name: "empty batch entry", kind: device.MessageInitiationType},
		{name: "closed", kind: device.MessageInitiationType, size: len(packet), err: net.ErrClosed},
	} {
		t.Run(test.name, func(t *testing.T) {
			underlying := fixtureBind{receive: func(packets [][]byte, sizes []int, _ []conn.Endpoint) (int, error) {
				binary.LittleEndian.PutUint32(packets[0][:4], test.kind)
				sizes[0] = test.size
				return 1, test.err
			}}
			bind := &observedBind{Bind: underlying}
			fns, port, err := bind.Open(0)
			if err != nil || port != 12345 || len(fns) != 1 {
				t.Fatalf("Open did not return the wrapped receiver and port: %v", err)
			}
			sizes := make([]int, 1)
			count, err := fns[0]([][]byte{packet}, sizes, make([]conn.Endpoint, 1))
			if count != 1 || err != test.err || sizes[0] != test.size {
				t.Fatal("receiver changed the underlying result")
			}
			if got := bind.initiation.Load(); got != test.want {
				t.Fatalf("initiation observed = %t, want %t", got, test.want)
			}
		})
	}
}
