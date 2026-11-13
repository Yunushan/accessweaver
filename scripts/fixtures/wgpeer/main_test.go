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
