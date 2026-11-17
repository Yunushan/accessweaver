package diagnostics

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"strconv"
	"strings"
	"time"
)

const stunCookie uint32 = 0x2112a442
const maxStunPacket = 4096

func bindingRequest() ([]byte, error) {
	packet := make([]byte, 20)
	binary.BigEndian.PutUint16(packet, 1)
	binary.BigEndian.PutUint32(packet[4:8], stunCookie)
	_, err := rand.Read(packet[8:20])
	return packet, err
}
func bindingResponse(packet, request []byte) (string, error) {
	if len(packet) < 20 || len(packet) > maxStunPacket || len(request) != 20 || binary.BigEndian.Uint16(packet) != 0x0101 || binary.BigEndian.Uint32(packet[4:8]) != stunCookie || !bytes.Equal(packet[8:20], request[8:20]) {
		return "", errors.New("invalid STUN binding response or transaction")
	}
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	if length%4 != 0 || length != len(packet)-20 {
		return "", errors.New("invalid STUN message length")
	}
	mapped := ""
	fingerprint := false
	for offset := 20; offset < len(packet); {
		if offset+4 > len(packet) {
			return "", errors.New("truncated STUN attribute")
		}
		kind := binary.BigEndian.Uint16(packet[offset:])
		size := int(binary.BigEndian.Uint16(packet[offset+2:]))
		end := offset + 4 + size
		if end > len(packet) {
			return "", errors.New("truncated STUN attribute data")
		}
		value := packet[offset+4 : end]
		switch kind {
		case 0x0020:
			if mapped != "" || len(value) < 4 || value[0] != 0 {
				return "", errors.New("invalid or duplicate XOR-MAPPED-ADDRESS")
			}
			port := binary.BigEndian.Uint16(value[2:4]) ^ uint16(stunCookie>>16)
			var ip net.IP
			switch value[1] {
			case 1:
				if len(value) != 8 {
					return "", errors.New("invalid mapped IPv4 address")
				}
				ip = make(net.IP, 4)
				cookie := request[4:8]
				for i := range ip {
					ip[i] = value[4+i] ^ cookie[i]
				}
			case 2:
				if len(value) != 20 {
					return "", errors.New("invalid mapped IPv6 address")
				}
				ip = make(net.IP, 16)
				mask := request[4:20]
				for i := range ip {
					ip[i] = value[4+i] ^ mask[i]
				}
			default:
				return "", errors.New("unsupported mapped address family")
			}
			if port == 0 {
				return "", errors.New("invalid mapped port")
			}
			mapped = net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
		case 0x8028:
			if fingerprint || size != 4 || end != len(packet) || binary.BigEndian.Uint32(value) != (crc32.ChecksumIEEE(packet[:offset])^0x5354554e) {
				return "", errors.New("invalid STUN fingerprint")
			}
			fingerprint = true
		default:
			if kind < 0x8000 {
				return "", errors.New("unknown required STUN attribute")
			}
		}
		offset = end + (4-size%4)%4
		if offset > len(packet) {
			return "", errors.New("truncated STUN attribute padding")
		}
	}
	if mapped == "" {
		return "", errors.New("STUN response has no XOR-MAPPED-ADDRESS")
	}
	return mapped, nil
}
func (d runner) stun(ctx context.Context, input Request, r *Report) {
	start := time.Now()
	var association net.Conn
	target := net.JoinHostPort(input.Host, strconv.Itoa(input.Port))
	endpointHost, endpointPort := input.Host, input.Port
	if input.Path == "socks5" {
		host, port, _ := net.SplitHostPort(input.Proxy)
		n, _ := strconv.Atoi(port)
		var err error
		association, err = d.dial(ctx, "tcp", host, n)
		if err != nil {
			r.Checks = append(r.Checks, check("Proxy", "failed", start, err.Error()))
			return
		}
		defer recordConnectionCleanup(r, closeOnCancel(ctx, association))
		relay, err := socksCommand(association, 3, "0.0.0.0", 0)
		if err != nil {
			r.Checks = append(r.Checks, check("Proxy", "failed", start, err.Error()))
			return
		}
		endpointHost, port, err = net.SplitHostPort(relay)
		if err != nil {
			r.Checks = append(r.Checks, check("Proxy", "failed", start, err.Error()))
			return
		}
		endpointPort, _ = strconv.Atoi(port)
		if endpointPort == 0 {
			r.Checks = append(r.Checks, check("Proxy", "failed", start, "SOCKS5 relay returned port zero"))
			return
		}
		if ip := net.ParseIP(endpointHost); ip != nil && ip.IsUnspecified() {
			endpointHost, _, _ = net.SplitHostPort(association.RemoteAddr().String())
		}
		r.Checks = append(r.Checks, check("Proxy", "ok", start, "SOCKS5 UDP association accepted; target DNS is delegated to the proxy"))
	}
	connection, err := d.dial(ctx, "udp", endpointHost, endpointPort)
	if err != nil {
		r.Checks = append(r.Checks, check("UDP/STUN", "failed", start, err.Error()))
		return
	}
	defer recordConnectionCleanup(r, closeOnCancel(ctx, connection))
	request, err := bindingRequest()
	if err != nil {
		r.Checks = append(r.Checks, check("UDP/STUN", "failed", start, err.Error()))
		return
	}
	packet := request
	if association != nil {
		destination, err := socksAddress(input.Host, input.Port)
		if err != nil {
			r.Checks = append(r.Checks, check("UDP/STUN", "failed", start, err.Error()))
			return
		}
		packet = append(append([]byte{0, 0, 0}, destination...), request...)
	}
	if _, err := connection.Write(packet); err != nil {
		r.Checks = append(r.Checks, check("UDP/STUN", "failed", start, err.Error()))
		return
	}
	buffer := make([]byte, maxStunPacket+263+1)
	count, err := connection.Read(buffer)
	if err != nil {
		r.Checks = append(r.Checks, check("UDP/STUN", "failed", start, err.Error()))
		return
	}
	response := buffer[:count]
	if association != nil {
		if len(response) < 4 || !bytes.Equal(response[:3], []byte{0, 0, 0}) {
			r.Checks = append(r.Checks, check("UDP/STUN", "failed", start, "invalid or fragmented SOCKS5 UDP response"))
			return
		}
		reader := bytes.NewReader(response[3:])
		origin, originPort, err := readSocksAddress(reader)
		if err != nil {
			r.Checks = append(r.Checks, check("UDP/STUN", "failed", start, err.Error()))
			return
		}
		// A proxy can resolve a destination name remotely, but must retain its
		// requested port and any explicit destination IP in the UDP envelope.
		expectedIP, originIP := net.ParseIP(input.Host), net.ParseIP(origin)
		if originPort != input.Port || expectedIP != nil && !expectedIP.Equal(originIP) || expectedIP == nil && originIP == nil && !strings.EqualFold(strings.TrimSuffix(input.Host, "."), strings.TrimSuffix(origin, ".")) {
			r.Checks = append(r.Checks, check("UDP/STUN", "failed", start, "SOCKS5 UDP response source does not match the requested target"))
			return
		}
		response = response[len(response)-reader.Len():]
	}
	mapped, err := bindingResponse(response, request)
	if err != nil {
		r.Checks = append(r.Checks, check("UDP/STUN", "failed", start, err.Error()))
		return
	}
	r.Checks = append(r.Checks, check("UDP/STUN", "ok", start, fmt.Sprintf("one binding exchange with %s; server-reported mapped address %s; server identity is unauthenticated", target, mapped)))
}
