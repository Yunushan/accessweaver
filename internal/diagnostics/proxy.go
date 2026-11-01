package diagnostics

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
)

// RFC 1928 only: unauthenticated SOCKS5. No credentials or fallback are sent.
func socksAddress(host string, port int) ([]byte, error) {
	var result []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			result = append([]byte{1}, v4...)
		} else {
			result = append([]byte{4}, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("SOCKS5 target name length is unsupported")
		}
		result = append([]byte{3, byte(len(host))}, []byte(host)...)
	}
	return binary.BigEndian.AppendUint16(result, uint16(port)), nil
}
func readSocksAddress(reader io.Reader) (string, int, error) {
	var kind [1]byte
	if _, err := io.ReadFull(reader, kind[:]); err != nil {
		return "", 0, err
	}
	size := 0
	switch kind[0] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return "", 0, err
		}
		size = int(length[0])
		if size == 0 {
			return "", 0, errors.New("empty SOCKS5 address")
		}
	default:
		return "", 0, errors.New("invalid SOCKS5 address type")
	}
	address := make([]byte, size+2)
	if _, err := io.ReadFull(reader, address); err != nil {
		return "", 0, err
	}
	host := string(address[:size])
	if kind[0] != 3 {
		host = net.IP(address[:size]).String()
	}
	return host, int(binary.BigEndian.Uint16(address[size:])), nil
}
func socksCommand(connection net.Conn, command byte, host string, port int) (string, error) {
	if _, err := connection.Write([]byte{5, 1, 0}); err != nil {
		return "", err
	}
	var method [2]byte
	if _, err := io.ReadFull(connection, method[:]); err != nil {
		return "", err
	}
	if method != [2]byte{5, 0} {
		return "", errors.New("SOCKS5 server did not accept unauthenticated access")
	}
	address, err := socksAddress(host, port)
	if err != nil {
		return "", err
	}
	if _, err := connection.Write(append([]byte{5, command, 0}, address...)); err != nil {
		return "", err
	}
	var reply [3]byte
	if _, err := io.ReadFull(connection, reply[:]); err != nil {
		return "", err
	}
	if reply[0] != 5 || reply[2] != 0 {
		return "", errors.New("invalid SOCKS5 reply")
	}
	if reply[1] != 0 {
		return "", fmt.Errorf("SOCKS5 request rejected with status %d", reply[1])
	}
	bound, boundPort, err := readSocksAddress(connection)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(bound, strconv.Itoa(boundPort)), nil
}

type bufferedTunnel struct {
	net.Conn
	reader *bufio.Reader
}

func (t *bufferedTunnel) Read(data []byte) (int, error) { return t.reader.Read(data) }
func httpConnect(connection net.Conn, host string, port int) (net.Conn, error) {
	authority := net.JoinHostPort(host, strconv.Itoa(port))
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: authority}, Host: authority, Header: make(http.Header)}
	if err := request.Write(connection); err != nil {
		return nil, err
	}
	// Limit untrusted proxy headers before net/http parses them; retain buffered
	// bytes so a server cannot make the tunnel drop early target data.
	reader := bufio.NewReader(connection)
	var headers []byte
	for {
		line, err := reader.ReadSlice('\n')
		if len(headers)+len(line) > 16384 {
			return nil, errors.New("HTTP CONNECT headers exceed 16 KiB")
		}
		headers = append(headers, line...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return nil, err
		}
		if bytes.HasSuffix(headers, []byte("\r\n\r\n")) {
			break
		}
	}
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(headers)), request)
	if err != nil {
		return nil, err
	}
	if response.ProtoMajor != 1 || response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP CONNECT rejected with status %d", response.StatusCode)
	}
	return &bufferedTunnel{Conn: connection, reader: reader}, nil
}
