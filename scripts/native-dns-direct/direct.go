// Package direct provides a bounded independent resolver path for hosted diagnostics.
// It never reports names, addresses, response contents, or operating-system errors.
package direct

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

type Result struct {
	Outcome     string `json:"outcome"`
	Code        string `json:"code"`
	AnswerCount int    `json:"answerCount"`
}

type lookupFunc func(context.Context, string) ([]net.IPAddr, error)

func allowedName(name string) bool {
	return name == "example.com" || name == "example.net" || name == "example.org"
}

// ParseServer accepts only a single literal unicast address without a scope.
// The input must be obtained privately by the guarded caller.
func ParseServer(text string) (netip.Addr, error) {
	if len(text) == 0 || len(text) > 64 {
		return netip.Addr{}, errors.New("server")
	}
	server, err := netip.ParseAddr(text)
	if err != nil || server.Zone() != "" {
		return netip.Addr{}, errors.New("server")
	}
	server = server.Unmap()
	if !server.IsGlobalUnicast() || server.IsLinkLocalUnicast() {
		return netip.Addr{}, errors.New("server")
	}
	return server, nil
}

// QueryInput reads only a bounded literal server from a private pipe. The
// caller must enforce the lifetime of the process supplying that pipe.
func QueryInput(ctx context.Context, input io.Reader) Result {
	return queryInput(ctx, input, Query)
}

func queryInput(ctx context.Context, input io.Reader, run func(context.Context, netip.Addr, string) Result) Result {
	refused := Result{Outcome: "refused", Code: "server"}
	if input == nil || run == nil {
		return refused
	}
	data, err := io.ReadAll(io.LimitReader(input, 65))
	if err != nil || len(data) > 64 {
		return refused
	}
	server, err := ParseServer(string(data))
	if err != nil {
		return refused
	}
	return run(ctx, server, "example.net")
}

// Query uses Go's DNS protocol client and the specified IP server, avoiding the
// Windows DNS Client service. It is intended for an already-guarded hosted caller.
// Server selection, trial concurrency, process ownership and firewall controls
// are the caller's responsibility. This result cannot qualify a production gate.
func Query(ctx context.Context, server netip.Addr, name string) Result {
	if !server.IsValid() || server.Zone() != "" {
		return Result{Outcome: "refused", Code: "server"}
	}
	server = server.Unmap()
	if !server.IsGlobalUnicast() || server.IsLinkLocalUnicast() {
		return Result{Outcome: "refused", Code: "server"}
	}
	endpoint := net.JoinHostPort(server.String(), strconv.Itoa(53))
	resolver := &net.Resolver{PreferGo: true, StrictErrors: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "udp" && network != "tcp" {
			return nil, errors.New("unsupported transport")
		}
		return (&net.Dialer{}).DialContext(ctx, network, endpoint)
	}}
	return query(ctx, name, func(ctx context.Context, name string) ([]net.IPAddr, error) {
		ips, err := resolver.LookupIP(ctx, "ip4", name)
		addresses := make([]net.IPAddr, len(ips))
		for i, ip := range ips {
			addresses[i] = net.IPAddr{IP: ip}
		}
		return addresses, err
	})
}

func query(parent context.Context, name string, lookup lookupFunc) Result {
	if parent == nil || !allowedName(name) || lookup == nil {
		return Result{Outcome: "refused", Code: "arguments"}
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	addresses, err := lookup(ctx, name+".")
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Result{Outcome: "refused", Code: "timeout"}
		}
		if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			return Result{Outcome: "refused", Code: "cancelled"}
		}
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			return Result{Outcome: "refused", Code: "timeout"}
		}
		return Result{Outcome: "refused", Code: "query-failed"}
	}
	if len(addresses) == 0 || len(addresses) > 64 {
		return Result{Outcome: "refused", Code: "answer-bound"}
	}
	count := 0
	for _, address := range addresses {
		ip, ok := netip.AddrFromSlice(address.IP)
		if !ok || address.Zone != "" || !ip.Unmap().IsGlobalUnicast() {
			return Result{Outcome: "refused", Code: "answer-shape"}
		}
		if ip.Unmap().Is4() {
			count++
		}
	}
	if count == 0 {
		return Result{Outcome: "refused", Code: "no-ipv4"}
	}
	return Result{Outcome: "answered", Code: "none", AnswerCount: count}
}
