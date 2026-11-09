// Package direct provides a bounded independent resolver path for hosted diagnostics.
// It never reports names, addresses, response contents, or operating-system errors.
package direct

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
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

// ParseServer accepts a unicast literal; link-local IPv6 requires a numeric scope.
// The input must be obtained privately by the guarded caller.
func ParseServer(text string) (netip.Addr, error) {
	if len(text) == 0 || len(text) > 64 {
		return netip.Addr{}, errors.New("server")
	}
	server, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Addr{}, errors.New("server")
	}
	zone := server.Zone()
	server = server.Unmap()
	if server.IsLinkLocalUnicast() {
		index, err := strconv.ParseUint(zone, 10, 32)
		if !server.Is6() || err != nil || index == 0 || strconv.FormatUint(index, 10) != zone {
			return netip.Addr{}, errors.New("server")
		}
		return server, nil
	}
	if zone != "" || !server.IsGlobalUnicast() {
		return netip.Addr{}, errors.New("server")
	}
	return server, nil
}

// ReadServers accepts only a bounded JSON array of distinct literal servers.
// The array and scope identifiers stay inside the guarded process.
func ReadServers(input io.Reader) ([]netip.Addr, error) {
	if input == nil {
		return nil, errors.New("server-set")
	}
	data, err := io.ReadAll(io.LimitReader(input, 2049))
	if err != nil || len(data) == 0 || len(data) > 2048 {
		return nil, errors.New("server-set")
	}
	var values []string
	if json.Unmarshal(data, &values) != nil || len(values) == 0 || len(values) > 8 {
		return nil, errors.New("server-set")
	}
	out := make([]netip.Addr, 0, len(values))
	seen := make(map[netip.Addr]bool, len(values))
	for _, value := range values {
		address, err := ParseServer(value)
		if err != nil || seen[address] {
			return nil, errors.New("server-set")
		}
		seen[address] = true
		out = append(out, address)
	}
	return out, nil
}

type SetResult struct {
	Total         int `json:"total"`
	Answered      int `json:"answered"`
	Rejected      int `json:"rejected"`
	OtherFailures int `json:"otherFailures"`
}

// QuerySet sends independent queries concurrently and publishes only counts.
// A timeout or ordinary DNS query failure counts as rejection; malformed or
// otherwise unusable responses cannot satisfy a blocked-path control.
func QuerySet(ctx context.Context, servers []netip.Addr) SetResult {
	return querySet(ctx, servers, Query)
}
func querySet(ctx context.Context, servers []netip.Addr, run func(context.Context, netip.Addr, string) Result) SetResult {
	if ctx == nil || run == nil || len(servers) == 0 || len(servers) > 8 {
		return SetResult{}
	}
	results := make([]Result, len(servers))
	var done sync.WaitGroup
	for i, server := range servers {
		done.Add(1)
		go func(i int, server netip.Addr) { defer done.Done(); results[i] = run(ctx, server, "example.net") }(i, server)
	}
	done.Wait()
	summary := SetResult{Total: len(results)}
	for _, result := range results {
		if result.Outcome == "answered" && result.Code == "none" && result.AnswerCount > 0 && result.AnswerCount <= 64 {
			summary.Answered++
		} else if result.Outcome == "refused" && result.AnswerCount == 0 && (result.Code == "timeout" || result.Code == "query-failed") {
			summary.Rejected++
		} else {
			summary.OtherFailures++
		}
	}
	return summary
}

// QueryInput reads only a bounded literal server from a private pipe. The
// caller must enforce the lifetime of the process supplying that pipe.
func QueryInput(ctx context.Context, input io.Reader) Result {
	return queryInput(ctx, input, Query)
}

func queryInput(ctx context.Context, input io.Reader, run func(context.Context, netip.Addr, string) Result) Result {
	refused := Result{Outcome: "refused", Code: "server"}
	if run == nil {
		return refused
	}
	server, err := ReadServer(input)
	if err != nil {
		return refused
	}
	return run(ctx, server, "example.net")
}

// ReadServer reads a single literal, bounded by the caller's process deadline.
func ReadServer(input io.Reader) (netip.Addr, error) {
	if input == nil {
		return netip.Addr{}, errors.New("server")
	}
	data, err := io.ReadAll(io.LimitReader(input, 65))
	if err != nil || len(data) > 64 {
		return netip.Addr{}, errors.New("server")
	}
	return ParseServer(string(data))
}

// TimedPair records monotonic offsets only. Callers must ensure that both
// functions terminate; the hosted parent enforces the process deadline.
type TimedValue[T any] struct {
	StartMicroseconds int64 `json:"startMicroseconds"`
	EndMicroseconds   int64 `json:"endMicroseconds"`
	Value             T     `json:"value"`
}
type TimedPair[A, B any] struct {
	First      TimedValue[A] `json:"first"`
	Second     TimedValue[B] `json:"second"`
	Overlapped bool          `json:"overlapped"`
}

func Concurrent[A, B any](first func() A, second func() B) TimedPair[A, B] {
	var result TimedPair[A, B]
	start := make(chan struct{})
	var ready, done sync.WaitGroup
	ready.Add(2)
	done.Add(2)
	clock := time.Now()
	go func() {
		defer done.Done()
		ready.Done()
		<-start
		result.First.StartMicroseconds = time.Since(clock).Microseconds()
		result.First.Value = first()
		result.First.EndMicroseconds = time.Since(clock).Microseconds()
	}()
	go func() {
		defer done.Done()
		ready.Done()
		<-start
		result.Second.StartMicroseconds = time.Since(clock).Microseconds()
		result.Second.Value = second()
		result.Second.EndMicroseconds = time.Since(clock).Microseconds()
	}()
	ready.Wait()
	close(start)
	done.Wait()
	result.Overlapped = result.First.StartMicroseconds < result.Second.EndMicroseconds && result.Second.StartMicroseconds < result.First.EndMicroseconds
	return result
}

// Query uses Go's DNS protocol client and the specified IP server, avoiding the
// Windows DNS Client service. It is intended for an already-guarded hosted caller.
// Server selection, trial concurrency, process ownership and firewall controls
// are the caller's responsibility. This result cannot qualify a production gate.
func Query(ctx context.Context, server netip.Addr, name string) Result {
	if !server.IsValid() {
		return Result{Outcome: "refused", Code: "server"}
	}
	server, err := ParseServer(server.String())
	if err != nil {
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
