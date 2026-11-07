package diagnostics

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"
)

type addressConnector func(context.Context, string, string) (net.Conn, error)
type addressDialResult struct {
	connection    net.Conn
	err           error
	cleanupFailed bool
}

// Keep native completion causes available to Go callers without publishing
// arbitrary Close/deadline implementation text in a diagnostic report.
type dialCompletionError struct{ cause error }

func (e *dialCompletionError) Error() string { return "diagnostic connection completion failed" }
func (e *dialCompletionError) Unwrap() error { return e.cause }
func completeDialConnection(connection net.Conn) error {
	if err := connection.Close(); err != nil {
		return &dialCompletionError{cause: err}
	}
	return nil
}

// Literal IP dials bypass net.Dialer's hostname-level fast fallback. Keep one
// resolved address set, race at most two TCP families, and complete every loser
// before returning the winning socket. UDP association selection stays serial.
func dialAddressSet(ctx context.Context, network string, addresses []net.IPAddr, port int, connect addressConnector, fallbackDelay time.Duration) (net.Conn, error) {
	if network != "tcp" && network != "udp" {
		return nil, net.UnknownNetworkError(network)
	}
	if len(addresses) == 0 || len(addresses) > 64 || port < 1 || port > 65535 || connect == nil {
		return nil, errors.New("invalid diagnostic address set or port")
	}
	for _, a := range addresses {
		if a.IP.To16() == nil {
			return nil, errors.New("invalid resolved diagnostic IP address")
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	primary := addresses
	var fallback []net.IPAddr
	if network == "tcp" {
		primary = nil
		firstIPv4 := addresses[0].IP.To4() != nil
		for _, a := range addresses {
			if (a.IP.To4() != nil) == firstIPv4 {
				primary = append(primary, a)
			} else {
				fallback = append(fallback, a)
			}
		}
	}
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan addressDialResult, 2)
	var workers sync.WaitGroup
	active := 0
	launch := func(group []net.IPAddr) {
		active++
		workers.Add(1)
		go func() { defer workers.Done(); results <- dialAddressSeries(work, network, group, port, connect) }()
	}
	launch(primary)
	var timer *time.Timer
	var fallbackC <-chan time.Time
	if len(fallback) > 0 {
		timer = time.NewTimer(fallbackDelay)
		fallbackC = timer.C
		defer timer.Stop()
	}
	disableFallback := func() {
		fallback = nil
		fallbackC = nil
		if timer != nil {
			timer.Stop()
		}
	}
	cancelC := ctx.Done()
	var connections []net.Conn
	var failures error
	cleanupFailed := false
	for active > 0 {
		select {
		case <-cancelC:
			cancel()
			cancelC = nil
			disableFallback()
		case <-fallbackC:
			if ctx.Err() == nil {
				launch(fallback)
			}
			disableFallback()
		case result := <-results:
			active--
			failures = errors.Join(failures, result.err)
			if result.cleanupFailed {
				cleanupFailed = true
				cancel()
				disableFallback()
			}
			if result.connection != nil {
				connections = append(connections, result.connection)
				cancel()
				disableFallback()
			}
			if active == 0 && len(connections) == 0 && !cleanupFailed && len(fallback) > 0 && ctx.Err() == nil {
				launch(fallback)
				disableFallback()
			}
		}
	}
	workers.Wait()
	// The first result carrying a socket owns the winning slot. All later
	// sockets must complete their Close even if cancellation arrived too late.
	for _, connection := range connections[min(1, len(connections)):] {
		if err := completeDialConnection(connection); err != nil {
			cleanupFailed = true
			failures = errors.Join(failures, err)
		}
	}
	if err := ctx.Err(); err != nil {
		failures = errors.Join(failures, err)
		cleanupFailed = true
	}
	if len(connections) == 0 {
		if failures == nil {
			failures = errors.New("diagnostic connection could not be established")
		}
		return nil, failures
	}
	winner := connections[0]
	if cleanupFailed {
		return nil, errors.Join(failures, completeDialConnection(winner))
	}
	if limit, ok := ctx.Deadline(); ok {
		if err := winner.SetDeadline(limit); err != nil {
			return nil, &dialCompletionError{cause: errors.Join(failures, err, completeDialConnection(winner))}
		}
	}
	return winner, nil
}

func dialAddressSeries(ctx context.Context, network string, addresses []net.IPAddr, port int, connect addressConnector) addressDialResult {
	var failures error
	for i, address := range addresses {
		if err := ctx.Err(); err != nil {
			return addressDialResult{err: errors.Join(failures, err)}
		}
		attempt := ctx
		cancel := func() {}
		if limit, ok := ctx.Deadline(); ok {
			now := time.Now()
			remaining := limit.Sub(now)
			if remaining <= 0 {
				return addressDialResult{err: errors.Join(failures, context.DeadlineExceeded)}
			}
			// Reserve a fair share for every remaining address in this family. A
			// stalled first candidate must not consume the complete probe budget.
			attempt, cancel = context.WithDeadline(ctx, now.Add(remaining/time.Duration(len(addresses)-i)))
		}
		connection, err := connect(attempt, network, net.JoinHostPort(address.String(), strconv.Itoa(port)))
		cancel()
		if err == nil && connection != nil {
			return addressDialResult{connection: connection}
		}
		if err == nil {
			err = errors.New("diagnostic dial returned no connection")
		}
		failures = errors.Join(failures, err)
		if connection != nil {
			if closeErr := completeDialConnection(connection); closeErr != nil {
				return addressDialResult{err: errors.Join(failures, closeErr), cleanupFailed: true}
			}
		}
	}
	return addressDialResult{err: failures}
}
