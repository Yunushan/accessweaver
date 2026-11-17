package diagnostics

import (
	"context"
	"errors"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type dialFixtureConn struct {
	net.Conn
	closes                atomic.Int32
	deadlineCalls         atomic.Int32
	deadline              time.Time
	deadlineErr, closeErr error
	closeStarted          chan struct{}
	closeRelease          <-chan struct{}
}

func (c *dialFixtureConn) Close() error {
	if c.closes.Add(1) == 1 && c.closeStarted != nil {
		close(c.closeStarted)
	}
	if c.closeRelease != nil {
		<-c.closeRelease
	}
	return c.closeErr
}
func (c *dialFixtureConn) SetDeadline(deadline time.Time) error {
	c.deadlineCalls.Add(1)
	c.deadline = deadline
	return c.deadlineErr
}

func TestResolvedAddressFallbackWhilePrimaryStalls(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection := &dialFixtureConn{}
	var fallback atomic.Bool
	connect := func(attempt context.Context, network, target string) (net.Conn, error) {
		if target == "[2001:db8::1]:443" {
			<-attempt.Done()
			return nil, attempt.Err()
		}
		if network != "tcp" || target != "192.0.2.1:443" {
			t.Error("dial escaped the resolved address set")
			return nil, errors.New("unexpected fixed endpoint")
		}
		if attempt.Err() != nil {
			t.Error("fallback began after its shared budget expired")
		}
		fallback.Store(true)
		return connection, nil
	}
	c, err := dialAddressSet(ctx, "tcp", []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}, {IP: net.ParseIP("192.0.2.1")}}, 443, connect, 5*time.Millisecond)
	if err != nil || c != connection || !fallback.Load() {
		t.Fatal("reachable alternate family was starved by the first address")
	}
	if connection.closes.Load() != 0 {
		t.Fatal("winning connection closed before handoff")
	}
	if c.Close() != nil || connection.closes.Load() != 1 {
		t.Fatal("caller could not complete its connection")
	}
}

func TestResolvedDialDeadlineFailureCompletesSocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	deadlineFailure := errors.New("fixed deadline failure")
	closeFailure := errors.New("fixed close failure")
	connection := &dialFixtureConn{deadlineErr: deadlineFailure, closeErr: closeFailure}
	c, err := dialAddressSet(ctx, "tcp", []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}, 443, func(context.Context, string, string) (net.Conn, error) { return connection, nil }, time.Millisecond)
	if c != nil || !errors.Is(err, deadlineFailure) || !errors.Is(err, closeFailure) || connection.closes.Load() != 1 {
		t.Fatal("unconfirmed deadline returned a successful owned connection")
	}
	if err.Error() != "diagnostic connection completion failed" {
		t.Fatal("native deadline or cleanup text escaped the fixed completion error")
	}
}

func TestResolvedDialRejectsEmptyOrInvalidAddressSet(t *testing.T) {
	for _, addresses := range [][]net.IPAddr{nil, {{IP: nil}}, {{IP: net.IP{1, 2}}}} {
		var calls int
		c, err := dialAddressSet(context.Background(), "tcp", addresses, 443, func(context.Context, string, string) (net.Conn, error) { calls++; return &dialFixtureConn{}, nil }, time.Millisecond)
		if err == nil || c != nil || calls != 0 {
			t.Fatal("invalid resolved addresses reached a connection attempt")
		}
	}
}

func TestResolvedDialCompletesLateLoserBeforeHandoff(t *testing.T) {
	for _, fault := range []bool{false, true} {
		name := "complete"
		if fault {
			name = "close-error"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			started, closing, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			closeFailure := errors.New("fixed late socket close failure")
			late := &dialFixtureConn{closeStarted: closing, closeRelease: release}
			if fault {
				late.closeErr = closeFailure
			}
			winner := &dialFixtureConn{}
			result := make(chan addressDialResult, 1)
			go func() {
				c, err := dialAddressSet(ctx, "tcp", []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}, {IP: net.ParseIP("192.0.2.1")}}, 443, func(attempt context.Context, _ string, target string) (net.Conn, error) {
					if target == "[2001:db8::1]:443" {
						close(started)
						<-attempt.Done()
						return late, nil
					}
					<-started
					return winner, nil
				}, time.Millisecond)
				result <- addressDialResult{connection: c, err: err}
			}()
			select {
			case <-closing:
			case <-ctx.Done():
				close(release)
				t.Fatal("late connection cleanup was not reached")
			}
			var early *addressDialResult
			select {
			case r := <-result:
				early = &r
			default:
			}
			close(release)
			var r addressDialResult
			if early != nil {
				r = *early
				t.Error("socket handoff preceded loser cleanup")
			} else {
				select {
				case r = <-result:
				case <-ctx.Done():
					t.Fatal("socket handoff did not complete after cleanup")
				}
			}
			if late.closes.Load() != 1 {
				t.Fatal("late socket cleanup was not completed exactly once")
			}
			if fault {
				if r.connection != nil || !errors.Is(r.err, closeFailure) || winner.closes.Load() != 1 {
					t.Fatal("failed loser cleanup returned an unconfirmed winner")
				}
			} else {
				if r.err != nil || r.connection != winner || winner.closes.Load() != 0 {
					t.Fatal("successful loser cleanup lost its winner")
				}
				if r.connection.Close() != nil || winner.closes.Load() != 1 {
					t.Fatal("winning socket cleanup failed")
				}
			}
		})
	}
}

func TestResolvedDialCancellationJoinsLateConnectors(t *testing.T) {
	parent, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	entered := make(chan struct{}, 2)
	result := make(chan addressDialResult, 1)
	first, second := &dialFixtureConn{}, &dialFixtureConn{}
	go func() {
		c, err := dialAddressSet(ctx, "tcp", []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}, {IP: net.ParseIP("192.0.2.1")}}, 443, func(attempt context.Context, _ string, target string) (net.Conn, error) {
			entered <- struct{}{}
			<-attempt.Done()
			if target == "[2001:db8::1]:443" {
				return first, nil
			}
			return second, nil
		}, time.Millisecond)
		result <- addressDialResult{connection: c, err: err}
	}()
	for range 2 {
		select {
		case <-entered:
		case <-parent.Done():
			t.Fatal("both address families did not start")
		}
	}
	cancel()
	select {
	case r := <-result:
		if r.connection != nil || !errors.Is(r.err, context.Canceled) || first.closes.Load() != 1 || second.closes.Load() != 1 {
			t.Fatal("cancellation handed off or abandoned a late connection")
		}
	case <-parent.Done():
		t.Fatal("canceled address workers were not joined")
	}
}

func TestResolvedDialSerialBudgetReservesLaterSameFamily(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	limit, _ := ctx.Deadline()
	winner := &dialFixtureConn{}
	calls := 0
	c, err := dialAddressSet(ctx, "tcp", []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("192.0.2.2")}}, 443, func(attempt context.Context, _ string, target string) (net.Conn, error) {
		calls++
		if target == "192.0.2.1:443" {
			share, ok := attempt.Deadline()
			if !ok || !share.Before(limit) {
				return nil, errors.New("first address received the entire shared budget")
			}
			<-attempt.Done()
			return nil, attempt.Err()
		}
		return winner, nil
	}, time.Millisecond)
	if err != nil || c != winner || calls != 2 || !winner.deadline.Equal(limit) || winner.deadlineCalls.Load() != 1 {
		t.Fatal("later same-family address lost its time or I/O deadline")
	}
	if c.Close() != nil || winner.closes.Load() != 1 {
		t.Fatal("same-family winner did not complete")
	}
}

func TestResolvedDialPrimaryFailureStartsFallbackImmediately(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	winner := &dialFixtureConn{}
	calls := 0
	c, err := dialAddressSet(ctx, "tcp", []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}, {IP: net.ParseIP("192.0.2.1")}}, 443, func(_ context.Context, _ string, target string) (net.Conn, error) {
		calls++
		if target == "[2001:db8::1]:443" {
			return nil, errors.New("fixed primary refusal")
		}
		return winner, nil
	}, time.Hour)
	if err != nil || c != winner || calls != 2 {
		t.Fatal("primary refusal waited for the fallback timer")
	}
	if c.Close() != nil {
		t.Fatal("immediate fallback winner did not complete")
	}
}

func TestResolvedDialUnneededFallbackAndUDPStaySerial(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			winner := &dialFixtureConn{}
			var calls atomic.Int32
			c, err := dialAddressSet(ctx, network, []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}, {IP: net.ParseIP("192.0.2.1")}}, 443, func(context.Context, string, string) (net.Conn, error) { calls.Add(1); return winner, nil }, time.Hour)
			if err != nil || c != winner || calls.Load() != 1 {
				t.Fatal("successful primary started an unnecessary fallback")
			}
			if c.Close() != nil || winner.closes.Load() != 1 {
				t.Fatal("serial winner did not complete")
			}
		})
	}
}

func TestResolvedDialRetainsFailuresAndCompletesPartialSocket(t *testing.T) {
	firstFailure, secondFailure, closeFailure := errors.New("fixed first dial failure"), errors.New("fixed second dial failure"), errors.New("fixed partial close failure")
	for _, fault := range []bool{false, true} {
		name := "dial-errors"
		if fault {
			name = "close-error"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			partial := &dialFixtureConn{}
			if fault {
				partial.closeErr = closeFailure
			}
			calls := 0
			c, err := dialAddressSet(ctx, "tcp", []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("192.0.2.2")}}, 443, func(context.Context, string, string) (net.Conn, error) {
				calls++
				if calls == 1 {
					return partial, firstFailure
				}
				return nil, secondFailure
			}, time.Hour)
			if c != nil || !errors.Is(err, firstFailure) || partial.closes.Load() != 1 {
				t.Fatal("partial failed dial lost ownership or cause")
			}
			if fault {
				if !errors.Is(err, closeFailure) || calls != 1 {
					t.Fatal("unconfirmed partial close permitted another attempt")
				}
			} else if !errors.Is(err, secondFailure) || calls != 2 {
				t.Fatal("all-failed dialing discarded an address cause")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	c, err := dialAddressSet(ctx, "tcp", []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}, 443, func(context.Context, string, string) (net.Conn, error) { calls++; return nil, nil }, time.Millisecond)
	if c != nil || !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal("pre-canceled probe attempted a connection")
	}
	c, err = dialAddressSet(context.Background(), "tcp", []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}, 443, func(context.Context, string, string) (net.Conn, error) { return nil, nil }, time.Millisecond)
	if c != nil || err == nil {
		t.Fatal("empty connector result reported success")
	}
}

func TestDirectDiagnosticUsesOnlyResolvedNativeFallback(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal("owned loopback listener unavailable")
	}
	defer listener.Close()
	if listener.SetDeadline(time.Now().Add(5*time.Second)) != nil {
		t.Fatal("owned listener deadline unavailable")
	}
	completed := make(chan error, 1)
	go func() {
		c, err := listener.AcceptTCP()
		if err != nil {
			completed <- err
			return
		}
		if err = c.SetReadDeadline(time.Now().Add(5 * time.Second)); err == nil {
			var b [1]byte
			_, err = c.Read(b[:])
			if errors.Is(err, io.EOF) {
				err = nil
			}
		}
		completed <- errors.Join(err, c.Close())
	}()
	resolutions := 0
	d := runner{lookup: func(context.Context, string) ([]net.IPAddr, error) {
		resolutions++
		return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 2)}, {IP: net.IPv4(127, 0, 0, 1)}}, nil
	}}
	report, err := d.diagnose(context.Background(), Request{Probe: profile.Probe{Host: "example.invalid", Port: listener.Addr().(*net.TCPAddr).Port, TimeoutSeconds: 2}}, managed.NewGuard(func() (*managed.Authority, error) { return nil, nil }))
	if err != nil || !report.Passed() || resolutions != 1 || len(report.Checks) != 2 || report.Checks[0].Name != "DNS" || report.Checks[1].Name != "TCP" {
		t.Fatal("native fallback did not retain one resolved diagnostic path")
	}
	select {
	case err := <-completed:
		if err != nil {
			t.Fatal("owned loopback connection cleanup failed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native diagnostic left its connection open")
	}
}
