package direct

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestQueryContract(t *testing.T) {
	ip := net.IPAddr{IP: net.ParseIP("192.0.2.53")}
	tests := []struct {
		name          string
		input         string
		answers       []net.IPAddr
		err           error
		outcome, code string
		count         int
	}{
		{"answer", "example.net", []net.IPAddr{ip}, nil, "answered", "none", 1},
		{"empty", "example.net", nil, nil, "refused", "answer-bound", 0},
		{"too-many", "example.net", make([]net.IPAddr, 65), nil, "refused", "answer-bound", 0},
		{"invalid-answer", "example.net", []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil, "refused", "answer-shape", 0},
		{"no-ipv4", "example.net", []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}}, nil, "refused", "no-ipv4", 0},
		{"failed", "example.net", nil, errors.New("private failure"), "refused", "query-failed", 0},
		{"timeout", "example.net", nil, context.DeadlineExceeded, "refused", "timeout", 0},
		{"cancelled", "example.net", nil, context.Canceled, "refused", "cancelled", 0},
		{"bad-name", "private.example", nil, nil, "refused", "arguments", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			r := query(context.Background(), tc.input, func(ctx context.Context, name string) ([]net.IPAddr, error) {
				calls++
				if name != tc.input+"." {
					t.Fatal("name was not absolute")
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 3*time.Second {
					t.Fatal("missing bounded deadline")
				}
				return tc.answers, tc.err
			})
			if r.Outcome != tc.outcome || r.Code != tc.code || r.AnswerCount != tc.count {
				t.Fatalf("unexpected closed result: %+v", r)
			}
			if (tc.code == "arguments") != (calls == 0) {
				t.Fatal("invalid request invoked lookup")
			}
		})
	}
}

func TestRejectInvalidServerWithoutNetwork(t *testing.T) {
	for _, s := range []string{"", "0.0.0.0", "127.0.0.1", "::ffff:127.0.0.1", "224.0.0.1", "fe80::1", "fe80::1%0"} {
		if _, err := ParseServer(s); err == nil {
			t.Fatal("invalid server accepted")
		}
	}
}

func TestParseServer(t *testing.T) {
	for _, text := range []string{"", "127.0.0.1", "::ffff:127.0.0.1", "255.255.255.255", "fe80::1", "fe80::1%0", "fe80::1%04", "2001:db8::1%4", "192.0.2.1\n", "192.0.2.1:53", "private.example"} {
		if _, err := ParseServer(text); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	for _, text := range []string{"192.0.2.1", "2001:db8::1", "fe80::1%4", "10.0.0.53"} {
		if _, err := ParseServer(text); err != nil {
			t.Fatal("valid literal rejected")
		}
	}
}

func TestPrivateInputBoundAndDispatch(t *testing.T) {
	for _, text := range []string{"", "127.0.0.1", "192.0.2.1\n", strings.Repeat("a", 65)} {
		calls := 0
		result := queryInput(context.Background(), strings.NewReader(text), func(context.Context, netip.Addr, string) Result {
			calls++
			return Result{Outcome: "answered", Code: "none", AnswerCount: 1}
		})
		if calls != 0 || result.Code != "server" {
			t.Fatal("invalid input dispatched")
		}
	}
	calls := 0
	result := queryInput(context.Background(), strings.NewReader("192.0.2.53"), func(_ context.Context, server netip.Addr, name string) Result {
		calls++
		if server.String() != "192.0.2.53" || name != "example.net" {
			t.Fatal("input changed")
		}
		return Result{Outcome: "answered", Code: "none", AnswerCount: 1}
	})
	if calls != 1 || result.Outcome != "answered" || result.AnswerCount != 1 {
		t.Fatal("valid input not dispatched")
	}
}

func TestConcurrentPairsWaitForBothAndReportOverlap(t *testing.T) {
	firstEntered, secondEntered := make(chan struct{}), make(chan struct{})
	done := make(chan TimedPair[int, int], 1)
	go func() {
		done <- Concurrent(func() int { close(firstEntered); <-secondEntered; time.Sleep(time.Millisecond); return 1 }, func() int { close(secondEntered); <-firstEntered; time.Sleep(time.Millisecond); return 2 })
	}()
	select {
	case result := <-done:
		if !result.Overlapped || result.First.Value != 1 || result.Second.Value != 2 || result.First.EndMicroseconds < result.First.StartMicroseconds || result.Second.EndMicroseconds < result.Second.StartMicroseconds {
			t.Fatal("concurrent timing or joining failed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent callbacks failed to join")
	}
}

func TestReadServersAndAggregate(t *testing.T) {
	for _, input := range []string{"", "[]", `["127.0.0.1"]`, `["192.0.2.1","::ffff:192.0.2.1"]`, `["fe80::1"]`, strings.Repeat("x", 2049)} {
		if _, err := ReadServers(strings.NewReader(input)); err == nil {
			t.Fatal("invalid server set accepted")
		}
	}
	servers, err := ReadServers(strings.NewReader(`["192.0.2.1","fe80::1%4","2001:db8::53"]`))
	if err != nil || len(servers) != 3 {
		t.Fatal("valid server set refused")
	}
	result := querySet(context.Background(), servers, func(_ context.Context, addr netip.Addr, name string) Result {
		if name != "example.net" {
			t.Error("unexpected name")
		}
		switch addr.String() {
		case "192.0.2.1":
			return Result{Outcome: "answered", Code: "none", AnswerCount: 1}
		case "fe80::1%4":
			return Result{Outcome: "refused", Code: "timeout"}
		default:
			return Result{Outcome: "refused", Code: "answer-shape"}
		}
	})
	if result.Total != 3 || result.Answered != 1 || result.Rejected != 1 || result.OtherFailures != 1 {
		t.Fatal("invalid aggregate")
	}
}
