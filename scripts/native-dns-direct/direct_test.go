package direct

import (
	"context"
	"errors"
	"net"
	"net/netip"
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
	for _, s := range []string{"", "0.0.0.0", "127.0.0.1", "::ffff:127.0.0.1", "224.0.0.1", "fe80::1", "fe80::1%4"} {
		addr, _ := netip.ParseAddr(s)
		if r := Query(context.Background(), addr, "example.net"); r.Code != "server" {
			t.Fatal("invalid server accepted")
		}
	}
}
