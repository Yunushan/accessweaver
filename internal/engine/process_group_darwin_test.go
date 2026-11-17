package engine

import "testing"

func TestDarwinExitedGroupRequiresExactUnreapedLeader(t *testing.T) {
	const leader = 12345
	cases := []struct {
		name    string
		count   int32
		members [2]int32
		want    bool
	}{
		{"only-leader", 1, [2]int32{leader, 0}, true},
		{"empty-or-denied", 0, [2]int32{}, false},
		{"other-member", 1, [2]int32{leader - 1, 0}, false},
		{"live-or-unknown-descendant", 2, [2]int32{leader, leader + 1}, false},
		{"invalid-size", -1, [2]int32{leader, 0}, false},
		{"inconsistent-slot", 1, [2]int32{leader, leader + 1}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := onlyObservedDarwinGroupLeader(leader, func(pgid int32, out *[2]int32, bytes int32) int32 {
				if pgid != leader || bytes != 8 {
					t.Fatal("unexpected Darwin group query")
				}
				*out = tc.members
				return tc.count
			})
			if got != tc.want {
				t.Fatalf("group confirmation = %v, want %v", got, tc.want)
			}
		})
	}
	if onlyObservedDarwinGroupLeader(leader, nil) {
		t.Fatal("missing Darwin group inventory cleared a signal failure")
	}
}
