//go:build linux || darwin || freebsd || openbsd

package audit

import (
	"errors"
	"os"
	"strconv"
	"testing"
)

func TestUnixAuditCredentialClassificationAndMixedStateRefusal(t *testing.T) {
	for _, uid := range []int{0, 1000, 2147483647} {
		snapshot := [4]int{uid, uid, 1000, 1000}
		got, err := principalFromCredentials(snapshot, snapshot)
		class := "user"
		if uid == 0 {
			class = "administrator"
		}
		if err != nil || got != (processPrincipal{"uid", strconv.Itoa(uid), class}) {
			t.Fatalf("wrong native credential class: %+v %v", got, err)
		}
	}
	normal := [4]int{1000, 1000, 1000, 1000}
	for _, test := range []struct{ before, after [4]int }{
		{[4]int{1000, 0, 1000, 1000}, [4]int{1000, 0, 1000, 1000}},
		{[4]int{1000, 1000, 1000, 0}, [4]int{1000, 1000, 1000, 0}},
		{normal, [4]int{0, 0, 1000, 1000}},
		{normal, [4]int{1000, 1000, 0, 0}},
		{[4]int{-1, -1, 1000, 1000}, [4]int{-1, -1, 1000, 1000}},
		{[4]int{1000, 1000, -1, -1}, [4]int{1000, 1000, -1, -1}},
	} {
		got, err := principalFromCredentials(test.before, test.after)
		if !errors.Is(err, ErrProcessIdentity) || got != (processPrincipal{}) {
			t.Fatal("mixed/changed native credentials admitted", err)
		}
	}
	got, err := currentProcessPrincipal()
	if err != nil || got.kind != "uid" || got.value != strconv.Itoa(os.Geteuid()) {
		t.Fatal("native effective UID differs", err)
	}
	class := "user"
	if os.Geteuid() == 0 {
		class = "administrator"
	}
	if got.class != class {
		t.Fatal("native class differs")
	}
}
