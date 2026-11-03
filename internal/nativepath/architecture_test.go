package nativepath

import "testing"

func TestWindowsMachineArchitecture(t *testing.T) {
	for _, tc := range []struct {
		machine uint16
		want    string
	}{
		{0x8664, "amd64"}, {0xaa64, "arm64"}, {0, ""}, {0x014c, ""}, {0x01c4, ""}, {0xffff, ""},
	} {
		got, err := windowsMachineArchitecture(tc.machine)
		if got != tc.want || (err != nil) != (tc.want == "") {
			t.Fatalf("machine %x: got %q, %v", tc.machine, got, err)
		}
	}
}
