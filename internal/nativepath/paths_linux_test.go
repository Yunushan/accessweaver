//go:build linux && (amd64 || arm64)

package nativepath

import (
	"reflect"
	"testing"
)

func TestLinuxManagedEnvironmentDoesNotInheritCallerSettings(t *testing.T) {
	for _, name := range []string{"PATH", "HOME", "LD_PRELOAD", "LD_LIBRARY_PATH", "GCONV_PATH", "BASH_ENV", "ENV", "PYTHONPATH", "NODE_OPTIONS", "ACCESSWEAVER_HOME"} {
		t.Setenv(name, "untrusted caller value")
	}
	env, err := ProcessEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(env, []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TZ=UTC"}) {
		t.Fatal("managed environment inherited caller-controlled values", env)
	}
}
