package engine

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

type configOwnedReader struct {
	*hashOwnedReader
	stats, reads, bytes int
	statCause           error
	afterRead           func()
}

func (r *configOwnedReader) Stat() (os.FileInfo, error) {
	r.stats++
	if r.statCause != nil {
		return nil, r.statCause
	}
	return r.file.Stat()
}
func (r *configOwnedReader) Read(p []byte) (int, error) {
	r.reads++
	n, err := r.hashOwnedReader.Read(p)
	r.bytes += n
	if r.afterRead != nil {
		fn := r.afterRead
		r.afterRead = nil
		fn()
	}
	return n, err
}

func TestConfigInputCompletion(t *testing.T) {
	for _, mode := range []string{"clean", "read", "close", "both", "stat-close", "panic"} {
		t.Run(mode, func(t *testing.T) {
			r := &configOwnedReader{hashOwnedReader: newHashOwnedReader(t)}
			readCause := errors.New("PRIVATE_READ_CAUSE")
			closeCause := &os.PathError{Op: "PRIVATE_CLOSE", Path: "PRIVATE_CONFIG_PATH", Err: errors.New("PRIVATE_CLOSE_CAUSE")}
			if mode == "read" || mode == "both" {
				r.readCause = readCause
			}
			if mode == "close" || mode == "both" || mode == "stat-close" {
				r.closeCause = closeCause
			}
			if mode == "stat-close" {
				r.statCause = readCause
			}
			original := &struct{ tag string }{"PRIVATE_PANIC"}
			if mode == "panic" {
				r.panicValue = original
			}
			var data []byte
			var err error
			var recovered any
			func() { defer func() { recovered = recover() }(); data, err = readOwnedConfigInput(r) }()
			if r.closes != 1 || r.actualClose != nil {
				t.Fatal("actual configuration reader Close not confirmed once")
			}
			if n, err := r.file.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrClosed) {
				t.Fatal("configuration reader remained open")
			}
			if mode == "panic" {
				if recovered != original {
					t.Fatal("original read panic lost")
				}
				return
			}
			if recovered != nil {
				t.Fatal("unexpected read panic")
			}
			if mode == "clean" {
				if err != nil || string(data) != "source-owned executable bytes" {
					t.Fatal("clean configuration bytes changed")
				}
				return
			}
			if data != nil || !errors.Is(err, errConfigInputUnavailable) || err.Error() != errConfigInputUnavailable.Error() {
				t.Fatal("unconfirmed bytes or private diagnostic escaped")
			}
			if r.readCause != nil || r.statCause != nil {
				if !errors.Is(err, readCause) {
					t.Fatal("read or Stat cause lost")
				}
			}
			if r.closeCause != nil {
				var cause *os.PathError
				if !errors.As(err, &cause) || cause != closeCause {
					t.Fatal("Close cause lost")
				}
			}
		})
	}
}

func TestConfigInputActualBoundAndMutation(t *testing.T) {
	for _, mode := range []string{"exact", "excess", "grow", "shrink"} {
		t.Run(mode, func(t *testing.T) {
			owned := newHashOwnedReader(t)
			initial := bytes.Repeat([]byte("x"), configInputLimit)
			if mode == "excess" {
				initial = append(initial, 'x')
			}
			if mode == "grow" || mode == "shrink" {
				initial = []byte("source-owned configuration")
			}
			if os.WriteFile(owned.file.Name(), initial, 0600) != nil {
				t.Fatal("owned bound fixture write failed")
			}
			r := &configOwnedReader{hashOwnedReader: owned}
			if mode == "grow" || mode == "shrink" {
				r.afterRead = func() {
					data := []byte("short")
					if mode == "grow" {
						data = bytes.Repeat([]byte("x"), configInputLimit+200)
					}
					if os.WriteFile(owned.file.Name(), data, 0600) != nil {
						t.Fatal("owned mutation failed")
					}
				}
			}
			data, err := readOwnedConfigInput(r)
			if r.closes != 1 || r.actualClose != nil || r.bytes > configInputLimit+1 {
				t.Fatal("reader bound or Close lost")
			}
			if mode == "exact" {
				if err != nil || !bytes.Equal(data, initial) {
					t.Fatal("exact 4 MiB refused")
				}
			} else if err == nil || data != nil {
				t.Fatal("oversize or changing input accepted")
			}
			if mode == "excess" && r.reads != 0 {
				t.Fatal("known oversized input was read")
			}
		})
	}
}

func TestConfigInputHookInspectionUsesObservedBytes(t *testing.T) {
	for _, key := range []string{"PreUp", "POSTUP", "PreDown", "PostDown"} {
		data := []byte("[Interface]\nPrivateKey = PRIVATE_VALUE\n  " + key + " = PRIVATE_COMMAND\n")
		err := inspectConfigBytes("wiresock", data)
		if err == nil || strings.Contains(err.Error(), "PRIVATE_") {
			t.Fatal("hook missed or value exposed")
		}
		for _, engine := range []string{"sing-box", "xray"} {
			if inspectConfigBytes(engine, data) != nil {
				t.Fatal("new upstream schema imposed")
			}
		}
	}
	if inspectConfigBytes("wiresock", bytes.Repeat([]byte("x"), 70<<10)) == nil {
		t.Fatal("existing Scanner line limit lost")
	}
}

func TestConfigInputFollowedAlias(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a Windows symlink can require a host privilege")
	}
	owned := newHashOwnedReader(t)
	alias := filepath.Join(filepath.Dir(owned.file.Name()), "alias")
	if os.Symlink(owned.file.Name(), alias) != nil {
		t.Fatal("owned alias unavailable")
	}
	data, err := readConfigInput(alias)
	if err != nil || string(data) != "source-owned executable bytes" {
		t.Fatal("followed alias compatibility changed")
	}
}

func TestConfigInputPrepareUsesOneInspectedRead(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("WireSock generation is a Windows adapter")
	}
	for _, mode := range []string{"replace-after-read", "hook-before-read", "close-failure"} {
		t.Run(mode, func(t *testing.T) {
			owned := newHashOwnedReader(t)
			root := filepath.Dir(owned.file.Name())
			p := profile.New("config-read-test", "PRIVATE_PROFILE", "wiresock")
			p.Binary = fixtureBinary(t, root, "wiresock-client")
			p.ConfigPath = owned.file.Name()
			p.Routing.Applications = []string{"app.exe"}
			original := "[Interface]\nPrivateKey = PRIVATE_VALUE\nAllowedApps = old.exe\n"
			hook := original + "PostUp = PRIVATE_COMMAND\n"
			if os.WriteFile(p.ConfigPath, []byte(original), 0600) != nil {
				t.Fatal("owned configuration write failed")
			}
			count := 0
			closeCause := errors.New("PRIVATE_CLOSE_CAUSE")
			read := func(path string) ([]byte, error) {
				count++
				if mode == "hook-before-read" {
					if os.WriteFile(path, []byte(hook), 0600) != nil {
						t.Fatal("owned hook fixture unavailable")
					}
				}
				if mode == "close-failure" {
					file, err := openConfigInput(path)
					if err != nil {
						t.Fatal("owned reader unavailable")
					}
					return readOwnedConfigInput(&configOwnedReader{hashOwnedReader: &hashOwnedReader{file: file, closeCause: closeCause}})
				}
				data, err := readConfigInput(path)
				if mode == "replace-after-read" {
					if os.WriteFile(path, []byte(hook), 0600) != nil {
						t.Fatal("owned replacement failed")
					}
				}
				return data, err
			}
			guard := managed.NewGuard(func() (*managed.Authority, error) { return nil, nil })
			binary, args, err := prepareWithConfigReader(p, root, guard, read)
			if count != 1 {
				t.Fatal("preparation reopened configuration")
			}
			generated := filepath.Join(root, "generated", p.ID+"-wiresock.conf")
			if mode != "replace-after-read" {
				if err == nil || binary != "" || args != nil {
					t.Fatal("unconfirmed or hooked input returned launch material")
				}
				if _, e := os.Lstat(filepath.Dir(generated)); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("failed input created generated evidence")
				}
				return
			}
			if err != nil || binary != p.Binary || len(args) < 3 || args[2] != generated {
				t.Fatal("confirmed preparation failed")
			}
			data, e := os.ReadFile(generated)
			if e != nil || string(data) != "[Interface]\nPrivateKey = PRIVATE_VALUE\nAllowedApps = app.exe\n" {
				t.Fatal("generated bytes were not the inspected bytes")
			}
			current, e := os.ReadFile(p.ConfigPath)
			if e != nil || string(current) != hook {
				t.Fatal("generation changed original path")
			}
		})
	}
}
