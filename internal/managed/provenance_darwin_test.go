//go:build darwin && (amd64 || arm64)

package managed

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

func darwinInputFixture(t *testing.T) (*os.File, []byte, string) {
	t.Helper()
	parent, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { parent.Close() })
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent.Name(), "native-engine")
	if err := os.WriteFile(path, image, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(image)
	return parent, image, hex.EncodeToString(hash[:])
}
func TestDarwinProtectedInputsBindActualMachOAndRejectMutableNeighbors(t *testing.T) {
	for _, kind := range []string{"valid", "digest", "script", "symlink", "hardlink", "neighbor-mode", "neighbor-acl", "fifo", "tree-bytes"} {
		t.Run(kind, func(t *testing.T) {
			parent, _, digest := darwinInputFixture(t)
			path := filepath.Join(parent.Name(), "native-engine")
			switch kind {
			case "digest":
				digest = string(bytes.Repeat([]byte{'0'}, 64))
			case "script":
				if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
					t.Fatal(err)
				}
				digest = ""
			case "symlink":
				if err := os.Rename(path, path+"-target"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+"-target", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+"-alias"); err != nil {
					t.Fatal(err)
				}
			case "neighbor-mode":
				neighbor := filepath.Join(parent.Name(), "plugin.json")
				if err := os.WriteFile(neighbor, []byte("{}"), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(neighbor, 0666); err != nil {
					t.Fatal(err)
				}
			case "neighbor-acl":
				neighbor := filepath.Join(parent.Name(), "plugin.json")
				if err := os.WriteFile(neighbor, []byte("{}"), 0644); err != nil {
					t.Fatal(err)
				}
				command := exec.Command("/bin/chmod", "+a", "everyone allow write", neighbor)
				command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatalf("owned ACL fixture: %s %v", output, err)
				}
				info, err := os.Stat(neighbor)
				if err != nil || info.Mode().Perm() != 0644 {
					t.Fatal("fixture mode changed", err)
				}
			case "fifo":
				if err := unix.Mkfifo(filepath.Join(parent.Name(), "pipe"), 0600); err != nil {
					t.Fatal(err)
				}
			case "tree-bytes":
				file, err := os.Create(filepath.Join(parent.Name(), "large-sparse"))
				if err != nil {
					t.Fatal(err)
				}
				if err := file.Truncate(maxDarwinInputBytes + 1); err != nil {
					file.Close()
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			err := checkDarwinInputAt(parent, "native-engine", digest, false, uint32(os.Geteuid()))
			if (err == nil) != (kind == "valid") {
				t.Fatal("incorrect protected input result", kind, err)
			}
		})
	}
}
func TestDarwinMachOLoaderAdmissionBoundsThinAndUniversalImages(t *testing.T) {
	parent, image, _ := darwinInputFixture(t)
	for _, kind := range []string{"thin", "fat32", "fat64", "cpu", "type", "commands", "command-bytes", "truncated", "fat-count", "fat-offset", "fat-subtype", "fat-reserved"} {
		t.Run(kind, func(t *testing.T) {
			data := bytes.Clone(image)
			switch kind {
			case "cpu":
				if runtime.GOARCH == "arm64" {
					binary.LittleEndian.PutUint32(data[4:8], 0x1000007)
				} else {
					binary.LittleEndian.PutUint32(data[4:8], 0x100000c)
				}
			case "type":
				binary.LittleEndian.PutUint32(data[12:16], 6)
			case "commands":
				binary.LittleEndian.PutUint32(data[16:20], 4097)
			case "command-bytes":
				binary.LittleEndian.PutUint32(data[20:24], 16<<20+1)
			case "truncated":
				data = data[:31]
			default:
				if kind != "thin" {
					wide := kind == "fat64" || kind == "fat-reserved"
					data = make([]byte, 4096+len(image))
					copy(data[4096:], image)
					magic := uint32(0xcafebabe)
					if wide {
						magic = 0xcafebabf
					}
					binary.BigEndian.PutUint32(data[:4], magic)
					binary.BigEndian.PutUint32(data[4:8], 1)
					binary.BigEndian.PutUint32(data[8:12], binary.LittleEndian.Uint32(image[4:8]))
					binary.BigEndian.PutUint32(data[12:16], binary.LittleEndian.Uint32(image[8:12]))
					if wide {
						binary.BigEndian.PutUint64(data[16:24], 4096)
						binary.BigEndian.PutUint64(data[24:32], uint64(len(image)))
						binary.BigEndian.PutUint32(data[32:36], 12)
					} else {
						binary.BigEndian.PutUint32(data[16:20], 4096)
						binary.BigEndian.PutUint32(data[20:24], uint32(len(image)))
						binary.BigEndian.PutUint32(data[24:28], 12)
					}
					switch kind {
					case "fat-count":
						binary.BigEndian.PutUint32(data[4:8], 33)
					case "fat-offset":
						binary.BigEndian.PutUint32(data[16:20], 0xfffffff0)
					case "fat-subtype":
						binary.BigEndian.PutUint32(data[12:16], 0x12345)
					case "fat-reserved":
						binary.BigEndian.PutUint32(data[36:40], 1)
					}
				}
			}
			path := filepath.Join(parent.Name(), "format-"+kind)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			err = checkDarwinMachO(file, int64(len(data)))
			valid := kind == "thin" || kind == "fat32" || kind == "fat64"
			if (err == nil) != valid {
				t.Fatal("incorrect bounded Mach-O admission", kind, err)
			}
		})
	}
}
