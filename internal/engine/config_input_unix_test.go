//go:build linux || darwin || freebsd || openbsd

package engine

import (
	"golang.org/x/sys/unix"
	"path/filepath"
	"testing"
)

func TestConfigInputSubstitutedFIFORefusedBeforeRead(t *testing.T) {
	owned := newHashOwnedReader(t)
	fifo := filepath.Join(filepath.Dir(owned.file.Name()), "substituted-fifo")
	if unix.Mkfifo(fifo, 0600) != nil {
		t.Fatal("owned FIFO unavailable")
	}
	// Directly exercise the post-advisory-open path without waiting for a writer.
	file, err := openConfigInput(fifo)
	if err != nil {
		t.Fatal("nonblocking owned FIFO open failed")
	}
	r := &configOwnedReader{hashOwnedReader: &hashOwnedReader{file: file}}
	data, err := readOwnedConfigInput(r)
	if err == nil || data != nil || r.reads != 0 || r.closes != 1 || r.actualClose != nil {
		t.Fatal("substituted FIFO read or Close contract lost")
	}
}
