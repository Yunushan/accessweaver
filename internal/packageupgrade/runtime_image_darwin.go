//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/ebitengine/purego"
)

// Apple libproc.h/libproc.c expose proc_pidpath(pid, buffer, uint32 size),
// returning an int byte length or zero/errno. Query only this process, with the
// fixed 4096-byte maximum; never accept a caller PID, library or symbol.
// https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.c
var processPathAPI = sync.OnceValues(func() (uintptr, error) {
	library, e := purego.Dlopen("/usr/lib/libproc.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if e != nil {
		return 0, e
	}
	symbol, e := purego.Dlsym(library, "proc_pidpath")
	if e != nil {
		return 0, errors.Join(e, purego.Dlclose(library))
	}
	// Keep the fixed library loaded for process life.
	return symbol, nil
})

func currentKernelExecutable() (string, error) {
	symbol, e := processPathAPI()
	if e != nil {
		return "", e
	}
	buffer := make([]byte, 4096)
	value, _, code := purego.SyscallN(symbol, uintptr(uint32(os.Getpid())), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	runtime.KeepAlive(buffer)
	count := int(int32(value))
	if count <= 0 {
		if uint32(code) != 0 {
			return "", syscall.Errno(uint32(code))
		}
		return "", errors.New("native executable path is unavailable")
	}
	if count >= len(buffer) || bytes.IndexByte(buffer, 0) != count {
		return "", errors.New("native executable path extent differs")
	}
	path := string(buffer[:count])
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("native executable path is not canonical")
	}
	return path, nil
}
