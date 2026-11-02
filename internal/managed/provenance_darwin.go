//go:build darwin && (amd64 || arm64)

package managed

import (
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

const maxDarwinInputBytes = int64(512 << 20)

func checkProtectedInput(path, digest string, directory bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return errors.New("managed inputs require a canonical absolute local path")
	}
	parent, err := darwintrust.OpenRootDirectory(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("untrusted managed parent: %w", err)
	}
	defer parent.Close()
	// Frameworks/helpers may sit beside Contents/MacOS rather than beside the
	// executable. Inspect the entire outer application bundle when one encloses
	// the input, including nested helper bundles, using the same strict bounds.
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, component := range components {
		if !directory && index == len(components)-1 {
			break
		}
		if !strings.HasSuffix(strings.ToLower(component), ".app") {
			continue
		}
		bundle, err := darwintrust.OpenRootDirectory("/" + strings.Join(components[:index+1], "/"))
		if err != nil {
			return err
		}
		count := 0
		var total int64
		inspectErr := checkDarwinInputTree(bundle, 0, 0, &count, &total)
		if err := errors.Join(inspectErr, bundle.Close()); err != nil {
			return err
		}
		break
	}
	return checkDarwinInputAt(parent, filepath.Base(path), digest, directory, 0)
}

// Only internal owned fixtures use a non-root owner. All runtime ancestors and
// leaves are opened from the fixed root-protection implementation above.
func checkDarwinInputAt(parent *os.File, name, digest string, directory bool, owner uint32) error {
	var input *os.File
	var err error
	if directory {
		input, err = darwintrust.OpenDirectoryAt(parent, name, owner)
	} else {
		input, err = darwintrust.OpenRegularAt(parent, name, owner)
	}
	if err != nil {
		return err
	}
	defer input.Close()
	tree := parent
	if directory {
		tree = input
	}
	count := 0
	var total int64
	if err := checkDarwinInputTree(tree, owner, 0, &count, &total); err != nil {
		return err
	}
	if directory {
		if digest != "" {
			return errors.New("directory contents cannot use a file digest")
		}
		return nil
	}
	before, err := input.Stat()
	if err != nil {
		return err
	}
	if before.Size() < 0 || before.Size() > maxDarwinInputBytes {
		return errors.New("managed input exceeds 512 MiB")
	}
	if before.Mode().Perm()&0111 != 0 {
		if err := checkDarwinMachO(input, before.Size()); err != nil {
			return err
		}
	}
	if digest != "" {
		if !digestPattern.MatchString(digest) {
			return errors.New("managed file requires a SHA-256 digest")
		}
		hash := sha256.New()
		size, err := io.Copy(hash, io.LimitReader(input, maxDarwinInputBytes+1))
		if err != nil {
			return err
		}
		if size > maxDarwinInputBytes {
			return errors.New("managed input exceeds 512 MiB")
		}
		if hex.EncodeToString(hash.Sum(nil)) != digest {
			return errors.New("managed input SHA-256 mismatch")
		}
	}
	after, err := darwintrust.Check(input, false, owner)
	if err != nil {
		return err
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return errors.New("managed input changed during inspection")
	}
	return nil
}

func checkDarwinInputTree(dir *os.File, owner uint32, depth int, count *int, total *int64) error {
	if depth > 32 {
		return errors.New("managed input directory exceeds 32 levels")
	}
	fd, err := unix.Openat(int(dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	scan := os.NewFile(uintptr(fd), dir.Name())
	defer scan.Close()
	if _, err := darwintrust.Check(scan, true, owner); err != nil {
		return err
	}
	for {
		entries, readErr := scan.ReadDir(128)
		for _, entry := range entries {
			*count++
			if *count > 4096 {
				return errors.New("managed input directory exceeds 4096 entries")
			}
			var child *os.File
			if entry.IsDir() {
				child, err = darwintrust.OpenDirectoryAt(scan, entry.Name(), owner)
			} else {
				child, err = darwintrust.OpenRegularAt(scan, entry.Name(), owner)
			}
			if err != nil {
				return err
			}
			if entry.IsDir() {
				err = checkDarwinInputTree(child, owner, depth+1, count, total)
			} else {
				info, statErr := child.Stat()
				err = statErr
				if err == nil {
					if info.Size() < 0 || info.Size() > maxDarwinInputBytes-*total {
						err = errors.New("managed input tree exceeds 512 MiB")
					} else {
						*total += info.Size()
					}
				}
			}
			if err := errors.Join(err, child.Close()); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

// Admit only bounded native loader headers; do not parse debug/symbol tables
// whose declared counts or duplicated names could allocate beyond this limit.
// The digest/protected tree establish input trust. This format admission is not
// code-signature, dylib-closure or vendor-behavior qualification.
type darwinMachOIdentity struct {
	cpu     macho.Cpu
	subtype uint32
}

func readDarwinMachOHeader(reader io.ReaderAt, size int64) (darwinMachOIdentity, error) {
	fail := func(message string) (darwinMachOIdentity, error) { return darwinMachOIdentity{}, errors.New(message) }
	var header [32]byte
	if size < 32 {
		return fail("managed executable has a truncated Mach-O header")
	}
	if _, err := reader.ReadAt(header[:], 0); err != nil {
		return darwinMachOIdentity{}, err
	}
	var order binary.ByteOrder
	switch binary.BigEndian.Uint32(header[:4]) {
	case 0xcffaedfe:
		order = binary.LittleEndian
	case 0xfeedfacf:
		order = binary.BigEndian
	default:
		return fail("managed executable requires a 64-bit Mach-O image; interpreter assets are not qualified")
	}
	if macho.Type(order.Uint32(header[12:16])) != macho.TypeExec {
		return fail("managed executable must be a Mach-O executable image")
	}
	commands, length := order.Uint32(header[16:20]), order.Uint32(header[20:24])
	if commands == 0 || commands > 4096 || length > 16<<20 || int64(length) > size-32 || uint64(commands)*8 > uint64(length) {
		return fail("managed Mach-O load commands exceed bounds")
	}
	data := make([]byte, length)
	if _, err := reader.ReadAt(data, 32); err != nil {
		return darwinMachOIdentity{}, err
	}
	text, entry := false, false
	for index := uint32(0); index < commands; index++ {
		if len(data) < 8 {
			return fail("managed Mach-O load command is truncated")
		}
		command, bytes := order.Uint32(data[:4]), order.Uint32(data[4:8])
		if bytes < 8 || bytes%8 != 0 || uint64(bytes) > uint64(len(data)) {
			return fail("managed Mach-O load command has invalid length")
		}
		current := data[:bytes]
		data = data[bytes:]
		switch macho.LoadCmd(command) {
		case macho.LoadCmdSegment64:
			if len(current) < 72 {
				return fail("managed Mach-O segment is truncated")
			}
			sections := order.Uint32(current[64:68])
			if sections > 4096 || uint64(len(current)) != 72+uint64(sections)*80 {
				return fail("managed Mach-O section table is invalid")
			}
			offset, length := order.Uint64(current[40:48]), order.Uint64(current[48:56])
			if offset > uint64(size) || length > uint64(size)-offset {
				return fail("managed Mach-O segment exceeds the image")
			}
			if strings.TrimRight(string(current[8:24]), "\x00") == "__TEXT" && length > 0 {
				text = true
			}
		case macho.LoadCmdUnixThread:
			if len(current) < 16 {
				return fail("managed Mach-O thread command is truncated")
			}
			entry = true
		case macho.LoadCmd(0x80000028): // Apple's LC_MAIN entry_point_command.
			if len(current) != 24 || order.Uint64(current[8:16]) >= uint64(size) {
				return fail("managed Mach-O entry command is invalid")
			}
			entry = true
		}
	}
	if len(data) != 0 || !text || !entry {
		return fail("managed Mach-O lacks a complete native loader header")
	}
	return darwinMachOIdentity{macho.Cpu(order.Uint32(header[4:8])), order.Uint32(header[8:12])}, nil
}
func checkDarwinMachO(file *os.File, size int64) error {
	if size < 8 || size > maxDarwinInputBytes {
		return errors.New("managed executable has invalid Mach-O bounds")
	}
	var header [8]byte
	if _, err := file.ReadAt(header[:], 0); err != nil {
		return err
	}
	want := macho.CpuAmd64
	if runtime.GOARCH == "arm64" {
		want = macho.CpuArm64
	}
	magic := binary.BigEndian.Uint32(header[:4])
	if magic == 0xfeedfacf || magic == 0xcffaedfe {
		identity, err := readDarwinMachOHeader(io.NewSectionReader(file, 0, size), size)
		if err != nil {
			return err
		}
		if identity.cpu != want {
			return errors.New("managed executable has the wrong native architecture")
		}
		return nil
	}
	var order binary.ByteOrder
	switch magic {
	case 0xcafebabe, 0xcafebabf:
		order = binary.BigEndian
	default:
		return errors.New("managed executable requires a native Mach-O file; interpreter assets are not qualified")
	}
	count := order.Uint32(header[4:8])
	wide := magic == 0xcafebabf
	width := int64(20)
	if wide {
		width = 32
	}
	if count == 0 || count > 32 || 8+int64(count)*width > size {
		return errors.New("managed universal Mach-O table exceeds bounds")
	}
	type slice struct {
		offset, length int64
		identity       darwinMachOIdentity
	}
	slices := make([]slice, 0, count)
	identities := map[darwinMachOIdentity]bool{}
	native := false
	for index := uint32(0); index < count; index++ {
		var raw [32]byte
		if _, err := file.ReadAt(raw[:width], 8+int64(index)*width); err != nil {
			return err
		}
		identity := darwinMachOIdentity{macho.Cpu(order.Uint32(raw[:4])), order.Uint32(raw[4:8])}
		offset, length := uint64(order.Uint32(raw[8:12])), uint64(order.Uint32(raw[12:16]))
		alignment := order.Uint32(raw[16:20])
		if wide {
			offset, length = order.Uint64(raw[8:16]), order.Uint64(raw[16:24])
			alignment = order.Uint32(raw[24:28])
			if order.Uint32(raw[28:32]) != 0 {
				return errors.New("managed universal Mach-O reserved field is nonzero")
			}
		}
		if identities[identity] || alignment > 31 || offset < uint64(8+int64(count)*width) || offset > uint64(size) || length == 0 || length > uint64(size)-offset || offset%(uint64(1)<<alignment) != 0 {
			return errors.New("managed universal Mach-O slice is invalid")
		}
		identities[identity] = true
		if identity.cpu == want {
			native = true
		}
		slices = append(slices, slice{int64(offset), int64(length), identity})
	}
	sort.Slice(slices, func(i, j int) bool { return slices[i].offset < slices[j].offset })
	for index, slice := range slices {
		if index > 0 && slices[index-1].offset+slices[index-1].length > slice.offset {
			return errors.New("managed universal Mach-O slices overlap")
		}
		identity, err := readDarwinMachOHeader(io.NewSectionReader(file, slice.offset, slice.length), slice.length)
		if err != nil {
			return err
		}
		if identity != slice.identity {
			return errors.New("managed universal Mach-O architecture differs from its table")
		}
	}
	if !native {
		return errors.New("managed universal executable lacks the native architecture")
	}
	return nil
}
