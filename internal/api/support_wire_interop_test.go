package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/privatefile"
	"github.com/Yunushan/accessweaver/internal/profile"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

var supportWireDirectories = []string{
	"internal/api", "internal/audit", "internal/buildinfo", "internal/engine",
	"internal/fileidentity", "internal/filelock", "internal/logfile", "internal/managed",
	"internal/nativepath", "internal/nativeprocess", "internal/privatefile", "internal/profile", "internal/workflow",
}
var supportWireFixedSources = []string{
	"go.mod", "go.sum", "internal/workflow/windows.ps1", "internal/api/server_test.go",
	"internal/api/support_test.go", "internal/api/support_wire_interop_test.go",
	"web/app.js", "web/system.js", "web/locales.js", "web/index.html", "web/app.css", "web/app.test.cjs",
}

type supportWireSource struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}
type supportWireFile struct {
	Name        string `json:"name"`
	Size        int    `json:"size"`
	SHA256      string `json:"sha256"`
	Status      int    `json:"status"`
	ContentType string `json:"contentType"`
}
type supportWireManifest struct {
	SchemaVersion int                 `json:"schemaVersion"`
	Sources       []supportWireSource `json:"sources"`
	Files         []supportWireFile   `json:"files"`
	Expected      struct {
		AvailableTotal  int    `json:"availableTotal"`
		AvailableEngine string `json:"availableEngine"`
	} `json:"expected"`
}

func supportWireHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func supportWireSourceHashes(t *testing.T, repository string) []supportWireSource {
	t.Helper()
	names := map[string]bool{}
	for _, name := range supportWireFixedSources {
		names[name] = true
	}
	for _, dir := range supportWireDirectories {
		entries, err := os.ReadDir(filepath.Join(repository, filepath.FromSlash(dir)))
		if err != nil || len(entries) > 512 {
			t.Fatal("support wire source directory unavailable")
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
				t.Fatal("support wire source is not a regular file")
			}
			names[dir+"/"+entry.Name()] = true
		}
	}
	if len(names) == 0 || len(names) > 512 {
		t.Fatal("support wire source count exceeded")
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	result := make([]supportWireSource, 0, len(ordered))
	var total int64
	for _, name := range ordered {
		path := filepath.Join(repository, filepath.FromSlash(name))
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 8<<20 {
			t.Fatal("support wire source unavailable")
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal("support wire source unavailable")
		}
		data, readErr := io.ReadAll(io.LimitReader(f, (8<<20)+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || len(data) > 8<<20 || int64(len(data)) != info.Size() {
			t.Fatal("support wire source read failed")
		}
		total += int64(len(data))
		if total > 8<<20 {
			t.Fatal("support wire source aggregate exceeded")
		}
		result = append(result, supportWireSource{Name: name, SHA256: supportWireHash(data)})
	}
	return result
}

// Optional source-bound interoperability producer. Only the actual in-process
// authenticated handler runs; it launches no engine, worker or network listener.
func TestSupportDesktopWireInterop(t *testing.T) {
	directory := os.Getenv("ACCESSWEAVER_SUPPORT_INTEROP")
	if directory == "" {
		t.Skip("explicit support wire fixture directory required")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("support wire output must be an existing ordinary directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("support wire output must be empty")
	}
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("support wire source location unavailable")
	}
	repository := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "../.."))
	sources := supportWireSourceHashes(t, repository)
	write := func(name string, data []byte) {
		t.Helper()
		f, err := privatefile.Create(filepath.Join(directory, name))
		if err != nil {
			t.Fatal("support wire private output unavailable")
		}
		n, writeErr := f.Write(data)
		if writeErr == nil && n == len(data) {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil || n != len(data) {
			t.Fatal("support wire private output incomplete")
		}
	}
	// The store and summaries belong only to this fixture, not host policy.
	guard := managed.NewGuard(func() (*managed.Authority, error) { return nil, nil })
	store, err := profile.NewStoreWithGuard(t.TempDir(), guard)
	if err != nil {
		t.Fatal("support wire controlled store unavailable")
	}
	server, err := New(store, engine.NewManagerWithGuard(store.Root, guard), nil)
	if err != nil {
		t.Fatal("support wire actual server unavailable")
	}
	server.Policy = guard
	server.Workflows = workflow.NewWithGuard(store.Root, guard)
	marker := "PRIVATE_SUPPORT_WIRE_FIXTURE"
	var saved profile.Profile
	for _, candidate := range profile.Builtins() {
		if candidate.Engine == "byedpi" {
			saved = candidate
			break
		}
	}
	if saved.Engine != "byedpi" {
		t.Fatal("support wire engine fixture unavailable")
	}
	saved.ID = "support-wire-fixture"
	saved.Name = marker
	saved.Description = marker
	saved.Notes = marker
	if err := server.Store.Save(saved); err != nil {
		t.Fatal("support wire profile fixture unavailable")
	}
	manifest := supportWireManifest{SchemaVersion: 1, Sources: sources}
	manifest.Expected.AvailableTotal = 1
	manifest.Expected.AvailableEngine = "byedpi"
	for _, name := range []string{"available.json", "unavailable.json"} {
		if name == "unavailable.json" {
			if err := os.WriteFile(filepath.Join(server.Store.Root, "profiles", marker+".json"), []byte(`{"incomplete":`), 0600); err != nil {
				t.Fatal("support wire unavailable fixture failed")
			}
		}
		response := request(t, server, "GET", "/api/v1/support", nil, server.Token, "127.0.0.1:54321")
		data := response.Body.Bytes()
		if response.Code != 200 || len(data) == 0 || len(data) > 16<<10 || !strings.HasPrefix(response.Header().Get("Content-Type"), "application/json") || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("support wire actual response failed")
		}
		for _, private := range []string{marker, saved.ID, server.Token, server.Store.Root} {
			encodedPrivate, err := json.Marshal(private)
			if err != nil || len(encodedPrivate) < 2 {
				t.Fatal("support wire privacy assertion unavailable")
			}
			if bytes.Contains(data, []byte(private)) || bytes.Contains(data, encodedPrivate[1:len(encodedPrivate)-1]) {
				t.Fatal("support wire actual response exposed fixture data")
			}
		}
		var report supportReport
		if err := json.Unmarshal(data, &report); err != nil || report.SchemaVersion != 1 || report.Scope != "metadata-only" {
			t.Fatal("support wire actual report malformed")
		}
		if name == "available.json" {
			if report.Profiles.Status != "available" || report.Profiles.Total == nil || *report.Profiles.Total != 1 || report.Profiles.ByEngine["byedpi"] != 1 {
				t.Fatal("support wire available count changed")
			}
		} else if report.Profiles.Status != "unavailable" || report.Profiles.Total != nil || len(report.Profiles.ByEngine) != 0 {
			t.Fatal("support wire unavailable count misrepresented")
		}
		write(name, data)
		manifest.Files = append(manifest.Files, supportWireFile{Name: name, Size: len(data), SHA256: supportWireHash(data), Status: response.Code, ContentType: response.Header().Get("Content-Type")})
	}
	after := supportWireSourceHashes(t, repository)
	if len(after) != len(sources) {
		t.Fatal("support wire sources changed")
	}
	for i := range after {
		if after[i] != sources[i] {
			t.Fatal("support wire sources changed")
		}
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil || len(encoded)+1 > 128<<10 {
		t.Fatal("support wire manifest exceeded")
	}
	write("manifest.json", append(encoded, '\n'))
}
