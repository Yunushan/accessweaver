//go:build linux && (amd64 || arm64)

package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/api"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/profile"
)

type startupObservation struct{ output chan []byte }

func (w *startupObservation) Write(data []byte) (int, error) {
	w.output <- bytes.Clone(data)
	return len(data), nil
}

// Consume actual startup output and its OS-private launcher, rather than
// restating a formatting template. No product executable/engine is launched.
func TestDesktopStartupOutputSupportsPrivateOwnerBootstrap(t *testing.T) {
	base := auditedImportDirectory(t)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(base, "cache"))
	t.Setenv("ACCESSWEAVER_NO_BROWSER", "1")
	store, err := profile.NewStore(filepath.Join(base, "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := api.New(store, engine.NewManager(store.Root), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	finished := false
	defer func() {
		cancel()
		if !finished {
			select {
			case err := <-done:
				if err != nil {
					t.Error("desktop shutdown failed", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("desktop did not shut down")
			}
		}
	}()
	observation := &startupObservation{output: make(chan []byte, 1)}
	go func() { done <- serveDesktop(ctx, server, observation) }()
	var text string
	select {
	case data := <-observation.output:
		text = string(data)
	case err := <-done:
		finished = true
		t.Fatal("desktop exited before startup", err)
	case <-time.After(10 * time.Second):
		t.Fatal("desktop did not publish its startup output")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatal("startup did not publish three complete lines")
	}
	address := strings.TrimPrefix(lines[0], "AccessWeaver is running at ")
	if !regexp.MustCompile(`^http://127\.0\.0\.1:[0-9]+$`).MatchString(address) {
		t.Fatal("startup listener is not a canonical loopback URL")
	}
	launcherURL := strings.TrimPrefix(lines[1], "Open this private launch file in your browser: ")
	parsed, err := url.Parse(launcherURL)
	if err != nil || parsed.Scheme != "file" || parsed.Host != "" {
		t.Fatal("startup launcher is not a local file URL")
	}
	page, err := os.ReadFile(parsed.Path)
	if err != nil {
		t.Fatal("startup launcher URL does not name the created private file")
	}
	credential := regexp.MustCompile(`accessweaver-session=([A-Za-z0-9_-]{43})`).FindSubmatch(page)
	if len(credential) != 2 || bytes.Contains([]byte(text), credential[1]) {
		t.Fatal("private credential missing from launcher or disclosed in startup output")
	}
	request, err := http.NewRequest(http.MethodGet, address+"/api/bootstrap", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-AccessWeaver-Token", string(credential[1]))
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("private owner bootstrap could not connect")
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	response.Body.Close()
	if readErr != nil || response.StatusCode != 200 || bytes.Contains(body, credential[1]) {
		t.Fatal("private owner bootstrap failed or disclosed its credential")
	}
	cancel()
	select {
	case err := <-done:
		finished = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("desktop shutdown did not finish")
	}
	if _, err := os.Stat(parsed.Path); !os.IsNotExist(err) {
		t.Fatal("shutdown left the private launcher behind")
	}
}
