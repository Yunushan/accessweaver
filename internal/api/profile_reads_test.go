package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/profile"
)

func TestConcurrentProfileAndSupportHTTPReads(t *testing.T) {
	s := makeServer(t)
	const count = 64
	for i := 0; i < count; i++ {
		p := profile.New(fmt.Sprintf("parallel-%04d", i), "Private concurrent fixture", "byedpi")
		if err := s.Store.Save(p); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var workers sync.WaitGroup
	failures := make(chan error, 4)
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := 0; i < 24; i++ {
				endpoint := "/api/v1/profiles"
				if i%2 != 0 {
					endpoint = "/api/v1/support"
				}
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+endpoint, nil)
				if err != nil {
					failures <- err
					return
				}
				request.Header.Set("X-AccessWeaver-Token", s.Token)
				response, err := client.Do(request)
				if err != nil {
					failures <- err
					return
				}
				body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
				response.Body.Close()
				if err != nil || response.StatusCode != http.StatusOK || len(body) > 1<<20 {
					failures <- fmt.Errorf("concurrent read failed: status %d, read error %v", response.StatusCode, err)
					return
				}
				if i%2 == 0 {
					var rows []profile.Profile
					if err := json.Unmarshal(body, &rows); err != nil || len(rows) != count {
						failures <- fmt.Errorf("profile read lost inventory: %v", err)
						return
					}
				} else {
					var report supportReport
					if err := json.Unmarshal(body, &report); err != nil || report.Profiles.Total == nil || *report.Profiles.Total != count {
						failures <- fmt.Errorf("support read lost inventory: %v", err)
						return
					}
					if strings.Contains(string(body), "Private concurrent fixture") || strings.Contains(string(body), s.Token) {
						failures <- fmt.Errorf("support read disclosed private fixture data")
						return
					}
				}
			}
		}()
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}
