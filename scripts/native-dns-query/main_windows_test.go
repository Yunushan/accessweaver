//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

type groupResult struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
}

var groups []groupResult

func mark(t *testing.T) {
	t.Cleanup(func() { groups = append(groups, groupResult{t.Name(), !t.Failed()}) })
}
func record() *windows.DNSRecord {
	r := &windows.DNSRecord{Type: windows.DNS_TYPE_A, Length: 4, Dw: 1}
	copy(r.Data[:], []byte{192, 0, 2, 53})
	return r
}
func invoke(t *testing.T, head *windows.DNSRecord, failure error) (queryReport, int) {
	t.Helper()
	frees := 0
	r := runQuery("example.com", func(name string, kind uint16, options uint32, extra *byte, out **windows.DNSRecord, reserved *byte) error {
		if name != "example.com" || kind != 1 || options != 0x19c8 || extra != nil || reserved != nil {
			t.Error("query contract")
		}
		*out = head
		return failure
	}, func(got *windows.DNSRecord, kind uint32) {
		if got != head || kind != 1 {
			t.Error("ownership contract")
		}
		frees++
	})
	if !r.RecordsReleased {
		t.Error("release before result")
	}
	return r, frees
}
func TestQueryUsesExactNativeOptionsAndReleases(t *testing.T) {
	mark(t)
	r, n := invoke(t, record(), nil)
	if r.Outcome != "answered" || r.Code != "none" || r.AnswerCount != 1 || r.RecordCount != 1 || !r.QueryInvoked || n != 1 {
		t.Error("answered contract")
	}
}
func TestQueryErrorReleasesPartialResult(t *testing.T) {
	mark(t)
	r, n := invoke(t, record(), errors.New("synthetic"))
	if r.Code != "query-failed" || r.AnswerCount != 0 || r.RecordCount != 0 || n != 1 {
		t.Error("partial ownership")
	}
}
func TestQueryErrorWithoutResultsOwnsNothing(t *testing.T) {
	mark(t)
	r, n := invoke(t, nil, errors.New("synthetic"))
	if r.Code != "query-failed" || n != 0 {
		t.Error("empty failure ownership")
	}
}
func TestEmptySuccessIsNotAnAnswer(t *testing.T) {
	mark(t)
	r, n := invoke(t, nil, nil)
	if r.Code != "answer-bound" || r.AnswerCount != 0 || n != 0 {
		t.Error("empty success")
	}
}
func TestInvalidNamesNeverInvokeNativeQuery(t *testing.T) {
	mark(t)
	for _, name := range []string{"", "EXAMPLE.COM", "example.com.", "private.synthetic", "example.com\x00private", "https://example.com", "8.8.8.8"} {
		calls := 0
		r := runQuery(name, func(string, uint16, uint32, *byte, **windows.DNSRecord, *byte) error { calls++; return nil }, func(*windows.DNSRecord, uint32) { calls++ })
		if r.Code != "arguments" || r.QueryInvoked || calls != 0 {
			t.Error("name admission")
		}
	}
}
func TestOnlyAnswerSectionARecordsCount(t *testing.T) {
	mark(t)
	head := record()
	head.Type = windows.DNS_TYPE_CNAME
	head.Next = record()
	head.Next.Dw = 3
	head.Next.Next = record()
	r, n := invoke(t, head, nil)
	if r.AnswerCount != 1 || r.RecordCount != 3 || n != 1 {
		t.Error("answer section")
	}
}
func TestMalformedARecordRefusedAndReleased(t *testing.T) {
	mark(t)
	for _, length := range []uint16{0, 3, 5, 65535} {
		head := record()
		head.Length = length
		r, n := invoke(t, head, nil)
		if r.Code != "record-shape" || r.AnswerCount != 0 || n != 1 {
			t.Error("record shape")
		}
	}
}
func TestNonUnicastAnswerRefused(t *testing.T) {
	mark(t)
	for _, value := range [][4]byte{{0, 0, 0, 0}, {127, 0, 0, 1}, {224, 0, 0, 1}, {255, 255, 255, 255}} {
		head := record()
		copy(head.Data[:], value[:])
		r, n := invoke(t, head, nil)
		if r.Code != "record-shape" || r.AnswerCount != 0 || n != 1 {
			t.Error("address class")
		}
	}
}
func TestRecordCycleRefusedAndHeadReleasedOnce(t *testing.T) {
	mark(t)
	head := record()
	head.Next = head
	r, n := invoke(t, head, nil)
	if r.Code != "record-bound" || r.AnswerCount != 0 || n != 1 {
		t.Error("cycle bound")
	}
}
func TestRecordCountBound(t *testing.T) {
	mark(t)
	head := record()
	head.Type = windows.DNS_TYPE_CNAME
	tail := head
	for i := 0; i < 128; i++ {
		tail.Next = record()
		tail = tail.Next
		tail.Type = windows.DNS_TYPE_CNAME
	}
	r, n := invoke(t, head, nil)
	if r.Code != "record-bound" || r.RecordCount != 128 || r.AnswerCount != 0 || n != 1 {
		t.Error("list bound")
	}
}
func TestAnswerCountBound(t *testing.T) {
	mark(t)
	head := record()
	tail := head
	for i := 0; i < 64; i++ {
		tail.Next = record()
		tail = tail.Next
	}
	r, n := invoke(t, head, nil)
	if r.Code != "answer-bound" || r.AnswerCount != 0 || n != 1 {
		t.Error("answer bound")
	}
}
func TestMaximumAnswersAccepted(t *testing.T) {
	mark(t)
	head := record()
	tail := head
	for i := 1; i < 64; i++ {
		tail.Next = record()
		tail = tail.Next
	}
	r, n := invoke(t, head, nil)
	if r.Code != "none" || r.AnswerCount != 64 || n != 1 {
		t.Error("answer boundary")
	}
}
func TestReportIsClosedAndPrivateDataFree(t *testing.T) {
	mark(t)
	r, _ := invoke(t, record(), nil)
	b, err := json.Marshal(r)
	var v map[string]any
	if err != nil || json.Unmarshal(b, &v) != nil || len(v) != 11 || len(b) > 1024 {
		t.Fatal("report shape")
	}
	for _, secret := range []string{"192.0.2.53", "example.com", "synthetic", "Next", "Ttl", "Data"} {
		if strings.Contains(string(b), secret) {
			t.Error("private field")
		}
	}
}
func TestMain(m *testing.M) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		os.Exit(2)
	}
	code := m.Run()
	path := os.Getenv("ACCESSWEAVER_DNS_QUERY_UNIT_REPORT")
	workspace := os.Getenv("GITHUB_WORKSPACE")
	if path != "" {
		hashes := map[string]string{}
		for _, name := range []string{"scripts/native-dns-query/main_windows.go", "scripts/native-dns-query/main_windows_test.go"} {
			b, err := os.ReadFile(filepath.Join(workspace, name))
			if err != nil {
				os.Exit(2)
			}
			h := sha256.Sum256(b)
			hashes[name] = hex.EncodeToString(h[:])
		}
		value := struct {
			SchemaVersion      int               `json:"schemaVersion"`
			SourceCommit       string            `json:"sourceCommit"`
			SourceSHA256       map[string]string `json:"sourceSHA256"`
			Groups             []groupResult     `json:"groups"`
			Passed             bool              `json:"passed"`
			NativeQueryInvoked bool              `json:"nativeQueryInvoked"`
		}{1, os.Getenv("GITHUB_SHA"), hashes, groups, code == 0, false}
		b, err := json.Marshal(value)
		if err != nil {
			os.Exit(2)
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			os.Exit(2)
		}
		_, writeErr := f.Write(b)
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			os.Exit(2)
		}
	}
	os.Exit(code)
}
