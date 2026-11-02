package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// Compare decoded maps, not just selected Job fields, so this also guards the
// complete public field/omission/time contract against the standard encoder.
func assertMetadataOutputMatchesStandard(t *testing.T, job Job) {
	t.Helper()
	expected, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err = json.Unmarshal(expected, &want); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err = WriteJobJSON(&output, job); err != nil {
		t.Fatal(err)
	}
	if !utf8.Valid(output.Bytes()) {
		t.Fatal("metadata produced invalid UTF-8")
	}
	var actual map[string]any
	if err = json.Unmarshal(output.Bytes(), &actual); err != nil {
		t.Fatalf("invalid job JSON: %v", err)
	}
	if !reflect.DeepEqual(want, actual) {
		t.Fatal("streamed metadata changed the public JSON schema or values")
	}
}

func TestMetadataOutputMatchesStandardJSONSemantics(t *testing.T) {
	allBytes := make([]byte, 256)
	for i := range allBytes {
		allBytes[i] = byte(i)
	}
	for _, value := range []string{
		"", string(allBytes), "</script><img src=x onerror=alert(1)>&",
		"\u2028\u2029\U0001f642\\u2028\\u2029",
		"\xff\xc0\xaf\xed\xa0\x80\xf4\x90\x80\x80\xe2\x82",
		strings.Repeat("<legacy private cause>\u2028", 2048),
	} {
		for _, finished := range []time.Time{{}, time.Date(2026, 11, 2, 3, 4, 5, 123456789, time.FixedZone("fixture", -(5*3600+30*60)))} {
			assertMetadataOutputMatchesStandard(t, Job{ID: value, Action: value, State: value, Error: value, StartedAt: time.Unix(1, 123).UTC(), FinishedAt: finished, Result: json.RawMessage("{\"answer\":17}")})
		}
	}
	// Exercise each required JSON escape and multi-byte/invalid UTF-8 character
	// immediately around the scratch-buffer boundary.
	for padding := (32 << 10) - 8; padding <= (32<<10)+2; padding++ {
		value := strings.Repeat("x", padding) + "\x00\"\\\b\f\n\r\t\U0001f642\u2028\u2029\xff\xe2\x82"
		assertMetadataOutputMatchesStandard(t, Job{ID: value, Action: value, State: value, Error: value})
	}
}

func FuzzWorkflowMetadataOutput(f *testing.F) {
	for _, value := range []string{"", "ordinary metadata", "\"\\\x00\b\f\n\r\t<>&", "\u2028\u2029\U0001f642", "\xff\xc0\xaf\xed\xa0\x80"} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		assertMetadataOutputMatchesStandard(t, Job{ID: value, Action: value, State: value, Error: value, StartedAt: time.Unix(1, 123).UTC(), Result: json.RawMessage("null")})
	})
}

func TestMetadataPersistenceAndHistoryRetainCompleteLegacyValues(t *testing.T) {
	value := strings.Repeat("<>&\u2028\u2029", 32768)
	job := Job{ID: value, Action: value, State: value, Error: value}
	original, err := encodeJob(job)
	if err != nil {
		t.Fatal(err)
	}
	if len(original) > 4*len(value)+1024 {
		t.Fatalf("persisted metadata expanded: %d", len(original))
	}
	for _, history := range []bool{false, true} {
		var output bytes.Buffer
		if history {
			if err = WriteHistoryReportJSON(&output, []Job{job}); err != nil {
				t.Fatal(err)
			}
			var rows []Job
			if err = json.Unmarshal(output.Bytes(), &rows); err != nil || len(rows) != 1 {
				t.Fatalf("history unreadable: %v", err)
			}
			if !reflect.DeepEqual(rows[0], job) {
				t.Fatal("history truncated private metadata")
			}
		} else {
			var retained Job
			if err = json.Unmarshal(original, &retained); err != nil || !reflect.DeepEqual(retained, job) {
				t.Fatalf("persistence changed metadata: %v", err)
			}
		}
	}
}

func TestMetadataPreflightRejectsInvalidFinishedTimeBeforeOutput(t *testing.T) {
	for _, finished := range []time.Time{
		time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.FixedZone("invalid", 24*3600)),
	} {
		job := Job{Error: strings.Repeat("private", 32768), FinishedAt: finished}
		for _, write := range []func(io.Writer) error{
			func(w io.Writer) error { return WriteJobJSON(w, job) },
			func(w io.Writer) error { return WriteHistoryJSON(w, []Job{{ID: "valid"}, job}) },
			func(w io.Writer) error { return WriteSystemReportJSON(w, "fixture", job) },
		} {
			var out bytes.Buffer
			if err := write(&out); err == nil || out.Len() != 0 {
				t.Fatal("invalid finished time committed partial output")
			}
		}
	}
}

type metadataWriteCounter struct{ calls int }

func (w *metadataWriteCounter) Write(data []byte) (int, error) { w.calls++; return len(data), nil }

func TestMetadataOutputStopsAtEveryFailedWrite(t *testing.T) {
	job := Job{ID: strings.Repeat("x", 96<<10), Action: "fixture", State: "failed", Error: strings.Repeat("\u2028\x00", 32<<10), Result: json.RawMessage("{\"ok\":true}")}
	count := &metadataWriteCounter{}
	if err := WriteJobJSON(count, job); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("metadata writer disconnected")
	for after := 0; after < count.calls; after++ {
		for _, short := range []bool{false, true} {
			writer := &outputFailureWriter{failAfter: after, short: short, err: failure}
			want := failure
			if short {
				want = io.ErrShortWrite
			}
			if err := WriteJobJSON(writer, job); !errors.Is(err, want) || writer.calls != after+1 {
				t.Fatalf("writer reused after failure at %d: %v (%d calls)", after, err, writer.calls)
			}
		}
	}
}

func BenchmarkWorkflowMetadataHistoryOutput(b *testing.B) {
	text := strings.Repeat("<>&\u2028\u2029", 32768)
	jobs := make([]Job, 8)
	for i := range jobs {
		jobs[i] = Job{ID: text, Action: text, State: text, Error: text}
	}
	b.SetBytes(int64(len(text) * 4 * len(jobs)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := WriteHistoryJSON(io.Discard, jobs); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWorkflowMetadataSmallJobOutput(b *testing.B) {
	job := Job{ID: "fixture", Action: "discover", State: "running"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := WriteJobJSON(io.Discard, job); err != nil {
			b.Fatal(err)
		}
	}
}
