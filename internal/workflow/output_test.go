package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestWorkflowOutputRetainsCompletePrivateValues(t *testing.T) {
	result := json.RawMessage(` {"html":"<script>","path":"C:\\private","lines":"\u2028\u2029"} `)
	original := append(json.RawMessage(nil), result...)
	job := Job{ID: "private-id", Action: "discover", State: "failed", StartedAt: time.Unix(1, 0).UTC(), Result: result, Error: strings.Repeat("<legacy cause>", 2048)}
	var out bytes.Buffer
	if err := WriteJobJSON(&out, job); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(out.Bytes(), []byte("\n")) {
		t.Fatal("missing record delimiter")
	}
	var decoded Job
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, result); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Result, compact.Bytes()) || decoded.Error != job.Error || decoded.ID != job.ID || decoded.State != job.State {
		t.Fatal("private export changed or shortened a value")
	}
	if !bytes.Equal(job.Result, original) {
		t.Fatal("export mutated the original result")
	}
	out.Reset()
	if err := WriteHistoryJSON(&out, []Job{job, job}); err != nil {
		t.Fatal(err)
	}
	var history []Job
	if err := json.Unmarshal(out.Bytes(), &history); err != nil || len(history) != 2 {
		t.Fatalf("unreadable array: %v", err)
	}
	for _, row := range history {
		if !bytes.Equal(row.Result, compact.Bytes()) || row.Error != job.Error {
			t.Fatal("array export changed a value")
		}
	}
	out.Reset()
	if err := WriteHistoryJSON(&out, nil); err != nil || out.String() != "[]\n" {
		t.Fatal("empty history changed its array shape")
	}
}

func TestWorkflowOutputRejectsInvalidRecordsBeforeWriting(t *testing.T) {
	for _, bad := range []Job{
		{Result: json.RawMessage(`{"broken":`)},
		{Result: json.RawMessage(`true,false`)},
		{StartedAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		var out bytes.Buffer
		if err := WriteJobJSON(&out, bad); err == nil || out.Len() != 0 {
			t.Fatal("invalid record committed output")
		}
		if err := WriteHistoryJSON(&out, []Job{{ID: "valid"}, bad}); err == nil || out.Len() != 0 {
			t.Fatal("invalid history committed a partial array")
		}
	}
	// A record valid on its own can exceed the decoder limit inside an array.
	deep := Job{Result: json.RawMessage(strings.Repeat("[", 9999) + "0" + strings.Repeat("]", 9999))}
	var single bytes.Buffer
	if err := WriteJobJSON(&single, deep); err != nil || !json.Valid(single.Bytes()) {
		t.Fatalf("valid single record rejected: %v", err)
	}
	var array bytes.Buffer
	if err := WriteHistoryJSON(&array, []Job{deep}); err == nil || array.Len() != 0 {
		t.Fatal("undecodable history array was emitted")
	}
}

type outputFailureWriter struct {
	calls     int
	failAfter int
	short     bool
	err       error
}

func (w *outputFailureWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls > w.failAfter {
		if w.short {
			return len(p) - 1, nil
		}
		return 0, w.err
	}
	return len(p), nil
}

func TestWorkflowOutputReturnsWriterFailuresAndStops(t *testing.T) {
	failure := errors.New("fixture output disconnected")
	for _, history := range []bool{false, true} {
		for _, short := range []bool{false, true} {
			for _, after := range []int{0, 1} {
				writer := &outputFailureWriter{failAfter: after, short: short, err: failure}
				job := Job{Result: json.RawMessage(`{"ok":true}`)}
				var err error
				if history {
					err = WriteHistoryJSON(writer, []Job{job})
				} else {
					err = WriteJobJSON(writer, job)
				}
				want := failure
				if short {
					want = io.ErrShortWrite
				}
				if !errors.Is(err, want) || writer.calls != after+1 {
					t.Fatalf("output error lost or writer reused: %v, calls=%d", err, writer.calls)
				}
			}
		}
	}
}

type outputCounter struct{ total, largest int }

func (w *outputCounter) Write(p []byte) (int, error) {
	w.total += len(p)
	w.largest = max(w.largest, len(p))
	return len(p), nil
}

func TestHistoryOutputWritesOneResultAtATime(t *testing.T) {
	result := json.RawMessage(`"` + strings.Repeat("<", 64<<10) + `"`)
	jobs := make([]Job, 8)
	for i := range jobs {
		jobs[i] = Job{ID: "fixture", Result: result}
	}
	writer := &outputCounter{}
	if err := WriteHistoryJSON(writer, jobs); err != nil {
		t.Fatal(err)
	}
	if writer.largest > len(result)+1024 || writer.total < len(result)*len(jobs) || writer.total > len(result)*len(jobs)+4096 {
		t.Fatalf("aggregate encoding or result expansion: largest=%d, total=%d", writer.largest, writer.total)
	}
}

func TestHistoryMetadataStreamsWithoutExpansion(t *testing.T) {
	for _, text := range []string{strings.Repeat("<&>", 32768), strings.Repeat("\u2028\u2029", 32768)} {
		jobs := make([]Job, 4)
		for i := range jobs {
			jobs[i] = Job{ID: text, Action: text, State: text, Error: text}
		}
		writer := &outputCounter{}
		if err := WriteHistoryJSON(writer, jobs); err != nil {
			t.Fatal(err)
		}
		if writer.largest > 32<<10 || writer.total > len(text)*4*len(jobs)+4096 {
			t.Fatalf("metadata expanded or buffered: input=%d largestWrite=%d total=%d", len(text)*4*len(jobs), writer.largest, writer.total)
		}
	}
}
