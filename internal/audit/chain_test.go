package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func fixtureProducer() Producer {
	return Producer{"user", strings.Repeat("a", 64), strings.Repeat("b", 40), "clean", "linux/amd64"}
}
func fixtureEvent(index int) Event {
	return Event{time.Date(2026, 11, 4, 12, 0, index, 0, time.UTC), strings.Repeat("c", 32), "profile.write", "intent"}
}
func fixtureChain(t *testing.T, count int) ([]Checkpoint, [][]byte) {
	t.Helper()
	start, err := NewStream(fixtureProducer())
	if err != nil {
		t.Fatal(err)
	}
	heads := []Checkpoint{start}
	lines := [][]byte{}
	for i := 0; i < count; i++ {
		line, next, err := Append(heads[len(heads)-1], fixtureEvent(i))
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
		heads = append(heads, next)
	}
	return heads, lines
}
func verifyFixture(data []byte, from, to Checkpoint) (Verification, error) {
	return VerifySegment(context.Background(), bytes.NewReader(data), from, to)
}
func expectRefusal(t *testing.T, data []byte, from, to Checkpoint) {
	t.Helper()
	result, err := verifyFixture(data, from, to)
	if err == nil || result != (Verification{}) {
		t.Fatalf("refusal returned success or partial evidence: %+v %v", result, err)
	}
}

func TestCompleteAndRetainedSuffixMatchExplicitCheckpoints(t *testing.T) {
	heads, lines := fixtureChain(t, 3)
	for _, start := range []int{0, 1, 2, 3} {
		data := bytes.Join(lines[start:], nil)
		result, err := verifyFixture(data, heads[start], heads[3])
		if err != nil || result.Records != 3-start || result.Bytes != int64(len(data)) || result.FromSequence != uint64(start) ||
			result.ToSequence != 3 || !result.CheckpointHashesMatched || result.Scope != "checkpoint-matched-segment" {
			t.Fatalf("%+v %v", result, err)
		}
	}
	for _, head := range heads {
		wire, err := EncodeCheckpoint(head)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := DecodeCheckpoint(wire)
		if err != nil || actual != head {
			t.Fatalf("checkpoint identity changed: %v", err)
		}
	}
	// Clock rollback is retained as a clock claim; sequence remains authoritative.
	event := fixtureEvent(0)
	event.OccurredAt = event.OccurredAt.Add(-time.Hour)
	line, next, err := Append(heads[3], event)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verifyFixture(line, heads[3], next); err != nil {
		t.Fatal(err)
	}
}
func TestAnchorsRefuseRewriteOmissionReorderDuplicateAndSplice(t *testing.T) {
	heads, lines := fixtureChain(t, 3)
	whole := bytes.Join(lines, nil)
	_, foreign := fixtureChain(t, 1)
	for name, data := range map[string][]byte{
		"empty": nil, "deleted-prefix": bytes.Join(lines[1:], nil),
		"deleted-suffix": bytes.Join(lines[:2], nil),
		"deleted-middle": append(append([]byte{}, lines[0]...), lines[2]...),
		"reordered":      bytes.Join([][]byte{lines[1], lines[0], lines[2]}, nil),
		"duplicate":      bytes.Join([][]byte{lines[0], lines[0], lines[1], lines[2]}, nil),
		"spliced":        bytes.Join([][]byte{lines[0], foreign[0], lines[2]}, nil),
		"partial":        whole[:len(whole)-1], "extra": append(append([]byte{}, whole...), lines[2]...),
		"extra-newline": append(append([]byte{}, whole...), '\n'),
	} {
		t.Run(name, func(t *testing.T) { expectRefusal(t, data, heads[0], heads[3]) })
	}
	// An attacker recomputing every later hash still cannot meet a retained end.
	next := heads[0]
	forged := []byte{}
	for i := 0; i < 3; i++ {
		event := fixtureEvent(i)
		event.Outcome = "completed"
		line, after, err := Append(next, event)
		if err != nil {
			t.Fatal(err)
		}
		forged = append(forged, line...)
		next = after
	}
	expectRefusal(t, forged, heads[0], heads[3])
	// Self-selected replacement anchors do match: this is why neither output nor
	// documentation may call a chain a signature or independently authenticated.
	if result, err := verifyFixture(forged, heads[0], next); err != nil || result.Scope != "checkpoint-matched-segment" {
		t.Fatalf("%+v %v", result, err)
	}
	for _, field := range []string{"actor", "source", "target"} {
		from, to := heads[1], heads[3]
		switch field {
		case "actor":
			from.Producer.ActorSHA256 = strings.Repeat("d", 64)
		case "source":
			from.Producer.SourceCommit = strings.Repeat("d", 40)
		case "target":
			from.Producer.Target = "darwin/arm64"
		}
		to.Producer = from.Producer
		expectRefusal(t, bytes.Join(lines[1:], nil), from, to)
	}
}
func TestCanonicalRecordsAndCheckpointsRefuseAmbiguousJSON(t *testing.T) {
	heads, lines := fixtureChain(t, 1)
	original := string(lines[0])
	changes := map[string]string{
		"duplicate":      strings.Replace(original, `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1),
		"case-alias":     strings.Replace(original, `"streamID"`, `"StreamID"`, 1),
		"unknown":        strings.Replace(original, `"event":{`, `"private":"PRIVATE_SECRET","event":{`, 1),
		"nested-unknown": strings.Replace(original, `"event":{`, `"event":{"token":"PRIVATE_SECRET",`, 1),
		"null":           strings.Replace(original, `"sequence":1`, `"sequence":null`, 1),
		"boolean":        strings.Replace(original, `"sequence":1`, `"sequence":true`, 1),
		"float":          strings.Replace(original, `"sequence":1`, `"sequence":1.0`, 1),
		"exponent":       strings.Replace(original, `"sequence":1`, `"sequence":1e0`, 1),
		"whitespace":     " " + original, "trailing": original + "{}\n", "crlf": strings.TrimSuffix(original, "\n") + "\r\n",
		"no-newline": strings.TrimSuffix(original, "\n"), "bad-unicode": strings.Replace(original, "profile.write", "profile.writ\xff", 1),
	}
	for name, value := range changes {
		t.Run(name, func(t *testing.T) {
			_, err := verifyFixture([]byte(value), heads[0], heads[1])
			if err == nil || strings.Contains(err.Error(), "PRIVATE_SECRET") {
				t.Fatal("ambiguous or private audit input accepted/exposed", err)
			}
		})
	}
	wire, err := EncodeCheckpoint(heads[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		" " + string(wire), strings.TrimSuffix(string(wire), "\n"),
		strings.Replace(string(wire), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1),
		strings.Replace(string(wire), `"producer":{`, `"producer":{"password":"PRIVATE_SECRET",`, 1),
		strings.Replace(string(wire), `"sequence":0`, `"sequence":null`, 1),
		strings.Replace(string(wire), `"target"`, `"TARGET"`, 1),
	} {
		c, err := DecodeCheckpoint([]byte(value))
		if err == nil || c != (Checkpoint{}) || strings.Contains(err.Error(), "PRIVATE_SECRET") {
			t.Fatal("ambiguous checkpoint accepted/exposed", err)
		}
	}
}
func TestProducerAndEventAllowlistsCannotRetainFreeText(t *testing.T) {
	private := "PRIVATE_TOKEN /private/profile secret@example.invalid"
	for _, field := range []string{"actorClass", "actorHash", "commit", "sourceState", "target"} {
		p := fixtureProducer()
		switch field {
		case "actorClass":
			p.ActorClass = private
		case "actorHash":
			p.ActorSHA256 = private
		case "commit":
			p.SourceCommit = private
		case "sourceState":
			p.SourceState = private
		case "target":
			p.Target = private
		}
		if c, err := NewStream(p); err == nil || c != (Checkpoint{}) || strings.Contains(err.Error(), private) {
			t.Fatal("private producer accepted/exposed")
		}
	}
	heads, _ := fixtureChain(t, 0)
	for _, field := range []string{"action", "outcome", "operation", "zeroTime", "offset"} {
		e := fixtureEvent(0)
		switch field {
		case "action":
			e.Action = private
		case "outcome":
			e.Outcome = private
		case "operation":
			e.OperationID = private
		case "zeroTime":
			e.OccurredAt = time.Time{}
		case "offset":
			e.OccurredAt = e.OccurredAt.In(time.FixedZone("private", 3600))
		}
		data, next, err := Append(heads[0], e)
		if err == nil || data != nil || next != (Checkpoint{}) || strings.Contains(err.Error(), private) {
			t.Fatal("private event accepted/exposed")
		}
	}
	for _, target := range []string{"windows/amd64", "windows/arm64", "linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "freebsd/amd64", "freebsd/arm64", "openbsd/amd64", "openbsd/arm64"} {
		p := fixtureProducer()
		p.Target = target
		if _, err := NewStream(p); err != nil {
			t.Fatal(target, err)
		}
	}
	p := fixtureProducer()
	p.SourceCommit = "unknown"
	if _, err := NewStream(p); err == nil {
		t.Fatal("unknown commit claimed clean")
	}
	p.SourceState = "unknown"
	if _, err := NewStream(p); err != nil {
		t.Fatal(err)
	}
}

type countedReader struct{ calls int }

func (r *countedReader) Read(p []byte) (int, error) { r.calls++; return 0, io.EOF }

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE_READER_FAILURE") }

type cancelReader struct {
	input  io.Reader
	cancel context.CancelFunc
}

func (r *cancelReader) Read(data []byte) (int, error) {
	n, err := r.input.Read(data)
	r.cancel()
	return n, err
}
func TestBoundsCancellationAndReadFailuresReturnNoPartialSuccess(t *testing.T) {
	heads, lines := fixtureChain(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := &countedReader{}
	if result, err := VerifySegment(ctx, reader, heads[0], heads[1]); !errors.Is(err, context.Canceled) || result != (Verification{}) || reader.calls != 0 {
		t.Fatal("pre-canceled verifier read data")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if result, err := VerifySegment(ctx, &cancelReader{bytes.NewReader(lines[0]), cancel}, heads[0], heads[1]); !errors.Is(err, context.Canceled) || result != (Verification{}) {
		t.Fatal("mid-read cancellation reported success", result, err)
	}
	result, err := VerifySegment(context.Background(), errorReader{}, heads[0], heads[1])
	if err == nil || result != (Verification{}) || strings.Contains(err.Error(), "PRIVATE_READER_FAILURE") {
		t.Fatal("reader error leaked or succeeded")
	}
	for _, data := range [][]byte{[]byte(strings.Repeat("x", MaxRecordBytes+1) + "\n"), append(lines[0], []byte(strings.Repeat("x", MaxRecordBytes+1))...)} {
		expectRefusal(t, data, heads[0], heads[1])
	}
	to := heads[1]
	to.Sequence = MaxSegmentRecords + 1
	reader = &countedReader{}
	if _, err := VerifySegment(context.Background(), reader, heads[0], to); err == nil || reader.calls != 0 {
		t.Fatal("excessive segment read data")
	}
	max := heads[1]
	max.Sequence = maxSequence
	if wire, next, err := Append(max, fixtureEvent(0)); err == nil || wire != nil || next != (Checkpoint{}) {
		t.Fatal("sequence capacity overflow accepted")
	}
	to = max
	to.Sequence++
	if _, err := EncodeCheckpoint(to); err == nil {
		t.Fatal("JSON-unsafe sequence accepted")
	}
	changed := heads[0]
	changed.Producer.ActorClass = "administrator"
	if _, err := EncodeCheckpoint(changed); err == nil {
		t.Fatal("genesis producer change accepted")
	}
	if _, err := VerifySegment(context.Background(), nil, heads[0], heads[0]); err == nil {
		t.Fatal("nil transport accepted")
	}
}
func TestExactSegmentRecordCapacity(t *testing.T) {
	start, err := NewStream(fixtureProducer())
	if err != nil {
		t.Fatal(err)
	}
	end := start
	var input bytes.Buffer
	for i := 0; i < MaxSegmentRecords; i++ {
		line, next, err := Append(end, fixtureEvent(i%60))
		if err != nil {
			t.Fatal(err)
		}
		input.Write(line)
		end = next
	}
	result, err := verifyFixture(input.Bytes(), start, end)
	if err != nil || result.Records != MaxSegmentRecords {
		t.Fatal(result, err)
	}
}
func FuzzCanonicalAuditDecoders(f *testing.F) {
	start, _ := NewStream(fixtureProducer())
	checkpoint, _ := EncodeCheckpoint(start)
	line, _, _ := Append(start, fixtureEvent(0))
	f.Add(checkpoint)
	f.Add(line)
	f.Add([]byte("{}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxRecordBytes+1 {
			return
		}
		if c, err := DecodeCheckpoint(data); err == nil {
			again, err := EncodeCheckpoint(c)
			if err != nil || !bytes.Equal(again, data) {
				t.Fatal("noncanonical checkpoint accepted")
			}
		}
		if r, err := decodeRecord(data); err == nil {
			again, _ := json.Marshal(r)
			if !bytes.Equal(append(again, '\n'), data) {
				t.Fatal("noncanonical record accepted")
			}
		}
	})
}

func TestIndependentGoldenVector(t *testing.T) {
	read := func(name string) []byte {
		data, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	start, err := DecodeCheckpoint(read("genesis.json"))
	if err != nil {
		t.Fatal(err)
	}
	end, err := DecodeCheckpoint(read("end.json"))
	if err != nil {
		t.Fatal(err)
	}
	line, next, err := Append(start, fixtureEvent(0))
	if err != nil || next != end || !bytes.Equal(line, read("events.jsonl")) {
		t.Fatal("independent protocol vector differs", err)
	}
	if result, err := verifyFixture(read("events.jsonl"), start, end); err != nil || result.Records != 1 {
		t.Fatal(result, err)
	}
}
