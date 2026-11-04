// Package audit defines bounded, metadata-only event chains. Hash linkage is
// evidence only against checkpoints retained through an independently trusted
// channel. It is not a signature, OS identity proof, or a durable journal.
package audit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
	"unicode/utf8"
)

const (
	MaxRecordBytes     = 2048
	MaxCheckpointBytes = 1024
	MaxSegmentRecords  = 4096
	MaxSegmentBytes    = MaxRecordBytes * MaxSegmentRecords
	maxSequence        = 1<<53 - 1 // Preserve integer identity in JSON collectors.
	domain             = "AccessWeaver audit v1\x00"
)

var (
	hexID    = regexp.MustCompile("^[a-f0-9]{32}$")
	hexHash  = regexp.MustCompile("^[a-f0-9]{64}$")
	commitID = regexp.MustCompile("^(?:[a-f0-9]{40}|[a-f0-9]{64}|unknown)$")
)

// Producer is a claim bound into the genesis checkpoint. Collectors must
// establish the actor and source through a trusted enrollment/OS channel;
// parsing this object does not authenticate either claim.
type Producer struct {
	ActorClass   string `json:"actorClass"`
	ActorSHA256  string `json:"actorSHA256"`
	SourceCommit string `json:"sourceCommit"`
	SourceState  string `json:"sourceState"`
	Target       string `json:"target"`
}

type Checkpoint struct {
	SchemaVersion int      `json:"schemaVersion"`
	StreamID      string   `json:"streamID"`
	Producer      Producer `json:"producer"`
	Sequence      uint64   `json:"sequence"`
	SHA256        string   `json:"sha256"`
}

// Event intentionally has no free-text, path, URL, request-body, error, token,
// profile name, or command-line field. New event classes require code review.
// Time is the producer's UTC clock claim; sequence establishes chain order.
type Event struct {
	OccurredAt  time.Time `json:"occurredAt"`
	OperationID string    `json:"operationID"`
	Action      string    `json:"action"`
	Outcome     string    `json:"outcome"`
}

type recordPayload struct {
	SchemaVersion  int    `json:"schemaVersion"`
	StreamID       string `json:"streamID"`
	Sequence       uint64 `json:"sequence"`
	PreviousSHA256 string `json:"previousSHA256"`
	ProducerSHA256 string `json:"producerSHA256"`
	Event          Event  `json:"event"`
}
type record struct {
	recordPayload
	SHA256 string `json:"sha256"`
}

func hash(label string, data []byte) string {
	sum := sha256.Sum256(append([]byte(domain+label+"\x00"), data...))
	return hex.EncodeToString(sum[:])
}
func validProducer(p Producer) bool {
	if p.ActorClass != "user" && p.ActorClass != "administrator" {
		return false
	}
	if !hexHash.MatchString(p.ActorSHA256) || !commitID.MatchString(p.SourceCommit) {
		return false
	}
	switch p.SourceState {
	case "clean", "modified", "unknown":
	default:
		return false
	}
	if p.SourceCommit == "unknown" && p.SourceState != "unknown" {
		return false
	}
	switch p.Target {
	case "windows/amd64", "windows/arm64", "linux/amd64", "linux/arm64",
		"darwin/amd64", "darwin/arm64", "freebsd/amd64", "freebsd/arm64",
		"openbsd/amd64", "openbsd/arm64":
		return true
	}
	return false
}
func validEvent(e Event) bool {
	if !hexID.MatchString(e.OperationID) || e.OccurredAt.IsZero() ||
		e.OccurredAt.Location() != time.UTC || e.OccurredAt.Year() < 1970 || e.OccurredAt.Year() > 9999 {
		return false
	}
	switch e.Action {
	case "profile.write", "profile.delete", "profile.import", "engine.start", "engine.stop",
		"workflow.submit", "workflow.cancel", "workflow.complete", "policy.install",
		"policy.remove", "policy.recover", "backup.create", "backup.restore",
		"support.export", "audit.export":
	default:
		return false
	}
	switch e.Outcome {
	case "intent", "accepted", "completed", "refused", "failed", "canceled", "indeterminate":
		return true
	}
	return false
}
func producerHash(p Producer) string {
	data, _ := json.Marshal(p)
	return hash("producer", data)
}
func genesis(c Checkpoint) string {
	data, _ := json.Marshal(struct {
		StreamID string   `json:"streamID"`
		Producer Producer `json:"producer"`
	}{c.StreamID, c.Producer})
	return hash("genesis", data)
}
func validateCheckpoint(c Checkpoint) error {
	if c.SchemaVersion != 1 || !hexID.MatchString(c.StreamID) || !validProducer(c.Producer) ||
		c.Sequence > maxSequence || !hexHash.MatchString(c.SHA256) {
		return errors.New("invalid audit checkpoint")
	}
	if c.Sequence == 0 && c.SHA256 != genesis(c) {
		return errors.New("audit genesis checkpoint differs")
	}
	return nil
}

// NewStream creates a random stream identity. Persist and enroll its checkpoint
// before accepting event claims. Replacing it silently would discard continuity.
func NewStream(p Producer) (Checkpoint, error) {
	if !validProducer(p) {
		return Checkpoint{}, errors.New("invalid audit producer")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Checkpoint{}, errors.New("audit stream randomness unavailable")
	}
	c := Checkpoint{SchemaVersion: 1, StreamID: hex.EncodeToString(id[:]), Producer: p}
	c.SHA256 = genesis(c)
	return c, nil
}

// Append prepares one canonical JSONL record and its successor checkpoint.
// It performs no I/O. A caller must commit the record before advancing its
// durable head, and must not claim that this function persisted anything.
func Append(before Checkpoint, event Event) ([]byte, Checkpoint, error) {
	if err := validateCheckpoint(before); err != nil {
		return nil, Checkpoint{}, err
	}
	if before.Sequence == maxSequence || !validEvent(event) {
		return nil, Checkpoint{}, errors.New("invalid audit event or sequence capacity")
	}
	payload := recordPayload{1, before.StreamID, before.Sequence + 1, before.SHA256, producerHash(before.Producer), event}
	encoded, _ := json.Marshal(payload)
	r := record{payload, hash("record", encoded)}
	data, _ := json.Marshal(r)
	data = append(data, '\n')
	if len(data) > MaxRecordBytes {
		return nil, Checkpoint{}, errors.New("audit record exceeds byte limit")
	}
	after := before
	after.Sequence, after.SHA256 = r.Sequence, r.SHA256
	return data, after, nil
}

func EncodeCheckpoint(c Checkpoint) ([]byte, error) {
	if err := validateCheckpoint(c); err != nil {
		return nil, err
	}
	data, _ := json.Marshal(c)
	data = append(data, '\n')
	if len(data) > MaxCheckpointBytes {
		return nil, errors.New("audit checkpoint exceeds byte limit")
	}
	return data, nil
}

// Canonical byte equality rejects duplicate/case-aliased/unknown/missing fields,
// nulls, alternate numbers, whitespace, invalid UTF-8 and trailing JSON.
func DecodeCheckpoint(data []byte) (Checkpoint, error) {
	var c Checkpoint
	if len(data) == 0 || len(data) > MaxCheckpointBytes || !utf8.Valid(data) || json.Unmarshal(data, &c) != nil {
		return Checkpoint{}, errors.New("invalid audit checkpoint encoding")
	}
	canonical, err := EncodeCheckpoint(c)
	if err != nil || !bytes.Equal(data, canonical) {
		return Checkpoint{}, errors.New("noncanonical audit checkpoint")
	}
	return c, nil
}
func decodeRecord(data []byte) (record, error) {
	var r record
	if len(data) == 0 || len(data) > MaxRecordBytes || !utf8.Valid(data) || json.Unmarshal(data, &r) != nil {
		return record{}, errors.New("invalid audit record encoding")
	}
	if r.SchemaVersion != 1 || !hexID.MatchString(r.StreamID) || r.Sequence == 0 ||
		r.Sequence > maxSequence || !hexHash.MatchString(r.PreviousSHA256) ||
		!hexHash.MatchString(r.SHA256) || !hexHash.MatchString(r.ProducerSHA256) || !validEvent(r.Event) {
		return record{}, errors.New("invalid audit record")
	}
	payload, _ := json.Marshal(r.recordPayload)
	if r.SHA256 != hash("record", payload) {
		return record{}, errors.New("audit record hash differs")
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(data, append(canonical, '\n')) {
		return record{}, errors.New("noncanonical audit record")
	}
	return r, nil
}

type Verification struct {
	SchemaVersion           int    `json:"schemaVersion"`
	Scope                   string `json:"scope"`
	StreamID                string `json:"streamID"`
	FromSequence            uint64 `json:"fromSequence"`
	ToSequence              uint64 `json:"toSequence"`
	Records                 int    `json:"records"`
	Bytes                   int64  `json:"bytes"`
	CheckpointHashesMatched bool   `json:"checkpointHashesMatched"`
}

// VerifySegment requires both independently trusted endpoints, including the
// expected final head. A self-consistent chain alone cannot detect an attacker
// rewriting its contents and all hashes, or deleting a suffix. No partial
// success is returned. Context is checked between reads; callers must supply
// regular-file input or enforce their transport's read deadline.
func VerifySegment(ctx context.Context, input io.Reader, from, to Checkpoint) (Verification, error) {
	zero := Verification{}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if err := validateCheckpoint(from); err != nil {
		return zero, err
	}
	if err := validateCheckpoint(to); err != nil {
		return zero, err
	}
	if input == nil || from.StreamID != to.StreamID || from.Producer != to.Producer ||
		to.Sequence < from.Sequence || to.Sequence-from.Sequence > MaxSegmentRecords {
		return zero, errors.New("incompatible audit segment checkpoints")
	}
	limited := &io.LimitedReader{R: input, N: MaxSegmentBytes + 1}
	reader := bufio.NewReaderSize(limited, MaxRecordBytes+1)
	current, count, total := from, 0, int64(0)
	for {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, io.EOF) && len(line) == 0 {
			break
		}
		if err != nil || len(line) > MaxRecordBytes || count >= MaxSegmentRecords ||
			current.Sequence >= to.Sequence || total+int64(len(line)) > MaxSegmentBytes {
			return zero, errors.New("audit segment is incomplete, excessive or unreadable")
		}
		r, err := decodeRecord(line)
		if err != nil {
			return zero, err
		}
		if r.StreamID != from.StreamID || r.Sequence != current.Sequence+1 || r.PreviousSHA256 != current.SHA256 || r.ProducerSHA256 != producerHash(from.Producer) {
			return zero, errors.New("audit sequence or predecessor differs")
		}
		current.Sequence, current.SHA256 = r.Sequence, r.SHA256
		count++
		total += int64(len(line))
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if current != to {
		return zero, errors.New("audit final checkpoint differs")
	}
	return Verification{1, "checkpoint-matched-segment", from.StreamID, from.Sequence, to.Sequence, count, total, true}, nil
}
