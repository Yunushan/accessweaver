# Audit event format and checkpoint verification

AccessWeaver now provides a bounded event-chain format and a read-only verifier for exported segments. Live user/administrator event recording, protected durable storage, retention acknowledgments and collector integration remain unfinished. The enterprise audit readiness gate remains missing.

## Verify a segment

Retain the complete starting and ending checkpoints through an independently trusted administrative or collector channel. Then run:

```text
accessweaver audit verify --events segment.jsonl --from retained-start.json --to retained-end.json
```

The command reads three regular files, snapshots at most 1,024 bytes per checkpoint and 8 MiB of event data, and uses one shared 15-second deadline for input reading and verification. It creates no profile directory, modifies no input, starts no engine and contacts no service. Paths, malformed input, reader errors and event contents are excluded from failure messages. A blocked file read returns a verification timeout; its one outstanding worker can remain blocked until process exit.

Success reports scope checkpoint-matched-segment, stream ID, endpoint sequences, record/byte counts and checkpointHashesMatched. Failure returns a nonzero exit status without partial-success JSON. An empty segment can match identical checkpoints and reports zero records.

Both endpoints are necessary. A retained ending checkpoint detects loss or rewriting up to that known head. Events after that checkpoint, or never collected, remain outside its proof. A retained starting checkpoint permits verification of a retained suffix after an earlier segment has been archived. Self-selected replacement checkpoints can make a rewritten chain match: neither a matching chain nor its producer fields establish OS identity, publisher trust or authenticity of the claimed action. Collectors must protect enrollment, transport and stored checkpoints independently.

## Canonical version-one format

Every checkpoint and event record is one canonical UTF-8 JSON object followed by exactly one LF byte. Field order and scalar encodings match the checked-in vectors. Duplicate, unknown, case-aliased or missing fields, null substitutions, alternate number encodings, invalid UTF-8, CRLF, extra whitespace, partial final records and trailing data refuse.

A checkpoint contains schemaVersion, streamID, producer, sequence and sha256. Stream IDs are random 128-bit values encoded as 32 lowercase hexadecimal characters. Sequences are integers from zero through 2^53 minus one for exact JSON collector interoperability. Sequence zero must match its computed genesis hash.

Producer fields are actorClass (user or administrator), actorSHA256, sourceCommit, sourceState and target. The actor hash is a claim supplied by a future trusted producer, not an OS identity lookup performed by this component. Source commits are complete 40/64-character lowercase hexadecimal IDs or explicit unknown; an unknown commit requires unknown source state. Targets retain all ten documented Windows/Linux/macOS/FreeBSD/OpenBSD amd64/arm64 combinations. A producer change requires another stream and separately trusted enrollment.

Each record contains schemaVersion, streamID, sequence, previousSHA256, producerSHA256, event and sha256. Its producer digest binds producer metadata even when verification starts at a nonzero checkpoint. The event contains only:

| Field | Contract |
| --- | --- |
| occurredAt | Nonzero UTC timestamp, canonical RFC3339 with optional fractional seconds; the producer's clock claim |
| operationID | 128-bit correlation ID encoded as 32 lowercase hexadecimal characters |
| action | One of the fixed actions below |
| outcome | intent, accepted, completed, refused, failed, canceled or indeterminate |

Actions are profile.write, profile.delete, profile.import, engine.start, engine.stop, workflow.submit, workflow.cancel, workflow.complete, policy.install, policy.remove, policy.recover, backup.create, backup.restore, support.export and audit.export. Accepted work and completed work have distinct outcomes. The format does not infer that an action occurred or reconcile intent/result pairs.

There is no free-text, path, URL, request-body, error, token, profile-name or command-line field. Future producers must construct hashes and correlation IDs from the intended sources; placing a secret in a field shaped like a digest would still disclose that secret. The verifier checks the format and checkpoint linkage rather than sanitizing deliberately misconstructed producer metadata.

A segment requires one stream/producer, strictly consecutive sequences, exact predecessor hashes and the expected final checkpoint. It is capped at 4,096 records and 2,048 bytes per record. Verification retains one record at a time and returns no partial result on cancellation, transport error, excess data, malformed input or endpoint mismatch. Clock rollback is retained as a clock claim; sequence establishes record order.

## Hash construction and interoperability

The digest primitive is Go's [SHA-256 implementation of FIPS 180-4](https://pkg.go.dev/crypto/sha256). Domain separation uses the bytes AccessWeaver audit v1 followed by NUL, then the label below and another NUL:

| Label | Hashed canonical JSON bytes, without LF |
| --- | --- |
| producer | The producer object |
| genesis | An object containing streamID followed by producer |
| record | The record fields in their defined order, excluding the final sha256 field |

The JSONL fixtures under internal/audit/testdata were computed independently using Python hashlib and explicit ordered JSON. Their producer, source and action are synthetic test values. The golden genesis is f46a1fa94779261f1f1af27a88fe00ce2bdb37d8b5ea4249371ffd39eec170d4; the one-record head is 583c916334fd758f8f5dbc020654193591b86955da324d96d35cb4f2b216887f.

```text
accessweaver audit verify --events internal/audit/testdata/events.jsonl --from internal/audit/testdata/genesis.json --to internal/audit/testdata/end.json
```

Run this repository example from a source checkout. It checks format interoperability. Its self-contained synthetic checkpoints are not evidence of a deployed audit trail.

## Remaining implementation and acceptance

The pure Append function prepares one record and its successor checkpoint. It performs no I/O. A durable producer must commit the record before advancing a saved head and preserve ambiguous interrupted writes for reconciliation. It must enforce protected ownership/ACLs, bounded admission and storage, retention tied to collector acknowledgment, independently pinned checkpoints and accurate asynchronous outcomes. Required-audit failures must have explicit behavior before operations are dispatched; a result-write failure after an operation cannot be treated as proof that the operation did not occur.

Controller/CLI/privileged-helper coverage, OS-derived actor attribution, consent-aware export, collector deployment and hostile-input/crash/full-disk/native acceptance across the supported desktop matrix remain required. [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final) provides the enterprise log-management context for those operational requirements. This protocol and CLI add no readiness score credit.
