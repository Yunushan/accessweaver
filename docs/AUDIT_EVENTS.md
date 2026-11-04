# Audit event format and checkpoint verification

AccessWeaver now provides a bounded event-chain format and a read-only verifier for exported segments. Live user/administrator event recording, protected storage on the other desktop platforms, retention acknowledgments and collector integration remain unfinished. The enterprise audit readiness gate remains missing.

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

Producer fields are actorClass (user or administrator), actorSHA256, sourceCommit, sourceState and target. The actor hash is a wire claim; the verifier performs no OS identity lookup. The separate internal ProcessProducer factory described below derives execution-principal metadata for future live producers. Source commits are complete 40/64-character lowercase hexadecimal IDs or explicit unknown; an unknown commit requires unknown source state. Targets retain all ten documented Windows/Linux/macOS/FreeBSD/OpenBSD amd64/arm64 combinations. A producer change requires another stream and separately trusted enrollment.

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

## Native execution-principal metadata

The internal ProcessProducer factory reads the executing OS principal and buildinfo.Current source metadata for all ten documented targets. It performs no account-name, directory-service, environment-identity or network lookup, creates no stream, and writes no event. A caller must supply a dedicated random 32-byte actor pseudonymization key, protect it separately from exported checkpoints, and authenticate its enrollment independently. The factory rejects an all-zero key; that check does not establish entropy or protect a caller-chosen weak key. Do not reuse signing, policy, enrollment-authentication or other secrets for this purpose.

The actorSHA256 field contains HMAC-SHA-256 over the domain bytes AccessWeaver audit v1, NUL, process-actor, NUL, OS name, NUL, principal scheme, NUL and the canonical native principal string. The scheme is uid for Unix and sid for Windows. The raw UID/SID and key are excluded from producer output and error messages. This pseudonym is stable only within its keyed OS namespace; it is not a signature or proof of enrollment. A low-entropy UID can be guessed if its pseudonymization key is disclosed. Key scope must distinguish installations, UID namespaces and enrollment lifecycles; UID reuse cannot identify a new human account without administrative reenrollment. The independent synthetic Linux UID-1000 vector with key bytes 00..1f is 6b3b544e27dc61c7a86ceac6517162669292d0f2279061ba9f1b59f690fdb512.

Unix reads real/effective UID and GID twice and refuses mixed or changing credentials. The executing effective UID is the principal; administrator means UID zero, with every other UID classified as user. This does not evaluate supplementary groups, capabilities or application roles. Windows reads the process token's SID and elevation status while pinned to one OS thread, and refuses a thread impersonation token or any token-query error. It changes no token or context. [OpenThreadToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken) supplies the impersonation-context check; [TOKEN_ELEVATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_elevation) defines zero/nonzero elevation classification.

These are execution-principal observations. They do not identify an HTTP requester, a person who earlier elevated the process, a login name or a human. OS credentials must not change concurrently with recording. Live producers must reconstruct and compare this metadata before each operation, retain OS/requester attribution separately if required, and enroll another stream for changed principal/class/source/target/key metadata. Parsing a producer supplied by someone else still authenticates none of these claims. Source fields are build-reported provenance, not publisher verification. This factory grants no policy authority and enables no CLI/controller event recording.

Portable tests independently check the HMAC vector, key/principal/OS separation, all ten target encodings, explicit unknown or malformed source handling, fixed private errors and resistance to spoofed identity environment variables. Native Unix tests check actual effective credentials and pure mixed/changed-credential refusals. A separately opted-in disposable hosted Windows fixture duplicates only its own token, requires impersonation to refuse, then verifies exact identity restoration. No account, policy, privilege or installed-product change is part of that fixture. Its actual Windows acceptance and full collector-backed attributable auditing remain separate requirements.

## Linux journal storage component

The internal Linux amd64/arm64 journal stores one genesis checkpoint and up to 4,096 canonical event records in events.journal, bounded by 1,024 bytes plus 8 MiB. It is not connected to the CLI, controller or privileged policy producers. The existing audit verify command still reads exported JSONL; the journal includes its genesis line and is not itself that export format.

A trusted caller must supply an already opened directory with protected ancestor bindings, effective-UID ownership and mode 0700 on persistent ext4, XFS or Btrfs storage. The component borrows that handle, retains its own descriptor, and exclusively creates or opens a private mode-0600, single-link file relative to it. Existing content/permissions are never repaired. Symlinks, extra hard links, changed file identity, unexpected ownership/modes, nonpersistent storage and excessive input refuse. Root and same-UID processes remain within the storage trust boundary; local hashes do not authenticate them.

The writer holds a nonblocking exclusive OS lock for its lifetime and serializes threads. It validates the complete existing stream against its retained head before each append. Initialization syncs both the genesis file and containing directory. Append reports a new checkpoint only after an exact write, file fsync and a final file/entry check. Cancellation is checked before mutation; once a write starts, its actual durability outcome is reported even if the context is canceled. Filesystem calls, mutex acquisition and fsync do not have a deadline supplied by this API. A future live producer must supply bounded admission and explicit required-audit behavior.

A failed/short write or failed sync returns no checkpoint, makes that handle unavailable for further append/snapshot, and preserves every existing byte. Such an error does not prove a record is absent. Reopening requires the independently retained complete genesis and expected ending checkpoint. Partial data, an extra complete record or missing records refuse. The implementation never infers a trusted new head from an unknown tail, truncates it, starts a replacement stream, retries an uncertain append or removes the journal. An administrator must reconcile uncertain state independently; an explicitly reconciled complete endpoint is verified and synced before reopening succeeds. Keeping the checkpoints beside the journal would not create an independent trust channel.

Snapshot returns a bounded copy with both endpoints after full verification. It grants no export consent or collector acknowledgment. At capacity the journal refuses new events. Rotation, deletion, acknowledgment persistence and retention are deliberately unavailable until the collector protocol can authorize them.

Linux race tests cover real storage/reopen, concurrent writers, stale endpoints, alias/mode/content replacement, full capacity, injected ENOSPC/partial writes/sync errors, cancellation and volatile-filesystem refusal. Two source-built subprocess fixtures are killed after actual half/complete writes before fsync; both preserve prior and unacknowledged bytes, and reopening with the old endpoint refuses. These process interruptions are not reboot or power-loss tests. Use a private persistent native directory for TMPDIR when running the journal tests; WSL's memory-backed /tmp is correctly refused. Native hosted Linux amd64/arm64 runs, hardware durability and the other desktop storage implementations remain separate acceptance requirements.

## Remaining implementation and acceptance

The pure Append function prepares one record and its successor checkpoint. It performs no I/O; the Linux journal supplies one storage implementation. A live durable producer must commit the record before advancing a saved head and preserve ambiguous interrupted writes for reconciliation. It must enforce protected ownership/ACLs, bounded admission and storage, retention tied to collector acknowledgment, independently pinned checkpoints and accurate asynchronous outcomes. Required-audit failures must have explicit behavior before operations are dispatched; a result-write failure after an operation cannot be treated as proof that the operation did not occur.

Controller/CLI/privileged-helper coverage, enrollment of OS-derived actor attribution, consent-aware export, collector deployment and hostile-input/crash/full-disk/native acceptance across the supported desktop matrix remain required. [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final) provides the enterprise log-management context for those operational requirements. This protocol and CLI add no readiness score credit.
