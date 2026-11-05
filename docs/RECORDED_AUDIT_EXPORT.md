# Record an explicit audit export

Linux and Windows amd64/arm64 offer a separate export-recorded command for a current, privately enrolled stream. It records access intent and a synchronous output outcome in that same protected journal. Ordinary audit export remains a read-only archive operation, including when the old actor key has been lost. Neither command enforces machine-wide export policy or authenticates a recipient.

```sh
(
  umask 077
  set -C
  accessweaver audit export-recorded --directory /home/operator/.accessweaver-import-audit --from trusted-genesis.json --to trusted-head.json --consent metadata-only > new-events.jsonl 2> new-access-observations.txt
)
```

Choose new private destinations, keep stdout and stderr separate, and retain both original endpoint inputs. Shell truncation happens before command startup and cannot be undone. Direct regular-file aliases between either output and the checkpoint inputs, journal, actor key or existing fixed machine authority refuse; stdout/stderr regular-file aliases also refuse. Wrappers and downstream pipes must not combine the streams or forward output into protected inputs. Console or pipe destinations are not automatically durable or private.

## Snapshot and access boundaries

The event output is exactly the canonical JSONL segment ending at the supplied pre-access head. Its own access intent and outcome are excluded from that artifact and appear in a subsequent export. Verify the new event file against the original input endpoints. Do not try to verify it against the newer access-result checkpoint.

A successful invocation emits two complete canonical checkpoint lines on stderr: the durably synced audit.export intent before stdout receives event bytes, followed by the durably synced outcome. Retain each complete checkpoint through an independently trusted administrative or collector channel. The second checkpoint is the new live head for a later command; two lines together are not a checkpoint input. On failure, stderr can contain zero, one or two complete observations followed by the CLI's generic error message. Preserve it, distinguish complete checkpoint lines from diagnostics, and reconcile before changing a retained head. Partial output or an unknown tail must never be adopted automatically.

The command requires the full current genesis/head, the current protected actor key and matching executing OS/build/target metadata. It reserves capacity for both access records, holds the native writer lock through snapshot, output and outcome, and fails before export when intent cannot be persisted or completely observed. Current keys, actors, builds or targets cannot silently impersonate historical producers. It never creates a replacement stream, repairs permissions, recreates a missing key, falls back to unrecorded export, adopts a journal tail, rotates storage or drops records.

Metadata-only consent is exact and mandatory before reading inputs. Checkpoints are capped at 1,024 bytes each and the pre-access segment at the existing 4,096-record/8-MiB bound. The shared cooperative fifteen-second context covers admission, input/snapshot verification and the check before the output write. Filesystem, fsync and stdout calls can block beyond it; there is no hard whole-command deadline. Once a write returns, its actual result is recorded even if cancellation occurred during that call. Outcome append uses the recorder's separate cooperative result context. At capacity, recorded export refuses instead of losing access records; the separate read-only archive command remains available and is not claimed to be recorded.

## Outcome meaning

Each admitted export uses one fresh operation ID with audit.export intent followed by completed, canceled, refused or indeterminate. No path, destination, recipient identity, exported payload, profile field or writer error enters those records. The producer identifies the executing process claim, not a human requester. Broader access attempts rejected before admission are not logged.

Completed means the local writer returned the full snapshot byte count without error. It does not establish that another process read the pipe, that a file was fsynced, that a collector accepted anything or that a recipient retained the artifact. A short write, writer error or unexpected panic is indeterminate, even if the writer reports zero bytes. A failed result append, result observation or journal close is also uncertain after export may have occurred. The command scopes standard-pipe signal handling so actual closed stdout/stderr errors reach these contracts; see [audit output failures](AUDIT_OUTPUT_FAILURES.md). No automatic retry, repair, deletion or rollback follows. If cancellation is observed before dispatch, event bytes are withheld and cancellation is recorded. Failed intent observation attempts a local refusal without exporting bytes.

## Validation and remaining qualification

Source tests cover exact consent/options, complete snapshot verification, stale endpoints, two-record capacity, durable observed intent, pre-dispatch and in-write cancellation, zero/partial/short/invalid writes, writer panic, result append/output loss, redaction and absence of profile capabilities. Real protected Linux journal tests use the actual CLI dispatcher, confirm later exports include earlier access records, preserve state on stale-head refusal, reject direct/hard-link/mixed output aliases and refuse changed/missing actor keys without fallback. Their seed events are explicitly synthetic; the tested export-access events describe actual source-command calls.

Normal-user WSL tests provide source and local protected-storage evidence. The [162f36b hosted Linux record](qualification/162f36b54865-linux-recorded-policy-export.json) verifies the separate administrator fixture on both amd64 and arm64: sixteen policy transaction records, a recorded export of that prior segment and two access records verified in a later eighteen-record archive. Exact original reports and provider ZIP digest checks are retained; this is not a cryptographic attestation or signed installed-product/managed-endpoint acceptance. The [d7137bb hosted record](qualification/d7137bb35452-linux-recorded-policy-export.json) verifies the subsequent standard-pipe correction on both Linux architectures: both complete jobs and the eighteen-record native scenario passed, with the seven closed-pipe subprocess cases included in the normal CLI suite. Cross-stream upgrades, hostile native failure/reboot/power-loss cases, collector enrollment, authenticated acknowledgments, retention and broad user/admin/async coverage remain separate. No readiness status or percentage is promoted by this implementation. See [the audit contract](AUDIT_EVENTS.md) for principal, checkpoint and storage trust boundaries.

Windows uses the [protected local NTFS backend and public-candidate qualification](WINDOWS_AUDIT_STORAGE.md). Preserve native UTF-8 output bytes in separate new destinations; the shell example above is for Linux.
