# Local policy acceptance state — integration in progress

Status: the record codec and Linux namespace primitive are implemented and tested. Native publication, loading, migration and recovery integration are still pending. The current runtime continues to use the existing installation value/file. This document does not qualify rollback protection, automatic last-known-good selection or independent revision escrow.

## Record contract

A separately protected acceptance record retains the exact bytes of the last accepted installation, including its pinned public key and signed envelope. The source is encoded as canonical base64 in a strict, versioned JSON object:

~~~json
{"schemaVersion":1,"installation":"BASE64_OF_EXACT_INSTALLATION_BYTES"}
~~~

The record limit is 262,400 bytes: the existing 192 KiB installation limit after base64 encoding plus bounded format overhead. A new record requires a currently valid installation. Historical reads authenticate the policy signature and revision at issuance, so expiry does not erase the accepted revision. Historical reads return no runtime authority. Current permissions must separately pass ordinary signature, validity-window and native-source checks.

The accepted revision, key identity and source digest are derived from the authenticated snapshot. They are not caller-provided counters. An older signed primary source, a changed key, or a whitespace-only rewrite fails exact source comparison. A candidate must advance the accepted revision, in addition to satisfying its operation's existing install, update, rotation or recovery authorization. Revision comparison alone never approves a signing-key change.

The implementation rejects duplicate/unknown/aliased fields, unsupported versions, empty snapshots, malformed or noncanonical base64, invalid signatures and oversize records. Missing decoded history is an error, rather than an implicit permission.

## Native integration requirements

1. Initial installation, update, rotation and recovery must publish the installation and acceptance record together. Preserve the existing protections, stale-reader checks, post-staging expiry checks and committed-result/error distinction.
2. Read the pair consistently before returning authority. Reject mismatch, corrupt acceptance history, unsupported storage versions and missing required records. Invalid primary policy remains blocked; retaining a snapshot does not silently reactivate its permissions.
3. Use the accepted revision during repair even when the primary source is empty or damaged. A lower externally supplied minimum cannot permit a candidate at or below a retained higher revision. Recovery still requires its independent key, exact source binding and signed approval.
4. Introduce an explicit native storage version requiring the companion record. Define migration from legacy installations and make the enforcement status distinguish unanchored legacy state. Removing a required record must not silently select legacy behavior.
5. Preserve raw-source export and source-byte identity. Define how approval binds damaged companion state before extending repair to a corrupt or missing mandatory record. Preserve current refusals for unsafe ownership, ACLs, reparse/link aliases, wrong registry types and unreadable storage.
6. Retain unknown and independently changed objects. Do not recursively remove a displaced policy directory. Check owned names, protection and expected contents before cleanup; report committed state if publication succeeded but cleanup/sync failed.

## Platform mechanisms

Windows can associate multiple registry operations with one native transaction. Extend the existing protected registry transaction to reserve and publish both values, with stale-read protection for the entire pair. Evaluate a bounded RegQueryMultipleValues read for consistent ordinary-user snapshots; its pointer/length/type results need explicit bounds validation. Preserve the 64-bit view and fixed native source selection. Microsoft documents [transacted writes](https://learn.microsoft.com/en-us/windows/win32/sysinfo/writing-and-deleting-registry-data) and [multi-value reads](https://learn.microsoft.com/en-us/windows/win32/sysinfo/retrieving-data-from-the-registry).

Linux needs the pair in a protected generation directory and one atomic publication. The tested primitive uses [RENAME_EXCHANGE](https://man7.org/linux/man-pages/man2/rename.2.html) to exchange complete directories beneath the verified parent. Integration must hold the protected writer lock, verify both directory identities/layouts/preimages, sync both files and the directory before exchange, and sync the parent afterward. Unsupported filesystems must return an error.

A reader that opened a directory before exchange stays on that generation. Cleanup can race with subsequent child-file opens: open both files and retry a bounded number of times if the active directory changed. Never pair records opened through separate path lookups across generations. Before exchange, reject unsupported directory contents without moving or deleting unrelated objects. Cleanup of a displaced generation must preserve unexpected or changed contents.

The standalone exchange primitive performs no deletion and does not implement these transaction or reader protections by itself.

## Required acceptance before activation

- Valid forward update and key rotation; denied older/equal revisions, restored primary files, retired keys and substituted keys.
- Corrupt/empty primary with intact accepted history; stale recovery minima cannot reset the floor.
- Expired historical snapshot retains its counter while granting no expired permissions.
- Missing/corrupt companion records and legacy migration have explicit fail-closed behavior and native diagnostics.
- Hold readers/writers around staging and publication; verify pair consistency, stale-reader rejection and bounded retries.
- Abrupt process exit before publication, namespace/registry commit failure, sync/cleanup failure and preserved unrelated/changed objects.
- Native Windows/Linux amd64 and arm64 tests, ordinary-user denial, and source/binary-bound public candidate evidence.

## Trust and remaining scope

Native protection is required before this record supplies authority about accepted history. A valid signature inside arbitrary user-supplied JSON does not establish enrollment.

A local record cannot establish a monotonic counter against an administrator restoring both records or rolling back the whole device. Independent deployment records or an appropriate external/hardware anchor remain necessary for that threat model. macOS/BSD machine policy, full damaged-storage recovery, signed deployment and endpoint lifecycle qualification remain open. All production-readiness requirements and gate statuses remain unchanged.

