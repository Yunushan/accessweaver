# Protected local policy acceptance state

Windows, Linux and macOS native policy installation, update, rotation and signed recovery publish the installation and a protected acceptance record together. Runtime loading checks the pair before constructing authority. This local history detects primary-only rollback and retains a revision floor during primary corruption; it does not qualify independent revision escrow, automatic last-known-good selection or complete enterprise deployment.

## Record and storage contract

The acceptance record retains the exact installation bytes, including its pinned public key and signed envelope, in a strict versioned object:

~~~json
{"schemaVersion":1,"installation":"BASE64_OF_EXACT_INSTALLATION_BYTES"}
~~~

Its limit is 262,400 bytes: the 192 KiB installation limit after base64 encoding plus bounded overhead. New records require a currently valid policy. Historical reads authenticate the signature and revision at issuance, so expiry does not erase the counter. Historical reads grant no permissions; runtime loading separately checks current validity and native source protection. Duplicate/unknown/aliased fields, noncanonical base64, unsupported versions, invalid signatures and oversize records fail closed.

Native writers normalize the installation wrapper to `schemaVersion: 2`, preserving its public key, minimum revision and signed envelope. Version two requires an acceptance record. `managed prepare` continues to produce the portable version-one installation for independent offline review. Existing protected version-one installations without a record retain legacy partial enforcement; the next successful update, rotation or signed recovery adopts the pair. `managed status` exposes `storageVersion` and, when authenticated history is available, `acceptedRevision`. Both legacy and paired enforcement remain `partial` while broader integration is unfinished.

A record must match the primary installation byte for byte. Restoring an older signed primary or rewriting its whitespace blocks runtime authority, authenticated installation export and ordinary updates/rotation. Missing, empty or corrupt mandatory acceptance state also blocks those operations. Removing the required record never selects legacy compatibility. Raw `export-source` remains available for a readable protected primary and does not authenticate it.

## Publication and reading

Windows stores `Installation` and `Acceptance` as bounded `REG_BINARY` values beneath the fixed protected 64-bit policy key. One native transaction reserves both preimages, including legacy absence of acceptance, and commits both replacements. Ordinary reads bracket the installation with two acceptance reads through the same protected key handle; changed acceptance causes at most three attempts. A stable mismatched pair is rejected, rather than used as a fallback. Registry type/size and ancestor owner/ACL protections remain mandatory. Microsoft describes [transacted registry writes](https://learn.microsoft.com/en-us/windows/win32/sysinfo/writing-and-deleting-registry-data).

Linux stores `installation.json` and `acceptance.json` in `/etc/accessweaver`. Under the persistent private parent writer lock, it creates a protected sibling generation, writes and syncs both files, syncs its directory, then publishes the complete directory. Initial publication uses `RENAME_NOREPLACE`; updates use [RENAME_EXCHANGE](https://man7.org/linux/man-pages/man2/rename.2.html). The verified parent is synced after publication. There is no copy/delete or one-file publication fallback when directory exchange is unsupported. Mode and root ownership, no-follow/single-link checks and qualified persistent-filesystem checks apply to both files.

Readers use one directory descriptor for the pair and compare its identity with the active directory before returning. They retry up to three times when publication changes generations, including cleanup racing file opens. Writer preflight checks directory identity, both raw preimages and the allowed layout. Unrelated active entries cause refusal before exchange. Cleanup checks protected names, directory identity and exact expected bytes before unlinking an owned generation; changed or unrelated contents are preserved for administrator inspection. Complete abandoned pairs are automatically reclaimed only if their authenticated record matches their source. Damaged displaced pairs remain for inspection. Cleanup remains bounded to 4096 scanned entries and 128 candidates per operation.

Publication may succeed before a later durability-sync or cleanup error. The known outcome remains `committed: true` with a nonzero command result. Inspect current status before retrying; never infer that a failed invocation left the old state active.

## Recovery and trust limits

Signed recovery still requires a separately elevated CLI, an independently trusted key/minimum, a fresh exact-source-bound approval and a valid higher-revision replacement. With an intact accepted history, the replacement must exceed its revision even when the primary is empty/corrupt and the external minimum is lower. Candidate and approval validity are checked again after staging. The retained snapshot never silently becomes active permissions.

Corrupt acceptance or a missing mandatory record is refused by signed recovery while the required storage marker is readable. Recovery of compound destruction, unsafe/unreadable native storage and independently anchored monotonic state remains open. If both record and identifying primary history are destroyed, the legacy recovery interface cannot infer prior adoption; an independently recorded highest revision remains essential. Native administrator trust is unchanged: restoring both records or rolling back a whole device cannot be detected by a local pair. Use independent deployment records or an appropriate external/hardware anchor for that threat model.

## Validation and remaining scope

Portable tests cover migration semantics, exact matching, missing/corrupt records, expiry without permission fallback and the retained recovery floor. Temporary Linux tests use real directory publication, concurrent readers, direct source/record changes, unrelated entries and alias rejection. Guarded hosted Windows/Linux transaction tests stage pairs before abrupt process exit, test primary rollback, lost/corrupt acceptance and stale-floor recovery, and emit source-bound results. Inspect the CI run for the exact source being deployed; a test definition or source-only check is not native endpoint qualification.

BSD machine policy, publisher signing, full damaged-storage recovery, physical power-loss/reboot, vendor lifecycle and real endpoint-management qualification remain open. Production-readiness requirements and gate statuses remain unchanged.

## macOS paired store

macOS uses the fixed root-owned `/Library/Preferences/AccessWeaver` generation and always requires its acceptance record. It has no legacy one-file runtime fallback. Descriptor/ACL/APFS checks, exclusive initial publication, atomic directory exchange, fsync/F_FULLFSYNC ordering, bounded consistent readers and exact-preimage cleanup are described in [MACOS_MANAGED_POLICY.md](MACOS_MANAGED_POLICY.md). Its guarded hosted transaction fixture exercises rollback/counter/floor checks and close-abort recovery. Automatic orphan reclamation, abrupt-process and power-loss qualification remain open; Windows/Linux results cannot substitute for the Mac results.
