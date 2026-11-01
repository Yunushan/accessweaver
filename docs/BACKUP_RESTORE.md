# Encrypted profile backup and restore

AccessWeaver provides an offline CLI workflow for saved profiles. The archive includes the typed profile fields and saved revision timestamps. It excludes machine policy/trust, signing keys, launch credentials, browser storage, logs, workflow/recovery journals, external engine/configuration files, installed services and network state. References to paths and literal arguments are profile data and are encrypted. Backups are not support summaries; share them only with intended recipients.

## Create and verify

Use a long, unique passphrase from a password manager. Provide it in a private UTF-8 file outside the application data directory, protected for your account. The CLI accepts 12-1024 UTF-8 bytes, removes exactly one final LF or CRLF, and preserves other spaces and Unicode bytes. There is no normalization. Do not put the passphrase in command arguments, shell history or an environment variable. Keep its recovery copy separately from the archive; a lost passphrase cannot be recovered by AccessWeaver.

With an existing profile store, run:

```text
accessweaver backup create --out profiles.awbackup --passphrase-file passphrase.txt
accessweaver backup inspect --archive profiles.awbackup --passphrase-file passphrase.txt
```

`ACCESSWEAVER_HOME` selects the source store as for ordinary profile commands. Create never seeds profiles or starts an engine. It takes one consistent snapshot under the shared profile lock. Reads are streamed and bounded to 4096 directory entries, 256 profiles, 1 MiB per profile in both compact and restored formatting and 8 MiB of snapshot JSON. Corrupt profiles, symbolic links in place of saved profile files/directories, duplicate IDs and oversize data stop the operation. Files referenced by profiles are never followed or packaged.

Output must be outside the source data directory, including parent aliases resolved by the OS. The file is created exclusively with mode 0600; existing files, including passphrase files, are never overwritten. Windows permissions inherit from the destination parent, so use a private user directory or an appropriately protected administrative destination. A write/sync/close failure returns nonzero and retains any incomplete encrypted output for inspection. Do not distribute it. Inspect authenticates/decrypts the complete archive and validates its schema, then reports only creation time, profile count and authentication status. It does not print profile contents or materialize plaintext files.

Create and inspect are read operations with the same profile-read access as the ordinary CLI. Restore requires the administrator policy's profile-change permission. Changing the destination or user root never selects or replaces machine policy.

## Restore without replacing existing data

Close controllers that will use the recovered store. Specify a canonical absolute path whose parent already exists and is private to your account. The destination itself must not exist:

```text
accessweaver backup restore --archive profiles.awbackup --passphrase-file passphrase.txt --into ABSOLUTE_NEW_DATA_DIRECTORY
```

The complete archive is authenticated and all profiles validated before creating that directory. Restore acquires controller and profile locks, writes a private incomplete marker bound to the canonical snapshot, stages and syncs profile files, and publishes the complete profiles directory. It preserves saved timestamps and records that preset initialization is already complete, including for an intentionally empty snapshot. Built-in profiles deleted before backup do not reappear on the next launch.

Ordinary constructors, reads and mutations reject a root containing `.restore-incomplete`. After an error or process termination, retain the original archive/passphrase and retry the same authenticated snapshot explicitly:

```text
accessweaver backup restore --archive profiles.awbackup --passphrase-file passphrase.txt --into ABSOLUTE_NEW_DATA_DIRECTORY --resume
```

Resume verifies the snapshot marker and destination contents. It reclaims only expected regular staged profile names; unexpected files, links and directories are preserved and stop recovery. If publication already occurred, every saved file must match the authenticated snapshot exactly before the marker can be removed. Existing complete data directories are never an implicit restore destination. A failure before the initial marker is fully created may reserve an empty/uninitialized directory; use another new directory after inspecting that failed attempt. Do not bypass recovery by removing the incomplete marker manually.

Successful restore reports `complete: true` and starts no engines. Point `ACCESSWEAVER_HOME` at the recovered directory when ready to use it. Review executable/configuration paths and arguments before running profiles, especially after an OS/device migration. Install qualified engines and separately recover vendor configuration, protected machine policy and OS state through their own administrative procedures. A profile snapshot cannot restore external WireGuard secrets, routes or services that it never included.

## Format and cryptography

Version one is binary: 44 bytes of authenticated header followed by AES-256-GCM ciphertext and a 16-byte authentication tag. All integers below are unsigned; the iteration count is big endian.

| Bytes | Meaning |
|---|---|
| 0-7 | ASCII `AWBACKUP` |
| 8 | Format version, `1` |
| 9 | KDF identifier, `1` = PBKDF2-HMAC-SHA256 |
| 10 | Cipher identifier, `1` = AES-256-GCM |
| 11 | Reserved, must be zero |
| 12-15 | Exactly 600000 iterations |
| 16-31 | Fresh random 16-byte salt |
| 32-43 | Fresh random 12-byte nonce |

The derived key is 32 bytes. The complete header is GCM additional authenticated data. Random salt/nonce bytes come from `crypto/rand`; algorithm identifiers and work factor are fixed and checked before derivation, preventing archive-selected excessive work or downgrade. The plaintext is one UTF-8 JSON object with `schemaVersion: 1`, `createdAt` and `profiles`; duplicate, unknown and case-aliased keys are rejected. There is no compression, algorithm negotiation or automatic migration to an unknown schema. Authentication failure reports one generic wrong-passphrase/damaged-archive error before profile parsing or filesystem changes.

The implementation uses Go's standard-library [PBKDF2](https://pkg.go.dev/crypto/pbkdf2) and AES-GCM, requiring source Go 1.24 or newer while release tooling remains pinned to its supported compiler. The fixed PBKDF2 cost follows the [OWASP HMAC-SHA256 work-factor guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2); [OWASP storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#symmetric) favors authenticated encryption. These choices do not make a weak passphrase strong or establish FIPS certification. Encryption authenticates possession of the passphrase, not a publisher or administrator approval of profile behavior.

## Qualification and limits

Portable tests cover round trips, randomization, wrong passphrases, changed header/ciphertext/tag, bounded parameters, strict schema, duplicate IDs, non-overwrite, policy denial and recovery before/after publication. Native subprocess tests abruptly exit while restore locks are held and require a later process to resume. `scripts/test-backup-interop.cjs` independently decrypts a Go-created archive with Web Crypto, encrypts one for Go inspection/restore, verifies exact saved revisions and rejects tampering/wrong passwords. CI runs this against native Windows, Linux and macOS CLI binaries and retains public source/binary-bound records in `build/backup-checks/`.

Unix restore syncs files and affected directories; Windows syncs files and uses write-through native rename publication. A final sync/console failure can follow publication: inspect the destination and command result before retrying. Crash/process-exit checks do not establish physical power-loss, disk-full, network-filesystem, every OS/filesystem/architecture, downgrade or disaster-recovery qualification. Windows ACL/private-storage and managed endpoint acceptance still require the intended deployment environment. Manual writes or removal/replacement of coordination files remain outside cooperating-process guarantees.

Restored profiles/staging are plaintext in the private destination, just like ordinary profile storage. Failed staging is retained for explicit resume; apply the organization's retention/deletion procedure after verified recovery. Best-effort clearing of temporary byte slices is not a promise to erase passwords, plaintext or keys from process memory, swap or crash dumps. This version has no password-prompt/dashboard backup integration, automatic backup schedule, escrow or complete-system recovery. Browser JSON export remains unencrypted. Full backup/privacy and enterprise gates remain partial until their broader acceptance requirements pass.
