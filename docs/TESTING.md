# Validation and manual testing

This document is a test procedure, not a claim that every procedure has passed. Record the exact commit, OS version, architecture, engine version and configuration for any result. Never put VPN credentials or sensitive traffic captures in public reports.

## Automated core checks

```bash
go vet ./...
go test ./... -count=1
go test -race ./...
node --check web/app.js
node --check web/system.js
node --check web/locales.js
node --test web/app.test.cjs
bash scripts/build-all.sh
```

CI runs native core tests on amd64 and arm64 Linux/Windows/macOS, with race checks on both Linux architectures. The [platform matrix](PLATFORMS.md) lists the actual runner labels, architecture/source assertions and remaining scope limits. Per-target native identity, backup, recovery and managed-policy records use architecture-specific artifact names. `scripts/check-native-environment.cjs` rejects cross SDKs, target mismatches and dirty/mismatched hosted build identities; its adversarial identity tests run in every native job. Command-generation tests check the arguments AccessWeaver produces; they do not execute upstream engines or confirm DPI effectiveness. Cross-builds check compilation only. Check [GitHub Actions](https://github.com/Yunushan/accessweaver/actions) for the actual run outcome.

## Native identity evidence

Native jobs assert the intended host and SDK before tests, then execute `version --json` from the built CLI and record its source, compiler, OS, architecture and SHA-256. For a local Linux amd64 check with a trusted built executable:

```sh
ACCESSWEAVER_EXPECT_GOOS=linux ACCESSWEAVER_EXPECT_GOARCH=amd64 GO_VERSION=1.27.3 GOTOOLCHAIN=local node scripts/check-native-environment.cjs --binary ./accessweaver
```

Use `windows`/`darwin` and `arm64` only for the actual intended native target; the checker rejects SDK/target mismatches. Local records with unknown source or a modified tree do not become clean hosted qualification. Hosted checks additionally require the expected commit, clean source and provider architecture. OS machine type, Node interpreter architecture and Go host/target are recorded separately; a helper interpreter is not used as a substitute for the tested Go executable's identity.

Native Windows installer compilation continues to build the documented amd64 installer payload on both Windows runner architectures. That is an installer build check, not a native arm64 installer or native vendor-driver acceptance. The architecture label on the artifact describes its runner; inspect the enclosed compiler/payload records for the produced installer target.

## Desktop UI smoke test

Use a disposable `ACCESSWEAVER_HOME` directory.

1. Start `accessweaver ui` as the normal desktop user and use its private launch-file URL. Confirm the printed listener is `127.0.0.1` and no external engine has started. Direct unauthenticated API requests, including bootstrap, must return 403.
2. Switch English/Turkish and dark/light themes. Check keyboard focus, narrow layouts and editor scrolling.
3. Create, save, duplicate and export a profile. Import it with a different ID and verify its arguments and domains round-trip.
4. Try invalid JSON, an unknown field and the same domain in both include/exclude lists. The core must reject invalid saves.
5. Preview an absent engine, a wrong-platform executable and unsupported application routing. Confirm actionable issues and that no process starts.
6. Run a diagnostic against a controlled target. Confirm DNS/TCP/TLS stages and certificate verification. Disconnect networking and confirm failure is distinguishable from success.
7. Close the application, restart, and check profile persistence. Offline/browser-only profiles require explicit export/import to reach this store.

Windows private-launcher ACL regression tests also parse real native security descriptors and inspect a temporary directory with an `OWNER RIGHTS` access-control entry. That SID represents the current object owner; it is accepted as an ACE principal only after the actual owner has independently passed validation. A foreign owner, `OWNER RIGHTS` used as an owner SID, and unrelated principals with replacement/permission-changing rights remain rejected. The tests change only their temporary directory, not machine/user-profile ACLs. [Microsoft defines these SID semantics](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers).

## Real browser acceptance

Development-only Playwright dependencies are pinned in `scripts/browser-tests/package-lock.json`; downloaded application users do not need Node.js. Build the controller as `build/browser-tests/accessweaver` on Unix or `build/browser-tests/accessweaver.exe` on Windows, then run:

```bash
npm ci --prefix scripts/browser-tests --ignore-scripts
cd scripts/browser-tests
npx playwright install chromium firefox webkit
npm test
```

The [Playwright browser documentation](https://playwright.dev/docs/browsers) explains host prerequisites. To use an already installed Microsoft Edge on Windows instead, set `$env:PW_BROWSER_CHANNEL='msedge'` in PowerShell and run `npm test -- --project=chromium`. `ACCESSWEAVER_BINARY` can select another candidate explicitly. Run as the ordinary desktop user, because the real controller refuses an elevated dashboard.

Each test starts a separate real Go controller with disposable state/cache under ignored `build/browser-state/`. It exercises the actual private launcher, authenticated UI and unauthenticated API rejection, save/reload/export/import collision, concurrent-tab revision rejection, preserved invalid JSON, unavailable-engine launch review, keyboard focus, reviewed machine-request export without execution, preferences and narrow layouts across all six screens in all four languages. The diagnostics browser case intercepts requests and checks exact selections without sending probe traffic. No engine or Windows maintenance operation is started. These tests do not certify screen-reader behavior or engine routing.

CI and release verification run the same suite on Chromium, Firefox and WebKit on Linux. Windows Edge is also locally testable; Linux WebKit does not certify native Safari/macOS. Results and failure screenshots under `build/browser-results/` identify the binary hash, runtime build metadata, OS/architecture, Node, Playwright and browser versions. Traces are disabled because they can retain session headers. Never upload `build/browser-state/`: it contains private launcher credentials and fixture profiles. Local fixture directories are retained for investigation; the harness stops each controller after use.

## External engine integration

Run on a disposable VM/device first. Obtain engines from their official upstreams, document the exact version and install only the required platform components.

| Check | Evidence to record |
|---|---|
| Prerequisites | OS/arch, engine version and provenance, driver/firewall state, privilege level |
| Plan | Resolved binary, arguments, working directory and domain-list semantics |
| Process | Actual startup, bounded output, duplicate-start rejection, stop and crash behavior |
| Traffic path | Independent evidence that the target application uses the selected proxy/interception path |
| Includes/excludes | Both included and excluded controlled domains, plus a domain absent from either list |
| Protocols | DNS, IPv4/IPv6, TCP/TLS, and separately any required UDP/voice/QUIC behavior |
| Recovery | App proxy settings, routes, driver/service and network-lock state after normal/abnormal stop |

For a SOCKS engine, test through the target application's configured proxy and its DNS behavior. For packet mode, independently confirm traffic reaches the relevant OS hook. A successful direct `doctor` result or `state: running` is not a substitute.

## Release packaging

```bash
bash scripts/package-release.sh preview
python3 scripts/verify-release.py dist/preview --execute-native
cd dist/preview
sha256sum -c SHA256SUMS.txt
```

On macOS, `shasum -a 256 -c SHA256SUMS.txt` can verify the checksum file. On Windows, compare `Get-FileHash -Algorithm SHA256 PATH` to the matching entry. Checksums are integrity metadata, not publisher signatures.

Inspect one Windows ZIP and one Unix tarball: the executable, LICENSE, third-party notice, security policy and docs should be present, with no third-party engines or credentials. On each intended platform, extract and run `accessweaver version`, then perform the UI smoke test. Test installation-free startup and shutdown before calling the target usable.

The release verifier checks all ten archives, their checksums, required notices and per-target `BUILD-INFO.json`. With `--execute-native`, it also runs metadata commands from the matching host archive, compares runtime identity and rejects unexpected user-state writes. This does not execute other architectures or validate their networking. Release builders stamp a common version, commit, source modification state and build time; `accessweaver version --json` and API bootstrap expose that identity. Modified-source builds remain explicitly labeled.

Release previews additionally authenticate and execute the actual packaged portable CLI on all six Windows/Linux/macOS targets before publication is eligible. Public `packaged-native-OS-ARCH` records bind runtime identity, backup/recovery interoperability, loopback diagnostics and Unix controller checks to the authenticated archive's executable hash. See [the staging procedure and limits](RELEASE_PROVENANCE.md#execute-the-authenticated-portable-candidate). `python3 -m unittest discover -s scripts -p test_stage_packaged_native.py -v` exercises staging rejection and snapshot ordering; `node --test scripts/check-packaged-evidence.test.cjs` rejects substituted runtime metadata/hashes. These regression fixtures do not substitute for real signature verification or native job results.

### Repeated portable builds

Cross-builds require Go, Bash and Python 3. `build-all.sh` uses the source commit timestamp for `builtAt` by default. Set `SOURCE_DATE_EPOCH` to a nonnegative integer up to 4294967295 to select a fixed UTC epoch explicitly; an empty, malformed or out-of-range value fails the build. Source trees without Git metadata use the current time unless an epoch is supplied.

Portable archives use sorted member names, fixed owner/permission metadata, UTC member timestamps and a gzip header without the random staging/output filename. ZIP timestamps clamp to 1980 and have two-second precision; runtime build metadata retains the actual selected epoch. The manifest records Python and zlib versions along with Go and source identity. The release workflow builds/packages twice and compares the complete checksum lists before upload.

Use a fresh checkout so `.gitattributes` supplies canonical LF source bytes, including embedded web and PowerShell files (`.cmd` stays CRLF). Existing working trees can still contain old checkout line endings. Rebuild with identical source bytes, build version, epoch, Go/Python/zlib versions and release label, retain the first `SHA256SUMS.txt` outside `dist`, then repeat the package command and compare it with the second checksum file. `python3 -m unittest discover -s scripts -p test_release_archive.py -v` checks metadata, ordering, timezone, content sensitivity and invalid epochs.

A repeated build on one machine does not satisfy independent trusted rebuild qualification. Windows installer reproducibility, signing, toolchain provenance and cross-host comparisons remain separate requirements; the reproducibility readiness gate stays partial.

## Production, premium and enterprise acceptance

The confirmed target is desktop quality and managed deployment across every documented desktop platform. A fleet-management backend, application-owned device enrollment and multi-tenant cloud service are outside this goal. [readiness-gates.json](readiness-gates.json) records 50 acceptance gates across functional parity, reliability, security, supply chain, platforms, validation, product quality, enterprise capabilities, operations and data/privacy. Each gate contributes two points only after its full acceptance requirement has source-bound evidence. Partial implementation does not count as a passed release gate. The assessment is in progress; this is not a certification or a claim of a completed score.

Evidence must identify the actual source/artifact, environment, procedure and result. Compilation, mocked commands and userspace fixture success cannot certify native routing. Do not change a failed/partial gate to passed merely because its implementation exists. Administrator-enforced local policy, signed configuration, managed installation/upgrade/rollback, local audit/support export and endpoint-management integration require implementation and adversarial integration tests. Local loopback authentication and portable archives alone do not satisfy those requirements. The five former fleet-backend gates were replaced by five managed-desktop gates after the user confirmed scope; no passed status or numerical credit was awarded for that change.

Current reliability additions include service log rotation (8 MiB plus two backups), per-workflow process log rotation (4 MiB plus two backups), bounded native-tool capture (4,194,304 UTF-16 code units per stdout/stderr stream), bounded result JSON (32 MiB) and individual history-record reads (64 MiB), and bounded shutdown that waits for a workflow's terminal history record. Capture overflow terminates the tool tree and fails the job; an installer leaving inherited pipes open is reported as incomplete capture. Malformed/oversized results are discarded from the API snapshot and recorded as durable failures. Contract tests cover concurrent logging, oversized output, rotation failures, stdout/stderr floods, exact capture limits, silent-tool timeouts, inherited installer pipes, malformed/oversized results and shutdown timeout/history recording. They do not establish long-duration resource budgets or complete failure recovery.

History listing also bounds the directory scan to 4,096 entries (including ignored files/directories) and the combined record reads to 64 MiB. It returns an explicit error rather than a partial list when either limit is exceeded; malformed JSON still consumes the byte budget. Listing preserves filename order and never rewrites or deletes retained outcomes, work directories or recovery journals. These limits bound listing work, not lifetime storage. Workflow directories and recovery histories still require a retention policy; per-file rotation alone does not bound lifetime disk use.

Concurrent profile-list requests under the controller process identity share only an in-progress read under the existing cross-process lock. Windows callers with an impersonation token stay synchronous on their original OS thread and never join a process-identity read; a restricted-token native test proves that a denied caller cannot inherit another reader's access. Each caller receives detached profile slices, can cancel independently, and the last cancellation stops an abandoned read. The result is detached from the store before releasing the OS lock; completed reads and errors are never cached.

Regression cases cover concurrent callers, canceled leaders/followers, abandoned lock acquisition, mutable-result isolation, and fresh reads after writes, deletion or corruption. Concurrent HTTP profile/support reads also run against a real isolated loopback server.

`go test ./internal/profile -run '^$' -bench '^BenchmarkList256$' -benchmem` compares serial and four-reader synthetic inventory cost; it does not measure browser rendering, vendor traffic or full desktop performance. Native CI and release verification retain `profile-benchmark-OS-ARCH` artifacts for all six Linux/Windows/macOS targets. The wrapper requires a clean expected commit and matching native host/SDK, rejects missing or invalid benchmark rows, and records per-call time/allocations with the actual reader count. Parallel `ns/op` is aggregate elapsed time divided by completed operations, not individual request latency. These are source-built synthetic measurements, not packaged-binary performance qualification or an enforcement of desktop resource/latency budgets.

## Windows process-resource attribution

`scripts/windows_handle_census.py` provides `HandleCensus(child)` for a live `subprocess.Popen` created by a test observer on 64-bit Windows. It requests only `PSS_CAPTURE_HANDLES | PSS_CAPTURE_HANDLE_BASIC_INFORMATION` and emits aggregate kernel object-type counts. It does not request object names, virtual-memory capture, stacks, thread contexts or traces. The implementation never dereferences object-name pointers, bounds entry/type-label reads, rejects unexpected name capture, and frees walk markers/snapshots on error. Close the census with its context manager; only use it with an owned disposable child. [Microsoft documents the snapshot flags](https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/ne-processsnapshot-pss_capture_flags).

Run `python3 -m unittest discover -s scripts -p test_windows_handle_census.py -v` for native counter agreement, private-name omission, observer-handle cleanup and injected-walk-error cleanup. Native cases run on the two Windows CI/release-verification targets; other platforms check supported rejection/decoding boundaries. No account, service, policy, network or trust-store change is required.

For a candidate investigation, authenticate the portable package before execution, keep its executable hash unchanged, and use disposable profile/state directories. Record raw process handle/thread counts and type counts before load and after cooldown across repeated identical windows. Keep the original limits and failed requests visible. A stable short window or a correlation with thread growth does not establish long-duration stability, explain every untyped handle, or satisfy the desktop performance gate. Never upload private state, launcher files, object names or process-memory snapshots as test evidence.

## Cross-process storage and controller checks

`go test ./internal/filelock ./internal/profile ./internal/api ./cmd/accessweaver -count=1` includes native subprocess tests. They verify exclusive ownership, ordinary and forced process exit, cancellation, persistent lock files, and six independent processes attempting to save the same reviewed profile revision. Exactly one save must succeed; stale deletion from another store must preserve that winner. CLI tests reject an import or foreground launch while a controller owns the root and verify release on failure. An API contention test requires HTTP 503 and `Retry-After: 1` without deleting the saved profile.

On Linux/macOS, build the core and run `python3 scripts/test-unix-controller.py ./accessweaver`. This starts an isolated real dashboard, rejects a second UI and CLI import, allows read-only CLI access, verifies authenticated owner bootstrap despite an unusable proxy setting, and checks graceful shutdown removes the private launcher before an import can succeed. It launches no engine and changes no account/service/driver/network settings. CI and release verification require this test on Unix runners.

These are local filesystem/process checks, not engine traffic tests. Run them natively on each supported OS and include `go test -race ./... -count=1` where a C compiler is available. Cross-building alone cannot validate `flock` or `LockFileEx` behavior. Do not infer Windows/WSL shared-store interoperability from separate Windows and Linux test success. Power-loss durability, filesystem corruption and backup/restore remain separate acceptance requirements.

## Known Go vulnerability checks

The separate `scripts/security-tools` module pins govulncheck, actionlint and their checksums. With the release Go toolchain installed (currently Go 1.27.3), run:

```bash
go -C scripts/security-tools mod download
go -C scripts/security-tools mod verify
go -C scripts/security-tools install golang.org/x/vuln/cmd/govulncheck
go -C scripts/security-tools install github.com/rhysd/actionlint/cmd/actionlint
"$(go env GOPATH)/bin/actionlint" -shellcheck= -pyflakes=
python3 -m unittest discover -s scripts -p test_vulnerability_report.py -v
GOVULNCHECK="$(go env GOPATH)/bin/govulncheck" bash scripts/check-vulnerabilities.sh
```

The runner checks the core's ten desktop OS/architecture configurations with CGO disabled, plus the optional fixture's Linux/amd64 and Windows/amd64 configurations. Each report records its SDK/scanner version, database timestamp, module inventory and target. CI repeats these checks and validates workflow expressions with actionlint; release packaging depends on their success. The scanner tool and fixture dependencies remain separate from the standard-library-only core. Dependabot monitors both optional modules weekly. The security job uses `GOTOOLCHAIN=local` so a dependency cannot silently substitute another SDK.

Govulncheck's JSON mode returns exit status zero even when it reports vulnerabilities. The report checker therefore validates the protocol, tool/SDK versions, official database, expected module and populated source inventory before assessing findings. Invalid/truncated reports, scanner errors, affected imported packages and reachable vulnerable symbols fail the gate. Raw JSON and summaries are retained as CI artifacts for 14 days, including on failure. See the [official govulncheck documentation](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) for output semantics and analysis limitations.

Module-only advisories stay visible when their affected packages are outside the compiled import graph. There is no per-ID suppression list. The fixture currently retains `GO-2026-5932` for the unused, unmaintained OpenPGP packages in `golang.org/x/crypto`; importing an affected package in a later change would fail the gate. Zero affected findings in these source configurations do not establish a complete security assessment or cover JavaScript, vendor engines/drivers, installer content or other SDK/build configurations. Source scanning and compilation do not replace the fixture's disposable-guest handshake/traffic qualification.

## Evidence vocabulary

- **Compiled:** compiler accepted the source for that target.
- **Unit-tested:** tests ran on the named host; mocked external engine behavior remains mocked.
- **UI-tested:** the interface was exercised in the named browser/environment.
- **Engine-tested:** the named upstream version actually launched and stopped on the named OS.
- **Traffic-tested:** the intended application/protocol was independently verified through the selected route.

Only the last two establish evidence about a particular external integration. None by itself establishes production readiness across other networks or releases.

## Workflow cancellation and administrator handoff

`go test ./cmd/accessweaver ./internal/workflow -count=1` now covers CLI cancellation waiting for terminal recording, bounded cancellation with an honest running snapshot, retained tool/output errors, rejected machine plans without administrator authority and a second authority check before job creation. These are controlled lifecycle tests; they do not execute Windows machine changes.

The real-browser suite also previews a machine DNS request, requires unavailable consent/apply controls, exports exactly the retained request JSON, verifies no workflow job directory was created, and invalidates export when inputs change. Local Windows Edge exercises the real process-token check; Linux CI exercises unsupported-platform review and export. Neither path applies DNS or launches an engine. Export is a manual administrator handoff, not an elevation broker or a signed approval artifact.

## Metadata support summaries

In Settings, **Export support summary** downloads a local JSON report from the authenticated `/api/v1/support` endpoint. It includes the common build identity, profile counts grouped only by known engine IDs, foreground state/log-line count and error-presence flags, and the latest workflow's action/state and result/error-presence flags. It sends nothing to a support service. It does not inspect vendor services or prove proxy/tunnel connectivity.

The report is constructed from explicit allowlisted fields. It excludes profile/job IDs and names, paths, arguments, domain/probe targets, referenced configuration contents, raw logs/results/error strings, browser/session storage and credentials. Unknown user-controlled engine/action/state labels are reduced to `other`/`unknown`. If profile storage cannot be read, its status is `unavailable` and its total is `null`, not a misleading zero; private parser/path errors are not exported. A previously authenticated core can still supply this report when ordinary profile loading fails. Offline browser-only mode has no core summary.

Go tests plant private values in profiles, referenced files, runtime errors/logs and job results and require their absence from exported JSON. They also test inaccessible/corrupt profile metadata and unauthenticated rejection. Browser-logic tests cover failed exports and preserved unrelated busy state; the real-browser suite verifies the download, omitted private profile values and export after corrupting only a disposable fixture profile. These checks do not qualify a complete redacted log bundle, tamper-evident audit trail or retention policy.

## Windows installer compilation

The Windows CI/release verification job compiles the existing Inno Setup installer with the runner-provided Inno Setup 6.7.1 compiler. It rejects compiler-version drift and records the compiler hash, installer hash/size and explicit unsigned/not-installed status in `build/installer-checks/compiler-artifact.json`; the installer and record are retained for 14 days. No tool installer is downloaded or run by this check, and the resulting application installer is not executed.

For an existing local compiler, run `./scripts/test-windows-installer.ps1 -Compiler 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe'`. Review a runner image/compiler change before updating the expected version. This records inputs and checks compilation; it is not a reproducibility/signing claim or native installation acceptance. Silent uninstall restoration failures are logged and abort before controller deletion, without the script's interactive message box. Validate that behavior, exit status, upgrade/rollback and recovery in a disposable Windows VM before managed production deployment. [Inno Setup documents the silent-uninstall flag](https://jrsoftware.org/ishelp/topic_isxfunc_uninstallsilent.htm).

## Signed administrator document checks

`go test ./internal/managed ./internal/workflow ./cmd/accessweaver -count=1` verifies signatures, strict parsing, validity/revision boundaries, approval input digests, private-key exclusion, exclusive envelope-file output and read-only CLI behavior. Local fuzzing can use `go test ./internal/managed -run=^$ -fuzz=FuzzDecodePolicy -fuzztime=15s` and the same command with `FuzzVerifyEnvelope`. Use disposable keys only. [Managed configuration](MANAGED_CONFIGURATION.md) documents the protocol and operator workflow. Windows includes partial native enforcement; native install/update transaction qualification, damaged-state/emergency recovery, other platforms and full native qualification remain requirements. A successful verification explicitly reports `runtimeEnforced: false`.

`go test ./internal/managed ./internal/profile ./internal/engine ./internal/workflow ./internal/api ./internal/nativepath -count=1` also covers denial before writes/launch, authority revocation during storage-lock waits and between preview/start, native descriptor rules, cold-process environment poisoning and a real read-only Windows PowerShell discovery worker. The latter performs local inventory queries only; it does not change services, networking or HKLM state. `scripts/test-windows-workflow.ps1` checks denied requests before network activity and administrator-pinned artifact hashes with mocked/native-free contracts. Windows Application Control may block local unsigned test fixtures; record that limitation and obtain native hosted/VM evidence without weakening host policy.

The CI-only `TestDisposableManagedPolicyNative` and `TestDisposablePolicyTransactionRollback` are separate opt-in tests on a fresh GitHub-hosted Windows VM. They temporarily create a protected policy key and protected inert executable to test actual native enforcement, limited-token denial, monotonic concurrent updates, expired-policy renewal and rollback after staged transaction/process abandonment, with scoped cleanup. They also abandon a staged key rotation, confirm the old key survives, then require atomic rotation, replay/retired-key denial and a successful new-key update. Ordinary local unit tests skip them. Never enable its disposable-runner flag on a desktop/self-hosted machine; see [the procedure and scope](MANAGED_CONFIGURATION.md#disposable-hosted-windows-acceptance).

Offline rotation tests cover independent old-key pinning, both signatures, exact previous state, preserved revision floors, changed-key enforcement, domain separation, duplicate/unknown/case-aliased fields, payload tampering, expired prior renewal, expired replacement denial, transaction failures and exclusive CLI output that cannot replace the signing key. `go test ./internal/managed -run=^$ -fuzz=FuzzVerifyRotation -fuzztime=15s` exercises parsing/signature boundaries with disposable deterministic fixture keys and no native installation.

Key-validation regressions include an identity-key signature fixture accepted by the underlying group equation without a private signing secret, every small-order point with both compressed sign bits, all noncanonical y-coordinate encodings, and generated-key compatibility. Policy verification, key parsing and planned rotation must reject the identity fixture. The disposable hosted test also writes a weak-key fixture through its administrator test handle and requires runtime policy loading/profile mutations to fail closed before restoring the valid fixture. The core still uses only the Go standard library; the coordinate-set reference is mathematical data rather than an additional cryptographic runtime.

## Linux managed policy

Linux unit tests exercise descriptor-based object protection, symlink/hardlink/FIFO refusal, immutable pending writes, non-replacing initial publication, stale administrator-write preservation, serialized revisions, bounded abandoned-stage cleanup and fixed child environments. They use private temporary roots with the test UID; native production entry points always choose the fixed root-owned `/etc` source. `go test -race ./... -count=1` covers these in the ordinary suite without enrolling its host.

The separate `scripts/test-linux-managed-policy.sh` acceptance step is restricted to a disposable hosted Linux VM and its explicit opt-in. It tests actual root-owned installation/update/rotation, UID/GID-65534 read/launch and denied mutations, real POSIX ACL mask behavior, tampered engine refusal, process exit before publication, stage reclamation and scoped cleanup. Do not run the opt-in on a desktop/self-hosted machine. See [the source, storage limits and native procedure](MANAGED_CONFIGURATION.md#protected-linux-source-and-update-behavior). Passing these tests alone grants no full desktop or power-loss qualification.

Active policy lifetime regression coverage is in `internal/managed/authorization_test.go`, `internal/engine/policy_test.go` and `internal/workflow/policy_test.go`. It checks retained policy identity, enrollment/removal, inaccessible sources, expiry, actual inert child termination, explicit restart and a durable failed workflow outcome even if the canceled worker returns success. The disposable native policy tests additionally apply an actual protected policy update while an engine is active; Linux includes the ordinary-user UID/GID-65534 controller. Source protection failures must also terminate active fixtures. Polling/cancellation and vendor recovery limitations are documented in [managed configuration](MANAGED_CONFIGURATION.md#policy-changes-during-active-operations). No root/administrator policy opt-in is permitted on developer desktops or self-hosted runners.

Encrypted profile backup coverage is in `internal/backup`, `internal/profile/snapshot_test.go` and `cmd/accessweaver/backup_test.go`. Native process-exit cases abandon staged/published restores while locks are held and require authenticated explicit resume. After a normal native CLI build, run `node scripts/test-backup-interop.cjs [PATH_TO_BINARY]` for independent Web Crypto interoperability and source/binary-bound metadata under `build/backup-checks/`. It uses private temporary profile/passphrase fixtures, starts no engines and makes no OS/network changes. CI/release verification runs it on Windows, Linux and macOS. [Backup and restore](BACKUP_RESTORE.md) defines scope, format, CLI procedures, privacy and remaining filesystem/desktop qualification.

Portable provenance checks run `python3 -m unittest discover -s scripts -p test_release_provenance.py -v` on the native CI matrix. Hosted release packaging then generates a real GitHub/Sigstore bundle, verifies all twelve subjects and runs `check_provenance_rejections.py` for changed artifact bytes and wrong identity pins. Inspect the source-bound `release-provenance-check` artifact and exact workflow run. [Provenance procedures and limits](RELEASE_PROVENANCE.md) distinguish these checks from publisher signing, trusted-builder isolation and complete release qualification.

SBOM regression tests run `python3 -m unittest discover -s scripts -p test_sbom.py -v`. The development-only `scripts/sbom-tools` module tests pinned-schema integrity, profile enforcement and denied remote loading. CI builds optional Windows fixtures without executing them, compares compiled/source module identities, emits their inventories and validates the documents. Portable packaging validates all ten artifact-bound documents before archiving; archive verification rejects missing SBOMs, changed executable bytes and changed notice evidence. Windows compilation retains payload/installer SBOMs and notices without installing the setup executable. See [SBOM scope and remaining qualification](SBOM.md).

See [explicit diagnostics](DIAGNOSTICS.md) for loopback proxy/STUN coverage, the parser fuzz command and the remaining real-network acceptance limits.

The guarded managed-policy transaction suites also exercise [signed administrator recovery](MACHINE_POLICY_RECOVERY.md), including damaged-state export, abandoned repair, independent key/floor checks and replay denial. Never enable their disposable-machine flags on a workstation.
