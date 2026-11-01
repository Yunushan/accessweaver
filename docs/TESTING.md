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

CI runs native unit tests on hosted Linux/Windows/macOS and race checks on Linux. Command-generation tests check the arguments AccessWeaver produces; they do not execute upstream engines or confirm DPI effectiveness. Cross-builds check compilation only. Check [GitHub Actions](https://github.com/Yunushan/accessweaver/actions) for the actual run outcome.

## Desktop UI smoke test

Use a disposable `ACCESSWEAVER_HOME` directory.

1. Start `accessweaver ui` as the normal desktop user and use its private launch-file URL. Confirm the printed listener is `127.0.0.1` and no external engine has started. Direct unauthenticated API requests, including bootstrap, must return 403.
2. Switch English/Turkish and dark/light themes. Check keyboard focus, narrow layouts and editor scrolling.
3. Create, save, duplicate and export a profile. Import it with a different ID and verify its arguments and domains round-trip.
4. Try invalid JSON, an unknown field and the same domain in both include/exclude lists. The core must reject invalid saves.
5. Preview an absent engine, a wrong-platform executable and unsupported application routing. Confirm actionable issues and that no process starts.
6. Run a diagnostic against a controlled target. Confirm DNS/TCP/TLS stages and certificate verification. Disconnect networking and confirm failure is distinguishable from success.
7. Close the application, restart, and check profile persistence. Offline/browser-only profiles require explicit export/import to reach this store.

## Real browser acceptance

Development-only Playwright dependencies are pinned in `scripts/browser-tests/package-lock.json`; downloaded application users do not need Node.js. Build the controller as `build/browser-tests/accessweaver` on Unix or `build/browser-tests/accessweaver.exe` on Windows, then run:

```bash
npm ci --prefix scripts/browser-tests --ignore-scripts
cd scripts/browser-tests
npx playwright install chromium firefox webkit
npm test
```

The [Playwright browser documentation](https://playwright.dev/docs/browsers) explains host prerequisites. To use an already installed Microsoft Edge on Windows instead, set `$env:PW_BROWSER_CHANNEL='msedge'` in PowerShell and run `npm test -- --project=chromium`. `ACCESSWEAVER_BINARY` can select another candidate explicitly. Run as the ordinary desktop user, because the real controller refuses an elevated dashboard.

Each test starts a separate real Go controller with disposable state/cache under ignored `build/browser-state/`. It exercises the actual private launcher, authenticated UI and unauthenticated API rejection, save/reload/export/import collision, concurrent-tab revision rejection, preserved invalid JSON, unavailable-engine launch review, keyboard focus, reviewed machine-request export without execution, preferences and narrow layouts across all six screens in all four languages. No engine, diagnostic traffic or Windows maintenance operation is started. These tests do not certify screen-reader behavior or engine routing.

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

### Repeated portable builds

Cross-builds require Go, Bash and Python 3. `build-all.sh` uses the source commit timestamp for `builtAt` by default. Set `SOURCE_DATE_EPOCH` to a nonnegative integer up to 4294967295 to select a fixed UTC epoch explicitly; an empty, malformed or out-of-range value fails the build. Source trees without Git metadata use the current time unless an epoch is supplied.

Portable archives use sorted member names, fixed owner/permission metadata, UTC member timestamps and a gzip header without the random staging/output filename. ZIP timestamps clamp to 1980 and have two-second precision; runtime build metadata retains the actual selected epoch. The manifest records Python and zlib versions along with Go and source identity. The release workflow builds/packages twice and compares the complete checksum lists before upload.

Use a fresh checkout so `.gitattributes` supplies canonical LF source bytes, including embedded web and PowerShell files (`.cmd` stays CRLF). Existing working trees can still contain old checkout line endings. Rebuild with identical source bytes, build version, epoch, Go/Python/zlib versions and release label, retain the first `SHA256SUMS.txt` outside `dist`, then repeat the package command and compare it with the second checksum file. `python3 -m unittest discover -s scripts -p test_release_archive.py -v` checks metadata, ordering, timezone, content sensitivity and invalid epochs.

A repeated build on one machine does not satisfy independent trusted rebuild qualification. Windows installer reproducibility, signing, toolchain provenance and cross-host comparisons remain separate requirements; the reproducibility readiness gate stays partial.

## Production, premium and enterprise acceptance

The confirmed target is desktop quality and managed deployment across every documented desktop platform. A fleet-management backend, application-owned device enrollment and multi-tenant cloud service are outside this goal. [readiness-gates.json](readiness-gates.json) records 50 acceptance gates across functional parity, reliability, security, supply chain, platforms, validation, product quality, enterprise capabilities, operations and data/privacy. Each gate contributes two points only after its full acceptance requirement has source-bound evidence. Partial implementation does not count as a passed release gate. The assessment is in progress; this is not a certification or a claim of a completed score.

Evidence must identify the actual source/artifact, environment, procedure and result. Compilation, mocked commands and userspace fixture success cannot certify native routing. Do not change a failed/partial gate to passed merely because its implementation exists. Administrator-enforced local policy, signed configuration, managed installation/upgrade/rollback, local audit/support export and endpoint-management integration require implementation and adversarial integration tests. Local loopback authentication and portable archives alone do not satisfy those requirements. The five former fleet-backend gates were replaced by five managed-desktop gates after the user confirmed scope; no passed status or numerical credit was awarded for that change.

Current reliability additions include service log rotation (8 MiB plus two backups), per-workflow process log rotation (4 MiB plus two backups), bounded native-tool capture (4,194,304 UTF-16 code units per stdout/stderr stream), bounded result JSON (32 MiB) and individual history-record reads (64 MiB), and bounded shutdown that waits for a workflow's terminal history record. Capture overflow terminates the tool tree and fails the job; an installer leaving inherited pipes open is reported as incomplete capture. Malformed/oversized results are discarded from the API snapshot and recorded as durable failures. Contract tests cover concurrent logging, oversized output, rotation failures, stdout/stderr floods, exact capture limits, silent-tool timeouts, inherited installer pipes, malformed/oversized results and shutdown timeout/history recording. They do not establish long-duration resource budgets or complete failure recovery. Workflow directories and recovery histories still require a retention policy; per-file rotation alone does not bound lifetime disk use.

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
