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

## Production, premium and enterprise acceptance

The confirmed target is desktop quality and managed deployment across every documented desktop platform. A fleet-management backend, application-owned device enrollment and multi-tenant cloud service are outside this goal. [readiness-gates.json](readiness-gates.json) records 50 acceptance gates across functional parity, reliability, security, supply chain, platforms, validation, product quality, enterprise capabilities, operations and data/privacy. Each gate contributes two points only after its full acceptance requirement has source-bound evidence. Partial implementation does not count as a passed release gate. The assessment is in progress; this is not a certification or a claim of a completed score.

Evidence must identify the actual source/artifact, environment, procedure and result. Compilation, mocked commands and userspace fixture success cannot certify native routing. Do not change a failed/partial gate to passed merely because its implementation exists. Administrator-enforced local policy, signed configuration, managed installation/upgrade/rollback, local audit/support export and endpoint-management integration require implementation and adversarial integration tests. Local loopback authentication and portable archives alone do not satisfy those requirements. The five former fleet-backend gates were replaced by five managed-desktop gates after the user confirmed scope; no passed status or numerical credit was awarded for that change.

Current reliability additions include service log rotation (8 MiB plus two backups), per-workflow process log rotation (4 MiB plus two backups), and bounded shutdown that waits for a workflow's terminal history record. Contract tests cover concurrent logging, oversized output, rotation failures and shutdown timeout/history recording. They do not establish long-duration resource budgets or complete failure recovery. Workflow directories and recovery histories still require a retention policy; per-file rotation alone does not bound lifetime disk use.

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
