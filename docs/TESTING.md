# Validation and manual testing

This document is a test procedure, not a claim that every procedure has passed. Record the exact commit, OS version, architecture, engine version and configuration for any result. Never put VPN credentials or sensitive traffic captures in public reports.

## Automated core checks

```bash
go vet ./...
go test ./... -count=1
go test -race ./...
node --check web/app.js
node --test web/app.test.cjs
bash scripts/build-all.sh
```

CI runs native unit tests on hosted Linux/Windows/macOS and race checks on Linux. Command-generation tests check the arguments AccessWeaver produces; they do not execute upstream engines or confirm DPI effectiveness. Cross-builds check compilation only. Check [GitHub Actions](https://github.com/Yunushan/accessweaver/actions) for the actual run outcome.

## Desktop UI smoke test

Use a disposable `ACCESSWEAVER_HOME` directory.

1. Start `accessweaver ui`. Confirm the printed listener is `127.0.0.1` and no external engine has started.
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
cd dist/preview
sha256sum -c SHA256SUMS.txt
```

On macOS, `shasum -a 256 -c SHA256SUMS.txt` can verify the checksum file. On Windows, compare `Get-FileHash -Algorithm SHA256 PATH` to the matching entry. Checksums are integrity metadata, not publisher signatures.

Inspect one Windows ZIP and one Unix tarball: the executable, LICENSE, third-party notice, security policy and docs should be present, with no third-party engines or credentials. On each intended platform, extract and run `accessweaver version`, then perform the UI smoke test. Test installation-free startup and shutdown before calling the target usable.

## Evidence vocabulary

- **Compiled:** compiler accepted the source for that target.
- **Unit-tested:** tests ran on the named host; mocked external engine behavior remains mocked.
- **UI-tested:** the interface was exercised in the named browser/environment.
- **Engine-tested:** the named upstream version actually launched and stopped on the named OS.
- **Traffic-tested:** the intended application/protocol was independently verified through the selected route.

Only the last two establish evidence about a particular external integration. None by itself establishes production readiness across other networks or releases.
