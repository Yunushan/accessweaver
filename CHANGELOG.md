# Changelog

## Unreleased

- Add real browser acceptance against isolated Go controllers, including concurrent tabs, private launch, editing/import/export, focus and four-language mobile layouts. Wrap maintenance review actions so they remain reachable on narrow screens.

- Bound Windows maintenance tool output and result/history record reads. Stop tools that exceed capture limits, report incomplete inherited-pipe capture, and persist malformed/oversized results as failures without breaking API JSON.

- Add pinned, fail-closed Go vulnerability checks to CI and release packaging. Update the separate WireGuard fixture to patched networking/crypto dependencies and Go 1.26 minimum; preserve unused-package advisories in reports.

- Coordinate profile operations across local processes with OS locks, reject competing foreground controllers/CLI imports, honor canceled waiters, and report store contention as retryable HTTP 503. Native Unix controller checks now run in CI and release verification; loopback probes bypass proxies.

- Reject stale dashboard profile saves/deletions and duplicate creation using the reviewed revision, preserving unsaved drafts on conflicts.
- Require unelevated desktop tokens for Discord/PTB/SplitCord installation, removal and launch. Keep their staging and journals in the user workflow directory and configure machine DNS separately.
- Block combined Discord repair until a privilege-separated broker can safely coordinate user application and administrator tasks. Application acceptance tests now run separately from the elevated VM controller.

## 0.1.0-alpha — 2026-10-31

Initial independent AccessWeaver application core.

- English-default responsive dashboard with Turkish translation, dark/light themes and offline profile editing.
- Portable versioned profiles with guided/JSON editing, import/export, duplication and local storage.
- External engine catalog, explicit command preview, readiness checks and managed foreground process lifecycle.
- Compatible adapter mappings for domain inclusion/exclusion, external configuration paths and optional executable hashes.
- Direct DNS/TCP/certificate-verified TLS diagnostics.
- Loopback API, request tokens, origin/host restrictions and strict request decoding.
- Go unit tests, cross-platform CI, local setup scripts and unsigned multi-target release packaging.
- 0BSD original source with separate third-party license references.

No native Android/iOS VPN application, engine installer, managed system routing, signed installer, audited security status or end-to-end ISP certification is included in this release.
