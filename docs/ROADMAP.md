# AccessWeaver delivery roadmap

The goal is a clear, editable networking workspace across desktop and mobile. Milestones below separate current orchestration from future native networking. Version labels express direction, not promised delivery dates.

## v0.1 alpha — implemented in this repository

- [x] English-default responsive interface, Turkish translation, dark/light theme
- [x] Guided profile editing + full JSON editor, import/export, duplication and deletion
- [x] Versioned JSON schema; atomic local storage; strict validation
- [x] External engine catalog and platform capability filtering
- [x] Managed include/exclude rules for ByeDPI and Zapret-family adapters; GoodbyeDPI inclusion
- [x] Read-only command previews, readiness issues and external configuration paths
- [x] Nine editable starter profiles with one-time seeding
- [x] Explicit process launch/stop; no shell interpolation; bounded logs
- [x] Optional executable SHA-256 comparison; executable basename allowlists
- [x] Read-only DNS/TCP/TLS diagnostics and CLI
- [x] Windows/Linux/macOS/FreeBSD/OpenBSD Go cross-build support (compilation, not certification)
- [x] Go unit tests, cross-platform CI configuration and unsigned ZIP/tar packaging
- [x] 0BSD original source, third-party notices and English/Turkish documentation

## v0.2 — dependable desktop foundations

- [ ] Install-free signed desktop binaries and platform-specific signed installers
- [ ] Driver, service, permission and OS network-state discovery
- [ ] Engine version/provenance verification; integrated update UI and changelogs
- [ ] Guided OS proxy/engine setup and native WireGuard tunnel lifecycle
- [ ] Transactional installer with OS-change preflight, system snapshot and rollback journal
- [ ] Explicit OS-native proxy setup and restoration with user consent
- [ ] More unit tests plus Windows/Linux/macOS/BSD VM integration tests

## v0.3 — advanced routing & intelligence

- [ ] Typed policy compiler for per-app, per-domain, per-port and IPv4/IPv6 policies
- [ ] Safe conversion to Windows WFP, Linux nftables, macOS NetworkExtension, BSD PF
- [ ] Connectivity checks for Discord text and UDP voice/STUN, TLS, QUIC and proxy paths
- [ ] Automatic profile discovery via active tests, not just theoretical parameter scores
- [ ] Observable, conservative failover with rollback, cooldown and no flapping
- [ ] ISP-aware profiles with explicit upstream version constraints and confidence levels

## v0.4 — mobile products

- [ ] Native Android app + VpnService backend and user permission flow
- [ ] Native iOS/iPadOS app + signed Packet Tunnel Provider extension
- [ ] Secure profile portability across desktop/mobile, without hidden cloud sync
- [ ] Mobile-specific battery, lifecycle, DNS, IPv6, traffic and app-review tests

## v1.0 — release candidate acceptance criteria

- [ ] Verified end-to-end operation on a published supported OS/device matrix
- [ ] Clear engine parity matrix and graceful unsupported-feature behavior
- [ ] Signed builds, SBOM, software supply-chain policy, third-party license audit
- [ ] Proven install/uninstall and rollback under failure injection
- [ ] Reproducible performance/latency benchmarks for multiple Turkish ISPs
- [ ] Evidence-backed documentation in English and Turkish
- [ ] Security assessment and publishable threat model

Reliability and compatibility claims require repeatable tests on representative devices and networks. A source build or successful child-process start is not sufficient evidence.
