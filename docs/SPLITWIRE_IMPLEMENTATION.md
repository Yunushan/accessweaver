# SplitWire implementation and verification status

Continuation of the [historical baseline audit](SPLITWIRE_PARITY_AUDIT.md), dated 2026-11-01. Comparison reference remains SplitWire-Turkey commit `766422ed8ca9cb5360e8d9d540e80722a0508efc`.

**Full behavioral parity is not yet certified.** The working tree now adds Windows workflows for the missing installation, application routing, DNS and maintenance features. Implemented operations are not all covered by live traffic tests. The original audit describes the earlier commit, not this implementation.

| Capability | Implementation | Verification boundary |
|---|---|---|
| Standard/alternative/custom WireSock setup; wgcf config generation | Windows workflow, official downloads, private application rules, modern CLI and SDK service paths | Config generation tested without account registration. Vendor tunnel/handshake tests pending. |
| Default/custom/browser app selection and native folder picker | Private WireSock configs and ProxiFyre rules; folder chooser and clear controls | Config compilation and input contracts tested. Local WireGuard fixture passes TCP/UDP over IPv4/IPv6; actual per-app WireSock/ProxiFyre traffic remains pending. |
| ByeDPI proxy, split ProxiFyre and DLL modes | Protected component staging, SCM host, driver prerequisite, firewall, drover backups | Native ByeDPI SOCKS HTTPS transfer and SCM stop/restart passed. Interception and Discord tests pending. |
| Zapret/Zapret2 scans, ISP presets and auto-install | Embedded upstream preset collections and MIT notice; blockcheck/Cygwin runner; completed common-strategy parser | Parser and native argument tests passed. Real strategy scans and ISP effectiveness pending. |
| Packet-engine service/one-shot and live hostlists | SCM lifecycle; saved/active lists; GoodbyeDPI argument restart | Native GoodbyeDPI/Zapret/Zapret2 service and live-toggle checks passed. One-shot and ISP effectiveness still need traffic evidence. |
| Encrypted DNS and restore | Native DoH or DNSCrypt, original per-family snapshot, bounded resolver readiness, interrupted-operation recovery | Native DoH configuration/restoration passed. DNSCrypt serves direct loopback queries, but ordinary Windows resolution timed out in Sandbox; unresolved pending full-VM diagnosis. |
| Discord/PTB/SplitCord install/start/remove, clean PTB, repair | Official x64 installers, curl TLS fallback, Explorer launch, proxied repair downloads, cache backup and drover deployment | Initial app run failed: Discord TLS errors and stalled SplitCord installation. Subsequent fixes need interactive VM retest. No account sign-in or voice test performed. |
| Refresh task, service discovery/conflicts, updates, logs | Scheduled reconnect, component/service discovery, Kaspersky/WARP indications, official release check and durable history | Discovery and read-only official update check passed. Sandbox reboot started ByeDPI but lost DNS because its adapter was recreated; overall reboot test failed. Full-VM refresh/reboot pending. |
| Individual/remove-all cleanup, recovery, uninstall | Owned service/task/firewall cleanup, DNS/drover restoration, conflict guards, registered core and explicit WireSock vendor uninstall | Core install/workflow-launched uninstall passed. WinDivert disappearance during cleanup caused error 1060; fixed and targeted native cleanup passed twice. Vendor uninstall remains untested. |
| English/Turkish/Russian/Spanish | Full UI dictionaries and operation labels, persisted selection | Dictionary coverage, language logic tests and Chrome smoke checks passed. |
| Existing profiles, foreground engines and diagnostics | Installed binary discovery, SDK app-config copy, IPv6 diagnostic validation fix | Go/API tests and real IPv4/IPv6 loopback tests passed. Diagnostics still use the ordinary network stack. |

## Native environment

The VMware full clone `AccessWeaver-Parity-Test` failed during Windows Setup before AccessWeaver execution. Its checkpoint remains available and it is powered off. Tests moved to an isolated Windows Sandbox with a read-only test bundle and writable results-only mapping. A fresh, independent Windows 10 VM named `AccessWeaver-Clean-Windows-Test` is now waiting for Windows setup, a disposable account and VMware Tools. Take a Windows-ready snapshot before native testing. Guest tests do not alter the host's DNS, installed apps or engine services.

Local raw evidence is under ignored `build/vm-tests/sandbox/`:

- `initial-seven-results.json`: first seven passing checks.
- `results/final-system/integration.json`: 11 passes, one DNSCrypt skip and one cleanup failure. Binary SHA-256 `358CC8B3957123F2E598B07AE299E958BB36010B9CF5C6F2A6ED5963AA843DEB`.
- `results/driver-cleanup/result.json`: targeted fix passed with a real WinDivert driver, repeated removal, and no remaining owned drivers/services. Binary SHA-256 `3D0B74A40A63804D987EFC99066A9062F00C80DF3B712CBC844A45BF293431C8`.
- `results/readiness-system/integration.json`: subsequent full system run with bounded logging and durable shutdown changes recorded **12 passes, one DNSCrypt skip and no failures**. Binary SHA-256 `A19BD59BAC4B05EB0B7F07A3AE913988AB86DD09A3F23268E110718CD87C3962`. This preceded later version/packaging changes.
- `results/wgpeer-self-test/self-test.json`: generated-key userspace fixture passed TCP/UDP over IPv4/IPv6, with a handshake and encrypted traffic counters. This validates the fixture, not WireSock.
- `applications-v1-results.json` and `results/reboot-results.json`: failed app/reboot tests retained for diagnosis.

Current local checks pass: Go tests and vet, 40 JavaScript tests, JavaScript syntax, PowerShell parsing/contracts, and ten platform cross-builds. Cross-building does not execute those platforms. The current tree has not been pushed or run through CI; no race-detector result is claimed for this tree. Native evidence above applies to its recorded binary, not automatically to later edits. Broader production, premium and enterprise acceptance is tracked in [readiness-gates.json](readiness-gates.json).

Reboot persistence, Windows 10 compatibility, WireSock handshakes, ProxiFyre TCP/UDP app interception, Discord voice, QUIC/STUN, IPv6 tunnel traffic, strategy effectiveness on each ISP, and cancellation during vendor installers require additional native evidence before a full-parity claim.
