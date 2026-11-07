# Platform coverage

Compilation, native execution, driver integration and successful traffic routing are different milestones. The project publishes these separately. No blanket six-platform networking parity or production certification is claimed.

| Platform | Core build targets | Current interface | Networking boundary |
|---|---|---|---|
| Windows | amd64, arm64 | CLI + local browser dashboard | External engines and drivers; foreground child termination only |
| Linux | amd64, arm64 | CLI + local browser dashboard | External engines; NFQUEUE/nftables and proxy setup remain external |
| macOS | amd64, arm64 | CLI + local browser dashboard | Proxy-oriented adapters; no Zapret2, signed native tunnel or notarized app |
| FreeBSD | amd64, arm64 | CLI + local browser dashboard | Compatible external binaries; divert/firewall setup external |
| OpenBSD | amd64, arm64 | CLI + local browser dashboard | Compatible external binaries; platform-specific restrictions apply |
| Android | No native application target | Responsive offline profile editor | No `VpnService`, packet capture or managed engine process |
| iOS / iPadOS | No native application target | Responsive offline profile editor | No Packet Tunnel Provider, app signing or VPN capability |

Use an operating-system version supported by both the compiler used for the binary and the installed engine. Release metadata records the compiler; consult [Go's minimum requirements](https://go.dev/wiki/MinimumRequirements) when choosing a build. An older source language minimum does not guarantee that a binary built with a newer compiler runs on an older OS.

CI/release verification is configured for native execution on six hosted targets:

| Target | Hosted runner | Intended native checks |
|---|---|---|
| Linux amd64 | `ubuntu-latest` | Unit/static/race, Unix controller/session isolation, backup/recovery interoperability, protected policy/rotation/recovery |
| Linux arm64 | `ubuntu-24.04-arm` | The same native Linux checks, including ordinary-user/root separation |
| Windows amd64 | `windows-latest` | Unit/static, workflow contracts, backup/recovery interoperability and protected policy/rotation/recovery with restricted-token checks |
| Windows arm64 | `windows-11-arm` | The same native core/policy checks on Windows 11 ARM64; installer compilation selects and verifies an ARM64 core payload |
| macOS arm64 | `macos-latest` | Unit/static, Unix controller ownership/shutdown and backup/recovery interoperability |
| macOS amd64 | `macos-15-intel` | The same native core checks on an Intel Mac |

The [hosted-runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) identify the provider's OS/architecture images; `-latest` labels can change OS releases. Native checks compare OS machine type, runner architecture, Go host/target/version and the executed CLI identity. A cross SDK, different target, wrong source or dirty hosted build fails validation. Public per-target records contain actual image/OS/toolchain and binary hashes; artifact names include both OS and architecture so one target cannot replace another's evidence. Test outcomes must be checked against the exact source-bound run, not inferred from this configured matrix.

Release previews also authenticate and execute the actual packaged portable cores on those six hosts. Publication requires every packaged check to pass. Separate `packaged-native-OS-ARCH` artifacts bind the archive/executable hashes to runtime identity, backup/recovery, loopback diagnostics and Unix controller checks; see [release provenance](RELEASE_PROVENANCE.md#execute-the-authenticated-portable-candidate). The source-built native policy tests above remain separate from packaged-candidate acceptance.

The ten packaging targets remain cross-compiled with `CGO_ENABLED=0`. BSD builds are not native BSD execution. Hosted core acceptance does not establish vendor driver/routing behavior, every OS version/distribution, domain/MDM enrollment, signed distribution, installer lifecycle/signatures or complete desktop qualification. Current run results belong in GitHub Actions; [TESTING.md](TESTING.md) defines what additional integration evidence is needed.

## Windows

External packet engines may need administrator privileges and compatible driver files. AccessWeaver does not elevate itself or install services/drivers automatically. Running the controller elevated also elevates its external children, so inspect the profile and configuration first.

The installer builder selects an amd64 or ARM64 core payload to match the host Go SDK, and CI verifies each on its corresponding Windows runner. The pinned Inno Setup 6 bootstrap remains x86; the architecture in the setup filename identifies its core payload, not a native ARM64 setup runtime. Compilation does not prove installation, upgrade, architecture migration, uninstall or external engine/driver compatibility.

Windows Packet Filter prerequisite selection uses the host architecture returned by [IsWow64Process2](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process2), including an emulated controller process. Bundle and upstream asset selection require one matching x64 or ARM64 MSI; a valid publisher signature and the [MSI Template Summary platform](https://learn.microsoft.com/en-us/windows/win32/msi/template-summary) must both pass before launch. Unknown OS identity, ambiguous assets and mismatched templates fail. This addresses the prerequisite selection path only. Other engine/driver asset selection, installation and traffic acceptance still need architecture-specific work; the portable ARM64 core does not qualify those integrations. The [vendor release](https://github.com/wiresock/ndisapi/releases/tag/v3.6.2) supplies separate x64 and ARM64 driver installers.

ProxiFyre, wgcf and DNSCrypt component selection also uses the host OS identity. Their native x64/ARM64 upstream asset names must match uniquely; local discovery reads bounded DOS/PE headers and selects the matching COFF machine even when a folder name suggests the other architecture. Final staged executable metadata is checked before reporting the component ready. A machine-field check establishes architecture eligibility only, not complete executable validity, signature trust, dependency compatibility or successful execution. Other packet engines, WireSock installation and injected DLL architecture still need separate integration work.

The binary can open its local dashboard without arguments. It still runs as a console application, not an installed Windows service or a native signed desktop application. Closing/terminating a process is not proof that vendor network state has been restored.

## Linux and BSD

Profile editing and ordinary diagnostics can run without elevated privileges. Packet interception needs upstream-specific OS setup. Use the engine's official documentation for NFQUEUE, divert sockets and firewall configuration; AccessWeaver does not generate those system rules. On headless systems, use the CLI. Do not expose the control API remotely to make the UI reachable.

Linux amd64/arm64 includes partial administrator policy through a fixed root-owned `/etc` source, root-only atomic install/update/rotation and guarded foreground inputs. Storage must have qualified persistent local filesystem semantics. [Managed configuration](MANAGED_CONFIGURATION.md#protected-linux-source-and-update-behavior) defines the current restrictions; services, generated/native-argument assets and full desktop qualification remain unfinished. BSD machine authority remains work.

BSD CLI/dashboard builds are targets; engine syntax, privileges and cleanup still need verification on the exact OS release and architecture. The manual [disposable guest core probe](TESTING.md#disposable-bsd-guest-core-probe) configures separate FreeBSD 15.1 amd64/arm64 paths; each requires its own successful target execution record. The current four-target emulated archive results are recorded below; full platform acceptance remains open. `tpws` is managed only as an explicit SOCKS proxy.

FreeBSD 15.1 amd64 and arm64 have source-bound emulated core results at `a16ab354dac590fa63d229b5482d1a9f5ed4cc47`: [both targets passed all 15 package tests and the CLI identity check](https://github.com/Yunushan/accessweaver/actions/runs/41555643070). Each ran as the ordinary guest user, passed 387 test instances including subtests and retained two Windows-only skips. Provider artifact digests and all package-log digests were independently verified, together with owned VM/capsule cleanup. Those TCG results cover the separately built core fixtures. The [archive-gated preview at exact source `ee2754dd80c813a47e168f39baa1d2c06f45737e`](https://github.com/Yunushan/accessweaver/actions/runs/41560984760) subsequently passed all 19 jobs, including both original FreeBSD release-archive executables. Their hashes and complete runtime build identities matched the authenticated archive contents; both passed encrypted-backup round trips, incorrect-passphrase rejection, all 15 unit packages and owned VM/capsule cleanup. Provider and package-log digests were independently verified. These historical results apply to those exact sources; the later corrected candidate below includes both BSD families.


The manual [OpenBSD guest probe](TESTING.md#disposable-openbsd-guest-core-probe) now configures independently installed OpenBSD 8.0 amd64/arm64 guests with signed installer inputs, private bootstrap, ordinary-user CLI/unit execution and owned cleanup. At corrected source `051e4dab8c70127e1ecc7530c0014c9a987a0d0f`, the [archive preview](https://github.com/Yunushan/accessweaver/actions/runs/41597250505) passed all 21 jobs, including original archived cores in all four FreeBSD 15.1/OpenBSD 8.0 amd64/arm64 guests. Each guest passed encrypted-backup checks and all 15 target-selected unit packages (393 passing instances and two Windows-only skips). Independent checks verified provider artifact and all 60 package-log digests, archive/runtime identity, pinned OpenBSD boot/SSH inputs and owned cleanup. The [source-bound evidence index](qualification/051e4dab8c70.json) preserves scoped results and digests. These CPU-emulated core results leave BSD machine policy, packet engines, traffic/routing, installer lifecycle, physical hardware and full platform qualification open.

The later [current-source public diagnostic checkpoint](qualification/e6490f5d15f0-bsd-public-diagnostic-checkpoint.json) at `e6490f5d15f08de87cf4de2cd53be6384519fa89` executed the source-built CLI and all 27 selected unit packages in each of the four FreeBSD/OpenBSD guests. All four jobs failed: 103 of 108 package executions passed and five failed. All identity, image/transport and owned-cleanup checks passed. The public reports were digest/source verified without collecting raw-log artifacts; the application Go/web sources are unchanged. This is failed current-source core qualification, distinct from the historical archived-core passes above. BSD runtime failures and full platform/managed acceptance remain open.

## macOS

macOS amd64/arm64 also have partial signed administrator policy through a fixed paired root-owned local-APFS source. [Native policy contracts and disposable acceptance](MACOS_MANAGED_POLICY.md) describe root-only CLI enrollment/update/rotation/recovery, protected Mach-O/bundle inputs, sanitized foreground launch and unqualified deployment/recovery boundaries. Both native architecture jobs must pass for the actual candidate.

Use a compatible local proxy or external configured core. Zapret2 is not offered; legacy Zapret is limited to `tpws` SOCKS mode in this adapter. Some external proxy tools may change system proxy settings themselves. Native network extensions, signing/notarization and rollback remain planned.

## Android

A native product needs an Android application using [VpnService](https://developer.android.com/develop/connectivity/vpn), the required service permission and a user consent flow. It also needs traffic forwarding, lifecycle management, battery/background testing and supported per-app policy. A mobile browser profile editor supplies none of those networking privileges.

## iOS / iPadOS

A native product needs a signed app and [Packet Tunnel Provider](https://developer.apple.com/documentation/networkextension/packet-tunnel-provider), correct entitlements/provisioning and actual tunnel forwarding. It needs real-device testing for routing, DNS, background lifecycle and distribution requirements. A browser or PWA cannot substitute for the provider.

## BSD lifetime fixture pipe roles

The public e6490f5 BSD diagnostics were mapped to immutable test source after explicit approval. All four targets reported the same sixteen Unix lifetime/shutdown roots; FreeBSD ARM64 separately reported a durable-result wait timeout. Catalog hashes were independently reconstructed before mapping, and no raw logs or private controller data were read. Reported source locations also include skip/helper sites and are not all failure assertions.

The lifetime fixture incorrectly required inherited pipe descriptor 3 to be read-only and descriptor 4 to be write-only. The [FreeBSD 15.1 pipe implementation](https://raw.githubusercontent.com/freebsd/freebsd-src/releng/15.1/sys/kern/sys_pipe.c) and [OpenBSD implementation](https://raw.githubusercontent.com/openbsd/src/master/sys/kern/sys_pipe.c) create both endpoints with read/write capabilities. The corrected fixture requires the intended role's capability and accepts that native bidirectional mode, while still rejecting the opposite-only mode, invalid modes and unexpected descriptor numbers. FIFO type, nonblocking setup, close-on-exec, bounded deadlines, anonymous inherited endpoints, source-built child identity and owned cleanup remain required. It continues to use one direction per endpoint; production process ownership and kqueue logic are unchanged.

A native regression checks the real `os.Pipe` descriptors and the positive/negative role table. The complete existing engine suites remain selected on all four BSD targets; the previously failed roots are not skipped. The [de805cc qualification receipt](qualification/de805ccbef8f-bsd-core-qualification.json) records all four native FreeBSD/OpenBSD AMD64/ARM64 core jobs passing the complete 27-package set: 108 package executions, 6,908 passing test instances and 48 explicit skips. Four public core ZIP digests, every package plan/catalog, source and transported binary hashes, native image/compiler/CLI identity and owned cleanup were verified. The same source also passes its ten-job parser/browser regression (56 native mutation reports, 318 browser cases and 150 unchanged performance caps) and four local-input jobs; twenty public report ZIP digests are verified in total. The unchanged durable-result deadline test passes in this run, without a dedicated timing fix or worst-case proof. These source-built disposable core checks do not qualify routing, installed lifecycle, signed distribution, actual hardware or any complete platform gate; browser resource failures from other runs remain open.
