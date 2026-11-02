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

The binary can open its local dashboard without arguments. It still runs as a console application, not an installed Windows service or a native signed desktop application. Closing/terminating a process is not proof that vendor network state has been restored.

## Linux and BSD

Profile editing and ordinary diagnostics can run without elevated privileges. Packet interception needs upstream-specific OS setup. Use the engine's official documentation for NFQUEUE, divert sockets and firewall configuration; AccessWeaver does not generate those system rules. On headless systems, use the CLI. Do not expose the control API remotely to make the UI reachable.

Linux amd64/arm64 includes partial administrator policy through a fixed root-owned `/etc` source, root-only atomic install/update/rotation and guarded foreground inputs. Storage must have qualified persistent local filesystem semantics. [Managed configuration](MANAGED_CONFIGURATION.md#protected-linux-source-and-update-behavior) defines the current restrictions; services, generated/native-argument assets and full desktop qualification remain unfinished. BSD machine authority remains work.

BSD CLI/dashboard builds are targets; engine syntax, privileges and cleanup still need verification on the exact OS release and architecture. The manual [disposable guest core probe](TESTING.md#disposable-bsd-guest-core-probe) is an initial FreeBSD 15.1 amd64 path; its existence and host-built test payload are not evidence of completed guest execution. The other BSD targets and full native platform acceptance remain open. `tpws` is managed only as an explicit SOCKS proxy.

## macOS

macOS amd64/arm64 also have partial signed administrator policy through a fixed paired root-owned local-APFS source. [Native policy contracts and disposable acceptance](MACOS_MANAGED_POLICY.md) describe root-only CLI enrollment/update/rotation/recovery, protected Mach-O/bundle inputs, sanitized foreground launch and unqualified deployment/recovery boundaries. Both native architecture jobs must pass for the actual candidate.

Use a compatible local proxy or external configured core. Zapret2 is not offered; legacy Zapret is limited to `tpws` SOCKS mode in this adapter. Some external proxy tools may change system proxy settings themselves. Native network extensions, signing/notarization and rollback remain planned.

## Android

A native product needs an Android application using [VpnService](https://developer.android.com/develop/connectivity/vpn), the required service permission and a user consent flow. It also needs traffic forwarding, lifecycle management, battery/background testing and supported per-app policy. A mobile browser profile editor supplies none of those networking privileges.

## iOS / iPadOS

A native product needs a signed app and [Packet Tunnel Provider](https://developer.apple.com/documentation/networkextension/packet-tunnel-provider), correct entitlements/provisioning and actual tunnel forwarding. It needs real-device testing for routing, DNS, background lifecycle and distribution requirements. A browser or PWA cannot substitute for the provider.
