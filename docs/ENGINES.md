# Engine adapters

The foreground profile runner launches separately installed tools and translates a small set of profile fields. Windows installation, drivers, firewall rules and credential provisioning are separate experimental [system workflows](WINDOWS_WORKFLOWS.md). Neither path certifies a strategy against an ISP. Foreground adapter behavior is defined in `internal/engine/catalog.go` and `internal/engine/plan.go`.

Use the upstream documentation for the **exact binary version you install**. No engine version is bundled or end-to-end certified in this alpha. The references below were reviewed on 2026-10-31.

Foreground Unix launches run in a private session. Shutdown retains exact-launch ownership through process observation and output drain; unresolved cleanup keeps the manager occupied. Review [engine lifetime and recovery](ENGINE_LIFETIME.md) before integrating tools that daemonize or change process groups.

## Supported commands

| ID | Executable by platform | Adapter behavior |
|---|---|---|
| `byedpi` | `ciadpi` on Windows, Linux, macOS, FreeBSD, OpenBSD | SOCKS listener, loopback required; guided include/exclude strategy groups |
| `zapret2` | Windows: `winws2`; Linux: `nfqws2`; FreeBSD/OpenBSD: `dvtws2` | Native arguments plus guided hostlists; explicit `--lua-desync` strategy required |
| `zapret` | Windows: `winws`; Linux: `nfqws` or `tpws`; BSD: `dvtws` or `tpws`; macOS: `tpws` | Native arguments plus guided hostlists; `tpws` requires SOCKS mode and a port |
| `goodbyedpi` | Windows: `goodbyedpi` | Native arguments; guided includes become `--blacklist FILE` |
| `wiresock` | Windows: `wiresock-client` | `run -config CONFIG -log-level error`; vendor SDK installation required |
| `sing-box` | Windows, Linux, macOS, FreeBSD, OpenBSD: `sing-box` | `run -c CONFIG` plus additional native options |
| `xray` | Windows, Linux, macOS, FreeBSD: `xray` | `run -config CONFIG` plus additional native options |
| `spoofdpi` | Windows, Linux, macOS: `spoofdpi` | Native argument array; external proxy configuration |
| `wireguard` | Catalog reference only | Launch rejected; use the official OS client for tunnel lifecycle |

Windows executable names may include `.exe`. Platform listing means the adapter accepts that combination; the chosen upstream build and technique must also support it. In particular, ByeDPI on macOS/BSD may require a user-built executable. WireGuard is intentionally not represented as a managed process: tools such as `wg-quick` can exit while leaving a tunnel behind.

## Command preview and process ownership

`accessweaver preview PROFILE_ID` returns the selected executable, arguments, working directory, generated file paths, warnings and blocking issues. The dashboard provides the same plan. Preview reads local prerequisites; it does not run the engine, write hostlists, or make network probes. `ready: true` means only that the adapter's local checks passed.

The executable must be a regular file with an allowed engine/platform basename. Use an absolute path or a name on `PATH`; relative executable paths containing directory separators are rejected. The child working directory is the executable's directory. Prefer absolute paths for Lua scripts and other assets. An allowed basename is not a trust check; optionally set a SHA-256 digest obtained from a source you independently trust.

The application manages one foreground child at a time. Daemon/service modes are rejected. POSIX shutdown sends a termination signal to the process group, then escalates if necessary. Windows stops the foreground child with process termination; it does not provide graceful vendor service control or guarantee cleanup of descendants, drivers, routes or network-lock state.

A successful start confirms process launch. The foreground CLI waits for that specific launch to finish, preserving immediate failures and policy-revocation errors even if another launch later begins. A stop request is separate from an accepted signal and a terminal process result. An accepted stop signal does not prove it caused the exit or restored network state. Stop retains its three-second graceful wait and one-second forced wait; native launch, signal and output calls have no hard whole-command deadline.

The CLI registers shutdown signals before launch. If its launch notice fails or is only partly written, it attempts to stop the owned process before returning a fixed notice error and any stop failure. A closed standard-output pipe follows the same path, with the previous SIGPIPE behavior restored afterward. Source tests use inert children, including actual closed-pipe cleanup and reaping; they do not qualify vendor networking or Windows descendant cleanup.

The separate [recorded foreground command](RECORDED_ENGINE_RUN.md) adds explicit consented Linux launch/terminal audit records while preserving normal launch permissions and the engine manager. It does not enable engines in the profile-editing audited desktop or make ordinary runs recorded.

## Domain rules

| Adapter | Include list | Exclude list | Meaning and limits |
|---|---|---|---|
| ByeDPI | `--hosts` strategy group | An earlier unmodified group | Excluded traffic still passes through the proxy; manipulation is skipped |
| Zapret / Zapret2 | Windows: `--hostlist=FILE`; Unix: `--hostlist-domains=...` | Windows: `--hostlist-exclude=FILE`; Unix: `--hostlist-exclude-domains=...` | Added to every `--new` section; actual hostname detection is upstream behavior |
| GoodbyeDPI | `--blacklist FILE` | Unsupported | Filters manipulation by available HTTP Host/TLS SNI, not every driver effect |
| Other adapters | Unsupported in guided fields | Unsupported in guided fields | Put supported routing in the external engine configuration |

On Unix, Zapret-family engines drop privileges before reading hostlists. Guided domains therefore use inline native options, avoiding private-file permission failures. These domains are visible in process arguments. Managed commands are limited to 64 KiB on Unix and 24 KiB on Windows; large lists should use user-managed native hostlist files with appropriate permissions and empty guided fields.

Generated files, where used, live under `ACCESSWEAVER_HOME/generated/` or the default application configuration root. They are recreated when starting a profile. Duplicate domains and the same domain in both lists are rejected. DNS names must be ASCII/IDNA; URLs, wildcard patterns and path strings are not accepted. The `^` exact-match prefix is accepted only for Zapret-family hostlists at launch.

Guided lists cannot be combined with native Zapret `--hostlist...` options or ByeDPI `--auto`/`--hosts` groups: clear the guided lists if you want to manage those options yourself. GoodbyeDPI native `--blacklist` conflicts with guided includes. The Windows WireSock adapter accepts guided `routing.applications`; other adapters reject that field. Guided rules are not a general application-routing implementation.

Hostlists do not establish per-app routing, a system-wide firewall, DNS protection or a complete split tunnel. HTTPS hostname visibility, QUIC, IPv6 and application behavior require independent testing. The direct diagnostic tool does not validate these rules.

## ByeDPI: first proxy workflow

1. Obtain `ciadpi` from [ByeDPI upstream](https://github.com/hufrea/byedpi) and retain its version information.
2. Set the executable path in the `discord-proxy` starter profile. Inspect its editable arguments and domain list.
3. Preview, then start. The default listener is `127.0.0.1:1080`; AccessWeaver rejects non-loopback binds in this managed mode.
4. Configure the intended application's SOCKS5 setting to use that listener. Enable proxy-side DNS if the application supports it.
5. Test through that application, including the actual feature you need. A text connection test is not evidence that voice or UDP works.
6. Restore that application's proxy setting when finished, then stop the engine.

The sample split strategy is illustrative; the project does not publish a tested ISP compatibility score. Applications without compatible proxy support may need an independent routing solution.

## Zapret and Zapret2

[Zapret 1 upstream](https://github.com/bol-van/zapret) marks that generation end-of-life and points to [Zapret2](https://github.com/bol-van/zapret2). Zapret2 uses Lua-driven strategies and does not currently provide macOS support. The [legacy BSD/macOS guide](https://github.com/bol-van/zapret/blob/master/docs/bsd.en.md) documents the limited macOS `tpws` path.

For packet mode, install the upstream driver or interception setup first: Windows WinDivert, Linux NFQUEUE, or BSD divert/firewall integration as applicable. AccessWeaver does not create those hooks. Add an explicit, version-compatible strategy and trusted Lua assets for Zapret2. Lua executes code with the engine's privileges; do not import unfamiliar scripts as if they were inert parameters.

For legacy `tpws`, managed mode requires `--socks` and an explicit `--port`. The adapter supplies a loopback bind when omitted and rejects public/interface binds. Configure the application proxy separately. Transparent redirection remains external.

## GoodbyeDPI

Install from [the official repository](https://github.com/ValdikSS/GoodbyeDPI), preserving the compatible WinDivert files and directory layout. The engine typically needs an elevated Windows process. Review the `-5` example preset and test its behavior on the intended network. Exclusion lists are rejected; there is no general application filter through this adapter.

## WireSock SDK

Use the [vendor SDK](https://wiresock.net/wiresock-sdk) and its [foreground CLI documentation](https://wiresock.net/documentation/wiresock-secure-connect/command-line-interface.html). Set `configPath` to an existing local WireGuard-style `.conf` file. AccessWeaver supplies `run -config`; optional managed arguments are limited to `-log-level`, `-lac` and `-network-lock`.

With empty `routing.applications`, application selection remains in the vendor configuration's `AllowedApps`/`DisallowedApps` fields. With guided application names, launch creates a private `generated/<profile-id>-wiresock.conf` copy, removes those two existing fields and adds `AllowedApps` for the selected names; the original configuration is unchanged. Preview reports this generated input without writing it. The copy includes the tunnel's private material and must stay inside a private configuration root. Enrolled managed launches reject generated inputs until protected staging/authorization is implemented. Config hooks named `PreUp`, `PostUp`, `PreDown` or `PostDown` block launch. Keep private keys out of profile notes and shared JSON. Native traffic tests remain required to establish actual application selection.

The SDK and Secure Connect desktop product have distinct license terms. Read [THIRD_PARTY.md](../THIRD_PARTY.md). If you enable network lock, abnormal termination may need the vendor's recovery procedure; AccessWeaver does not automatically reset vendor state.

## Optional cores

- [sing-box](https://sing-box.sagernet.org/) and [Xray-core](https://github.com/XTLS/Xray-core) require `configPath` to a readable local regular file no larger than 4 MiB. The adapter supplies the `run` and config arguments. Duplicate config/command options are rejected. External files are not exported with the profile. Review listeners, routing, credentials and TUN settings before running.
- [SpoofDPI](https://github.com/xvzc/spoofdpi) accepts native arguments. Some versions may change macOS system proxy settings; inspect the installed version's settings and recovery instructions. AccessWeaver cannot restore arbitrary changes made by an external engine.
- [WireGuard](https://www.wireguard.com/) remains a reference entry until its native tunnel setup, teardown and recovery can be managed accurately.

Additional engines are alternatives for particular configurations, not universally better solutions. Choose by tested behavior, platform support, upstream maintenance and applicable licensing.
