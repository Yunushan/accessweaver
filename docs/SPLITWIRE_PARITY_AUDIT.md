# SplitWire-Turkey feature audit

Audit date: 2026-10-31 (Europe/Istanbul).

**AccessWeaver does not currently provide full SplitWire-Turkey feature parity.** Its profile editor, command planning and foreground engine manager work within the tested scope. Most of SplitWire's installation, application interception, persistent Windows service, DNS and application repair workflows are absent. Shared engine names do not establish equivalent capabilities.

This audit checks the existing implementation; it does not add the missing integrations or change application source code. SplitWire's features below were established from its source, not by executing its installers or certifying its own reliability.

## Baseline and method

- AccessWeaver commit: `8da44c9c8b0d02e8cd3ffb4bb03dbf1b79f78ba5`; working tree initially clean.
- SplitWire commit: [`766422ed8ca9cb5360e8d9d540e80722a0508efc`](https://github.com/cagritaskn/SplitWire-Turkey/tree/766422ed8ca9cb5360e8d9d540e80722a0508efc), retrieved from its default branch during this audit.
- Compared its [README](https://github.com/cagritaskn/SplitWire-Turkey/blob/766422ed8ca9cb5360e8d9d540e80722a0508efc/README.md), [UI controls](https://github.com/cagritaskn/SplitWire-Turkey/blob/766422ed8ca9cb5360e8d9d540e80722a0508efc/src/SplitWireTurkey/MainWindow.xaml), [event handlers](https://github.com/cagritaskn/SplitWire-Turkey/blob/766422ed8ca9cb5360e8d9d540e80722a0508efc/src/SplitWireTurkey/MainWindow.xaml.cs), [configuration generation](https://github.com/cagritaskn/SplitWire-Turkey/blob/766422ed8ca9cb5360e8d9d540e80722a0508efc/src/SplitWireTurkey/Services/WireGuardService.cs) and [WireSock lifecycle](https://github.com/cagritaskn/SplitWire-Turkey/blob/766422ed8ca9cb5360e8d9d540e80722a0508efc/src/SplitWireTurkey/Services/WireSockService.cs).
- Traced AccessWeaver's UI, API, profiles, presets, engine catalog, argument generation, process lifecycle, diagnostics, setup scripts and CI/release configuration.
- Ran Windows/amd64 checks with checksum-verified portable Go 1.27.3 and Node 26.5.1. Go was initially absent from PATH. Tools, test profiles and raw evidence are isolated in ignored `build/parity-audit/`.
- Exercised the live dashboard in Chrome and the compiled application's real HTTP API. Used an already-installed ByeDPI binary for a loopback SOCKS TCP transfer.
- Existing machine networking was left in place. SplitWire was already open; successful direct Internet diagnostics cannot be attributed to AccessWeaver's routing.

Status meanings: **Present** = corresponding capability exists; **Partial** = narrower/manual capability; **Missing** = no implementation; **Gap** = concrete compatibility or behavior failure. Present does not imply every upstream binary/version/network has been tested.

## Feature-by-feature comparison

The rows cover the functional controls in the pinned SplitWire UI, including features present in code beyond its README. Repeated help, visibility and service-status controls are grouped with their corresponding function.

| SplitWire feature / option | AccessWeaver status | Current behavior and evidence |
|---|---|---|
| Standard installation | Missing | No combined wgcf, WireSock, ByeDPI, drover, firewall or DNS workflow. `scripts/setup.ps1` only compiles AccessWeaver. |
| Alternative installation | Missing | No equivalent alternate WireSock/ByeDPI provisioning workflow. |
| Download/register wgcf account and generate WARP configuration | Missing | No wgcf adapter, account registration or key/config provisioning. |
| Download/install WireSock and prerequisites | Missing | External vendor installation required. |
| Connect to current Secure Connect 3.x product | Gap | Installed `wiresock-connect-cli.exe` 3.4.8.1 is rejected; catalog accepts only `wiresock-client`. |
| Use an existing WireSock configuration | Partial | SDK-style foreground `run -config` adapter exists; needs separately installed compatible client and local `.conf`. No tunnel traffic test performed. |
| Default Discord/Roblox application selection | Missing | No discovery or generated `AllowedApps` rules. Domain lists are not process filters. |
| Include browsers in WireSock tunneling | Missing | No browser toggle or generated browser application list. Manual vendor config is external. |
| Optional WireSock refresh scheduled task | Missing | No Task Scheduler installation, periodic refresh or cleanup. |
| Show custom folder controls | Partial | A generic application-path field exists, but its values block launch. It cannot select folders for working routing. |
| Add application folders | Missing | No functional folder picker/compiler for app routing. |
| Clear selected application folders | Partial | Metadata can be cleared in the editor; there is no installed routing policy to update. |
| Custom installation using folder selection | Missing | `routing.applications` is explicitly unsupported in `Preview`. |
| Generate custom WireGuard/WireSock `.conf` only | Missing | JSON profile export does not generate a vendor tunnel configuration. |
| ByeDPI split installation with ProxiFyre | Missing | ByeDPI launch exists; ProxiFyre interception, driver/prerequisite installation and services do not. |
| Include browsers in ByeDPI interception | Missing | Applications must configure a compatible proxy themselves or use an external interception solution. |
| ByeDPI DLL/drover installation for Discord | Missing | No DLL deployment or Discord injection integration. |
| Remove ByeDPI/ProxiFyre/drover installation | Missing | Stop terminates the owned foreground child; it does not uninstall components. |
| Launch ByeDPI as an explicit local proxy | Present | Real installed binary started, accepted generated include/exclude arguments, transferred local SOCKS TCP data and stopped. |
| Zapret automatic strategy detection/install | Missing | No blockcheck runner, strategy selection or service installation. |
| Zapret quick/standard/full scan options | Missing | Diagnostics are direct DNS/TCP/TLS checks, not strategy scans. |
| Zapret preset selection | Partial | Editable generic profiles exist, but the upstream preset collection is not included. |
| Zapret manual preset argument editing | Present | Argument arrays editable through guided and JSON editors. Native syntax/version compatibility remains the user's responsibility. |
| Zapret persistent service install | Missing | Managed daemon/service arguments are rejected. |
| Zapret one-shot execution | Partial | Foreground adapter exists; executable, WinDivert and working strategy must be supplied. No real Zapret traffic test performed. |
| Zapret exclusion-list editing/save | Partial | Guided exclusions compile into hostlist arguments and files; command generation is tested. Filtering effectiveness is unverified. |
| Zapret live exclusion enable/disable with backup | Missing | Active profile edits are blocked; no hot-toggle or preserved active/backup hostlist workflow. |
| Remove Zapret services/installation | Missing | No vendor service/driver removal. |
| Zapret2 automatic strategy detection/install | Missing | No blockcheck2 orchestration or automatic install. |
| Zapret2 quick/standard/full scan options | Missing | No scan-level controls or strategy discovery. |
| Zapret2 Turkish ISP preset collection | Missing | No corresponding Turk Telekom, Superonline, Vodafone, Kablonet or mobile ISP collection. `zapret2-custom` is an incomplete setup template. |
| Try ISP presets before a full Zapret2 scan | Missing | No active preset ranking/trial engine. |
| Zapret2 manual preset editing | Present | Arbitrary native argument arrays can be edited; a `--lua-desync` strategy must be supplied. |
| Zapret2 persistent service install | Missing | Foreground ownership only. |
| Zapret2 one-shot execution | Partial | `winws2` adapter exists; Lua assets, strategy and interception setup are external. Not traffic-tested. |
| Zapret2 exclusion-list editing/save | Partial | Hostlists applied to every strategy group in argument tests. No domain-effectiveness test. |
| Zapret2 live exclusion enable/disable with backup | Missing | No in-place running-engine list toggle or backup restoration. |
| Remove Zapret2 services/installation | Missing | No service, driver or installation cleanup. |
| GoodbyeDPI preset collection | Partial | One editable `-5` starter profile; no matching upstream collection. |
| GoodbyeDPI manual preset argument editing | Present | Literal native arguments accepted. |
| GoodbyeDPI blacklist enable/disable | Partial | Nonempty guided includes generate `--blacklist FILE`; an empty list omits it. Active profile changes require stop/edit/restart. |
| GoodbyeDPI blacklist editing/save | Partial | Includes editable; no equivalent default Discord/Roblox/Wattpad list. Starter contains two Discord domains. General exclusions are rejected. |
| GoodbyeDPI persistent service install | Missing | No SCM lifecycle or startup registration. |
| GoodbyeDPI one-shot execution | Partial | Foreground adapter exists; elevation and compatible WinDivert are external. Not traffic-tested. |
| Remove GoodbyeDPI services/installation | Missing | Foreground stop only. |
| Repair Discord / remove cache / reinstall stable | Missing | No Discord application maintenance backend. |
| Install Discord PTB | Missing | No download/install workflow. |
| Clean PTB installation removing stable Discord | Missing | No equivalent option. |
| Detect/start/install/remove stable Discord | Missing | Runtime status describes one owned engine process, not installed Discord applications. |
| Detect/start/install/remove Discord PTB | Missing | No PTB discovery or management. |
| Install/detect/start/remove SplitCord-Turkey | Missing | Present in upstream UI/source; no AccessWeaver equivalent. |
| Show installed network service statuses | Missing | No service discovery dashboard. |
| Individual removal of WireSock, ByeDPI, ProxiFyre, winws/winws2, Zapret/Zapret2, GoodbyeDPI, WinDivert, drover and DNSCrypt | Missing | None of these system removal handlers exists. |
| Automatically apply DNS on installs/runs/scans | Missing | No adapter DNS mutation backend or switch. |
| Choose DNSCrypt versus native Windows DoH | Missing | No provider/method selection. |
| Install/start DNSCrypt and redirect DNS to local resolver | Missing | No encrypted-DNS service management or adapter DNS configuration. |
| Configure native Windows DoH / Google DNS / Quad9 | Missing | DNS diagnostics only inspect current resolution. |
| Remove all services in dependency order | Missing | Single-child ownership does not implement system service cleanup. |
| Restore DNS/DoH to DHCP/defaults | Missing | No network-state journal or restore operation. |
| Undo changes and uninstall the application | Missing | Portable core packaging; no matching system rollback/uninstaller. |
| Automatic Windows firewall rules for installed engines | Missing | No managed firewall rules. |
| Detect Kaspersky, missing WinDivert or conflicting WARP/engines | Missing | Platform/name/file/hash checks exist, but not this driver/service/AV conflict discovery. |
| Multiple methods remaining active across reboot | Missing | One foreground child at a time; no boot service persistence. |
| English/Turkish interface | Present | Live language switching verified; HTML translation-key tests pass. |
| Russian/Spanish interface | Missing | Only English and Turkish dictionaries/options exist. |
| Dark/light theme and persisted preference | Present | Theme selection and root attribute update verified. Chrome Dark Reader overrides rendered colors, so this browser did not establish clean light-theme visual correctness. |
| About/help/source links | Partial | Engine documentation, setup guidance, project/license links and version exist; no matching contextual help for absent workflows. |
| Check for newer application release and notify | Missing | Version reporting/manual release links exist; no update checker. |
| Installation logs | Partial | Bounded in-memory engine logs exist; no installer logs or durable install/repair history. |
| Exit / stop activity | Partial | Core shutdown owns its foreground child. It does not stop/uninstall independent system services or guarantee Windows descendant/driver/network cleanup. |

## Confirmed failures and practical blockers

1. **Per-application split tunneling is unavailable.** `internal/engine/plan.go:148` rejects every nonempty `routing.applications` list. The runtime check reproduced this using `Discord.exe`. Adding application paths in the editor cannot deliver SplitWire's main workflow. WireSock can receive app rules through an independently prepared vendor config, but AccessWeaver does not generate or validate that routing.
2. **The installed modern WireSock product is incompatible with this adapter.** `internal/engine/catalog.go:31` only allows the `wiresock-client` basename, and `plan.go:447` generates the SDK foreground command. The installed Secure Connect CLI at `C:\Program Files\WireSock Secure Connect\command-line\wiresock-connect-cli.exe` reports version 3.4.8.1 and fails preview's executable check. Supporting this product needs a separate service/profile lifecycle; merely adding its filename would not implement its different commands.
3. **IPv6 diagnostic inputs fail after profile validation succeeds.** `profile.ValidateHost` accepts IP literals, and the browser test explicitly accepts IPv6 probe hosts. However, `internal/diagnostics/doctor.go:30` calls `ValidateDomain`. Saving a profile with `probe.host = "::1"` succeeds; sending that probe to `/api/v1/diagnose` returns a failed `input` check. Use the host validator consistently and add a local IPv6 test. The same inappropriate domain validator accepts the hostlist-only `^` prefix into the diagnostic path, though that is not a valid probe hostname.
4. **All nine unmodified starter profiles were unready on this machine.** Preview reported missing executable paths/configuration and, for Zapret2, a missing strategy. Explicitly pointing the disposable ByeDPI profile at the installed binary made that profile ready. The application does not discover SplitWire's bundled binaries automatically.
5. **No current test establishes equivalent Discord access or voice behavior.** Direct diagnostics use the ordinary host stack. Local SOCKS transfer establishes a working ByeDPI proxy path, but not Discord interception, hostname filtering, DNS protection, UDP/STUN/QUIC, IPv6 traffic or bypass reliability on this ISP.

## Verification results

| Check | Result | Scope / limitation |
|---|---|---|
| `node --check web/app.js` | Pass | JavaScript syntax. |
| `node --test web/app.test.cjs` | 30 passed | Isolated browser logic with stub DOM; not a full browser suite. |
| `go vet ./...` | Pass | Windows host, Go 1.27.3. |
| `go test ./... -count=1 -v` with coverage | 26 top-level tests passed, 1 skipped | Windows symlink test explicitly skips without privileges. Subtests also passed. |
| Statement coverage | 57.4% overall | API 59.1%, diagnostics 8.2%, engine 78.6%, profile 58.8%, CLI 0%. Coverage is not evidence of parity. |
| `go build -trimpath ... ./cmd/accessweaver` | Pass | Standalone Windows/amd64 executable. |
| Local race detector | Unavailable | This host lacks a configured cgo C compiler; invocation reports `-race requires cgo`. Exact-commit Linux CI race check passed. |
| Real HTTP API integration | 11 checks passed | Includes successful reproduction of the two identified gaps; a reproduction passing does not mean the product bug is fixed. |
| Real ByeDPI lifecycle and proxy transfer | Pass | Existing binary, localhost SOCKS5 on port 41080, local TCP echo, generated lists, duplicate-start rejection, active-profile mutation rejection, stop. No global proxy/DNS/route changes. |
| Direct DNS/TCP/TLS to `example.com` | Pass | API and live Chrome UI; certificate verified. Uses existing machine networking. |
| CLI smoke checks | Pass | Version, profile list, show, schema validation and blocked Zapret2 preview. |
| Chrome dashboard smoke | Pass within scope | Create/save profile, guided-to-JSON transfer, exclusion helper, readiness review with disabled start, English/Turkish switch, theme state, diagnostic results. Light colors affected by Dark Reader. |
| GitHub CI for audited commit | All 14 jobs successful | Windows/Linux/macOS tests, Linux race detector and ten cross-builds; inspected actual job conclusions. |
| Release workflow for audited commit | Successful run exists | Packaging evidence; no installer or tunnel certification. Another run was cancelled. |

Exact-commit CI: [run 41239593538](https://github.com/Yunushan/accessweaver/actions/runs/41239593538). Successful release workflow: [run 41239641532](https://github.com/Yunushan/accessweaver/actions/runs/41239641532).

ByeDPI executable used: `C:\Program Files\SplitWire-Turkey\res\byedpi\ciadpi.exe`. Its SHA-256 was pinned in the disposable profile:

```text
eb53ceeeb981cc6735ac24bb1e51e725280b86630e80fdf19ddc4ee4a5b54ef4
```

The file did not supply a product version. Its help output confirmed the adapter's relevant native options. The hash records the tested artifact, not an independent authenticity verification.

Local raw evidence, intentionally excluded from Git:

- `build/parity-audit/go-tests.log`
- `build/parity-audit/coverage`
- `build/parity-audit/runtime-check.cjs`
- `build/parity-audit/runtime-results.json`
- `build/parity-audit/ci-results.json`
- `build/parity-audit/reference/` (pinned upstream source/presets)

## Work needed for parity

1. Correct the diagnostic host validation mismatch; expand real diagnostic tests beyond invalid input.
2. Implement explicit modern WireSock product discovery and native lifecycle, wgcf/config generation, application/browser policy compilation and working interception for applications that do not support SOCKS directly.
3. Add managed prerequisites, service/driver/firewall installation and removal, reboot persistence, dependency/conflict checks, observable verification and restoration of changed OS state.
4. Add DNSCrypt/native DoH configuration and recovery, strategy scanning with scan levels, upstream-versioned preset collections and live exclusion controls.
5. Add Discord/PTB/SplitCord maintenance, remaining languages, update checking and durable operational logs if full product parity remains the goal.
6. Before claiming working parity, run isolated Windows integration tests for install/reboot/uninstall and fault recovery, then measure actual target application traffic, includes/excludes, IPv4/IPv6, text and UDP voice on representative Turkish networks. Repeat native tests for each additional platform separately.

AccessWeaver also offers capabilities outside this baseline: portable JSON profile CRUD/import/export, explicit launch plans and integrity pins, direct staged diagnostics, optional SpoofDPI/sing-box/Xray adapters, and cross-platform core builds. Those are useful additions, but do not supply the missing Windows integration workflows.
