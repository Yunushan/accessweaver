# Windows installation and repair

The **Installation & repair** dashboard and `system` CLI manage Windows components separately from foreground profiles. They require Windows PowerShell 5.1. The dashboard must run as the normal desktop user. Its administrative handoff is unfinished, so applying machine changes currently requires a separately elevated `system apply` CLI invocation. Application install, removal and start must run unelevated in the intended desktop account. Inspection and preview work without elevation. See the verification limits in [SECURITY.md](../SECURITY.md) before deployment.

These workflows are experimental. See [implementation and verification status](SPLITWIRE_IMPLEMENTATION.md) before deployment. Native results apply to the recorded Windows build and component versions, not every network or vendor release.

## Review and run

Select an operation and component, then review the generated plan. Machine plans identify their administrator requirement and remain unavailable to apply from the unelevated dashboard. **Export reviewed request** downloads only the reviewed JSON request, without a session token, plan ID or approval. Keep the file private: native arguments and paths may be sensitive. Review it again with `system preview` and explicitly apply it in a separately elevated CLI. Eligible user operations can be confirmed and applied in the dashboard. Changing an input invalidates the plan. Plans expire after ten minutes and can be consumed once. Only one operation runs per controller. Machine operations also use an administrator-only mutex across instances; user application operations do not share that machine mutex.

The CLI accepts the same JSON request:

```powershell
accessweaver.exe system operations
accessweaver.exe system discover
accessweaver.exe system presets
accessweaver.exe system preview request.json
accessweaver.exe system apply request.json --confirm
accessweaver.exe system history
```

`system history` and the final `system apply`/`system discover` snapshot use compact JSON with a trailing newline. Their fields, complete result values and full retained legacy errors are preserved; metadata strings stream in bounded chunks. Redirect exports to a private file; they can contain configuration, paths and tool output. An output-write failure returns an error and can leave an incomplete destination file. Dashboard report reads preserve complete result values with compact streaming JSON. A busy status reader receives HTTP 503; the dashboard retries that read without repeating the reviewed operation. Cancellation and history use separate admission, and interrupted report transfers are aborted rather than completed as partial downloads.

Pressing Ctrl+C during `system apply` requests cancellation and waits up to eight seconds for shutdown and outcome recording before returning a nonzero exit status. The CLI prints the actual final job snapshot. If shutdown times out, it reports that cancellation did not finish and preserves the actual running state rather than inventing a terminal result. Inspect the recovery journal before retrying. A vendor cleanup or rollback is not certified by the controller merely exiting.

For example, install an automatic ByeDPI proxy service without app interception:

```json
{"action":"install","engine":"byedpi","mode":"service","dns":"unchanged"}
```

ByeDPI listens on `127.0.0.1:1080`. Applications must use this proxy, or select `split` mode to install ProxiFyre and its Windows Packet Filter prerequisite. `dll` mode deploys drover to an installed stable Discord. `once` runs until cancellation. Optional `applications` and `browsers` compile the interception selection; default selections include Discord and Roblox.

An optional `bundlePath` supplies a local official Windows component bundle. Otherwise supported components download from allowlisted upstream releases. Unsigned assets require a SHA-256 digest; signed vendor installers also require successful Authenticode verification. Downloads and dependencies remain governed by their own licenses. A hash identifies an artifact; it does not establish its trustworthiness.

## WireSock

`install` with `engine: "wiresock"` supports `alternative` (WireSock only), `standard` (WireSock plus ByeDPI/drover) and `custom` (selected apps). `config` generates only a private configuration. `connect`, `disconnect`, `refresh` and `remove` manage its lifecycle. Modern Secure Connect uses its vendor CLI; the legacy SDK client retains its different service commands.

Supply `configPath` to avoid registering an account. A new wgcf/WARP account requires explicitly setting `acceptCloudflareTerms: true` after reviewing [Cloudflare's terms](https://www.cloudflare.com/application/terms/). AccessWeaver does not reuse another application's wgcf account or private keys. Command hooks in supplied tunnel configurations are rejected. Application rules replace existing `AllowedApps`/`DisallowedApps` in a private copy; the original file is preserved.

Managed imports use unique `AccessWeaver-...` vendor profile names. Remove a managed WireSock method before replacing it. An independently installed legacy SDK service blocks managed setup to avoid replacing its configuration. Vendor products are retained when removing AccessWeaver's method.

An explicit `vendor-uninstall` operation with `engine: "wiresock"` also invokes the registered Secure Connect/legacy vendor uninstaller after removing the managed profile. Review its plan: vendor removal can affect independently created vendor profiles. `remove-all` does not invoke this operation.

Configuration paths, application names/folders, `browsers`, `profileId` and `refresh` are optional inputs. `refresh` installs a five-minute reconnect task. A completed connect command or running service does not prove a tunnel handshake or working application traffic.

## Packet engines and hostlists

Zapret, Zapret2 and GoodbyeDPI support `install` with `mode: "service"` or `"once"`. Choose an included preset or supply `args` as a JSON string array. Every argument is passed literally, without a shell. Zapret2 needs matching Lua assets. System installation owns its hostlist arguments; use the foreground profile runner for independently managed native list options.

Use `hostlist` with `domains` and `enabled` to save or toggle the list. Zapret/Zapret2 lists are exclusions; GoodbyeDPI lists are inclusions. Disabling preserves the saved list. GoodbyeDPI restarts to update its blacklist argument. Zapret reload behavior depends on the upstream version. A service/list test does not establish filtering effectiveness.

`scan` and `auto-install` run upstream blockcheck with `scan: "quick"`, `"standard"` or `"full"`. Provide its Windows bundle, including Cygwin, through `bundlePath`. `targets` are the hosts to test; `domains` are unrelated hostlist entries. Zapret2 tries the included ISP strategies before its broader scan. Full mode maps to upstream's force scan.

Auto-install selects only a completed reported common strategy, preferring HTTPS. It refuses incomplete output, shell commands and incompatible native strategies. Reports are retained. A scan for HTTPS is not a UDP voice or ISP reliability test.

## DNS and application maintenance

`dns` selects `doh` (native Windows DoH with Google/Quad9 and no UDP fallback) or `dnscrypt`. Installation optionally applies the selected DNS method first. `dns-restore` restores the saved original per-adapter IPv4/IPv6 DHCP/static state and native DoH metadata. Keep the snapshot until restoration completes. DNSCrypt can bootstrap its upstream resolver list using its own configured bootstrap resolvers.

`app-install`, `app-start` and `app-remove` support `discord`, `discord-ptb` and `splitcord`. PTB's `clean` option first removes stable Discord. These operations reject administrator/SYSTEM tokens and session zero before discovering or executing user applications. They use a per-job `application/` staging directory and journal under the ordinary workflow directory, avoiding protected machine storage. Configure DNS with a separate reviewed machine operation. Do not run multiple controllers against the same application at once. Removal can sign you out; existing account sessions are not test fixtures.

`app-repair` is currently blocked in both preview and execution. Its combined user uninstallation/reinstallation and privileged proxy/DLL steps require a privilege-separated broker. To reinstall an application, review separate unelevated remove/install operations. Manage the proxy and DLL setup separately through elevated machine operations. The protected-journal `recover` command handles machine journals only; a user application journal records outcomes and does not guarantee reversal of vendor installer changes.

`updates` checks AccessWeaver's official GitHub release metadata. It does not install an update.

## Ownership, cancellation and recovery

Components, private profiles, service configuration, backups and persistent logs live under `%ProgramData%\AccessWeaver`, with administrator/SYSTEM access. Foreground profiles and workflow history use the ordinary AccessWeaver data directory. New history records retain compact result JSON (up to 32 MiB); the summary error is capped at 16 KiB with a visible truncation notice. Inspect the full result, when available, and private process log for details. History listing has a combined 64 MiB read limit; old records and recovery evidence are not automatically deleted or repaired. Keep private configurations and logs out of public issue reports. The dashboard shortens large/deep result previews and marks them visibly. Use **Export latest status** for the current controller report or **Export full history** for complete retained JSON. These private exports can contain sensitive configuration or tool output and are separate from the metadata-only support summary. Downloads do not delete or modify history.

`remove` removes a selected managed method; `remove-all` removes owned methods in dependency order and restores DNS/drover files. Independent services, vendor installations and private recovery evidence are retained. Explicit WinDivert removal verifies that the driver's path belongs to the managed component store; shared external drivers are refused.

The Windows installer registers a normal uninstaller. It restores owned system changes before deleting the application and aborts deletion when restoration fails. Portable users can run `uninstall`, stop the core, then remove the portable directory. Protected recovery data is retained for review.

Cancelling kills the job's process tree. Sudden termination can bypass PowerShell cleanup, so inspect the journal before retrying. The recovery action accepts only a protected journal filename:

```json
{"action":"recover","journalId":"workflow-0123456789abcdef0123456789abcdef.json"}
```

Recovery validates resource ownership and expected file hashes. It refuses to overwrite files changed independently since installation. DNS changes and imported managed WireSock profiles have explicit recovery entries. Vendor installers can make changes outside the journal; restore the disposable VM checkpoint when validating them.

## Building and testing

The unsigned installer is built with an explicitly supplied Inno Setup compiler and a Windows Go SDK matching the intended core payload:

```powershell
./scripts/build-windows-installer.ps1 -Compiler 'C:\Tools\Inno Setup\ISCC.exe' -Version 0.1.0 -TargetArch amd64
# On an ARM64 Windows build host with its ARM64 Go SDK:
./scripts/build-windows-installer.ps1 -Compiler 'C:\Tools\Inno Setup\ISCC.exe' -Version 0.1.0 -TargetArch arm64
```

`-TargetArch` defaults to the Go SDK host architecture and rejects cross-host builds because the staged core must execute its `version --json` check. The build checks its PE machine before execution, then compares version, source commit/state, build time, compiler, platform and architecture. Outputs are named `accessweaver-VERSION-windows-amd64-setup.exe` or `accessweaver-VERSION-windows-arm64-setup.exe`. The corresponding [Inno architecture requirement](https://jrsoftware.org/is6help/topic_setup_architecturesallowed.htm) is `x64compatible` or `arm64`, with 64-bit install mode for each. Inno Setup 6 retains its x86 bootstrap; an ARM64 payload does not imply a native ARM64 setup runtime, vendor drivers, signing or installation qualification. The existing application ID is shared; cross-architecture upgrades still require disposable-VM testing.

`scripts/test-windows-workflow.ps1` runs filesystem/pure-function contracts and mocked DNS cmdlets without changing host services or networking. `scripts/test-windows-integration.ps1` deliberately changes a disposable guest; it checks for a virtual machine and an administrator token. It requires a test-only binary/component bundle and writable results directory. Run it only in an explicitly disposable guest, never a production VM.

`scripts/build-windows-fixtures.ps1` builds the optional WireGuard userspace peer and selected/unselected traffic probes from separately pinned modules. The core remains standard-library-only. The fixture generates temporary private keys inside the guest and does not register a WARP account. `scripts/test-windows-wiresock.ps1 -DisposableVM` uses it to check actual handshake, TCP/UDP, IPv4/IPv6, application selection, refresh and disconnect. Build the fixtures before running this suite.

For the dedicated VMware guest, finish Windows setup and install VMware Tools, then take a Windows-ready snapshot. Share the test bundle read-only as `AccessWeaver-Test`, and only its results directory writable as `AccessWeaver-Results`. The host sets the exact VM identity in the `accessweaverParity` guest variable. Inside that guest, double-click `Start-Parity-Tests.cmd` in the test share and accept UAC. The elevated controller accepts fixed machine-test stages (`system`, `wiresock`, `reboot-prepare`, `exit`) from `control.json`; it does not accept shell commands or passwords. An `apps` request is rejected with instructions to run `test-windows-apps.ps1 -DisposableVM` separately in an unelevated PowerShell window. That script records results under `%LOCALAPPDATA%\AccessWeaver-App-Test-Results` (or its `-ResultsDirectory` argument) and fails the run if any check fails. Collect those results separately. Administrative drover lifecycle checks require a separate elevated test stage. A completed machine stage means its script finished; inspect per-check JSON results for pass/fail. Reboot verification runs once at startup and publishes its result separately.

See [implementation status](SPLITWIRE_IMPLEMENTATION.md) for recorded results and remaining gaps. Full parity is not yet certified.

Managed ByeDPI system installation owns its listener, port and process mode. Native strategy arguments must use full option names; protected-option abbreviations, short clusters, option terminators and argument files are rejected before a plan is retained or a direct installer changes DNS/components. One-shot child tools allow a day-long timeout, while the workflow manager still caps a job at 90 minutes and cancellation remains available.

## Administrator machine policy

A protected signed Windows policy can restrict workflow requests and remote component retrieval, independently of the caller's user data root. Requests must match their signed input approval; downloads also require permission and pinned artifact hashes. The actual worker rechecks authority and receives permissions with its retained in-memory request. System utilities, shared storage and PowerShell modules use trusted OS/machine settings rather than inherited path/module variables. Current policy support is partial: managed native-argument assets and service-host authorization are blocked, and enrollment/recovery/revocation still need implementation and disposable-endpoint qualification. [Managed configuration](MANAGED_CONFIGURATION.md) documents the format, source protection and deployment limits. Existing running jobs are not automatically revoked.
