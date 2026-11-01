# Security policy

AccessWeaver `0.1.0-alpha` is experimental. It is not an audited VPN, anonymity system, firewall or kill switch. The security boundary includes every external executable, configuration file and script that you choose to run.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/Yunushan/accessweaver/security/advisories/new) when enabled for the repository. If it is unavailable, open a minimal issue asking the maintainer for a private contact channel; do not publish exploit details, secrets or private logs. No response-time commitment or dedicated security team is currently advertised.

Please include the affected commit/version, OS/architecture, impact, and minimal reproduction. Distinguish an AccessWeaver flaw from behavior of a third-party engine. Only the current alpha is actively developed; there is no long-term-support release line.

## Implemented controls

- The UI/API binds to `127.0.0.1` on an ephemeral port. Every API request requires a random per-process token, including bootstrap and read requests. Allowed-host and browser-origin checks apply separately.
- The dashboard refuses elevated/root execution. An OS-private launch file delivers its credential through a URL fragment; the browser removes the fragment and retains the credential in session storage. Bootstrap does not disclose it. Ordinary local processes running as the same user remain trusted.
- Windows machine storage rejects unexpected owners, access controls and reparse points before reuse. Service-host reuse also verifies its digest against the running controller.
- Browser assets are local, with a restrictive content security policy and no third-party JavaScript or analytics.
- Profiles use versioned JSON, strict unknown-field rejection, request/file size limits and validated filenames. Saved files are atomically replaced with private modes where supported.
- Engine invocation uses argument arrays. Platform-specific executable basenames and optional SHA-256 pins are checked before launch.
- Preview explains the command and local readiness issues. Unsupported managed routing and known service/daemon options are rejected.
- Managed ByeDPI binds to loopback. WireSock command hooks are rejected, and supported external configuration paths must reference local regular files.
- Engine output is held in a bounded in-memory buffer rather than automatically persisted.

These controls reduce particular attack paths; they are not a sandbox. A source review completed on 2026-11-01 identified three local privilege-boundary findings. Session and machine-storage remediation has regression evidence, but complete remediation and native qualification remain unfinished.

## Known limits

Foreground engines inherit the controller's permissions. Running the controller elevated expands the impact of engine arguments, Lua scripts and configuration. Foreground executable checks do not authenticate a publisher; a matching basename proves nothing, and a hash is only as trustworthy as its source. Windows workflow downloads use allowlisted sources with digest or Authenticode checks, but this is not a complete supply-chain audit. File/configuration checks do not remove every time-of-check/time-of-use risk.

The loopback token protects against browser-origin attacks and unauthenticated access from other local accounts; it does not isolate processes with the dashboard user's permissions. Profiles and browser storage are not encrypted. Use a private configuration directory; do not expose the control port, tunnel it to remote users, or treat it as a multi-user API. Foreground controllers/profile writes are not coordinated across instances. Windows system workflows use a separate machine-wide mutex, which does not provide multi-user authorization or fleet policy.

The Windows administrative handoff is incomplete: the ordinary dashboard cannot yet apply operations that require elevation. Separately elevated CLI workflows still execute per-user application installers/uninstallers with the controller's permissions. The per-user uninstaller finding remains unresolved; application maintenance must not be treated as production-qualified.

The foreground manager owns a child, not arbitrary services or system state. Windows foreground stop uses process termination and does not guarantee vendor cleanup or descendant termination. Windows maintenance workflows separately manage owned services/tasks/firewall rules, preserve DNS/file state in protected journals, and refuse conflicting file recovery. Abrupt termination and external vendor installers can bypass or exceed that recovery. Service hosts and maintenance jobs have bounded process logs; complete history retention is not yet enforced. A stopped process may leave independently configured routes, proxies, drivers or network lock in effect. Signed distribution/updates, native mobile VPN isolation and service-level privilege separation are not implemented.

A successful direct diagnostic does not prove proxy use, DNS privacy, tunnel enforcement, UDP/QUIC coverage or anonymity. Imported profiles, referenced files and Lua scripts need review before use. Config files may contain secrets and powerful options even when the profile JSON does not.

AccessWeaver itself has no telemetry. Third-party engines may have their own network behavior, telemetry and licensing policies; see [THIRD_PARTY.md](THIRD_PARTY.md).
