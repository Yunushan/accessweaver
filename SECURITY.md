# Security policy

AccessWeaver `0.1.0-alpha` is experimental. It is not an audited VPN, anonymity system, firewall or kill switch. The security boundary includes every external executable, configuration file and script that you choose to run.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/Yunushan/accessweaver/security/advisories/new) when enabled for the repository. If it is unavailable, open a minimal issue asking the maintainer for a private contact channel; do not publish exploit details, secrets or private logs. No response-time commitment or dedicated security team is currently advertised.

Please include the affected commit/version, OS/architecture, impact, and minimal reproduction. Distinguish an AccessWeaver flaw from behavior of a third-party engine. Only the current alpha is actively developed; there is no long-term-support release line.

## Implemented controls

- The UI/API binds to `127.0.0.1` on an ephemeral port. API requests enforce allowed hosts and browser origins, and state-changing requests require a random per-process token.
- Browser assets are local, with a restrictive content security policy and no third-party JavaScript or analytics.
- Profiles use versioned JSON, strict unknown-field rejection, request/file size limits and validated filenames. Saved files are atomically replaced with private modes where supported.
- Engine invocation uses argument arrays. Platform-specific executable basenames and optional SHA-256 pins are checked before launch.
- Preview explains the command and local readiness issues. Unsupported managed routing and known service/daemon options are rejected.
- Managed ByeDPI binds to loopback. WireSock command hooks are rejected, and supported external configuration paths must reference local regular files.
- Engine output is held in a bounded in-memory buffer rather than automatically persisted.

These controls reduce particular attack paths; they are not a complete security review or sandbox.

## Known limits

External engines inherit the controller's permissions. Running the controller elevated expands the impact of engine arguments, Lua scripts and configuration. AccessWeaver does not authenticate an executable's publisher; a matching basename proves nothing, and a hash is only as trustworthy as its source. File/configuration checks do not remove every time-of-check/time-of-use risk.

The loopback token protects against browser-origin attacks, not other local processes with the user's permissions. Profiles and browser storage are not encrypted. Use a private configuration directory; do not expose the control port, tunnel it to remote users, or treat it as a multi-user API. Multiple controller instances are not coordinated through a machine-wide lock.

The manager owns a foreground child, not arbitrary services or system state. Windows currently uses process termination; it does not guarantee graceful vendor cleanup or descendant termination. A stopped process may leave externally configured routes, proxies, drivers or network lock in effect. System rollback, signed installers, signed updates, native mobile VPN isolation and service-level privilege separation are not implemented.

A successful direct diagnostic does not prove proxy use, DNS privacy, tunnel enforcement, UDP/QUIC coverage or anonymity. Imported profiles, referenced files and Lua scripts need review before use. Config files may contain secrets and powerful options even when the profile JSON does not.

AccessWeaver itself has no telemetry. Third-party engines may have their own network behavior, telemetry and licensing policies; see [THIRD_PARTY.md](THIRD_PARTY.md).
