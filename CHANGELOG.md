# Changelog

## Unreleased

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
