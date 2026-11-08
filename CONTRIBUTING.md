# Contributing

AccessWeaver welcomes focused contributions in English or Turkish. Start with [the architecture](docs/ARCHITECTURE.md), [current platform coverage](docs/PLATFORMS.md), and [roadmap](docs/ROADMAP.md).

## Local development

Use a supported Go release meeting the source minimum in `go.mod` (currently Go 1.26); CI pins Go 1.27.3. The root module pins `golang.org/x/sys` and `github.com/ebitengine/purego` for native OS interfaces, with checksums in `go.sum`. Separate tooling and optional fixture modules have their own pinned dependencies. The embedded application has no npm build; Node.js and browser-test dependencies support development checks. See [third-party notices](THIRD_PARTY.md) and [SBOM scope](docs/SBOM.md).

```bash
go run ./cmd/accessweaver ui
go vet ./...
go test ./... -count=1
go test -race ./...
node --check web/app.js
node --test web/app.test.cjs
```

The race detector needs a supported host and C toolchain. CI runs the full suite on native Linux amd64/arm64 and selected paired-policy storage tests on both Mac architectures. `ACCESSWEAVER_HOME` can point at a disposable development directory; `ACCESSWEAVER_NO_BROWSER=1` suppresses automatic browser opening. Do not develop against profiles containing personal VPN credentials.

## Issue triage

Follow [the support policy](docs/SUPPORT_POLICY.md) for safe evidence, impact classification, escalation and version coverage. Confirm severity and reproduction scope, record ownership when assigned, and close with the fixing source or a verified workaround. Sensitive vulnerabilities follow [SECURITY.md](SECURITY.md).

## Pull requests

- Describe the concrete problem, resulting behavior and validation performed.
- Preserve explicit engine launch, platform checks and rejection of unsupported rules.
- Test security-sensitive behavior: profile validation, command construction, local API boundaries, file handling and process lifecycle.
- Keep UI strings synchronized across English, Turkish, Russian and Spanish. Update both readmes when user-facing behavior changes.
- Keep platform claims tied to evidence. Record compilation, unit tests, real engine invocation and actual routed connectivity separately.
- Do not add credentials, capture logs, engine binaries, drivers or installer payloads to the repository.
- Explain the license and security impact of any new dependency. Prefer standard Go and browser APIs where practical.

For a new engine adapter, provide primary upstream references, exact executable names per OS, supported configuration syntax, version assumptions, domain-list semantics, startup/stop behavior, privilege requirements and failure cases. Include command-generation tests. Preserve a clear distinction between a catalog entry and managed tunnel support.

## Before requesting review

Format Go changes with `gofmt`, run the checks above, and perform the relevant [manual smoke tests](docs/TESTING.md). CI checks run on each pull request. If your change affects one platform, name the OS and architecture actually exercised rather than generalizing to every supported target.

Original contributions are distributed under [0BSD](LICENSE). Preserve applicable notices when incorporating material from elsewhere. Security reports should follow [SECURITY.md](SECURITY.md), not a public issue template.
