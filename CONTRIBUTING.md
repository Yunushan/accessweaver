# Contributing

AccessWeaver welcomes focused contributions in English or Turkish. Start with [the architecture](docs/ARCHITECTURE.md), [current platform coverage](docs/PLATFORMS.md), and [roadmap](docs/ROADMAP.md).

## Local development

Use a current supported Go release (source minimum: Go 1.23). Node.js is used only for browser JavaScript checks and tests. The application has no npm build or third-party Go module dependencies.

```bash
go run ./cmd/accessweaver ui
go vet ./...
go test ./... -count=1
go test -race ./...
node --check web/app.js
node --test web/app.test.cjs
```

The race detector needs a supported host and C toolchain. It runs in the Linux CI job. `ACCESSWEAVER_HOME` can point at a disposable development directory; `ACCESSWEAVER_NO_BROWSER=1` suppresses automatic browser opening. Do not develop against profiles containing personal VPN credentials.

## Pull requests

- Describe the concrete problem, resulting behavior and validation performed.
- Preserve explicit engine launch, platform checks and rejection of unsupported rules.
- Test security-sensitive behavior: profile validation, command construction, local API boundaries, file handling and process lifecycle.
- Keep UI strings in both English and Turkish. Update both readmes when user-facing behavior changes.
- Keep platform claims tied to evidence. Record compilation, unit tests, real engine invocation and actual routed connectivity separately.
- Do not add credentials, capture logs, engine binaries, drivers or installer payloads to the repository.
- Explain the license and security impact of any new dependency. Prefer standard Go and browser APIs where practical.

For a new engine adapter, provide primary upstream references, exact executable names per OS, supported configuration syntax, version assumptions, domain-list semantics, startup/stop behavior, privilege requirements and failure cases. Include command-generation tests. Preserve a clear distinction between a catalog entry and managed tunnel support.

## Before requesting review

Format Go changes with `gofmt`, run the checks above, and perform the relevant [manual smoke tests](docs/TESTING.md). CI checks run on each pull request. If your change affects one platform, name the OS and architecture actually exercised rather than generalizing to every supported target.

Original contributions are distributed under [0BSD](LICENSE). Preserve applicable notices when incorporating material from elsewhere. Security reports should follow [SECURITY.md](SECURITY.md), not a public issue template.
