# Repository and release maintenance

The project repository is [Yunushan/accessweaver](https://github.com/Yunushan/accessweaver). The primary branch is `main`. The source version is `0.1.0-alpha`; packaging labels do not modify the application's version string.

## First contribution

```bash
git clone https://github.com/Yunushan/accessweaver.git
cd accessweaver
git switch -c my-change
bash scripts/setup.sh
```

On Windows, use `./scripts/setup.ps1`. Run the checks in [CONTRIBUTING.md](CONTRIBUTING.md) before pushing. GitHub authentication and repository access are required for publication, but not for local development.

## CI

[CI](.github/workflows/ci.yml) runs static analysis and unit tests on hosted Linux, Windows and macOS runners. A separate Linux job runs the race detector. Cross-builds cover amd64/arm64 for Linux, Windows, macOS, FreeBSD and OpenBSD. Hosted Linux/macOS/Windows unit tests do not certify external engine integration; BSD cross-builds do not execute BSD binaries.

The workflow uses a read-only default token and pins third-party actions to full commit hashes. Keep these pins current through reviewed dependency updates. There are no project dependencies to cache with `go.sum` in this standard-library-only application.

## Unsigned preview artifacts

Run **Release artifacts** from Actions, or run locally:

```bash
bash scripts/package-release.sh preview
```

This requires Go, Bash and Python 3. It creates `dist/preview/` with ten target archives, `BUILD-MANIFEST.json` and `SHA256SUMS.txt`. Windows uses ZIP; other systems use gzip-compressed tar so executable modes survive extraction. The archives include the core executable, readme files, documentation and license notices. They do not include engines, credentials, drivers or an installer.

The manifest records the compiler, source commit when available, target architectures, hashes and explicit unsigned/untested flags. Builds use `CGO_ENABLED=0`. Portable packaging uses a fixed source epoch and normalized archive metadata; the workflow compares two complete package runs before upload. Use a fresh checkout and identical source/toolchain inputs for comparisons (see [rebuild checks](docs/TESTING.md#repeated-portable-builds)). Independent trusted rebuild qualification and signed releases remain outstanding. The packaging script does not run a real engine.

## Publishing a prerelease

1. Review CI results for the exact commit and the manual evidence in [docs/TESTING.md](docs/TESTING.md).
2. Update the changelog and the application's version constants together.
3. Create and push the intended version tag, for example `v0.1.0-alpha`.
4. The release workflow reruns checks, packages artifacts and publishes a GitHub **prerelease** for a `v*` tag. Publishing a release in the GitHub UI also triggers packaging and attaches assets to that existing release. Manual workflow runs upload artifacts only.
5. Inspect the release, check downloaded checksums and state the tested OS/engine versions in release notes. All packages remain unsigned unless a separate signing process is actually implemented.

Do not present a checksum as a digital signature, a cross-build as a device test, or a successful process launch as working interception. Never attach third-party binaries without separately satisfying their licensing and provenance requirements.

## Repository settings

Maintainers should enable private vulnerability reporting and branch protections appropriate to the project. Require passing CI for changes to the primary branch. Security settings, branch protections, code signing and release attestations are account/repository settings and are not automatically enabled by these source files.
