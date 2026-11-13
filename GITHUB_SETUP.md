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

The workflow uses a read-only default token and pins third-party actions to full commit hashes. Keep these pins current through reviewed dependency updates. The root `go.mod` and `go.sum` pin the native OS interface dependencies; separate tooling/fixture modules retain their own manifests and sums. Current setup-go steps disable its dependency cache explicitly. Verify the actual manifests and [SBOM scope](docs/SBOM.md) when changing dependencies.

## Preview artifacts and build provenance

Run **Release artifacts** from Actions, or run locally:

```bash
bash scripts/package-release.sh preview
```

This requires Go, Bash and Python 3. It creates `dist/preview/` with ten target archives, `BUILD-MANIFEST.json` and `SHA256SUMS.txt`. Windows uses ZIP; other systems use gzip-compressed tar so executable modes survive extraction. The archives include the core executable, readme files, documentation, license notices and a binary-bound CycloneDX 1.6 `SBOM.cdx.json`. Packaging validates its schema and the archive verifier checks its identity and notice hashes. [SBOM scope and limits](docs/SBOM.md) includes the separate fixture/installer inventories. They do not include engines, credentials, drivers or an installer.

The manifest records the compiler, source commit when available, target architectures, hashes and explicit unsigned/untested flags. Builds use `CGO_ENABLED=0`. Portable packaging uses a fixed source epoch and normalized archive metadata; the workflow compares two complete package runs before upload. Use a fresh checkout and identical source/toolchain inputs for comparisons (see [rebuild checks](docs/TESTING.md#repeated-portable-builds)). Independent trusted rebuild qualification and signed releases remain outstanding. The packaging script does not run a real engine.

Hosted packaging additionally signs build provenance for the ten archives, manifest and checksum file, retains `BUILD-PROVENANCE.sigstore.json`, verifies all twelve subjects and exercises rejection cases before uploading. This makes thirteen distribution files. Local packaging produces the original twelve files and cannot impersonate a hosted workflow identity. [Provenance verification](docs/RELEASE_PROVENANCE.md) requires an independently approved commit/ref and trusted GitHub CLI. OS binaries remain unsigned; publisher signing/notarization is still outstanding.

## Publishing a prerelease

1. Review CI results for the exact commit and the manual evidence in [docs/TESTING.md](docs/TESTING.md).
2. Update the changelog and the application's version constants together.
3. Create and push the intended version tag, for example `v0.1.0-alpha`.
4. The release workflow reruns checks and verifies the portable build. It creates a draft, uploads the missing assets and verifies all 13 GitHub-reported SHA-256 digests before publishing the prerelease. If upload is interrupted, rerun the publish job with the original workflow artifacts. A fresh build may have a different attestation bundle and will fail the digest check. An existing published prerelease is checked for an exact match. A mismatch leaves the existing assets in place and fails the run. Manual workflow runs upload Actions artifacts only.
5. Inspect the release and verify the signed provenance against the independently approved commit/ref before extracting or running artifacts. The publisher job repeats this check after artifact download. State the tested OS/engine versions in release notes. OS binaries remain unsigned until publisher signing/notarization is implemented.

Do not present a checksum as a digital signature, a cross-build as a device test, or a successful process launch as working interception. Never attach third-party binaries without separately satisfying their licensing and provenance requirements.

## Repository settings

Maintainers should enable private vulnerability reporting and branch protections appropriate to the project. Require passing CI for changes to the primary branch. Security settings, branch protections and publisher code signing require account/repository ownership and are not automatically enabled by these source files. Hosted release provenance uses scoped OIDC/attestation permissions and depends on GitHub plan/service availability; a failed attestation blocks distribution rather than silently dropping verification.
