# Debian package deployment

Build an AccessWeaver `.deb` for Debian-compatible Linux amd64 or arm64 using Python 3.11 or later and `dpkg-deb` 1.21.9 or later. The package installs the controller in `/usr/bin/accessweaver` and its build identity, SBOM, copyright, notices and documentation in `/usr/share/doc/accessweaver`. It contains no dependency bootstrap, maintainer scripts, service units or machine policy. The output directory must be private to the build operator. Package construction uses root ownership metadata and works without elevated privileges. [dpkg-deb manual](https://manpages.debian.org/trixie/dpkg/dpkg-deb.1.en.html).

## Build from an approved input

Keep the portable release in a private workspace. Authenticate the Linux target with the approved commit and ref using the [portable provenance procedure](RELEASE_PROVENANCE.md#verify-a-downloaded-candidate) and `--target linux/amd64` or `--target linux/arm64`. Take the exact archive digest from the authenticated `SHA256SUMS.txt`. Use your organization's public package contact for the Debian `Maintainer` field. AccessWeaver's product support is best effort and owned by the repository maintainer through GitHub issues. [Support policy](SUPPORT_POLICY.md).

```sh
python3 scripts/build-linux-deb.py ARCHIVE.tar.gz --sha256 VERIFIED_ARCHIVE_SHA256 \
  --arch amd64 --maintainer 'Organization Packaging <packaging@example.org>' \
  --output-directory PRIVATE_OUTPUT_DIRECTORY
```

The builder verifies the SHA-256 of the exact private copy it packages, along with the archived ELF target, SBOM and license evidence. It derives the package version from the clean build identity. Stable versions use `x.y.z`. Preview versions use `-alpha`, `-beta` or `-rc`, with an optional numeric iteration such as `-rc.2` and no build suffix. Debian orders `2.0.0~rc.2` before `2.0.0`. Use a new version for changed deployment bytes. The builder refuses to replace an existing package.

The generated `.deb` is unsigned. Record the final package SHA-256 and the approved source identity in the deployment handoff. For an APT-managed rollout, authenticate your organization’s signed repository metadata and scope the repository key with `Signed-By`. For direct installation, compare the final package against its independently approved digest in administrator-controlled staging before invoking `dpkg`. [APT repository authentication](https://manpages.debian.org/stable/apt/apt-secure.8.en.html).

## Build an organization-signed APT snapshot

The APT builder uses Python 3.11 or later, `dpkg-scanpackages` from `dpkg-dev`, `gpg` and `gpgv`. Put only approved AccessWeaver `.deb` files in a private input directory. Record each package SHA-256 from the approved build handoff and repeat `--package-sha256` for every file, including versions retained for rollback. Use your organization's existing OpenPGP repository signing key or agent-backed signing subkey and an independently provisioned binary public keyring. Confirm the full primary fingerprint through your key administration process. [Debian package indexing](https://manpages.debian.org/trixie/dpkg-dev/dpkg-scanpackages.1.en.html).

```sh
python3 scripts/build-linux-apt-repository.py APPROVED_PACKAGE_DIRECTORY NEW_REPOSITORY_DIRECTORY \
  --suite accessweaver-managed --valid-days 7 \
  --gnupg-home ORGANIZATION_GNUPG_HOME --keyring APPROVED_PUBLIC_KEYRING.gpg \
  --fingerprint APPROVED_PRIMARY_FINGERPRINT \
  --package-sha256 AMD64_PACKAGE_FILENAME APPROVED_AMD64_SHA256 \
  --package-sha256 ARM64_PACKAGE_FILENAME APPROVED_ARM64_SHA256
```

The builder snapshots approved packages, generates architecture-specific indexes, and signs `InRelease`. It verifies both the recovered metadata bytes and the primary fingerprint before it publishes the complete snapshot at a new local destination. It supports one to sixteen package files and metadata validity of one to thirty days. Renew signed metadata before its `Valid-Until` deadline. The output contains no signing material or public trust configuration. [APT repository authentication](https://manpages.debian.org/trixie/apt/apt-secure.8.en.html).

Deploy the independently approved `.gpg` keyring to `/etc/apt/keyrings/accessweaver.gpg`, readable by APT. Configure `/etc/apt/sources.list.d/accessweaver.sources` using the HTTPS URL of your approved repository and the same primary fingerprint. Use the target architecture on your endpoint.

```text
Types: deb
URIs: https://packages.example.org/accessweaver
Suites: accessweaver-managed
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/accessweaver.gpg APPROVED_PRIMARY_FINGERPRINT
```

For a rolling channel, upload and verify new pool and `by-hash` objects before exposing the new `InRelease`. Serve the signed metadata with content-based revalidation so two publications within the same second return the current bytes. Retain prior immutable objects through the validity window of any metadata that references them, plus your rollback retention window. Keep each package filename bound to its original bytes and issue a new version for changes. Use normal APT authentication and expiry checks. [APT sources and by-hash acquisition](https://manpages.debian.org/trixie/apt/sources.list.5.en.html).

Use `sudo apt-get -o APT::Update::Error-Mode=any update` and `sudo apt-get install accessweaver=APPROVED_DEBIAN_VERSION` for managed installation. Compare the selected version and origin with the rollout record. The detection, engine recovery and policy-retention checks below also apply to APT. Your endpoint management tooling owns channel promotion and the rollout schedule.

## Install, detect and roll back

Run these commands on a disposable endpoint first. Stage the correct architecture on the host. The package operations are noninteractive and install no service or network engine.

```sh
sudo dpkg --refuse-downgrade --install /trusted/staging/APPROVED_PACKAGE.deb
dpkg-query -W -f='${Status}\t${Version}\t${Architecture}\n' accessweaver
sudo dpkg --verify accessweaver
/usr/bin/accessweaver version --json
```

For detection, require `install ok installed`, the approved Debian version and architecture, and no output from `dpkg --verify`. Compare the CLI identity with the approved deployment record and `/usr/share/doc/accessweaver/BUILD-INFO.json`. `--refuse-downgrade` can leave an existing newer package in place, so verify the installed version even when the command succeeds.

Upgrades use the same install command with a newer approved package. For an authorized software rollback, verify the previous archive and its compatibility with the current policy and profile formats, then use `dpkg --force-downgrade --install` with the previous approved `.deb`. Verify the installed version and protected policy status afterward. Package rollback leaves the current policy revision and trust records in place. Use the [separate managed policy recovery procedure](MANAGED_CONFIGURATION.md#protected-linux-source-and-update-behavior) when policy recovery is required.

Stop active AccessWeaver controllers and verify recovery of any active engine or network workflow before changing or removing the package. To remove the package, run `sudo dpkg --purge accessweaver` and verify that its executable, documentation and registration are gone. The package leaves `/etc/accessweaver` and users' profiles in place. Manage these separately under the endpoint's retention policy. The package never launches, stops or reconfigures a vendor engine and does not request a reboot.

## Scope of current verification

The [direct package probe](../scripts/test-linux-deb-lifecycle.py) inspects both package architectures and exercises install, upgrade, reinstall, downgrade refusal, explicit rollback and purge on the host's native architecture. It verifies the installed CLI as an ordinary user and checks an independent `dpkg` database. The first installed controller imports an ordinary user's profile and enrolls a signed policy in the private package root. The upgraded controller advances the policy from revision 1 to 2. Reinstall, package rollback and a purge followed by reinstall must preserve the accepted revision, protection and profile. The rolled-back controller must reject a replay of revision 1.

```sh
sudo python3 -B scripts/test-linux-deb-lifecycle.py --arch amd64 \
  --old OLD_AMD64_ARCHIVE --old-sha256 OLD_AMD64_SHA256 \
  --new NEW_AMD64_ARCHIVE --new-sha256 NEW_AMD64_SHA256 \
  --other ARM64_ARCHIVE --other-sha256 ARM64_SHA256
```

On ARM64, pass `--arch arm64`, two ARM64 archives and one AMD64 archive. The probe requires the kernel and `dpkg` architectures to match the selected endpoint. Run it on qualified persistent storage under `/var/tmp` with OpenSSL and `chroot` available. The [Ubuntu 26.04 WSL AMD64 evidence](qualification/16632c4b2a7f-linux-deb-lifecycle.json) records the earlier package-assembly and AMD64 endpoint results.

The [signed APT probe](../scripts/test-linux-apt-repository.py) uses disposable Ed25519 keys, a loopback HTTP repository and private APT and dpkg state. It requires two approved versions for each architecture and a SHA-256 pin for each `.deb`. It checks by-hash retrieval, ordinary-user execution, installation, upgrade, purge and reinstall. Both probes read the same real imported profile through the installed controller and require it to refuse unapproved profile writes and engine starts. The fixture uses an inert engine file and temporary policy keys. APT must refuse the wrong scoped key, expired metadata, and altered signatures, indexes or package bytes. [Ubuntu WSL APT evidence](qualification/4caa86d5b6d0-linux-apt-repository.json).

The [native lifecycle workflow](../.github/workflows/linux-package-lifecycle.yml) runs the two probes on separate GitHub-hosted Ubuntu 24.04 AMD64 and ARM64 jobs. It builds two fixture versions from the exact source under test. It verifies that both probes consumed the same package bytes and installed the same native binaries. Each successful job uploads a source-bound digest summary and the two probe reports. Check both results for the candidate commit. [GitHub-hosted runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

On a disposable supported Linux host with the repository's Go toolchain, Python 3.11 or later, Debian package tools, GnuPG, OpenSSL and administrator access for the isolated probes, run the same entry point from the clean candidate checkout.

```sh
bash scripts/test-linux-package-candidate.sh amd64 "$(git rev-parse HEAD)" /var/tmp/accessweaver-package-report
```

The [exact-source AMD64 rehearsal](qualification/227b43d8500e-linux-package-candidate.json) ran this entry point on Ubuntu 26.04 WSL. Both package routes installed the same executable bytes for the two fixture versions and preserved synthetic policy and profile files. The architecture check refused an ARM64 report on that AMD64 host. The [packaged managed-state evidence](qualification/16632c4b2a7f-linux-packaged-managed-policy.json) verifies both package routes on Ubuntu 26.04 WSL AMD64 with two versions built from distinct source commits.

Production rollout still requires results for the approved release packages and native endpoint architectures. It also requires organization signing and hosting, reboot and active-engine checks, and validation through the organization's endpoint-management tools.
