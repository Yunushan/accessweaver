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

The [isolated lifecycle probe](../scripts/test-linux-deb-lifecycle.py) verifies package contents on both architectures and exercises native Linux AMD64 installation, upgrade, reinstall, downgrade refusal, intentional rollback and purge. It checks an independent `dpkg` database and ordinary-user execution. It tracks synthetic protected policy and profile files across every transition. Use a disposable AMD64 machine and two approved AMD64 archives with increasing versions, plus an ARM64 archive and all three verified digests.

```sh
sudo python3 -B scripts/test-linux-deb-lifecycle.py \
  --old OLD_AMD64_ARCHIVE --old-sha256 OLD_AMD64_SHA256 \
  --new NEW_AMD64_ARCHIVE --new-sha256 NEW_AMD64_SHA256 \
  --arm64 ARM64_ARCHIVE --arm64-sha256 ARM64_SHA256
```

The source-bound [Ubuntu 26.04 WSL AMD64 evidence](qualification/16632c4b2a7f-linux-deb-lifecycle.json) records the exact archive, package, executable, builder and probe digests. The probe verified both assembly targets and ran dpkg and the installed CLI on AMD64.

Managed rollout still requires a signed repository or approved distribution mechanism, native ARM64 lifecycle testing, reboot and active-engine checks, and deployment through the organization's endpoint-management tools.
