# Portable build provenance

The hosted release workflow builds the ten portable core archives twice, compares the complete checksums, and generates one signed GitHub/Sigstore build-provenance bundle covering twelve subjects: ten archives, `BUILD-MANIFEST.json` and `SHA256SUMS.txt`. The retained `BUILD-PROVENANCE.sigstore.json` is the thirteenth distribution file. It cannot checksum or attest itself; its certificate/signature and transparency evidence are verified through the trusted Sigstore roots used by GitHub CLI.

The action is `actions/attest` v4.2.2 pinned to commit `1e69f48acb82d1966a394da916b4c1698aa569d6`. Only the packaging job has `id-token: write` and `attestations: write`; ordinary test jobs retain read-only permissions. There is no long-lived signing key, custom predicate, registry upload or unsigned fallback. A signing or verification error prevents release artifact upload/publication. [GitHub's attestation documentation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) describes the identity/certificate mechanism and repository-plan requirements.

## Verify a downloaded candidate

Use a trusted, supported GitHub CLI that implements all flags used by `scripts/verify_release_provenance.py`, together with Python 3 and the verifier from the reviewed candidate source commit. Later verifiers may require newer inventory/content contracts and reject older alpha archives; use the approved candidate version rather than removing checks. Missing tools, unsupported flags, unavailable trust services or verification failures stop acceptance; do not remove constraints to make verification pass. The archive download must be in a private directory containing only the thirteen release files. Do not extract or run a downloaded executable first.

Obtain the expected full source commit and complete ref from your independently approved release record. Do not copy these trust choices from an unverified manifest or bundle. For an approved release tag, run:

```text
python scripts/verify_release_provenance.py DOWNLOADED_DIRECTORY --source-commit FULL_TRUSTED_COMMIT --source-ref refs/tags/APPROVED_VERSION_TAG
```

A manual preview uses its independently recorded commit and `refs/heads/main`. The verifier pins all of the following:

- repository `Yunushan/accessweaver` and host `github.com`;
- signer workflow `Yunushan/accessweaver/.github/workflows/release.yml`;
- both source and signer-workflow digests to the approved commit;
- the exact approved source ref;
- OIDC issuer `https://token.actions.githubusercontent.com`;
- SLSA provenance v1 predicate and GitHub-hosted runners;
- each artifact's actual digest, through the signed bundle.

The manifest is authenticated before it chooses which archive names to inspect. Exactly the ten documented targets must appear, and the source state must be clean. After authenticating every subject, the verifier runs the existing archive/checksum/content/embedded-identity checks with binary execution disabled. It never treats checksums alone, an action summary or an attestation-shaped JSON file as signature verification. The compatibility `verify-release.py` integrity command remains available, but does not authenticate provenance by itself.

For one subject, the underlying [GitHub CLI verification command](https://cli.github.com/manual/gh_attestation_verify) is:

```text
gh attestation verify ARTIFACT --bundle BUILD-PROVENANCE.sigstore.json --hostname github.com --repo Yunushan/accessweaver --signer-workflow Yunushan/accessweaver/.github/workflows/release.yml --source-digest FULL_TRUSTED_COMMIT --signer-digest FULL_TRUSTED_COMMIT --source-ref FULL_TRUSTED_REF --cert-oidc-issuer https://token.actions.githubusercontent.com --predicate-type https://slsa.dev/provenance/v1 --deny-self-hosted-runners --format json
```

A retained bundle supports verification without downloading the attestation again, but trust-root material may still need network access/cache. Fully air-gapped trust-root provisioning/refresh remains work. GitHub documents that bundle-only name checks cannot detect later repository/owner renames or name reuse. Independently pinned commits/refs and organizational repository/ownership controls remain necessary.

## Workflow and acceptance evidence

Manual **Release artifacts** runs create preview artifacts and attestations without creating a GitHub release. Tag/release publication additionally downloads the packaged artifact and repeats provenance/content verification before uploading its thirteen files. Product archives/checksums remain reproducible; timestamped provenance certificates/bundles are produced after the repeated-build comparison and are not claimed byte-reproducible.

`test_release_provenance.py` checks command constraints, authenticate-before-parse ordering, all-subject coverage and failure/no-fallback behavior. Those mocked calls do not prove cryptographic verification. The packaging job also runs `check_provenance_rejections.py` against its real signed bundle: changed subject bytes and wrong source digest/ref/workflow/repository must return failure, while the correct manifest verifies before and after those probes. Public results are retained in the `release-provenance-check` artifact; source-bound run results determine whether this procedure actually passed.

## Execute the authenticated portable candidate

After packaging, `packaged-native` runs on native amd64 and arm64 Windows, Linux and macOS hosts. It downloads the same thirteen-file artifact set that publication consumes. `stage_packaged_native.py` copies bounded inputs into a private snapshot, authenticates all twelve subjects against the independently supplied workflow commit/ref, and validates archive contents before staging only the matching native executable. Authentication never executes candidate code. Its GitHub credential is scoped to that step; candidate execution runs in subsequent steps.

The jobs compare the executed version, source state, build time, compiler, platform, architecture and executable SHA-256 with the authenticated `BUILD-INFO.json` and staging receipt. They run independent backup/recovery interoperability and nine loopback diagnostic cases: direct TCP, untrusted TLS rejection, SOCKS5 and HTTP CONNECT tunnels, proxy refusal, direct STUN, wrong transaction rejection, timeout and SOCKS5 UDP. Unix jobs additionally exercise controller ownership, private bootstrap and shutdown; Linux checks cross-user session denial. The public `packaged-native-OS-ARCH` artifacts retain receipts and source/binary-bound results. Temporary profiles, passphrases and launcher credentials are excluded.

Publication depends on all six packaged native jobs and both packaged FreeBSD guest jobs as well as packaging. A manual preview still creates no release. Inspect the exact run outcomes before claiming acceptance; configured steps alone are not passing evidence. The public TLS fixture key is intentionally nonsecret and used only to test rejection of an untrusted loopback server. It is never installed in a trust store.

These checks execute the actual stripped, trimpath, CGO-disabled portable cores, rather than substituting a separate test build. They do not qualify BSD execution, OS publisher signatures, native installers, vendor network changes or managed deployment. The manifest's aggregate `targetExecutionTested: false` remains accurate because the ten-target set still includes unqualified OpenBSD targets; each FreeBSD archive also requires its own source-bound guest result. Individual records retain `productionQualificationComplete: false`.


The [manual preview for exact source `00a5122bef6d58607186fcd22e9e32fd5cd542c0`](https://github.com/Yunushan/accessweaver/actions/runs/41544531520) passed all 17 jobs, including actual portable-candidate execution on all six desktop targets. Independent verification authenticated all twelve Sigstore subjects, checked all ten archives and passed the five real provenance-rejection probes. The six packaged evidence ZIPs were checked against their provider SHA-256 digests; runtime receipts and acceptance/interoperability/diagnostic reports were then matched to the authenticated archive and actual embedded binary hashes. Each target passed backup/recovery interoperability and nine loopback diagnostic cases, with Unix controller checks where applicable. This is evidence for that specific unsigned core candidate, not later source revisions, BSD execution, signed installers or full desktop readiness.

## Remaining signing and trust requirements

The manifest's `unsigned: true` and the unsigned-alpha artifact labels still describe the OS binaries. Build provenance identifies a GitHub workflow and source; it does not provide Windows Authenticode, macOS Developer ID/notarization, an installer signature or authenticated in-product update selection. Publisher certificates, signing-key ownership, deployment application control and those native distribution checks remain required.

The current workflow is not claimed SLSA Build Level 3 or a proof that build code is benign. A compromised approved workflow/runner/dependency can falsify its build behavior. Review, branch/tag protection, separation of duties, trusted builder isolation, independent rebuilds and release revocation/recovery remain requirements. Attested alpha artifacts are still subject to every unfinished functional, security, desktop and enterprise readiness gate.


## Packaged FreeBSD guest acceptance

The release workflow configures separate archived-candidate jobs for FreeBSD amd64 and arm64 on matching-architecture Linux hosts. `stage_packaged_native.py --freebsd-guest` uses an explicit guest-only target policy; the ordinary native entry point continues to reject cross-host/BSD selection. The credential-scoped step snapshots and authenticates all twelve distribution subjects before staging the selected archived binary and its build receipt. It never executes candidate code. The subsequent guest step receives no `GH_TOKEN` setting.

The guest driver retains its hosted opt-in, native host/SDK checks, pinned image/firmware, private capsule, restricted user networking and pinned SSH host key. Its handoff consumer opens the private staging directory once, reads bounded owner-controlled regular single-link files through that descriptor, rejects duplicate/unknown receipt fields and verifies source/ref/target and executable digest. It copies the exact staged executable into the payload and does not rebuild that CLI. The copied payload digest must match the authenticated receipt before packaging or launching a guest; subsequent transport checks remain bound to that digest. Independently compiled unit-test binaries remain separate. In the guest, transport hashes and the archived CLI's complete runtime build identity must match the authenticated receipt.

The archived executable creates, authenticates and restores a private encrypted single-profile backup; the restored profile must match exactly, and an incorrect passphrase must fail authentication. Only fixed boolean observations are retained. Temporary profile contents, passphrases and encrypted backups remain inside the private disposable guest. All target-matching unit packages must also pass, with owned VM/capsule cleanup required. Results retain archive, manifest, bundle and executable digests for independent linkage to the signed distribution set.

These acceptance requirements passed for the exact source recorded below; each later candidate still requires its own successful hosted run. They do not establish OpenBSD execution, cross-implementation BSD backup interoperability, OS publisher signing, packet-engine/routing, hardware, lifecycle, managed BSD deployment or complete platform qualification. Publication requires both guest jobs to succeed; failures have no unsigned/rebuilt-CLI fallback.

The [manual preview for exact source `a16ab354dac590fa63d229b5482d1a9f5ed4cc47`](https://github.com/Yunushan/accessweaver/actions/runs/41555879348) passed all 17 jobs after retrying a provider artifact-upload DNS failure on the Intel Mac. Independent verification authenticated twelve subjects, validated all ten archives and passed all five real rejection probes. All six packaged evidence ZIP provider digests were verified; 46 JSON records were matched to the authenticated archives and embedded executable bytes. Each native target passed backup/recovery interoperability and all nine loopback diagnostic cases, with Unix controller checks where applicable. This historical preview precedes the packaged FreeBSD jobs and proves no archived BSD execution.


The [corrected archive-gated preview for exact source `ee2754dd80c813a47e168f39baa1d2c06f45737e`](https://github.com/Yunushan/accessweaver/actions/runs/41560984760) passed all 19 jobs, including six packaged native targets and both packaged FreeBSD targets. Source CI passed all 22 jobs. Independent verification authenticated all twelve Sigstore subjects, validated all ten archives and passed the five real rejection probes. All eight packaged evidence ZIP provider digests were verified. The six native sets retained 46 JSON records matching their authenticated archives and embedded binaries, with backup/recovery interoperability, nine loopback diagnostics per target and Unix controller checks where applicable.

Each FreeBSD target's staged receipt, full runtime build identity and executable hash matched the actual binary extracted from its authenticated archive. Both FreeBSD 15.1 guests ran as `awtest` (UID 1001), passed encrypted backup create/authenticate/restore, exact profile read-back, plaintext-exclusion and wrong-passphrase rejection checks, and passed all 15 unit packages: 387 passing test instances including subtests and two Windows-only skips each. Every package-log digest was verified, along with owned emulator/capsule cleanup. Both used CPU emulation; physical hardware, full platform/engine/routing/lifecycle acceptance, administrator BSD policy, OpenBSD execution and OS publisher signing remain open. The aggregate `targetExecutionTested: false` and all 50 readiness-gate statuses remain unchanged.

The [preview at exact source `00817dc7d8cbc310c54c64542be830c8f8428cba`](https://github.com/Yunushan/accessweaver/actions/runs/41576168154) revalidated the eight archived desktop core candidates after the workflow-admission persistence correction: all 19 jobs passed. Independent verification checked all 12 Sigstore subjects, ten archive contents, five real rejection cases, all eight evidence ZIP digests and all 46 native-target records against their original archived executable bytes. Each archived FreeBSD target passed offline backup validation and 15 packages with 390 passing instances and two Windows-only skips, including both new admission cases; all 30 package-log digests and cleanup were checked. Separate OpenBSD source-core execution passed both architectures but did not execute their release archives. The same source's standalone CI retained a Windows ARM64 discovery deadline failure (21/22 jobs); the successful preview does not resolve it. Publisher signatures, full platform acceptance and all readiness-gate status requirements remain outstanding.

## Packaged OpenBSD guest acceptance

The release workflow now configures two `packaged-openbsd` jobs, using matching native Linux amd64/arm64 hosts and the authenticated OpenBSD 8.0 installer/bootstrap already exercised by the source-core probe. Each job independently authenticates the complete distribution before staging the selected original OpenBSD archive executable. The explicit `--openbsd-guest` staging entry point is separate from both native staging and `--freebsd-guest`; each BSD entry requires its own OS and matching Linux host architecture. The staging flags are mutually exclusive. The private handoff validates source/ref, OS/architecture, execution environment, complete build identity, bounded receipt/executable reads and the original binary digest through a held directory descriptor. Native staging continues to reject BSD targets.

`scripts/test-openbsd-guest.py --packaged-candidate` copies that exact binary into the private payload, compiles only the separate target unit-test executables, and requires the runtime CLI's full build identity and digest to match the authenticated receipt. There is no rebuilt-CLI fallback. Before all 15 target packages run, the original archived CLI must create, inspect and restore an encrypted offline backup, preserve the exact profile and reject an incorrect passphrase. Reports retain fixed booleans and digests; private bootstrap media, credentials and disks remain excluded. The installed system boots without installer, seed or ARM miniroot media and runs the candidate as ordinary `awtest`. The existing hosted opt-ins, restricted networking, pinned SSH, deadlines and owned cleanup remain required.

Release publication now also requires both packaged OpenBSD jobs. Configuration and mocked guard tests do not establish archive execution: the first successful exact-source preview and independent artifact/provenance/log verification remain required. Publisher signing, routing, privileged operations, lifecycle, hardware and full platform readiness remain unqualified. All 50 gate statuses are preserved.
