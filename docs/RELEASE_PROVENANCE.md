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

Publication depends on all six packaged jobs as well as packaging. A manual preview still creates no release. Inspect the exact run outcomes before claiming acceptance; configured steps alone are not passing evidence. The public TLS fixture key is intentionally nonsecret and used only to test rejection of an untrusted loopback server. It is never installed in a trust store.

These checks execute the actual stripped, trimpath, CGO-disabled portable cores, rather than substituting a separate test build. They do not qualify BSD execution, OS publisher signatures, native installers, vendor network changes or managed deployment. The manifest's aggregate `targetExecutionTested: false` remains accurate because the ten-target set includes four unexecuted BSD targets. Individual records retain `productionQualificationComplete: false`.

## Remaining signing and trust requirements

The manifest's `unsigned: true` and the unsigned-alpha artifact labels still describe the OS binaries. Build provenance identifies a GitHub workflow and source; it does not provide Windows Authenticode, macOS Developer ID/notarization, an installer signature or authenticated in-product update selection. Publisher certificates, signing-key ownership, deployment application control and those native distribution checks remain required.

The current workflow is not claimed SLSA Build Level 3 or a proof that build code is benign. A compromised approved workflow/runner/dependency can falsify its build behavior. Review, branch/tag protection, separation of duties, trusted builder isolation, independent rebuilds and release revocation/recovery remain requirements. Attested alpha artifacts are still subject to every unfinished functional, security, desktop and enterprise readiness gate.
