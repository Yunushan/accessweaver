# Signed managed configuration

Current status: signed administrator documents and partial Windows runtime enforcement through protected machine configuration. The production/enterprise readiness gates remain partial. Verification alone returns `runtimeEnforced: false`; offline tools do not enroll or authorize a machine. Windows initial installation and monotonic updates use native registry transactions. Non-Windows machine policy, damaged-state/emergency recovery, protected input staging, service authorization and managed-endpoint qualification remain work.

## Document and trust contract

A policy contains `schemaVersion: 1`, a monotonically increasing `revision`, `issuedAt`, `expiresAt`, permission booleans (`allowDiagnostics`, `allowProfileChanges`, `allowDownloads`), launch/workflow approvals and optional pinned `downloads` rules. An empty allowlist and false permissions express denial. The verifier checks the supplied clock, rejects expiry at or before that clock, and allows issuance at most five minutes ahead for clock skew. Revisions must be positive JSON-safe integers (at most 9007199254740991). Changing any policy byte, including whitespace, invalidates its signature.

The envelope has four fields: `schemaVersion`, `keyId`, `payload` and `signature`. `payload` is standard padded base64 of the exact UTF-8 policy bytes. `keyId` is lowercase SHA-256 of the raw 32-byte Ed25519 public key. `signature` is standard padded base64 of an Ed25519 signature over the bytes `AccessWeaver managed policy v1` followed by a NUL byte and then the exact payload. Trust keys require canonical compressed coordinates and reject every small-order point before signature verification. Curve decoding and signatures still use the Go standard library. This avoids treating a degenerate-key signature equation as proof of a signing secret. Coordinate encoding follows [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.3); the low-order coordinate set is cross-checked against the [tagged libsodium reference](https://github.com/jedisct1/libsodium/blob/1.0.20-RELEASE/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c). No algorithm negotiation or envelope-supplied public key is accepted. The verifier uses only the public key selected independently by the operator. The implementation uses [Go's Ed25519 package](https://pkg.go.dev/crypto/ed25519).

Policy input is limited to 64 KiB, envelopes to 128 KiB, and each launch/workflow/download allowlist to 128 rules. Unknown fields, case aliases, duplicate keys at any level, trailing documents, noncanonical base64, malformed hashes and inconsistent private keys are rejected. Use UTF-8 without a BOM for signed policy documents. The original payload remains embedded in the envelope; decoding and re-encoding it before verification is invalid.

`--minimum-revision N` requires a policy revision strictly greater than N. N must come from trusted prior deployment state. The review command does not save it, enroll a key, rotate trust, import policy, prevent local state rollback or change profiles. Windows runtime verifies the revision floor in the protected installation value. `managed update` derives the next floor from the authenticated enrolled revision; direct administrator/MDM registry writes must preserve that invariant themselves. Passing a command-line number alone is not persistent rollback protection.

## Offline administrator workflow

Keep signing keys outside the source checkout and managed endpoints, on a protected signing workstation. Only unencrypted Ed25519 PKCS#8 PEM input is currently supported; HSM, encrypted-key and signing-service integration remain work. This utility does not generate or change key-file permissions. An existing organization key may be used, or [OpenSSL `genpkey`](https://docs.openssl.org/3.5/man1/openssl-genpkey/) can create an offline Ed25519 key:

```bash
umask 077
openssl genpkey -algorithm ED25519 -out signer.private.pem
accessweaver managed public-key --private-key signer.private.pem
```

Transfer only the printed public key to the review/deployment environment through your trusted administrative channel. The output is base64 of the raw public key, not a PEM block or base64 of an entire SubjectPublicKeyInfo document. Never distribute the private signing key with the envelope, logs or support artifacts.

Author a policy with current UTC validity timestamps. This example expresses denial of all governed operations when deployed as protected Windows installation data. The signing command alone does not activate it:

```json
{
  "schemaVersion": 1,
  "revision": 1,
  "issuedAt": "2026-11-01T00:00:00Z",
  "expiresAt": "2026-11-02T00:00:00Z",
  "allowDownloads": false,
  "allowDiagnostics": false,
  "allowProfileChanges": false,
  "launches": [],
  "workflows": []
}
```

Set actual issuance/expiry values before signing, then run:

```bash
accessweaver managed validate policy.json
accessweaver managed sign policy.json --private-key signer.private.pem --out envelope.json
accessweaver managed verify envelope.json --public-key BASE64_PUBLIC_KEY --minimum-revision 0
```

`--out` writes UTF-8 directly and exclusively creates a new output file. An existing file is never overwritten, including when it names the signing key or policy source. A write, sync or close failure returns an error; any incomplete new file is retained for inspection and must not be distributed. Without `--out`, signing writes to stdout; PowerShell 5.1 redirection encodes stdout as UTF-16, so use `--out` there. To create the source policy from PowerShell 5.1, use `[IO.File]::WriteAllText(path, json, [Text.UTF8Encoding]::new($false))` rather than its BOM-producing UTF8 `Set-Content`.

Review output includes the parsed policy, key ID, payload SHA-256, `signatureValid: true`, and `runtimeEnforced: false`. Invalid input returns a nonzero exit status with no successful review JSON. None of these commands starts an engine, probes a network, writes application profile state, changes Windows settings or installs policy.

## Binding approvals to inputs

```bash
accessweaver managed digest-profile profile.json
accessweaver managed digest-workflow request.json
```

These commands print `inputSHA256` and `runtimeEnforced: false`. A digest grants no authority by itself. It must match an approval in the signed, protected machine policy.

A launch input digest binds version, engine, binary/configuration references, the profile's expected executable hash, arguments and all routing lists. Display identity, names, descriptions, notes, update timestamps and diagnostic probes are excluded because they do not control engine launch. Empty and absent lists normalize consistently; the profile SHA-256 spelling normalizes to lowercase. Other list ordering and spelling remain significant. Separate `binarySHA256` and optional `configSHA256` rule fields are required to identify file contents rather than only their references. Approval must also cover executable dependencies and referenced assets through future provenance checks.

A workflow digest binds every field of the validated typed `workflow.Request`, including its action, engine, paths, selected applications, domain/target lists, flags, URL/hash and journal ID. JSON formatting and omitted zero values normalize through that typed representation. Unknown actions receive no digest. Input digests use SHA-256 of `AccessWeaver managed launch input v1` or `AccessWeaver managed workflow input v1`, followed by a NUL byte and the respective typed JSON bytes. CLI and runtime use the same helpers. Compatibility vectors retain the version-one digests produced by commit `0178f99`.

Launch rules contain `engine`, `inputSHA256`, `binarySHA256` and optional `configSHA256`. Workflow rules contain `action` and `inputSHA256`. Duplicate engine/action plus input-hash approvals are rejected. The Windows runtime compares these approvals before execution and checks permission again at mutation/start boundaries. Separate input-provenance limits below still apply. Installation data is user-readable approval data, so manifest URLs must not carry credentials or private tokens.

## Protected Windows source and runtime behavior

Windows reads only the 64-bit registry view at `HKLM\SOFTWARE\Policies\AccessWeaver`, value `Installation` of type `REG_BINARY`. It contains a single UTF-8 JSON object with `schemaVersion: 1`, `publicKey`, `minimumRevision` and the signed `envelope`. One value prevents readers mixing a new key, old revision floor and different envelope. The key and fixed ancestors must be owned by SYSTEM, Administrators or TrustedInstaller, with no ordinary-principal rights to mutate values, subkeys, ownership or DACLs. Ordinary deny ACEs, inherit-only ACEs and Windows owner placeholders are handled explicitly; unsupported ACE forms fail closed. [Windows documents registry access rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights).

An absent protected key means unmanaged. A present key with a missing/empty value, weak ACL, inaccessible data, invalid signature, stale revision or expired policy blocks governed actions; it never silently falls back to unmanaged mode. `ACCESSWEAVER_HOME`, user profiles, browser storage and environment variables cannot choose the authority. There is no user-facing bypass switch.

Prepare a candidate file locally with the existing pinned public key and trusted prior revision:

```bash
accessweaver managed prepare envelope.json --public-key BASE64_PUBLIC_KEY --minimum-revision 0 --out installation.json
accessweaver managed status
```

Preparation validates the envelope and exclusively creates a UTF-8 file. It does not write the registry. Existing endpoint-management tooling can invoke the separately elevated `managed install` command below, or deploy that complete file as one `REG_BINARY` value with administrator-only write/ownership permissions and ordinary-user read access. A suitable leaf descriptor is `O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)`. Validate deployment only on disposable managed test endpoints first. No test in the ordinary unit suite creates, modifies or deletes HKLM keys on its host.

`managed status` reports `supported`, `configured`, `valid`, the enrolled `keyId`, revision/expiry and `enforcement` (`none`, `partial` or `blocked`). Invalid/unreadable state returns a nonzero exit status and structured blocked status; configured includes state that cannot safely be excluded because source protection failed. Unix targets currently report unsupported machine enforcement and retain ordinary behavior. Offline `managed verify` still reports `runtimeEnforced: false` because a reviewed file is not machine enrollment.

Current guarded paths are:

- Profile save, revision-based save, delete and first-run seeding. Read-only policy skips seeding. Saves/deletes check permission again after acquiring the storage lock; reads remain available.
- CLI and authenticated API diagnostics before probing a network.
- Foreground launch preview, preparation and final process start. Approval binds the version-one input digest and expected binary/configuration hashes. Generated routing files and raw native-argument assets fail closed until protected staging/validation exists. Files require trusted administrator ownership and non-user-writable ancestor/sibling protection on fixed local drives. Reparse points and alternate data streams are refused; directory inspection is streamed and bounded to 4096 entries/32 levels, and individual hashing to 512 MiB. This conservatively excludes locations such as ordinary user directories and default broadly writable ProgramData ancestors. Use qualified immutable application storage; native location/alias compatibility remains to be tested.
- Reviewed Windows workflow requests, rechecked after preview and again by the actual worker. Supplied configuration/bundle paths must pass native provenance checks; raw native-argument assets are blocked pending protected compilation. `allowDownloads: false` blocks release lookups and component retrieval before network activity. With downloads enabled, `downloads` entries pin each implicit dependency's exact HTTPS URL and SHA-256; remote release metadata cannot replace a pin. A directly approved `download` request already binds its own URL/hash through the signed request digest. Publisher verification remains an additional check for signed installers. Network activity intrinsic to an approved vendor program, including explicitly approved WARP registration, still needs vendor/native qualification.
- The `service-host` entry point. Enrolled machines currently reject these service starts until signed service-specific authorization and protected broker integration exist. Existing running jobs/services are not automatically revoked or terminated by policy changes. Pending starts cannot outlive manager shutdown while waiting for policy/provenance I/O.

Native workers resolve system tools through `GetSystemDirectoryW`. Shared storage is derived from the ACL-checked machine `ProfileList\ProgramData` setting, expanding only OS-derived SystemDrive/SystemRoot/WINDIR values. Program Files and common-program roots likewise come from protected machine registration rather than caller environment values. This avoids caller-environment expansion in the ordinary common-directory API. Tests compare the result with that API in the normal environment and repeat lookup in a fresh process with poisoned environment values. PowerShell workers use a trusted working directory and module path, remove CLR/module/runtime injection variables, and use protected temporary storage for machine changes. Managed foreground engines receive a sanitized environment tied to the same authority read as final launch authorization. These controls do not sandbox an approved vendor executable.

## Initial installation and monotonic Windows updates

Run these commands through the existing endpoint-management channel or a separately elevated administrator CLI. Keep the dashboard unelevated. They change the fixed machine policy source and require an effective administrator token, including when the calling thread impersonates a user.

```bash
accessweaver managed install installation.json --public-key BASE64_PUBLIC_KEY
accessweaver managed update next-envelope.json
accessweaver managed status
```

`install` requires the public key obtained independently through the administrator's trusted channel and checks it against the prepared document. It refuses every existing policy key, including damaged or expired installations, rather than replacing enrolled trust. New keys have administrator-only mutation/ownership permissions and ordinary-user read access. No user-selected registry path is accepted.

`update` accepts only an envelope. It reads the enrolled key and authenticates the previously accepted policy, requires a strictly higher revision signed by that same key, and saves that previous revision as the new floor. It never accepts a replacement key or caller-supplied floor. Identical and older revisions are errors; competing imports of the same revision cannot both commit. The updater reserves the native value for writing and compares it with the separately read committed document before deriving approval, so a stale reader must abort after another revision commits. Invalid signatures, damaged prior state and unknown source protection stop the update. There is no automatic bootstrap or reset fallback.

An expired prior policy remains blocked for runtime operations. The updater can authenticate its original signature and recover its revision at its issuance time solely to validate a fresh, currently valid higher revision. This historical check does not construct runtime authority or reuse expired permissions. A missing, corrupted or unauthenticatable prior policy needs a separately reviewed administrator recovery procedure; this command does not bypass it.

The implementation uses a local [KTM transaction](https://learn.microsoft.com/en-us/windows/win32/api/ktmw32/nf-ktmw32-createtransaction) and [transacted registry handles](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeytransactedw), with a 15-second transaction timeout and no named coordination object. Initial key creation and the complete installation value are staged before commit. Pending state is not published; closing the last uncommitted transaction handle aborts it. Candidate validity is checked again after staging, so expiry during contention prevents commit. There is no non-transactional fallback if the native facility is unavailable. The transaction DLL is loaded from the OS system directory, independent of application/current directories and PATH.

Successful output contains the operation, previous/new revisions, key ID, payload hash, `committed: true` and `enforcement: "partial"`. It excludes signing keys and policy contents. A transaction conflict or failure returns nonzero; inspect `managed status` before retrying. Console/handle failures can occur after commit, so a failed invocation must not be treated as proof that no change took effect. Never restore an older installation document to make a retry pass. Keep reviewed policy sources offline; to reverse policy intent, sign the desired settings again with a new revision. Publisher signing, last-known-good recovery, power-loss/reboot acceptance and integration with real endpoint-management deployment remain unfinished.

## Planned signing-key rotation

Windows supports a separately elevated `managed rotate` command. It uses the same protected registry transaction, stale-state reservation, final expiry check and atomic installation document as ordinary updates. The old key authorizes one exact replacement key and signed policy; the replacement policy's signature proves possession of the new key. The accepted revision must still increase. Rotation does not reset the floor or bootstrap a missing/damaged source.

Export the current public installation document on an enrolled endpoint, then transfer it through the administrative channel to the offline signing environment:

```bash
accessweaver managed export-installation --out previous-installation.json
```

Export checks native source protection and authenticates its historical signature/revision. It can export an expired policy for renewal/rotation planning without authorizing its permissions. It contains the public key and public approval data; keep its access appropriate to the organization. It contains no private signing key. Output uses exclusive creation and never overwrites an existing file. Unix machine export remains unsupported.

Author a currently valid next policy with a revision higher than the enrolled revision and sign it with the new key. Obtain `NEW_PUBLIC_KEY` from that key and `OLD_PUBLIC_KEY` through the independent trusted channel. On the offline signer, run:

```bash
accessweaver managed sign next-policy.json --private-key next.private.pem --out next-envelope.json
accessweaver managed sign-rotation next-envelope.json --previous-installation previous-installation.json --next-public-key NEW_PUBLIC_KEY --private-key old.private.pem --out rotation.json
accessweaver managed verify-rotation rotation.json --previous-installation previous-installation.json --public-key OLD_PUBLIC_KEY
```

The old private key must match the authenticated prior installation. The new key must differ, and the next envelope must have a valid new-key signature, validity window and higher revision before signing. The review command independently pins the old public key and reports previous key/revision/payload hash, the next verified policy and `runtimeEnforced: false`. Signing and review do not install, probe a network, or create application user state. Never transfer either private key to an endpoint.

Deploy only the public rotation document through the existing management channel and apply it in the separately elevated CLI:

```bash
accessweaver managed rotate rotation.json
accessweaver managed status
```

The endpoint binds authorization to its actual enrolled key ID, revision and exact signed policy payload SHA-256. Any intervening policy update, even to different contents at the same revision through an administrator's direct write, makes the old rotation stale. Export and sign against the current state again. After commit, ordinary updates signed by the retired key are rejected; updates require the new key. Replaying the rotation is rejected. The result includes previous/new key IDs and revisions with `committed: true` and `enforcement: "partial"`.

The rotation wrapper uses the same four-field envelope encoding but a separate signature domain: UTF-8 `AccessWeaver managed key rotation v1`, a NUL byte, then the exact payload bytes. The payload contains `schemaVersion: 1`, `previousKeyId`, `previousRevision`, `previousPayloadSHA256`, `nextPublicKey` and `nextEnvelope`. The old key signs the complete payload. The embedded new policy retains its own ordinary policy signature and exact payload bytes. Unknown/duplicate/case-aliased fields, noncanonical base64, mismatched prior state and invalid signatures are rejected. Rotation payloads are bounded to 132 KiB and outer envelopes to 192 KiB; ordinary policy/envelope limits still apply. Rotation signatures cannot authorize ordinary policy documents or vice versa.

An expired prior policy can participate in planned rotation through historical metadata authentication, while runtime operations remain blocked until a currently valid replacement commits. Expiry of the replacement prevents signing/review/apply. This is planned rotation with possession of the old key. Loss or compromise of that key, corruption of the trust source, out-of-band recovery, protected last-known-good state and fleet rollout/reboot qualification remain separate requirements. A holder of the old private key can authorize transitions while that key remains enrolled; this procedure does not solve signer compromise. Keep the old key offline and retire it according to the organization's signing controls after qualified rollout.

## Remaining integration and acceptance

Last-known-good and damaged-state/emergency recovery must still be implemented and exercised; transactional install/update and planned key rotation need full desktop, reboot and deployment qualification; manual endpoint-management writes can misconfigure state, and a trusted administrator can replace it. Complete non-Windows authority storage/enforcement, protected generated/native-argument inputs, signed service authorization and privilege separation. Test supported Windows versions/architectures, relocated/native path aliases, dependency/configuration behavior, policy expiry/revocation while jobs run, reboot, upgrade/downgrade and uninstall recovery. Policy can deliberately block recovery or uninstall requests too, so deployment must include a separately reviewed administrator recovery procedure. Do not deploy an empty allowlist over active production services as an experiment.

All controllers and service copies must use the qualified build. Publisher signing and OS application-control/deployment rules are still needed to prevent older or modified binaries, arbitrary same-user code injection and execution outside this installation from bypassing an application-level check. The current implementation is not an isolation boundary against arbitrary code with the controller's permissions.

Tests cover signatures and strict parsing, revision/time boundaries, native descriptor validation, read-only registry access, approval/provenance decisions, profile-lock and workflow/start revocation races, API denial, pinned download contracts and a real read-only PowerShell discovery process under an untrusted environment. Native install/routing/managed-domain acceptance remains a disposable-VM qualification requirement. No compilation, mocked provenance decision or ordinary CI pass grants full enterprise readiness credit.

## Disposable hosted Windows acceptance

The dedicated CI/release step runs `TestDisposableManagedPolicyNative` and `TestDisposablePolicyTransactionRollback` on a fresh GitHub-hosted Windows VM after ordinary tests. It requires the explicit `ACCESSWEAVER_DISPOSABLE_POLICY_TEST=1` opt-in, the hosted Windows runner context, an administrative non-SYSTEM account and absence of any existing AccessWeaver policy. Never set this flag on a desktop or self-hosted runner. [GitHub documents per-job hosted VM isolation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job).

The tests temporarily create a protected policy key through the actual installer and one uniquely named protected Program Files fixture directory. It approves and starts an inert test-only executable, checks read-only profiles and denied diagnostics/workflows/service starts, probes registry/file write denial with an impersonated token whose administrator SID and privileges are disabled, rejects changed executable bytes and verifies that invalid installed policy cannot become unmanaged. Cleanup removes only its newly created key and validates the exact fixture directory before recursive deletion. It does not install vendor software, change services/DNS/firewall settings or send network probes. The fixture branch exists only in a Go test binary and is absent from production builds. Additional checks cover actual initial installation, refusal to replace an enrolled key, concurrent same-revision updates, signing-key substitution and expired-policy renewal. A second test stages initial/update documents without commit, reads the previously committed state, then closes or abruptly exits a child process and requires native rollback before a later valid update. A deterministic stale-reader case also attempts reservation after a newer revision has committed and requires rejection without changing that revision. Rotation checks abruptly exit a child with a staged new key, require the old key/revision to remain effective, then commit the rotation, reject replay/retired-key updates and accept a new-key update. These tests create persistent registry keys only for the duration of the disposable job and delete their own keys during cleanup; they do not qualify reboot/power-loss behavior.

Public result metadata is retained under `build/managed-policy-checks/`; check the exact source-bound CI run for its outcome. Hosted Windows Server coverage is not domain/MDM enrollment, Windows desktop/ARM acceptance, interactive browser qualification or real driver/network lifecycle acceptance. Failed cleanup fails the test; an evidence field indicating scheduled cleanup alone does not prove completion.
