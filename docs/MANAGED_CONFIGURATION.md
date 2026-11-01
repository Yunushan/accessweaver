# Signed managed configuration

Current status: administrator tooling for review, signing and signature verification. Machine enrollment, protected trust/revision storage and runtime policy enforcement are still required. Verification returns `runtimeEnforced: false`; it does not authorize or apply any operation. The policy readiness gate remains missing, and configuration readiness remains partial.

## Document and trust contract

A policy contains `schemaVersion: 1`, a monotonically increasing `revision`, `issuedAt`, `expiresAt`, permission booleans and launch/workflow approval rules. An empty allowlist and false permissions express denial. The verifier checks the supplied clock, rejects expiry at or before that clock, and allows issuance at most five minutes ahead for clock skew. Revisions must be positive JSON-safe integers (at most 9007199254740991). Changing any policy byte, including whitespace, invalidates its signature.

The envelope has four fields: `schemaVersion`, `keyId`, `payload` and `signature`. `payload` is standard padded base64 of the exact UTF-8 policy bytes. `keyId` is lowercase SHA-256 of the raw 32-byte Ed25519 public key. `signature` is standard padded base64 of an Ed25519 signature over the bytes `AccessWeaver managed policy v1` followed by a NUL byte and then the exact payload. No algorithm negotiation or envelope-supplied public key is accepted. The verifier uses only the public key selected independently by the operator. The implementation uses [Go's Ed25519 package](https://pkg.go.dev/crypto/ed25519).

Policy input is limited to 64 KiB, envelopes to 128 KiB, and each allowlist to 128 rules. Unknown fields, case aliases, duplicate keys at any level, trailing documents, noncanonical base64, malformed hashes and inconsistent private keys are rejected. Use UTF-8 without a BOM for signed policy documents. The original payload remains embedded in the envelope; decoding and re-encoding it before verification is invalid.

`--minimum-revision N` requires a policy revision strictly greater than N. N must come from trusted prior deployment state. The review command does not save it, enroll a key, rotate trust, import policy, prevent local state rollback or change profiles. Passing a command-line number alone is not persistent rollback protection.

## Offline administrator workflow

Keep signing keys outside the source checkout and managed endpoints, on a protected signing workstation. Only unencrypted Ed25519 PKCS#8 PEM input is currently supported; HSM, encrypted-key and signing-service integration remain work. This utility does not generate or change key-file permissions. An existing organization key may be used, or [OpenSSL `genpkey`](https://docs.openssl.org/3.5/man1/openssl-genpkey/) can create an offline Ed25519 key:

```bash
umask 077
openssl genpkey -algorithm ED25519 -out signer.private.pem
accessweaver managed public-key --private-key signer.private.pem
```

Transfer only the printed public key to the review/deployment environment through your trusted administrative channel. The output is base64 of the raw public key, not a PEM block or base64 of an entire SubjectPublicKeyInfo document. Never distribute the private signing key with the envelope, logs or support artifacts.

Author a policy with current UTC validity timestamps. This example expresses denial of all operations; it is a document example, not an enforced lockdown:

```json
{
  "schemaVersion": 1,
  "revision": 1,
  "issuedAt": "2026-11-01T00:00:00Z",
  "expiresAt": "2026-11-02T00:00:00Z",
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

These commands print `inputSHA256` and `runtimeEnforced: false`. A digest grants no authority. It is a review artifact for a future protected-policy compiler and runtime guard.

A launch input digest binds version, engine, binary/configuration references, the profile's expected executable hash, arguments and all routing lists. Display identity, names, descriptions, notes, update timestamps and diagnostic probes are excluded because they do not control engine launch. Empty and absent lists normalize consistently; the profile SHA-256 spelling normalizes to lowercase. Other list ordering and spelling remain significant. Separate `binarySHA256` and optional `configSHA256` rule fields are required to identify file contents rather than only their references. Approval must also cover executable dependencies and referenced assets through future provenance checks.

A workflow digest binds every field of the validated typed `workflow.Request`, including its action, engine, paths, selected applications, domain/target lists, flags, URL/hash and journal ID. JSON formatting and omitted zero values normalize through that typed representation. Unknown actions receive no digest. Input digests use SHA-256 of `AccessWeaver managed launch input v1` or `AccessWeaver managed workflow input v1`, followed by a NUL byte and the respective typed JSON bytes. CLI and runtime code must use the same helpers.

Launch rules contain `engine`, `inputSHA256`, `binarySHA256` and optional `configSHA256`. Workflow rules contain `action` and `inputSHA256`. Duplicate engine/action plus input-hash approvals are rejected. These rules currently record signed administrative intent only.

## Remaining integration and acceptance

The managed installation needs a protected machine trust anchor, authenticated enrollment/key rotation, monotonic revision storage and atomic import/recovery before these documents can control behavior. Ordinary-user environment variables, profile JSON and browser storage must not select or replace that authority. CLI, loopback API, workflow workers and service-host entry points must enforce the same effective policy and recheck authority at execution time. Executable/configuration provenance, mutable generated files, DLL/assets, download restrictions, privilege separation, running-job revocation, policy expiry and uninstall recovery need explicit integration and adversarial tests on managed endpoints.

Test document handling with `go test ./internal/managed ./internal/workflow ./cmd/accessweaver -count=1`. Tests cover signed payload tampering, key substitution, protocol separation, external signers supplying malformed JSON, revision/time boundaries, input digests, exclusive output creation and absence of application-state mutation. Fuzz targets exercise the policy and envelope parsers. This evidence does not certify managed deployment or grant readiness credit for enforcement.
