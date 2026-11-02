# Administrator recovery of machine policy

This procedure repairs an existing, readable, protected Windows/Linux machine source whose policy JSON, signature or signing key is unusable. It requires a separately elevated native CLI, a fresh signed replacement policy, an independently trusted Ed25519 public key and the endpoint's independently recorded minimum revision. It never deletes the enrollment, temporarily enables unmanaged behavior, or starts network/vendor operations. Policy keys are separate from Windows Authenticode/macOS Developer ID publisher certificates.

Use ordinary `managed update` for a healthy enrollment and `managed rotate` for a planned key change. Emergency recovery can deliberately replace the policy signing key, so treat the offline approval and the endpoint administrator's independently obtained key/revision records as a deployment trust decision. The current policy cannot forbid a trusted native administrator from repairing its source; ordinary users receive no recovery permission.

## Preserve evidence and establish independent trust

Record the endpoint, incident/change approval, installed build identity, effective administrator and observed policy error through the organization's existing change process. Stop or account for affected work before changing policy. Revocation does not undo routing/vendor changes or terminate separately installed services, and a recovered source does not restart canceled jobs.

Inspect the fixed source and export its exact raw bytes into a private destination outside the application data store:

```text
accessweaver version --json
accessweaver managed status
accessweaver managed export-source --out damaged-source.bin
```

`status` returns nonzero for damaged/expired policy. `export-source` reads only the fixed OS source and verifies native source protection; it does not authenticate damaged contents or grant their permissions. It works for bounded source bytes, including invalid UTF-8/JSON, invalid signatures and an existing zero-byte file or zero-length Windows REG_BINARY value. Existing output files are never overwritten. It preserves BOMs, line endings and whitespace because every byte participates in the repair identity. Keep the exported file unchanged.

An empty snapshot is bound by SHA-256 in the signed approval. It does not establish enrollment or authority: native application still requires the existing protected file/value and rejects an absent source. Empty configuration remains blocked until a valid repair commits. Record the independent highest revision and trusted key even when the damaged source contains no recoverable history.

Obtain the trusted replacement policy public key and highest accepted revision from independent deployment/change records. Do not derive either from the damaged snapshot or copy them blindly from a supplied recovery file. If the highest accepted revision is unknown, escalate through the administrator's recovery process rather than guessing a lower floor. Retain the last accepted authenticated installation and revision records separately during normal rollout; the application cannot reconstruct a destroyed counter or establish trust in an unknown key.

## Prepare and review the offline approval

On the offline administration system, review a complete replacement policy with a revision strictly greater than the independently recorded minimum. Preserve the intended permissions explicitly; an empty allowlist denies operations. Use a healthy existing policy key or a separately approved replacement key. Never deploy its private key to the endpoint.

The following example assumes independent records establish revision 42 and the reviewed replacement uses revision 43 or greater:

```text
accessweaver managed sign revised-policy.json --private-key policy-key.pem --out next-envelope.json
accessweaver managed sign-recovery next-envelope.json --previous-source damaged-source.bin --minimum-revision 42 --private-key policy-key.pem --valid-for 1h --out recovery.json
accessweaver managed verify-recovery recovery.json --previous-source damaged-source.bin --public-key TRUSTED_BASE64_PUBLIC_KEY --minimum-revision 42
```

The signed recovery payload binds the SHA-256 of the exact prior bytes, explicit minimum revision, exact next signed envelope and approval issuance/expiry. Its signature uses a distinct machine-recovery domain so policy or rotation signatures cannot authorize a repair. Approval lifetime must be positive and no longer than 24 hours. The endpoint clock must be within the approval window; there is no grace period after expiry or before issuance. The replacement policy must also be valid when applied.

Review reports include the old-source hash, approval payload hash, minimum revision, expiry, replacement key/policy identity, new permissions and whether prior history could authenticate. `signatureValid: true` and `runtimeEnforced: false` describe offline review, not native application or production qualification. If prior history authenticates, including an expired policy, recovery additionally enforces its actual revision even when the supplied floor is lower. If it does not authenticate, the independently recorded minimum is essential; damaged fields cannot supply a trustworthy counter.

## Apply and verify on the endpoint

Transfer only the reviewed approval and necessary public/deployment records through the approved channel. On the intended endpoint, use a separately elevated CLI and independently supplied public key/revision:

```text
accessweaver managed recover recovery.json --public-key TRUSTED_BASE64_PUBLIC_KEY --minimum-revision 42
accessweaver managed status
accessweaver managed export-installation --out recovered-installation.json
```

The endpoint requires an existing protected source and compares its actual bytes with the approval. A changed source, different key/floor, wrong signature/domain, invalid or stale replacement, and not-yet-valid/expired approval abort recovery. The same native transaction and stale-reader checks used by normal updates protect publication. Both approval and replacement validity are checked again after staging. A staged process exit leaves the prior damaged source blocked; a new explicit attempt is required. Recovery never selects authority from `ACCESSWEAVER_HOME`, an API request or a user profile.

Successful output reports `operation: recover`, `committed: true`, the new revision/key/payload identity and the prior-source/recovery-payload hashes. Save the reviewed approval, exact source snapshot, command outcome and post-recovery authenticated export with the change record. These local receipts do not provide an independently protected audit trail by themselves. Compare status and the exported installation with the reviewed replacement before restarting approved operations. A replay against the repaired source fails because the prior bytes no longer match.

A native commit can publish and then encounter a durability-sync, handle-close or output failure. Known publication is retained as `committed: true` in JSON even when the command returns nonzero. An error or absence of a successful receipt is not proof that no publication occurred: inspect current native status before retrying. Do not remove policy or coordination state to clear an error. A replacement already published requires a new source-bound approval for any further repair.

## Limits and qualification

This path retains native owner/ACL, persistent-filesystem, reparse/link and size/type requirements. It refuses missing sources, oversize values, wrong Windows registry types, unsafe owners/ACLs and unreadable or structurally damaged native storage. Those failures require a separately reviewed OS/deployment recovery procedure; this command does not chmod, delete, unenroll, recreate or silently adopt unsafe storage. Automatic last-known-good fallback, a protected independent revision escrow and comprehensive damaged-storage recovery remain outstanding. Restoring an older signed installation directly is not a qualified rollback; reissue the desired policy contents under a fresh revision and approval.

Portable tests exercise exact-source binding, independently pinned keys/floors, strict JSON/base64, signature-domain separation, expiry before and after staging, authenticated-history anti-rollback, replay and transaction failures. CLI tests preserve binary snapshots and refuse overwriting approvals/private keys. Temporary Linux fixtures exercise real atomic publication and source replacement. The existing disposable Windows/Linux transaction suites additionally damage and truncate their own temporary protected sources, reject bootstrap replacement of the existing enrollment, abruptly abandon repair candidates, require blocked state to persist, apply a new-key repair and reject mismatched keys/floors and replay. Ordinary-user native probes reject the repair operation. These cases run only behind the established hosted opt-ins, with scoped cleanup; inspect the exact source-bound CI run for results.

`scripts/test-recovery-interop.cjs` independently verifies Go approvals with Web Crypto and signs a replacement policy/approval for native Go review. It checks binary-source hashes, wrong keys/floors, changed source/signatures, expiry and signature-domain separation, without enrolling policy or creating user state. CI and release verification run it on amd64/arm64 Windows, Linux and macOS, require the executed CLI to match the intended native target, and retain source/binary-bound public records per target.

The signed-payload fuzz target runs with `go test ./internal/managed -run '^$' -fuzz FuzzSignedRecoveryPayload -fuzztime 30s -fuzzminimizetime 1s -parallel 2`. Process-exit and hosted VM checks do not qualify physical power loss, every supported desktop/architecture, domain/MDM deployment, vendor recovery or storage exhaustion. Full managed-deployment and recovery gates remain partial.

Windows readers recheck the value type and size with a second [RegQueryValueExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw) call, including for zero-length snapshots. Reserving an existing zero-length value uses [RegSetValueExW](https://learn.microsoft.com/en-us/windows/desktop/api/winreg/nf-winreg-regsetvalueexw) inside the protected transaction; staged replacement policies must still be nonempty.
