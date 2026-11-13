# Incident containment and recovery exercise

This runbook covers a suspected compromised release, engine/dependency or policy signer in an existing managed desktop deployment. Use the organization's incident and endpoint-management processes. AccessWeaver does not provide a fleet quarantine service, publisher-certificate revocation service or automatic repair of third-party network changes. This procedure is not evidence that a production incident has been handled.

## Establish responsibility and preserve evidence

Before a deployment exercise, record the incident commander, release/build owner, policy-key custodian, endpoint administrator, communications owner and independent recovery approver. Record the affected versions, source commits, OS/architectures, approved artifact hashes, first observation and decisions in UTC. These roles must be assigned by the deploying organization; this repository does not promise a response time or supply an on-call team. Follow [the vulnerability reporting guidance](../SECURITY.md) for a private report.

Treat suspected publisher/build/policy-key compromise or unauthorized execution as a trust incident requiring immediate owner review. Distinguish it from a reproducible product failure with intact trust. Set severity and response targets through the existing incident process, and record why they were chosen.

Stop rollout and promotion of the suspect version. Preserve immutable build/attestation subjects and release metadata in a restricted incident record before changing their distribution. Do not delete signatures or mutable release tags to make a verification error disappear. Record the source/version/hash denylist in the organization's deployment controls. Removing a download alone does not revoke installed copies, cached archives or a valid old signature. Do not rerun or execute a suspected binary merely to collect its version.

Publish the revocation list and its SHA-256 fingerprint through the independent release-control channel. Use the [signed-release verifier](RELEASE_PROVENANCE.md#approve-the-final-signed-desktop-artifacts) to confirm that it refuses the suspect candidate with the current list, including a cached copy that still has a valid approval signature. Verify that the approved replacement passes with the same list before reopening deployment. Use the organization's endpoint controls to account for already installed copies.

Use a separately trusted, approved CLI to inspect an endpoint. Save only the evidence needed for the incident and protect exports outside the application data store. The Settings support summary is explicit, local and metadata-only; it is not a complete incident bundle or an authenticated native inventory. Raw profiles, histories, logs and policy-source snapshots can contain private information and need separate handling and approval before transfer.

## Contain managed operations

With an uncompromised current policy key, review and sign a policy at a revision above the highest accepted revision. Remove suspect launch/download/workflow rules; disable other permissions when required by the incident plan. An empty allowlist denies those operations. Preserve a known independent copy of the trusted public key and highest accepted revision. Do not lower the revision or delete policy/acceptance history to regain access.

Apply the reviewed envelope through the organization's approved administrator channel:

```text
accessweaver managed update containment-envelope.json
accessweaver managed status
accessweaver managed export-installation --out containment-installation.json
```

Confirm the installed key, revision and permissions against the independently reviewed change. A failed command or missing receipt does not prove that publication did not happen. Inspect current state before retrying, especially after a sync, handle-close or output error. Existing export destinations are not overwritten.

Live managed authorizations detect policy identity changes and cancel their owned operations. This is polling, not an instantaneous endpoint-wide kill switch. Verify that the actual affected work stopped; inspect separately installed vendor processes, services, drivers, routing and DNS through the organization's native procedures. A policy change does not undo their effects or terminate arbitrary programs. Record any work that remains unaccounted for. Restarting the UI or recovering a policy must not be treated as proof of network restoration.

If the current policy key is suspect, do not use it as the sole authority for recovery approval or trust a replacement key supplied by the damaged endpoint. Have the independent incident approver and policy custodian supply the replacement public key and revision floor through a separate trusted channel. Coordinate OS/application-control and signing-service actions with their owners; those revocations do not happen through `managed update`.

## Recover trust and a known-good candidate

Use [machine-policy recovery](MACHINE_POLICY_RECOVERY.md) for an existing readable protected source with damaged policy/signatures or an approved emergency key replacement. Preserve its exact bytes with `managed export-source`; independently establish the highest accepted revision. Prepare a fresh replacement envelope and short-lived, source-bound approval offline. Transfer no private key to the endpoint. Follow the documented `sign-recovery`, `verify-recovery` and `recover` commands with independently supplied key and minimum revision.

Approval must bind the exact damaged bytes and exceed both the independent floor and retained accepted history. A changed source, wrong key/floor, expired approval, replay or stale revision requires a new review. If protected storage or its mandatory history is unreadable or corrupt, stop and escalate to the native deployment recovery owner. Do not recreate storage or reset enrollment as an undocumented workaround.

After a known publication, inspect status and export the authenticated installation even if cleanup reported an error. Verify the replacement key/revision and intended permissions before any fresh operation. Old authorization grants and canceled work must remain invalid. Restore only reviewed permissions; recovery must not automatically restore suspect download, launch or workflow rules.

Select a replacement product/engine through a clean review/build path. Independently authenticate its source/provenance and expected publisher identity; a checksum downloaded beside an untrusted archive is insufficient. If the publisher key, workflow or builder was compromised, approval of the old identity alone is insufficient. Have the release and signing owners establish replacement trust. An old authentic signature does not prove the version is safe or currently approved. Preserve profiles/policy, and perform approved staged install/upgrade/reboot/rollback acceptance before broad rollout. Do not deploy an older policy revision as a product rollback.

## Exit criteria and rehearsal record

Record each of the following as pass, fail, unverified or not applicable with a reason and evidence. Reopen rollout only after the designated incident approver accepts the remaining risk.

- Suspect release/dependency distribution is contained, with cached/installed scope accounted for and immutable evidence preserved.
- A separately authenticated containment policy denies the intended operations; old grants are canceled and affected native processes/network changes are accounted for.
- Independent signing/key trust, accepted revision and recovery approval are reviewed; stale revisions, changed sources, wrong keys/floors and replay are refused.
- Failed preparation/publication keeps state blocked; known publication remains discoverable after a reported cleanup failure.
- Recovered permissions match review, old work stays canceled, and new operations require fresh authorization. Suspect allowlists remain excluded until independently approved.
- Replacement artifact, native installation/reboot/rollback, real traffic restoration, fleet detection and communications are verified for the affected desktop cohort.
- Owners record containment/recovery times, evidence locations, unresolved gaps, communications and follow-up actions. Exercise this process again after material trust or deployment changes.

## Repeatable source-level policy rehearsal

`TestPolicyIncidentContainmentAndRecoveryDrill` in `internal/managed/incident_drill_test.go` exercises twelve ordered phases using real policy/recovery signatures, retained acceptance history, transaction orchestration, policy admission and an actual live authorization monitor. The transaction storage is controlled in memory; keys and damaged source are synthetic. It opens no listener, starts no vendor executable, changes no native policy and contacts no signing or release service.

Run it as an ordinary user from a clean source checkout:

```text
go test ./internal/managed -run '^TestPolicyIncidentContainmentAndRecoveryDrill$' -count=1
go test -race ./internal/managed -run '^TestPolicyIncidentContainmentAndRecoveryDrill$' -count=1
```

The exercise starts with signed revision 40, publishes deny-by-default revision 41, observes old-grant cancellation, refuses stale/untrusted updates, damages the controlled source while retaining accepted history, and rejects enrollment reset, wrong recovery inputs and a lowered-floor rollback. Staging/commit faults and approval expiry leave the source blocked. New-key revision 42 remains reported as published despite an injected Close error. Replay and the former signer are refused, old work remains canceled, and only a fresh authorization regains explicitly restored permissions. Launch and workflow allowlists remain empty.

The complete root-module Linux qualification workflow includes the exercise in both unit and race runs and reports only fixed source-known root names, outcomes and subtest counts. A passing source rehearsal proves these controlled policy contracts. It does not prove native storage protection/publication, physical durability, installed vendor cleanup, network recovery, compromised-builder detection, real release or certificate revocation, or an organization's response readiness. The full incident-response and desktop-readiness gates remain incomplete until those affected-cohort exercises have their own evidence.

The [fa28695 qualification receipt](qualification/fa28695b38da-policy-incident-drill.json) records all six first-attempt native Linux core jobs passing. The drill passes twelve phases in each AMD64/ARM64 unit/race run, totaling 48 phase completions with no skips or retries. Each complete test run passes 769 of 787 cataloged roots and explicitly skips 18; both vet runs cover all 29 packages. The changed managed test package also compiles for all ten targets without executing those artifacts. The native endpoint and organizational limits above remain open; no formal readiness gate is promoted.
