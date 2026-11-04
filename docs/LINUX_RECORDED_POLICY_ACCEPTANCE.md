# Hosted Linux recorded policy transaction acceptance

The opt-in disposable Linux policy script now includes a separate source-built CLI fixture for recorded install, update, key rotation and damaged-source recovery on amd64 and arm64. It leaves the existing administrator update, ordinary-user required-profile-audit, ACL, engine revocation and policy transaction fixtures intact. The ordinary-user worker keeps its fifteen-second deadline. No installed product is run by the new fixture.

## Scenario and assertions

The fixture refuses preexisting machine authority or coordination state. It creates a private journal under a random root-owned /etc fixture directory and retains administrator-class genesis and current-head checkpoints. It calls the actual audit CLI dispatcher and fixed native machine-policy backend. There is no injectable machine authority, alternate root or private-key command option.

The successful transactions enroll revision 10, update to 11, rotate to a fresh key at 12 and recover the exact deliberately damaged source to revision 13 using a separately selected public key and independent floor 12. All signing keys are ephemeral fixture keys generated in memory; no organizational signing material is used. Each successful publication must produce two continuous checkpoints and the exact active key, revision and accepted revision.

A retry with a stale retained head must produce no checkpoint and preserve both journal and native source/acceptance bytes. A corrupt rotation signature, wrong recovery public key, wrong independent recovery floor and recovery replay must preserve the exact native pair. Each native refusal retains its conservative indeterminate result after the intent, rather than claiming that a generic native failure proves no publication occurred. The fixture checks the actual byte preservation independently.

The final metadata-only consented export must verify from the retained genesis through the ending checkpoint with sixteen records: four completed transactions and four indeterminate refusals, each with an intent/result pair and a distinct matching operation ID. The exact ordered actions/outcomes are checked; request documents, damaged source text and fixture paths must not escape into exported events. A final export-recorded invocation must return exactly that prior sixteen-record artifact and separately observe access checkpoints 17 and 18. A subsequent ordinary archive export must verify eighteen records and the last audit.export intent/completed pair with its own distinct operation ID. The public report therefore distinguishes sixteen policyTransactionVerifiedRecords, two recordedAuditExportVerifiedRecords and eighteen total verifiedRecords. This local write result is not a collector acknowledgment or an independent checkpoint trust channel. See [recorded export semantics](RECORDED_AUDIT_EXPORT.md).

Cleanup removes only the fixture's exact directory identities and persistent coordination file. Unexpected replacement identities are retained and fail the test. The enclosing script still requires machine policy, coordination and native publication stages to be absent afterward. The public report marks cleanup scheduled; complete job/script success is also needed to establish cleanup completion.

## Qualification boundary

Normal-user WSL checks compile the fixture and run ordinary CLI tests with native opt-in disabled. They execute no root policy transaction. Both Linux architecture fixtures compile without being run locally. Actual privileged acceptance is restricted to the already opted-in, source-built disposable GitHub-hosted Linux jobs; successful compilation is not native acceptance.

The new report is build/managed-policy-checks/linux-native-recorded-policy.json. Its source commit, platform, architecture, toolchain, assertions and counts must be matched to the exact successful hosted job and retained provider artifact. Until that evidence exists, all four new native wrapper cases remain pending. Provider ZIP digest matching alone is not a cryptographic attestation.

This test extension does not qualify signed installed products, other operating systems, reboot or power loss, broad administrative or asynchronous action coverage, mandatory administrator audit, collector deployment, retention or the full enterprise audit gate. It changes no readiness status. See [audit format and remaining integration](AUDIT_EVENTS.md), [machine recovery](MACHINE_POLICY_RECOVERY.md) and [machine acceptance history](MACHINE_POLICY_ACCEPTANCE.md).
