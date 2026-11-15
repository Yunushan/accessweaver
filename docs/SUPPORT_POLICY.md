# Support and release lifecycle

AccessWeaver is an experimental alpha. There is no production-supported or long-term-support release line. The current alpha is actively developed, as described in [the security policy](../SECURITY.md); publisher signing and installed-product qualification remain incomplete.

## Current service and ownership

The repository maintainer owns product-support intake and triage through [GitHub issues](https://github.com/Yunushan/accessweaver/issues). Support is best effort: there is no guaranteed initial response, update interval or resolution time. No on-call service, coverage hours or enterprise support contract is offered. Private security escalation follows [SECURITY.md](../SECURITY.md). A backup maintainer and dedicated escalation coverage have not been assigned.

A deploying organization owns its endpoint administration, incident response and recovery decisions. Repository issue intake does not supply those operational roles. Before managed rollout, record the responsible people and available contact channels using [the incident procedure](INCIDENT_RESPONSE.md).

## Report a problem

Sign in to GitHub to report a problem. Use the bug-report form when available and follow the information and redaction guidance below for any public issue. [Repository issues](https://github.com/Yunushan/accessweaver/issues) and [bug-report form](https://github.com/Yunushan/accessweaver/issues/new?template=bug_report.yml).

On 2026-11-15, GitHub reported public issues enabled and private vulnerability reporting disabled. The default branch contained the bug-report form, and the signed-in submission path still needs a support exercise. Use the maintainer-contact fallback in SECURITY.md for private reports while private vulnerability reporting is disabled. [GitHub reporting status documentation](https://docs.github.com/en/rest/repos/repos#check-if-private-vulnerability-reporting-is-enabled-for-a-repository).

For a suspected vulnerability, follow [SECURITY.md](../SECURITY.md), including its private-reporting availability and fallback rules. Keep exploit details and sensitive evidence out of public issues. A product malfunction with suspected release, dependency or signing-key compromise follows the [incident procedure](INCIDENT_RESPONSE.md).

For an ordinary development report, include:

- Expected and observed behavior, reproducible steps and whether a safe workaround exists.
- AccessWeaver version and commit from existing build metadata or trusted endpoint inventory, plus OS version and architecture. Enter `unknown` for any build value you cannot verify.
- The known engine name, version and operating mode when an external engine is involved.
- A source-known failure code if one is available, and which independent observation supports a traffic or recovery claim.

Keep profile contents, credentials, tokens, account/device names, addresses, executable paths, command arguments, raw logs and exception text out of the report and its attachments. Use synthetic examples for reproduction. Do not execute a suspected binary solely to obtain its version.

The optional [local support summary](SUPPORT.md) provides metadata-only JSON after explicit export. Review it before sharing. It does not inspect vendor services, prove routing, provide a full incident bundle or authorize collection of other local files. Sensitive evidence requires a separately agreed private channel and the reporter's explicit approval before transfer. No automatic upload or private evidence collection is part of issue intake.

## Triage and escalation

The reporter chooses an impact category. The repository maintainer confirms severity after checking scope and reproduction. Severity determines triage priority; it does not create a response or resolution deadline under best-effort support.

| Severity | Impact | Handling |
| --- | --- | --- |
| S0 — containment or recovery | Suspected compromise, unauthorized changes, data loss, or unsafe/unavailable network recovery | Route suspected vulnerabilities privately. The deployment's incident owner handles containment and endpoint recovery; preserve recovery evidence locally. |
| S1 — blocking failure | A supported development workflow is unusable with no safe workaround | Record the affected candidate/platform and reproduction; avoid asking the reporter to repeat invasive operations without a recovery procedure. |
| S2 — degraded operation | A feature fails but a safe workaround exists | Record and verify the workaround and its limits. |
| S3 — minor issue or question | Cosmetic, documentation or informational issue | Group duplicates and identify the affected screen or documentation. |

Triage records the source/version, OS/architecture, impact, reproduction status, responsible maintainer, related issue and any planned next update. Distinguish a product defect, an upstream-engine problem, an unsupported configuration and an environment/preparation failure. Keep private evidence in its agreed restricted location.

Preserve DNS originals, recovery journals and independent checkpoints until recovery is verified. Follow the documented [Windows recovery behavior](WINDOWS_WORKFLOWS.md) and the deploying administrator's procedures. Do not delete recovery state, lower policy revisions or retry privileged changes just to clear an error.

A closure records the fixing commit or verified workaround, the actual validation scope and remaining limits. Compilation, mocked callbacks and a running engine alone do not establish installed lifecycle, traffic routing or recovery. Issue intake remains best effort even when a maintainer accepts an issue; accepting it does not create a response or resolution deadline.

## Version lifecycle

| Build line | Current treatment |
| --- | --- |
| Current alpha development | Reproduction and fixes can be considered on an identified source commit. The repository maintainer provides best-effort issue support. Production support, guaranteed response targets and a maintenance period remain uncommitted. |
| Older alpha builds and arbitrary source snapshots | No backport or ongoing-maintenance commitment is advertised. Preserve the affected build identity when reporting a regression. |
| Stable or LTS releases | No such supported line is currently offered. |

Before a production or LTS line is promoted, its owner must publish the supported versions/platforms, security-fix and backport policy, start/end-of-support dates, retirement notice period, escalation route and response coverage. Pin the approved candidate and document upgrade, rollback and retirement in the deploying organization's managed-package procedures. A newer upload alone does not establish compatibility, support coverage or safe rollback.

## Support exercise for managed rollout

Use an authorized reporter, the repository maintainer and the endpoint owner. Prepare an intended managed test endpoint with the identified candidate and a synthetic profile. Agree on the exercise window and give the public report a title that identifies it as a test.

1. Have the reporter submit a synthetic degraded-operation case through the signed-in bug form. Include the candidate version and commit, platform, reproduction, impact and a safe workaround. Have the maintainer confirm the report is usable, assign severity S2 and record the proposed workaround.
2. Exercise the security route with a separate synthetic case of suspected release compromise. Check private vulnerability reporting first. If it is unavailable, exercise the minimal public request for private contact and record whether an agreed private route was established. Keep the synthetic security details in that private route once available. [Security reporting procedure](../SECURITY.md).
3. Have the endpoint owner exercise the recovery handoff on the test endpoint and record an independent observation of restored operation. Have the maintainer close the ordinary test report with the verified workaround or fixing commit and its validation scope. [Incident response procedure](INCIDENT_RESPONSE.md).

Record the candidate identity, endpoint cohort, exercise date, severity and result for each step. Retain approved issue references and a restricted reference to private evidence. Record an unavailable or incomplete step explicitly. Exercise timing is an observation under best-effort support.

## Conditions still required for production support

The repository maintainer and best-effort GitHub issue intake are assigned. Before production support is advertised, verify public issue intake and private vulnerability reporting, confirm the maintainer escalation route, and publish a supported-version and end-of-life policy the maintainer can meet. The published policy must describe the support coverage actually offered, including the best-effort commitment. Exercise an intake, private escalation, recovery handoff and closure on an intended managed endpoint. Until those commitments and exercises are verified, support operations remain partially implemented.
