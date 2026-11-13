# Support and release lifecycle

AccessWeaver is an experimental alpha. There is no production-supported or long-term-support release line. The current alpha is actively developed, as described in [the security policy](../SECURITY.md); publisher signing and installed-product qualification remain incomplete.

## Current service and ownership

The repository maintainer owns product-support intake and triage through [GitHub issues](https://github.com/Yunushan/accessweaver/issues). Support is best effort: there is no guaranteed initial response, update interval or resolution time. No on-call service, coverage hours or enterprise support contract is offered. Private security escalation follows [SECURITY.md](../SECURITY.md). A backup maintainer and dedicated escalation coverage have not been assigned.

A deploying organization owns its endpoint administration, incident response and recovery decisions. Repository issue intake does not supply those operational roles. Before managed rollout, record the responsible people and available contact channels using [the incident procedure](INCIDENT_RESPONSE.md).

## Report a problem

When repository issue reporting is enabled, use the [bug-report form](https://github.com/Yunushan/accessweaver/issues/new?template=bug_report.yml). If the form is unavailable, use an available repository issue channel with the same minimal information. On 2026-11-13, the public tracker loaded and GitHub directed new issue submissions to sign-in. Private vulnerability reporting availability remains unverified. Confirm both submission paths before relying on them for a deployment.

For a suspected vulnerability, follow [SECURITY.md](../SECURITY.md), including its private-reporting availability and fallback rules. Keep exploit details and sensitive evidence out of public issues. A product malfunction with suspected release, dependency or signing-key compromise follows the [incident procedure](INCIDENT_RESPONSE.md).

For an ordinary development report, include:

- Expected and observed behavior, reproducible steps and whether a safe workaround exists.
- AccessWeaver version and commit from existing build metadata, plus OS version and architecture.
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

## Conditions still required for production support

The repository maintainer and best-effort GitHub issue intake are assigned. Before production support is advertised, verify public issue intake and private vulnerability reporting, confirm the maintainer escalation route, and publish a supported-version and end-of-life policy the maintainer can meet. The published policy must describe the support coverage actually offered, including the best-effort commitment. Exercise an intake, private escalation, recovery handoff and closure on an intended managed endpoint. Until those commitments and exercises are verified, support operations remain partially implemented.
