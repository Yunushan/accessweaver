# Real browser acceptance

The reusable [browser workflow](../.github/workflows/browser.yml) exercises Chromium, Firefox and WebKit against the real Go controller. Each matrix job runs the complete existing suite for its browser, with isolated controller state and loopback traffic. The native desktop, installer and ten-target cross-build jobs remain separate.

Browser jobs retain ubuntu-latest, pinned Go 1.27.3, Node 26.8.2, locked Playwright 1.64.1, SHA-pinned actions, read-only repository permissions, disabled checkout credential persistence, npm ci --ignore-scripts and the moderate advisory threshold. The job timeout remains 20 minutes.

## Preinstalled browser environment

The official Playwright Noble image supplies browser binaries and their Linux libraries. Its version must match the installed Playwright packages; [Playwright documents the GitHub container configuration](https://playwright.dev/docs/ci). This workflow pins both its 1.64.1 tag and immutable OCI digest:

```text
mcr.microsoft.com/playwright:v1.64.1-noble@sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f
```

The container runs as UID 1001, with an init process and 1 GiB of shared memory. Early checks require writable home, workspace, runner temporary directory and tool cache. They fail without changing ownership, relaxing permissions or falling back to root. The real controller retains its elevation refusal and private-state checks.

The fixed /etc machine-policy parent uses a separate anonymous Docker volume populated from the image. [Docker documents this initialization behavior](https://docs.docker.com/engine/storage/volumes/). Early read-only checks require root ownership, no ordinary-user write access and one of the existing qualified filesystem types. The real controller still performs its full machine-authority checks; the workflow does not change that policy. The disposable hosted environment owns the volume; explicit volume deletion and installed-product persistence remain separate qualification work.

After locked package installation, check-image-environment.cjs checks the expected lock and installed package versions, /ms-playwright cache selection and all three public browser executable paths. It reads metadata and checks access; it launches nothing and runs no installer. The complete browser tests establish actual startup, libraries, Chromium headless-shell availability and dashboard behavior. File-presence checks alone cannot establish those results.

The image browser cache stays separate from private controller state. No APT or Playwright browser installation runs during these jobs. Image pulling and npm access still require working network services, and a version or digest change requires renewed hosted acceptance. The digest binds the retrieved registry content; no publisher-signature or desktop-release qualification is claimed for it.

## Retained failure and qualification limits

At source 9a256bba4a1b3ccc1752bf6262df4385c82c6db4, the [Firefox prerequisite record](qualification/9a256bba4a1b-firefox-prerequisite-time-limit.json) retains the configured five-minute step timeout. Provider timestamps span 312 seconds including shutdown. APT fetch markers continued until shortly before the timeout, with no package-setup marker; browser installation and dashboard execution were skipped. The record establishes neither a particular mirror/network cause nor a product assertion failure.

The image configuration removes per-job prerequisite provisioning. Its initial hosted run and subsequent isolated-volume qualification are retained below. No old job is rerun, no browser or assertion is removed, and no deadline is increased. Repository testing instructions remain in [TESTING.md](TESTING.md); all fifty readiness gates and ten desktop targets remain in scope.


The first image run at source d3d4c8f83b45d93ed1856652622f40c1b37af460 [retains 39 Chromium controller-setup failures](qualification/d3d4c8f83b45-browser-policy-filesystem-refusal.json). The image and ordinary-user checks passed, then the controller refused its /etc parent on filesystem 0x794c7630 before producing a launcher. The other two browser jobs also failed; only Chromium log details are diagnosed in this record. At that point, the isolated-volume correction still required fresh complete browser results. No native storage guard, fixture assertion, browser project or deadline is relaxed.

The [004174e qualification receipt](qualification/004174e6a619-browser-policy-filesystem.json) now verifies all 39 existing cases in each original browser: 117 passed, with no skips, failures, flakes or retries. CI run 41920343251 and all three complete browser jobs succeeded on that exact source. The receipt retains controlled case results, source comparisons, provider artifact digests verified before ZIP parsing and report hashes; raw reports and private controller artifacts remain unpublished. This establishes the stated source-built browser scenarios, not signed desktop, vendor-networking or full production qualification.


The modal keyboard save contracts cover guided and JSON editors with an explicitly delayed save response, successful persistence and a controlled refusal. While saving, feedback retains focus, Tab and Shift+Tab stay inside the dialog, native disclosure summaries remain keyboard reachable, and Escape/Ctrl+S cannot close or duplicate the pending save. When no sequential control exists, the programmatically focusable dialog is the fallback. Unrendered/invisible/inert/disabled candidates are excluded. Failed saves retain the draft and focus feedback; successful saves return focus to the opener. The full existing browser suites and original deadlines remain required.

Each browser separately retains four source/binary-bound fixed-schema contract reports under `modal-keyboard-<browser>`. They contain only seven fixed source hashes, the candidate identity, fixed scenario/check names and pass/fail status; no DOM, URLs, private filesystem paths, profiles, credentials, error messages or traces. These reports establish only the stated source-built browser keyboard flows, not a native screen-reader assessment, installed desktop or complete accessibility/readiness gate. The ordinary local Docker daemon was unavailable during preparation; real browser qualification is performed by the existing pinned ordinary-user hosted workflow.
