# Real browser acceptance

The reusable [browser workflow](../.github/workflows/browser.yml) exercises Chromium, Firefox and WebKit against the real Go controller. Each matrix job runs the complete existing suite for its browser, with isolated controller state and loopback traffic. The native desktop, installer and ten-target cross-build jobs remain separate.

Browser jobs retain ubuntu-latest, pinned Go 1.27.3, Node 26.8.2, locked Playwright 1.64.1, SHA-pinned actions, read-only repository permissions, disabled checkout credential persistence, npm ci --ignore-scripts and the moderate advisory threshold. The job timeout remains 20 minutes.

## Preinstalled browser environment

The official Playwright Noble image supplies browser binaries and their Linux libraries. Its version must match the installed Playwright packages; [Playwright documents the GitHub container configuration](https://playwright.dev/docs/ci). This workflow pins both its 1.64.1 tag and immutable OCI digest:

```text
mcr.microsoft.com/playwright:v1.64.1-noble@sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f
```

The container runs as UID 1001, with an init process and 1 GiB of shared memory. Early checks require writable home, workspace, runner temporary directory and tool cache. They fail without changing ownership, relaxing permissions or falling back to root. The real controller retains its elevation refusal and private-state checks.

After locked package installation, check-image-environment.cjs checks the expected lock and installed package versions, /ms-playwright cache selection and all three public browser executable paths. It reads metadata and checks access; it launches nothing and runs no installer. The complete browser tests establish actual startup, libraries, Chromium headless-shell availability and dashboard behavior. File-presence checks alone cannot establish those results.

The image browser cache stays separate from private controller state. No APT or Playwright browser installation runs during these jobs. Image pulling and npm access still require working network services, and a version or digest change requires renewed hosted acceptance. The digest binds the retrieved registry content; no publisher-signature or desktop-release qualification is claimed for it.

## Retained failure and qualification limits

At source 9a256bba4a1b3ccc1752bf6262df4385c82c6db4, the [Firefox prerequisite record](qualification/9a256bba4a1b-firefox-prerequisite-time-limit.json) retains the configured five-minute step timeout. Provider timestamps span 312 seconds including shutdown. APT fetch markers continued until shortly before the timeout, with no package-setup marker; browser installation and dashboard execution were skipped. The record establishes neither a particular mirror/network cause nor a product assertion failure.

The new image configuration removes per-job prerequisite provisioning. Its fresh three-browser hosted results are required before claiming successful acceptance. No old job is rerun, no browser or assertion is removed, and no deadline is increased. Repository testing instructions remain in [TESTING.md](TESTING.md); all fifty readiness gates and ten desktop targets remain in scope.
