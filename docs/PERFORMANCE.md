# Desktop performance acceptance

The formal performance gate requires startup, UI responsiveness, CPU/RAM/handles, throughput, latency and long-duration stability across the supported desktop matrix. A source-built Linux browser measurement is one component of that requirement. The gate remains incomplete until the installed candidate and native environments have matching evidence.

## Versioned engineering budgets

[scripts/browser-tests/performance-budgets.json](../scripts/browser-tests/performance-budgets.json) defines version-one regression targets, chosen before the first measurements. They are engineering targets for a reference environment with at least two logical CPUs, not hardware-independent guarantees or an external certification. Changes require an explicit rationale and fresh qualification; a failed result must remain visible.

| Measurement | Budget |
|---|---:|
| Controller launch to private launcher, 256 profiles | 1,500 ms |
| First authenticated dashboard ready and finite animations complete | 3,000 ms |
| Five warm reloads, nearest-rank p95 | 1,500 ms |
| 24 measured navigation actions, p95 | 500 ms |
| Ten editor-open actions, p95 | 500 ms |
| Authenticated 256-profile read latency, p95 | 250 ms |
| 96-request burst, four concurrent requests | at least 20 requests/s |
| 60-second load at four requested reads/s | at least 3.8 completed requests/s, no failed reads |
| Controller CPU during load, one logical CPU = 100% | at most 50% average |
| Sampled controller resident memory | at most 192 MiB |
| Sampled controller descriptors / threads | at most 128 each |
| Memory growth after five-second cooldown | at most 64 MiB |
| Descriptor / thread growth after cooldown | at most 2 / 8 |

The new case seeds exactly 256 synthetic private profiles before starting the ordinary controller. It starts no engine, sends no diagnostic/vendor traffic, and runs no installation or OS maintenance. All requests target its own authenticated loopback API; credentials remain in the browser. Actions cover all six views and repeated editor opening, including during load. All original 51 functional/accessibility cases, projects and deadlines remain intact; the added performance case has its own 120-second limit inside the unchanged ten-minute suite and twenty-minute job limits. Native non-Linux performance remains separate.

The populated store includes the normal exclusive initialization marker, so startup retains exactly 256 profiles. Launcher readiness tolerates its intermediate document until app state exists. Navigation settles before editor timing starts; navigation and reads run concurrently during load. Absolute monotonic waits recheck the minimum after early timer wakeups, and the measured duration still rounds down. Timings use monotonic clocks and include automation round trips, authenticated response decoding and finite animation completion. Controller launch detection has the existing 25 ms polling granularity. One newly started controller and five reloads provide regression samples, not confidence intervals or an INP certification. The fixture uses new owned state/cache directories; OS and executable caches are not flushed. Percentiles use nearest rank and retain full numeric precision for budget comparisons.

The observer accepts only the fixture's live ChildProcess, checks its direct parent and stable kernel start time, and reads bounded numeric [/proc/pid/stat](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html) fields and descriptor counts. Native getconf values convert CPU clock ticks and resident pages. It never reads descriptor targets, process arguments, account profiles or memory dumps. Samples are serialized at roughly 250 ms intervals; maxima are sampled maxima, not continuous peak guarantees. CPU/RAM/descriptors/threads cover the controller, excluding browser/renderer processes. Resource observation is joined before fixture cleanup.

The retained desktop-performance artifacts contain only fixed metric/stage/failure-kind names, numeric counts, source/binary hashes and bounded toolchain/environment metadata. No DOM, account IDs, URLs, private paths, profiles, tokens or native error messages are serialized. Output is exclusive, source inputs are bounded and records are copied before asynchronous hashing. A missing/failed observation, request, workload or report cannot qualify. Full browser results remain separate private artifacts and need not be read to inspect these fixed reports.

## Full desktop qualification still required

The sixty-second workload is a CI regression baseline, not long-duration stability. Qualify the authenticated installed candidate on all ten documented OS/architecture targets using representative minimum and typical hardware. Repeat cold/warm startup and interactions with empty, typical and 256-profile stores, all four languages, both themes, narrow/wide layouts and the supported native browsers; retain percentiles and failure counts. Measure browser/renderer and controller resources together, scheduling load, idle and cooldown windows. Run an eight-hour working-day soak with navigation, polling, editing and owned engine traffic; preserve worst windows and resource growth. Throughput must also include actual selected/unselected TCP, UDP, DNS and IPv4/IPv6 traffic, with budgets declared before testing. Include disk exhaustion, denied resources, disconnect, cancellation, suspend/reboot, install/upgrade/rollback and recovery acceptance. Signing, provenance, traffic correctness and actual native screen-reader/UI performance remain independent release requirements. No formal gate or 100% readiness claim follows from this source-built baseline.

The measurement uses [Playwright test timeouts](https://playwright.dev/docs/api/class-test#test-set-timeout) and [page evaluation](https://playwright.dev/docs/api/class-page#page-evaluate). Browser setup and evidence limits are documented in [BROWSER_ACCEPTANCE.md](BROWSER_ACCEPTANCE.md).

## Verified source-built baseline

The [0b98e4a acceptance receipt](qualification/0b98e4aa0c2a-desktop-performance-baseline.json) binds [run 42317438315](https://github.com/Yunushan/accessweaver/actions/runs/42317438315) to all 156 passing cases, three complete budget reports and 144 delayed-save checks, with no skips, retries or unrecognized titles. Each benchmark has 256 profiles, five reloads, 24 measured navigations, ten editor opens, 96 burst reads and 240 load reads over at least 60,001 measured milliseconds. The environment is the pinned ordinary-user Linux amd64 image, English/dark at the configured 1280 by 900 CSS pixels, with four available logical CPUs. Numbers below are rounded for presentation; budget comparisons and the JSON receipt retain full precision.

| Browser | Launcher ms | Dashboard ms | Navigation p95 ms | Editor p95 ms | API p95 ms | Controller CPU % of one core | Sampled RSS MiB |
|---|---:|---:|---:|---:|---:|---:|---:|
| chromium | 33.10 | 304.05 | 399.89 | 182.56 | 33.10 | 1.93 | 16.42 |
| firefox | 34.22 | 416.28 | 367.54 | 319.96 | 25.00 | 1.97 | 16.39 |
| webkit | 38.46 | 659.87 | 482.94 | 344.43 | 22.00 | 2.13 | 16.36 |

The product view entrance is now 160 ms, preserving its fade, translation, easing and reduced-motion rules. The retained receipt includes the preceding failed measurements and their source corrections; no budget was raised. Provider ZIP digests are verified before parsing, and suite, performance and keyboard reports must agree on the executed binary for each browser. The 20 affected product/CLI compile checks cover all ten targets; they are compile-only. Long-duration, browser/renderer resources, signed installation, actual traffic and full native desktop gates remain incomplete.

## Native architecture expansion

The full three-browser workload now has native amd64 and arm64 jobs with the same version-one targets. Native runner/SDK/controller/Node checks and browser ELF instruction-set checks precede execution. Architecture-qualified artifact names keep each runtime separate; reports must match their actual native architecture and executed binary. This expands native measurement coverage without changing the accepted workload, deadlines or budget caps. Fresh six-job results are required before claiming native ARM64 acceptance. See [BROWSER_ACCEPTANCE.md](BROWSER_ACCEPTANCE.md#native-linux-browser-matrix). Controller-only resource scope and remaining ten-target/eight-hour requirements remain unchanged.
