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

Timings use monotonic clocks and include automation round trips, authenticated response decoding and finite animation completion. Controller launch detection has the existing 25 ms polling granularity. A single cold launch and five reloads provide regression samples, not confidence intervals or an INP certification. Percentiles use nearest rank and retain full numeric precision for budget comparisons.

The observer accepts only the fixture's live ChildProcess, checks its direct parent and stable kernel start time, and reads bounded numeric [/proc/pid/stat](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html) fields and descriptor counts. Native getconf values convert CPU clock ticks and resident pages. It never reads descriptor targets, process arguments, account profiles or memory dumps. Samples are serialized at roughly 250 ms intervals; maxima are sampled maxima, not continuous peak guarantees. CPU/RAM/descriptors/threads cover the controller, excluding browser/renderer processes. Resource observation is joined before fixture cleanup.

The retained desktop-performance artifacts contain only fixed metric/stage names, numeric counts, source/binary hashes and bounded toolchain/environment metadata. No DOM, account IDs, URLs, private paths, profiles, tokens or native error messages are serialized. Output is exclusive, source inputs are bounded and records are copied before asynchronous hashing. A missing/failed observation, request, workload or report cannot qualify. Full browser results remain separate private artifacts and need not be read to inspect these fixed reports.

## Full desktop qualification still required

The sixty-second workload is a CI regression baseline, not long-duration stability. Qualify the authenticated installed candidate on all ten documented OS/architecture targets using representative minimum and typical hardware. Repeat cold/warm startup and interactions with empty, typical and 256-profile stores; retain percentiles and failure counts. Measure browser/renderer and controller resources together, scheduling load, idle and cooldown windows. Run an eight-hour working-day soak with navigation, polling, editing and owned engine traffic; preserve worst windows and resource growth. Throughput must also include actual selected/unselected TCP, UDP, DNS and IPv4/IPv6 traffic, with budgets declared before testing. Include disk exhaustion, denied resources, disconnect, cancellation, suspend/reboot, install/upgrade/rollback and recovery acceptance. Signing, provenance, traffic correctness and actual native screen-reader/UI performance remain independent release requirements. No formal gate or 100% readiness claim follows from this source-built baseline.

The measurement uses [Playwright test timeouts](https://playwright.dev/docs/api/class-test#test-set-timeout) and [page evaluation](https://playwright.dev/docs/api/class-page#page-evaluate). Browser setup and evidence limits are documented in [BROWSER_ACCEPTANCE.md](BROWSER_ACCEPTANCE.md).

The initial 49e9090 run registered 52 cases and passed all original 51 in every browser. The new case stopped at dashboard readiness after measuring 29.79-32.09 ms to the private launcher; it did not collect the remaining measurements. Source review found that its 256 synthetic profiles lacked the normal presets-initialized marker, so ordinary first-run startup also seeds built-in profiles and cannot meet the exact 256-profile readiness predicate. The fixture now creates the same exclusive marker bytes as a normally initialized populated store. Product seeding, all budgets, workload sizes, browser projects and deadlines remain unchanged. The failed run remains retained; fresh source-corrected full-browser measurement is required.

At 0fe5bc2, all original 51 cases pass in every browser; Chromium also passes the performance case. Its 256-profile dashboard takes 367 ms, API p95 is 11.5 ms, and the controller averages 1.15% of one CPU during the load. Firefox completes the full workload but reports editor p95 551.925 ms against 500 ms. WebKit stops at dashboard readiness. The editor measurement starts before the newly opened profiles view finishes its 220 ms entrance animation, so it can include another action's work; navigation now completes before editor timing starts. Readiness now returns false on the intermediate private-launch document until app state exists. Schema-two reports add only an allowlisted failure-kind code, with no error text. Navigation and the four read requests now run concurrently during load. Workloads, budgets, finite animations, browser list and deadlines remain unchanged. These are source-corrected measurement boundaries, not a claim that every observed failure has already been resolved.

At 97c5f10, every browser completes the full workload; Chromium and Firefox pass all budgets. Firefox editor p95 is now 263 ms after its navigation precondition completes, and WebKit readiness succeeds with the launcher guard. WebKit alone misses navigation p95: 503.994 ms against 500 ms. All other timing, throughput, CPU, memory, descriptor, thread and cooldown budgets pass. The product view entrance now uses a 160 ms fade/translation in place of 220 ms, shortening its fixed presentation cost while retaining the same animation, easing and reduced-motion behavior. The benchmark still waits for the animation to finish; no metric target, workload or deadline changes. Fresh full measurement is required.
