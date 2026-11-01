# Disposable WireGuard test peer

This optional test module is separate from AccessWeaver's dependency-free core. It uses the official WireGuard-Go userspace netstack to serve an HTTP fixture and UDP echo over IPv4 and IPv6. It does not create a host tunnel, change routes/DNS, install a driver, register a WARP account or use real VPN credentials.

The patched fixture dependencies require Go 1.26 or later; CI uses Go 1.27.3. Build with `scripts/build-windows-fixtures.ps1`. Run the resulting binaries only inside the disposable test VM. `ACCESSWEAVER_TEST_VM=1` is required. `wgpeer self-test DIRECTORY` checks the fixture itself using two userspace peers; `wgpeer serve DIRECTORY` writes an ephemeral client configuration, a readiness record and traffic counters. Keep the private client configuration inside the guest. Only counters belong in public reports.

The default WireGuard bind listens on a dynamically allocated UDP port in the guest. The client configuration uses its loopback endpoint. No host firewall rule or host listener is required. The reserved test destinations are `198.51.100.1` and `fd42:6177::1`, TCP port 8080 and UDP port 7000.

Implementation API reference: [WireGuard's official netstack server example](https://git.zx2c4.com/wireguard-go/tree/tun/netstack/examples/http_server.go). The WireGuard revision and all transitive module checksums are pinned in this module. The build script copies dependency license notices into the private test bundle; this fixture is not included in core release archives.

Known-vulnerability checks cover Linux/amd64 and Windows/amd64 source configurations. Dependencies are updated through the fixture's separate module; the core remains standard-library-only. A source scan or compilation does not requalify the fixture's handshake/traffic behavior: rerun its self-test in the disposable guest after dependency updates. The unused, unmaintained `golang.org/x/crypto/openpgp` packages may produce a module-level advisory even though they are not imported or linked by this fixture; reports retain that advisory instead of suppressing its ID.
