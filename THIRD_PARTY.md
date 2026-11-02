# Third-party engines and licenses

The native Zapret/Zapret2/GoodbyeDPI parameter collections in
`internal/workflow/presets/` are adapted from SplitWire-Turkey commit
`766422ed8ca9cb5360e8d9d540e80722a0508efc` under its MIT license.
The copyright and permission notice is retained alongside those files in
`LICENSE.SplitWire-Turkey`. These collections are version-dependent inputs,
not evidence that a strategy works on a particular network.

AccessWeaver's original source is licensed under [0BSD](LICENSE). Go dependencies are pinned in `go.mod` and `go.sum`, and artifact SBOMs identify modules actually compiled for each target; the browser application does not load third-party JavaScript or remote fonts. The repository and release packaging do not bundle external engines or their drivers.

The following tools are independent projects. Catalog entries and links do not grant redistribution rights, change their licenses, or imply endorsement. License references below were reviewed on 2026-10-31; check the exact release you install and all of its dependencies.

| Project | Upstream license reference | Distribution boundary |
|---|---|---|
| Zapret | [MIT](https://github.com/bol-van/zapret/blob/master/docs/LICENSE.txt) | Check bundled dependencies and platform components |
| Zapret2 | [MIT](https://github.com/bol-van/zapret2/blob/master/docs/LICENSE.txt) | Check bundled dependencies and platform components |
| ByeDPI | [MIT](https://github.com/hufrea/byedpi/blob/main/LICENSE) | Independently installed |
| GoodbyeDPI | [Apache-2.0](https://github.com/ValdikSS/GoodbyeDPI/blob/master/LICENSE) | WinDivert has a [separate license](https://github.com/basil00/WinDivert/blob/master/LICENSE) |
| WireSock SDK / Secure Connect | [SDK EULA](https://wiresock.net/license/wiresock_sdk_eula), [Secure Connect EULA](https://wiresock.net/license/wiresock_eula) | Proprietary vendor terms differ by product and use; not bundled |
| WireGuard | [wireguard-go MIT](https://github.com/WireGuard/wireguard-go/blob/master/LICENSE), [wireguard-tools GPL-2.0](https://github.com/WireGuard/wireguard-tools/blob/master/COPYING) | Licenses differ by component; catalog reference only |
| SpoofDPI | [Apache-2.0](https://github.com/xvzc/spoofdpi/blob/main/LICENSE) | Independently installed |
| sing-box | [GPL-3.0-or-later and additional upstream terms](https://github.com/SagerNet/sing-box/blob/testing/LICENSE) | Review license and dependency obligations before any redistribution |
| Xray-core | [MPL-2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE) | Review per-file and dependency obligations |

## WireSock product distinction

AccessWeaver's foreground adapter targets the Windows SDK client, `wiresock-client.exe`. Windows system workflows separately support the modern Secure Connect CLI and vendor services. Their CLI behavior and licensing are not interchangeable.

The [SDK vendor page](https://wiresock.net/wiresock-sdk) describes a free evaluation tier with limited permitted use and telemetry, and separate commercial/OEM arrangements. Read the applicable agreement for your deployment. AccessWeaver's own no-telemetry design and 0BSD license do not extend to an engine launched by it.

## Adding or distributing an engine

Before adding bundled code, packages, installers or drivers, document the exact version, source, license, notices, transitive dependencies, redistribution permissions and verification procedure. Running a user-installed executable through an adapter is not evidence that the executable is trustworthy or legally redistributable.

The preset collections identified above are the included SplitWire-Turkey assets. AccessWeaver's workflow implementation is original code. Project names and trademarks belong to their respective owners.

## Development-only browser tools

Browser acceptance uses Playwright under [Apache-2.0](https://github.com/microsoft/playwright/blob/main/LICENSE) and `@axe-core/playwright`/axe-core under [MPL-2.0](https://github.com/dequelabs/axe-core/blob/develop/LICENSE). Exact versions and package integrity hashes are retained in `scripts/browser-tests/package-lock.json`; package distributions retain their upstream notices. These tools run only in development/CI and are not embedded in the distributed dashboard or Go core.

## Generated software inventories

Portable archives include a binary-bound CycloneDX SBOM and checksum-bound license evidence. VM fixture bundles and unsigned Windows installer compilation have separate inventories; they do not add runtime dependencies to the core. [SBOM procedures and boundaries](docs/SBOM.md) describe schema validation, copied notices and unfinished native/redistribution review. Inno Setup-generated installers retain their compiler distribution's custom license notice; no SPDX identifier or complete native dependency closure is invented for that runtime.


## Native macOS protection dependencies

The `internal/darwintrust` package uses `golang.org/x/sys` v0.49.0 under [BSD-3-Clause](https://github.com/golang/sys/blob/v0.49.0/LICENSE) for descriptor-relative filesystem operations, and `github.com/ebitengine/purego` v0.11.2 under [Apache-2.0](https://github.com/ebitengine/purego/blob/v0.11.2/LICENSE) for native extended-ACL and atomic directory-rename APIs without CGO. Their exact module hashes are pinned. It supports the partial native macOS policy reader and paired publisher. Ordinary unit fixtures and read-only parent checks do not enroll machine policy; separate explicitly guarded disposable-host tests exercise enrollment. The fixed OS library remains an operating-system dependency; complete native library and signed-distribution qualification remains separate.
