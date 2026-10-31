# Third-party engines and licenses

AccessWeaver's original source is licensed under [0BSD](LICENSE). Its Go runtime dependencies are from the Go standard library; the browser application does not load third-party JavaScript or remote fonts. The repository and release packaging do not bundle external engines or their drivers.

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

AccessWeaver's command adapter targets the Windows SDK foreground client, `wiresock-client.exe`. The WireSock Secure Connect desktop application is a separate vendor product. Their CLI behavior and licensing are not interchangeable.

The [SDK vendor page](https://wiresock.net/wiresock-sdk) describes a free evaluation tier with limited permitted use and telemetry, and separate commercial/OEM arrangements. Read the applicable agreement for your deployment. AccessWeaver's own no-telemetry design and 0BSD license do not extend to an engine launched by it.

## Adding or distributing an engine

Before adding bundled code, packages, installers or drivers, document the exact version, source, license, notices, transitive dependencies, redistribution permissions and verification procedure. Running a user-installed executable through an adapter is not evidence that the executable is trustworthy or legally redistributable.

AccessWeaver is inspired by a profile-oriented workflow; it does not include SplitWire-Turkey source code or assets. Project names and trademarks belong to their respective owners.
