# Explicit network diagnostics

Diagnostics send network traffic only after a user request. They do not change DNS, routes, proxy settings or the running engine. The selected path and protocol are included in the report. Saved profile probes keep their original schema; these additional options apply to standalone CLI/API/dashboard diagnostics.

## CLI

Options precede the hostname:

```sh
accessweaver doctor example.com
accessweaver doctor --path socks5 --proxy 127.0.0.1:1080 example.com
accessweaver doctor --path http-connect --proxy 127.0.0.1:8080 example.com
accessweaver doctor --transport stun stun.example.com
accessweaver doctor --path socks5 --proxy 127.0.0.1:1080 --transport stun stun.example.com
accessweaver doctor --tls=false --port 8080 --timeout 10 example.com
```

`stun.example.com` is a placeholder: supply an actual STUN server you trust and are authorized to contact. No public STUN server is chosen automatically. TCP defaults to port 443 with verified TLS; STUN defaults to port 3478 without TLS and requires an explicit hostname. `--port`, `--tls=true|false` and `--timeout 1..60` override defaults. The timeout bounds the whole attempt, including resolution, proxy negotiation and TLS/STUN. Interrupts cancel the attempt. Failed requested checks print a JSON failure report and return a nonzero exit status; policy denials return an error without presenting a successful report.

## Dashboard and authenticated API

Select the path and protocol on Diagnostics. Proxy paths require a `host:port` authority, with brackets for IPv6; URLs and credentials are rejected. Selecting UDP/STUN clears the hostname so you must choose its server, sets port 3478 and disables TLS and HTTP CONNECT. Returning to TCP restores the displayed default TCP target and TLS options. Reports and exported JSON identify the exact requested path, transport and proxy.

`POST /api/v1/diagnose` retains the original flat probe body and adds optional fields:

```json
{"host":"example.com","port":443,"tls":true,"timeoutSeconds":5,"path":"socks5","transport":"tcp","proxy":"127.0.0.1:1080"}
```

Missing `path` and `transport` default to `direct` and `tcp`. Invalid options produce an `input` failure check before network activity. Completed checks, including network failures, use HTTP 200 with per-check statuses; clients must inspect every status. Policy denial, source failure or observed revocation returns HTTP 403. Cancellation before work can return HTTP 408. Session authentication and loopback restrictions still apply.

## What each path establishes

- **Direct TCP/TLS:** resolve the destination once, connect only to an address from that lookup, and optionally verify the destination certificate chain and hostname with the OS trust store. DNS and TCP durations are separate; TLS requires version 1.2 or newer. This uses the OS network stack and does not independently identify a packet engine or tunnel.
- **SOCKS5 TCP/TLS:** resolve/connect to the proxy, negotiate RFC 1928 unauthenticated CONNECT, and optionally verify TLS end to end to the requested target. Domain destinations are sent to the proxy without local target DNS resolution. Authentication requirements, refusal or malformed replies fail the selected path; there is no direct fallback.
- **HTTP CONNECT TCP/TLS:** send an HTTP/1.1 CONNECT authority to the chosen proxy, require a successful 2xx response with at most 16 KiB of headers, retain early tunnel bytes, and optionally verify target TLS. Target DNS remains at the proxy. Proxy credentials, HTTPS proxy transport, authentication negotiation and redirect following are unsupported.
- **Direct/SOCKS5 UDP/STUN:** send one random-transaction binding request and read one response within the overall deadline (no retransmission). A SOCKS5 UDP ASSOCIATE holds its TCP control connection for the exchange; fragmented datagrams are rejected. The UDP reply must come from the connected direct server or chosen relay. Proxy envelopes must retain the requested port and any explicit destination IP. For domain targets, remote DNS and the returned target IP are trusted to the proxy.

The bounded STUN parser checks the transaction, message type, cookie, lengths, XOR-MAPPED-ADDRESS for IPv4/IPv6, and the CRC fingerprint when present. Missing/duplicate mapped attributes, unsupported mandatory attributes, error responses and authentication challenges fail this basic unauthenticated probe. It is not a full authenticated STUN/TURN/ICE client. The reported mapped endpoint is the server's unauthenticated observation; a SOCKS5 result describes the proxy's server-facing mapping. A STUN exchange does not establish NAT type, inbound reachability, application routing, voice quality, QUIC or WireGuard connectivity.

SOCKS5/HTTP proxy negotiation itself is unauthenticated and unencrypted. Use a trusted proxy and network; TLS authenticates only the target when enabled. Reports may contain target/proxy names and public mapped addresses. Review an exported report before sharing it; nothing is uploaded automatically.

## Managed cancellation and evidence

All probe stages retain one managed authorization. The existing policy monitor closes owned sockets on observed enrollment, removal, expiry, payload/key change or source failure; a final source check also runs before returning. Polling limitations and administrative recovery requirements are described in [managed configuration](MANAGED_CONFIGURATION.md#policy-changes-during-active-operations).

Loopback Go fixtures cover direct IPv4/IPv6, trusted and untrusted TLS, SOCKS5/HTTP tunnels with remote target DNS, HTTP rejection/oversized headers/large buffered tunnel data, STUN IPv4/IPv6 parsing/fingerprints/malformed inputs, SOCKS5 UDP framing/source mismatch, timeouts and active policy failure. A parser fuzz target is available with `go test ./internal/diagnostics -run '^$' -fuzz FuzzBindingResponse -fuzztime 30s`. API tests check legacy request compatibility and HTTP 403 on active policy failure. Browser tests intercept diagnostic requests to inspect selections without sending probe traffic. Native vendor/application routing and real network acceptance remain separate readiness gates.

Protocol references: [SOCKS5 RFC 1928](https://www.rfc-editor.org/rfc/rfc1928), [HTTP CONNECT RFC 9110 section 9.3.6](https://www.rfc-editor.org/rfc/rfc9110#section-9.3.6), [STUN RFC 8489](https://www.rfc-editor.org/rfc/rfc8489).
