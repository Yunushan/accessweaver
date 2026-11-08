# DNS wire acceptance

The current native DNS qualification proves ordinary resolver operation and independent DNS/DoH state restoration. It does not prove encrypted transport. The DNS readiness gate remains failed pending its full failure/reboot acceptance.

## Decoder and source qualification

`scripts/dns-wire-evidence.cjs` is a pure, bounded PCAPNG decoder for the four fixed Google/Quad9 addresses configured by the Windows product. It accepts one PCAPNG section, Ethernet (including up to two VLAN tags), IPv4/IPv6 and TCP TLS traffic to those endpoints. Unsupported formats, fragmented IP, missing TCP starts, gaps, conflicting retransmission, truncated records, mismatched resolver SNI and reported capture drops refuse observation. Capture, packet, flow, segment, handshake and stream sizes have explicit bounds.

A positive decoder observation requires a client/server hello and encrypted application-data record framing in both directions on the same TCP flow, with no observed TCP/UDP port 53 packet to the configured endpoints. Consistent retransmission and reordered segments are reconstructed, including sequence wrap. Results contain fixed provider labels and bounded counters/booleans. Packet bytes, addresses, timestamps, names and arbitrary exception text are not returned. There is no command-line entry that opens arbitrary capture files.

TLS framing does not independently authenticate a peer, decrypt DNS, establish the query's transport, prove lossless capture, or exclude traffic outside the supplied capture. The decoder therefore always returns `ordinaryResolverBound=false`, `negativeControlPassed=false` and `productionQualificationComplete=false`. A native coordinator must supply the independent controls below; a decoder result alone cannot qualify DNS privacy.

The synthetic contracts include malformed and incomplete input, two byte orders, four providers, TCP retransmission/reordering, missing server evidence, cross-flow mixing, plaintext DNS, drop metadata, privacy projection and a deterministic 4,096-input mutation sweep. Run these pure fixtures with:

```sh
node scripts/dns-wire-evidence.test.cjs
```

The separate `dns-wire-contracts.yml` workflow runs those source contracts on Linux, Windows and macOS AMD64/ARM64 with pinned Node 26.8.2, source hashes and fixed public JSON. Its guarded reporter only queries Packet Monitor help, status and filter listing on Windows, with bounded in-memory output and fixed capability classifications. It does not capture packets, change filters, stop an existing session, change DNS/firewall state or run the product. Unrecognized output remains unrecognized. Hosted results must be verified for the exact source before capability availability is assumed.

At source `df354fb0b9d8`, the [verified source receipt](qualification/df354fb0b9d8-dns-wire-source.json) records all six hosted jobs passing: 216 contract groups and 24,576 synthetic mutation inputs across the six hosts. All six provider ZIP digests and report source hashes verified. Both Windows architectures reported the required start/filter/conversion options, a stopped session, an empty filter set and five completed read-only queries. These observations permit preparation of the controlled native driver; they are not packet-capture or encrypted-transport acceptance.

## Required native DoH procedure

The future hosted driver must retain the existing fresh non-domain VM, native architecture/source-built controller, absent interop variables, private evidence and independent baseline/state/recovery checks. Both Windows architectures require their own result.

1. Verify that no packet-monitor session or filters already exist; unknown state refuses. Record the complete independent DNS/DoH baseline and a healthy ordinary resolver. Do not remove someone else's filters or monitoring session.
2. Install only uniquely owned endpoint-and-port capture filters for the four product resolver addresses. Verify the exact filter set before capture. Capture whole packets at NIC components into a bounded private buffer/file; do not collect unrelated endpoints, ETW providers or application logs.
3. Begin observation before invoking the real product's DoH configuration, so a fresh TLS handshake is available. Verify actual configured family rows and no UDP fallback. Block outbound TCP/UDP port 53 while probing the ordinary OS resolver after cache clearing; keep the required fixed-domain queries distinct from bootstrap checks.
4. Stop the owned observation, convert its private ETL to PCAPNG and decode it on the disposable VM. Refuse bounded-output overflow, incomplete capture, nonzero loss indicators, unsupported conversion or insufficient TLS evidence. Raw ETL/PCAPNG, keys, query payloads, host identities and utility output must not be uploaded.
5. Establish causality separately: with plaintext DNS still blocked, block TCP 443 to all four configured resolvers and require a fresh ordinary-resolver query to fail. Remove only those owned TLS blocks, verify removal, clear the resolver cache and require the same query to succeed again. Cached answers or an existing unrelated connection cannot substitute for these controls.
6. Always restore the actual product originals and independently verify complete state. Retain originals and containment on failed/unverifiable recovery until the disposable VM is destroyed. After verified state recovery, retire only owned rules/filters, verify retirement and test the healthy original resolver. Join all owned children/capture work before publishing.
7. Publish only source/binary identities, closed stage/failure codes, fixed provider labels, bounded counters and the independent control booleans. Report actual DoH wire qualification only when all controls and cleanup pass together.

This procedure is not yet implemented or natively qualified. DNSCrypt requires separate evidence for the selected encrypted upstream protocol; a local DNSCrypt listener or a running service is insufficient. Real interface-index change, failure variants, reboot/power-loss, installed managed endpoints and the other readiness gates remain separate requirements.

## Format and tool references

Packet Monitor applies all conditions within a filter and combines filters as alternatives; its defaults capture multiple stack components and only a packet prefix. The driver must explicitly narrow the endpoints/components and request whole packets. See [Microsoft's command formatting](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon-syntax), [capture options](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-start) and [filter syntax](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-filter-add).

PCAPNG conversion loses Packet Monitor's component/drop distinctions, so conversion alone cannot prove delivery or losslessness. See [Microsoft's ETL conversion documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-etl2pcap). The decoder's section/interface/enhanced-packet framing follows the [PCAPNG format draft](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-06.html).
