# Artifact-bound software inventory

Portable archives contain `SBOM.cdx.json`, a deterministic CycloneDX 1.6 document for their exact executable. Optional Windows VM fixtures have separate `.exe.cdx.json` documents. The Windows installer includes its staged application SBOM and produces an external installer `.exe.cdx.json` sidecar. Fixture modules and installer runtime are not represented as dependencies of the install-free core.

## Generation and identity

`scripts/sbom.py` reads the executable's Go build information with `go version -m -json`; it never starts target binaries. It requires `CGO_ENABLED=0`, matching compiler version/target and the selected main package. Using that same compiler, target, tags and CPU build settings, it obtains the actual Go package import graph and compares its selected module paths, versions and Go module sums with the binary. Replacement modules, incomplete package metadata and mismatched identities stop generation.

The inventory records the executable SHA-256, version, source commit/state, target, Go standard library, selected non-standard modules and their actual import relationships. It also hashes non-standard-library embedded assets selected by `go:embed`, including browser assets, original workflow code and the adapted SplitWire parameter collections. The four MIT preset/notice assets identify upstream commit `766422ed8ca9cb5360e8d9d540e80722a0508efc`. Dependency nodes have explicit leaf declarations and references must be unique, resolved and reachable from the application.

Core identity comes from the same `BUILD-INFO.json` used in packaging. Optional fixture identity records the repository commit/state and target/compiler read from the built fixture; fixture binaries are not executed outside their disposable-VM procedure. Deterministic UUIDs derive from artifact bytes/source, timestamps use the recorded build/source epoch, and components/edges/notices are sorted. No module-cache paths, credentials, runtime profiles or generated VPN keys enter the document.

## License evidence and limits

The generator copies available license/copyright/notice files from selected module roots and the ancestors of their compiled packages. The Go runtime notice comes from the exact compiler distribution. Each component's `accessweaver:license-evidence` property lists relative notice filenames and SHA-256 values. Known source declarations use SPDX identifiers; copied evidence is retained rather than inventing an identifier for an unknown module license. This inventory is not a legal opinion or a substitute for a complete redistribution review.

Original source uses the repository's 0BSD notice. Adapted SplitWire parameters retain their MIT notice. The standard library and known `golang.org/x` modules retain Go's BSD notice; other fixture modules retain their own copied notices. The [CycloneDX specification](https://github.com/CycloneDX/specification) schemas are vendored only in development tooling with their Apache-2.0 license and immutable source commit/hash records. They are not application dependencies.

The installer sidecar binds the actual setup executable hash and retains the staged application inventory as a separate component. It identifies the Inno Setup runtime through the measured compiler-engine banner/version, records the compiler executable hash and preserves the installed compiler's license notice. The compiler hash is a build ingredient, not a claim that the compiler executable is installed with AccessWeaver. Full native compression/helper dependency and notice closure still needs review. All documents deliberately retain `compositions.aggregate: incomplete`; generation/schema success does not earn complete SBOM/readiness qualification.

OS-provided DLLs/frameworks, the complete internals of the Go toolchain/runtime, build services and independently installed engines are outside this compiled-module/embedded-asset inventory. These boundaries are explicit. Do not infer whole-system inventory, vulnerability absence, license compliance or a qualified network engine from an SBOM.

## Validation and distribution

The development-only module `scripts/sbom-tools` pins the JSON Schema validator and dependencies. It validates against the committed CycloneDX 1.6, SPDX identifier and JSF schemas after checking their exact SHA-256 values. It rejects remote/unregistered schema loading and explicitly requires the CycloneDX 1.6 profile. `SOURCE.json` records the upstream specification commit. Build tooling needs the pinned supported release Go compiler; application source still has its separately documented Go minimum.

Portable packaging validates every generated document against those schemas before archiving. The archive verifier requires the SBOM, compares its executable/build identity, checks graph structure and verifies each referenced notice's actual archived bytes. Removing the SBOM, changing a binary or altering a notice fails verification. The existing release build-provenance bundle authenticates the complete archives containing the SBOMs; a separate CycloneDX-predicate attestation is not currently emitted.

Windows installer compilation validates both the payload and installer sidecar against the schema, retains the sidecar with the unsigned installer and copies notices into public compilation evidence. CI's fixture check builds the Windows fixtures without executing them, generates their SBOMs and validates them on Linux. The fixture build script also emits SBOMs/notices in the private disposable bundle. Updating dependencies does not requalify VM traffic, native installation or recovery.

To inspect a document with trusted source tooling:

```text
go -C scripts/sbom-tools mod download
go -C scripts/sbom-tools mod verify
go -C scripts/sbom-tools run . --schemas ../sbom/schema ABSOLUTE_SBOM_PATH
```

This validates structure/profile, not publisher identity. For downloaded portable artifacts, [verify build provenance first](RELEASE_PROVENANCE.md), using an independently approved source commit/ref. Only then inspect/extract the authenticated archive. Public fixture/installer reports belong to their exact source/binary hashes, not automatically to a later rebuild.

## Remaining acceptance

Complete native installer/runtime notice review, independently validate representative downstream SBOM ingestion and maintain reviewed license/version changes. Include signed production installers and their full build ingredients when that release path exists. Qualify every supported platform/architecture and operational SBOM update/revocation process. The supply-chain gate remains partial until all of those requirements and complete license closure are evidenced.
