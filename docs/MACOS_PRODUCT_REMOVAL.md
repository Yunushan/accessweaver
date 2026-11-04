# macOS product removal work

Whole-product uninstall and retained-copy reclamation remain incomplete. The sealed product helper provides a read-only ownership inspection of protected core history, retained copies, incoming payloads, the public application, registrations and selected Installer receipts. It removes nothing, advances no generation, forgets no receipt and accesses no private user profile or managed policy.

## Inspect an exact candidate

Use the external source/ref/workflow/run and architecture pins in [release provenance](RELEASE_PROVENANCE.md). Authenticate every candidate subject before reading reports. The command belongs to the separate product-application helper, accessweaver-product-installer, extracted from that exact authenticated component. Ordinary core and standalone desktop helpers cannot substitute for it.

Stage the verified helper in private root-owned storage and recheck its bytes against the authenticated component before execution. Never execute an installed app, core or public launcher as root. Disposable unsigned-host qualification does not provide a publisher signature or approve production distribution.

Arrange clean controller shutdown, then invoke the externally verified staged helper:

    sudo "$trusted_product_helper" inspect-product-removal

No caller path, seal, environment override or deletion flag is accepted. Both compiled core/desktop seals must match the active release. The helper requires no pending deployment, the existing writer lock and an exclusive runtime lease. Canonical protected history must identify every complete retained copy. Abandoning a partial copy does not make its contents removable.

## Ownership checks

Schema two additionally requires every incoming directory to match an identity from protected history. Complete manifests, native payloads, detached metadata, paths, ownership and modes are verified through protected descriptors. Unknown, missing, linked, changed or conflicting input remains untouched and causes refusal.

Receipt identifiers are fixed core/application IDs or content-addressed registration IDs. The expected core receipt location comes from the compiled manifest seal; application and registration locations are fixed. Root-owned single-link receipt plist/BOM files must have the expected modes and bounded sizes. Unknown receipts in the product namespace or missing expected receipts cause refusal.

The helper invokes only the fixed system pkgutil for read-only metadata and file-list queries, with a minimal environment and root working directory. Metadata must match the expected ID, version, root volume and exact location. File lists must match the paths derived from the verified incoming, public-app and registration inventories. Unsafe, extra, duplicate or missing paths are refused. Queries share a thirty-second deadline, each query has a five-second limit, and stdout/stderr capture is bounded. Raw tool errors are not returned.

The incoming and receipt snapshots are checked again before returning. The fingerprint binds their root/file identities and hashes as well as protected core history, registration digests and public app identity. It does not replace signature validation or a future deletion transaction.

## Scope of the result

A completed schema-two observation has operation inspect-product-removal, state inspected and inventoryScope core-history-public-app-registrations-incoming-receipts. Incoming/receipt counts, incomingPayloadsInspected, installerReceiptsInspected and installerReceiptPathsVerified describe only completed read-only verification. Every refusal, including close/deadline failure, clears completion flags, counts and fingerprint. mutationPerformed, productUninstallQualified and productionQualificationComplete remain false.

The JSON is an observation, not a saved deletion capability. Files can change after its leases are released. A future remover must revalidate the complete mutation set, publish durable removal intent in a state layout that existing readers refuse, perform identity-bound mutations and prove interrupted removal/retry. It must preserve user profiles, backups, private launch/session data and administrator policy according to its explicit retention contract. Fixture-owned cleanup is not an uninstaller.

## Qualification

The earlier [source-bound record at 7fa9afc17892](qualification/7fa9afc17892-macos-removal-inspection.json) qualifies only schema-one core/history/public-app/registration inspection. It does not qualify these added incoming/receipt checks.

Portable tests cover receipt ID/version/volume/location binding, exact file-list sets, aliases/traversal, duplicate identities, extent bounds and bounded-output cancellation. The disposable product fixture requires twenty-two packaged-helper inspections per architecture: three complete observations and nineteen preserving refusals, including incoming/receipt changes, aliases, an unknown receipt and successful restoration. Existing live-controller, stale helper, public/registration and partial-copy cases remain required. Fresh native outcomes and independent all-subject authentication must qualify the new scope before any readiness claim.

A private removal barrier is being developed behind the existing writer and runtime leases. It stages a canonical inactive deployment record, a canonical complete plan and a canonical removal-intent record in one protected directory, syncs all three files and the directory, checks the unchanged active preimage, then swaps the directory atomically with the visible state. The intent binds the prior generation, active slot identity, retained high-water release, desktop-record seal, inventory fingerprint, complete plan hash and reserved displacement name. The plan also binds authority/coordination vnodes and exact protected history identities/hashes. The displaced active record remains retained. Existing controller and launcher readers require a single-file state directory, so they refuse the bundle after the writer exits.

Only owned test fixtures call this primitive. It has no command or package-phase entry point, deletes no payload and forgets no receipt. The private publisher persists the complete canonical plan. Its non-creating reopen path reacquires both existing exclusive leases and validates the exact compiled core/desktop seals, intent/plan/state relationships, original coordination identities, displaced preimage and full retained history. This validates metadata only. A production remover still needs filesystem reconciliation, identity-bound mutations, public-app quarantine, journaled known absences, interrupted retry and reinstall handling. Incomplete staging directories are preserved; ordinary installer recovery does not yet interpret them. Returned-error boundary tests establish publication behavior, not SIGKILL, reboot or power-loss recovery.

The [schema-two ownership qualification at 87d6a161bc23](qualification/87d6a161bc23-macos-removal-ownership.json) authenticates all 122 candidate subjects, validates ten real provenance rejection probes and twenty passive binary SDK inspections, and binds all 44 native helper inspection commands to their exact packaged bytes. Both architectures completed three full inventories and nineteen preserving refusals, including the added incoming/receipt checks and exact fixture restoration. All 22 source-bound CI jobs passed. This qualifies read-only observation on unsigned disposable hosts. It does not qualify the later private barrier, a deletion capability, interrupted retry, publisher trust or whole-product uninstall.

The current implementation also builds a private canonical per-object plan in memory. For each retained core and incoming copy, public app, registration store and selected receipt file, it captures protected device/inode identity, file mode, size, content hash and modification/change timestamps. Directories and parent identities are recorded; catalogs come from the verified sealed manifests, protected registrations and selected receipt snapshot. Unexpected names, aliases, missing parents, duplicate vnodes, cross-device entries or conflicting core/input identities refuse. Mutation roots exclude unrelated receipts, user data, policy, backups and authority-history metadata. Protected history is retained as a separate validation binding.

Both complete plans must match before the ownership fingerprint becomes complete. The shared inspection deadline and cumulative two MiB/16,384-object metadata bounds apply; capacity or deadline failure preserves the installation and returns refusal. The canonical decoder is a structural contract, not a trust anchor or authorization to delete. Ownership inspection remains read-only. Only owned fixtures call the private publisher/reopener; they do not reconcile current payload objects or authorize deletion. Missing/replaced coordination files or changed/missing/extra history refuse without recreation or repair. Mutation reconciliation, directory relocation/quarantine, journaled known absences, receipt forgetting and reinstall handling remain unfinished. Fresh exact-source native qualification is required for this stronger fingerprint.
