# macOS product removal work

Whole-product uninstall and retained-copy reclamation remain incomplete. The sealed product helper now provides a read-only inspection of the protected core history, retained core copies, public application and desktop registrations. It does not remove or deactivate anything, forget Installer receipts, inspect incoming payloads, or access private user profiles or managed policy.

## Inspect an exact candidate

Use the external source/ref/workflow/run and architecture pins in [release provenance](RELEASE_PROVENANCE.md). Authenticate every candidate subject before reading reports. The inspection command belongs to the separate product-application helper, accessweaver-product-installer, extracted from that exact authenticated component. The ordinary core helper and standalone desktop helper do not implement it.

Stage the verified helper in private root-owned storage and recheck its actual bytes against the authenticated component before execution. Never execute the installed app, installed core or public launcher as root. The unsigned disposable-host qualification does not supply an approved publisher signature or authorize production distribution.

Arrange clean controller shutdown, then invoke the externally verified staged helper:

    sudo "$trusted_product_helper" inspect-product-removal

No path, seal, environment override or deletion flag is accepted. Inspection requires both compiled core/desktop seals, the exact active release, no pending deployment, the existing deployment writer lock and an exclusive runtime lease. It refuses a running controller, inactive or differently sealed active release, newer registration, incomplete or noncanonical retained history, unknown or missing retained copy, changed bytes, unsafe ownership/modes or aliases. A preparation referenced only by older history still requires a complete verified copy; abandoning a partial copy does not turn it into removable data.

A successful result has operation inspect-product-removal and state inspected. It reports the generation, compiled identity, bounded inventory counts and a SHA256 fingerprint binding the core records/slot identities, registration digests and public app identity. The complete known inventories are checked again before the result is returned. Any error, including a close error, yields refusal.

## Scope of the result

The fixed inventoryScope is core-history-public-app-registrations. mutationPerformed, incomingPayloadsInspected, installerReceiptsInspected, productUninstallQualified and productionQualificationComplete remain false. A refused inspection reports no completed inventory fingerprint or counts.

The JSON is an observation, not a saved deletion capability or an authorization token. Files can change after inspection returns and releases its leases. A future remover must reacquire the leases, revalidate its complete mutation set, authenticate incoming payload and receipt ownership, durably record intent and test interrupted removal/retry before deleting any program object. Neither this command nor [explicit copy recovery](MACOS_PRODUCT_RECOVERY.md) supplies that transaction.

User profiles, backups, private launch/session data and administrator policy need explicit retention contracts in that future procedure. Fixture-owned cleanup in native tests is not a product uninstaller.

## Validation

Portable contracts cover protected slot/history consistency, stale identity, pending or inactive state, conflicting inode/seal claims, newer history and capacity bounds. The guarded root-owned native copy fixture adds complete legacy/schema-2 inventories, unknown-copy refusal and unchanged noncanonical history before restoration. The real product fixture runs two complete inspections and fourteen preserving refusals on each native architecture, including serving-controller exclusion and partial-copy preservation. Its helper digests bind to the actual independently authenticated product components.

Fresh exact-source native results and independent all-subject authentication are required before claiming this implementation passed native acceptance. Signing, uninstall, interrupted removal recovery and managed endpoint acceptance remain separate open requirements.
