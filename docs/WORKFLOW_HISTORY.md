# Workflow history inspection

The history browser captures a private inventory, pages its metadata, and opens or exports an exact selected record. It is available from the system tools panel and the `system history` CLI. It does not delete or move records, working directories, application backups or protected machine journals. All entries remain protected from retirement.

Choose **Capture inventory** to build or refresh the captured view. Capture is an explicit action: reading a page or selected record never creates a missing data directory, coordination file or inventory. Capture can start when no workflow is active in that data directory; if another operation owns it, capture returns busy without starting a worker. The capture has its own cancellation control and does not change current-job cancellation, operation review consent, folder inputs or recovery selections.

Inventory entries include ordinary record files, job working directories and unknown objects. The count is an entry count, not a count of completed jobs. Malformed and legacy records stay visible. Oversized, unreadable and special objects remain protected and identify why raw export is unavailable. Metadata pages contain bounded known action/state values and presence flags. Complete results, raw errors and filesystem paths are excluded from these pages.

## CLI

Bare `system history` keeps the existing complete JSON-array export, filename order and resource limits. The additive commands are:

```text
system history lifecycle
system history capture
system history list [--limit N] [--snapshot SNAPSHOT] [--cursor CURSOR]
system history get REF --revision REVISION
system history export REF --revision REVISION [--out PRIVATE_FILE]
```

Use the snapshot, opaque cursor, reference and revision returned by the program. They are not filesystem paths or execution approvals. References select an observed inventory entry rather than trusting the `id` inside a saved record. Separate CLI invocations use the same persisted inventory. The captured order is stable within that inventory; it does not promise chronological order.

For example, in PowerShell:

```powershell
$inventory = accessweaver.exe system history capture | ConvertFrom-Json
$page = accessweaver.exe system history list --snapshot $inventory.snapshot --limit 64 | ConvertFrom-Json
$record = $page.items | Where-Object rawAvailable | Select-Object -First 1
accessweaver.exe system history get $record.recordRef --revision $record.revision
accessweaver.exe system history export $record.recordRef --revision $record.revision --out .\private-record.bin
```

`--out` creates a new private file exclusively and refuses an existing destination. Windows creates a protected current-user/SYSTEM DACL before any payload write. Current macOS direct-file export requires a local APFS filesystem with ownership enabled and no inherited ACL. Protection failures preserve an empty newly created file and return an error before writing contents; existing files and ACLs are never repaired. Raw bytes are checked against the selected revision before opening the destination. A later write, flush or close failure returns a nonzero status and can leave an incomplete new file; the previous destination is never overwritten. Default raw stdout adds no newline or JSON wrapper. Use the browser download or `--out` for binary evidence in Windows PowerShell 5.1: native byte-preserving redirection was introduced in [PowerShell 7.4](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_redirection?view=powershell-7.5).

Selected metadata-only entries can use an explicitly empty revision with `get`; raw export requires a complete SHA-256 revision. Unknown or repeated flags, malformed references, missing revisions and extra arguments are rejected rather than falling back to the broad legacy export.

## Controller storage observation

The desktop **Controller evidence storage** card, `system storage [status]` and `GET /api/v1/system/storage` read the current controller's conservative source-accounting commitments. The GET accepts no query parameters, creates no missing tracking storage, limits its JSON response to 4 KiB and uses its own read slot and five-second request budget. Slow history transfers, current-job cancellation and profile editing do not share that slot. An authenticated ordinary desktop can inspect it when profile loading fails; profile-audited mode continues to deny this system surface.

The states are `uninitialized`, `tracked` and `pending`. Uninitialized tracking excludes legacy and untracked evidence; it does not mean the disk is empty, and the desktop hides its zero-counter table. A tracked state is an observation, not an admission grant or proof that finalization finished. The generation and known action identify the tracked source commitment. Read failure clears previously displayed accounting rather than turning it into an empty or clean state.

The tracked protocol covers only planned controller evidence for each workflow start and its original lifecycle controls: request/script snapshots, local logs, reports, job records and completion metadata allowances. Separately bounded history-capture and reconciliation-maintenance components, legacy evidence and uncontrolled files are excluded. The numbers describe tracked generations, reserved logical bytes, retained logical charge, uncertain logical charge and logical allowance for finalization. These buckets must not be added into a disk-use estimate: a known current owner can hold a reservation while finalization remains active; an unconfirmed original owner is reported as uncertain commitment rather than available capacity. Zero reserved bytes with a nonzero uncertain charge is not free space. Prior retained charge can remain in either state. These logical allowances do not measure total disk usage, available space, filesystem overhead or native-writer consumption. Legacy accounting is explicitly `not-included`; aggregate quota enforcement, physical-capacity guarantees, native-writer containment and worker-journal bounds are all false in this protocol. No cleanup, deletion, retirement, quota override or admission permission follows from these values.

Start and folder admission can return HTTP 409 with fixed `workflow-storage-capacity` or `workflow-storage-pending` codes. The desktop preserves request and recovery inputs and the current result, clears the reviewed plan and consent, and exposes the storage observation. This remains an observed refusal across navigation, generic status refresh and old reconciliation-receipt reads; those reads cannot grant admission. A storage refusal also invalidates older reconciliation review/receipt eligibility. Only a newly adopted explicit backend operation review or a changed session/mode clears its feedback; a new confirmed attempt still faces backend admission checks. No operation is queued or replayed automatically. Current-job cancellation and history inspection remain independently available; neither observation implies that an accepted run has stopped.

Storage reads use fixed private categories for invalid requests, policy denial or unavailable policy, busy observation, ended requests, pending evidence, source-capacity refusal and unavailable coordination. Their text contains no operating-system paths or saved payloads. This operator surface exposes the source protocol's actual limits; it does not complete native aggregate-quota, reviewed-retirement, vendor-cleanup or managed-endpoint qualification.

## Local completion tracking

The desktop **Completion tracking** card and `system history lifecycle` read a bounded local receipt projection without capturing history or creating missing storage. Refresh is independent of slow history downloads, operation review and current-job cancellation. Authenticated inspection remains available when profile loading fails; profile-audited sessions continue to deny system history. The HTTP route is `GET /api/v1/system/history/lifecycle`; it accepts no query parameters and uses a separate single-reader gate.

The states are `none`, `intent`, `sealed`, `released` and `blocked`, with an optional tracked job ID and a local `admissionBlocked` flag. `none` leaves legacy evidence protected. `released` records observed local worker, record and original lease closure; it does not certify vendor cleanup, escaped descendants, physical power-loss durability, retirement eligibility or disk capacity. All states retain `retirement-unavailable` protection. This projection alone is never permission to start another operation.

Unresolved or malformed evidence prevents new workflow admission. Start and folder actions return HTTP 409 with the fixed `workflow-lifecycle-pending` code. The desktop retains request and recovery inputs, clears review consent and exposes completion status and history inspection without replaying a mutation. Read errors never become a clean completion state. A later released current receipt does not clear the desktop's observed admission refusal: other orphan or staging evidence can still block the backend admission scan. Inspect and preserve unresolved evidence. The separate reviewed reconciliation below can retry a local release acknowledgment only when the original owners provide positive closure evidence; it never retries the original workflow, deletes evidence or grants retirement. Storage quotas remain separate work.

## Reviewed local reconciliation

The desktop **Review local closure** card offers an explicit review of a local release acknowledgment. Refreshing status is read-only and independent of history transfers, current-job cancellation and operation review. An unavailable status is not proof of release. Unknown or crashed owners stay unavailable: a new session cannot infer that their resources were closed. Under signed managed authority, the separate `allowWorkflowLifecycleReconciliation` permission must be explicitly enabled; profile changes, profile audit settings and history-retirement permission do not grant it.

Choose **Review local release**, inspect the generation, preassigned reconciliation identifier, expiry, review fingerprint and closed metadata stages, then provide the separate consent before **Apply reviewed reconciliation**. A review expires after five minutes. Editing identifiers, leaving the panel or changing session or mode invalidates the review and consent. Applying submits its plan once. Original failed outcomes and recovery evidence remain unchanged. A completed receipt records only the original local owners' closure and preserved metadata stages; it does not certify vendor cleanup, escaped descendants, general workflow admission, deletion or retirement.

Keep the reconciliation identifier before applying. A canceled browser wait, lost response or error may occur after durable intent was accepted. **Read operation receipt** checks that known identifier; only a pending response starts bounded read-only polling, for at most 20 reads. **Stop checking receipt** ends those reads without undoing or repeating an operation. Navigation retains the attempted identifier in the same session; a session or audited-mode change clears private reconciliation state from the page. Nothing automatically replays Apply. An incomplete operation requires a new explicit **Review resuming this operation** and fresh consent, and may still be refused if positive ownership evidence is unavailable or policy or evidence changed.

Only a completed receipt matching this page's own reviewed operation, generation, intent, seal and complete preserved-object list clears its observed workflow-admission refusal; the page then reads actual completion tracking again. Acceptance is one-shot and bound to the refusal observed when that review began. Re-reading an older completed receipt, or receiving its first response after a later admission refusal, cannot clear the newer refusal. A generic released status, another operation's receipt or a historical receipt does not clear that refusal. A later backend admission scan remains authoritative and can still refuse other unresolved evidence.

The additive routes are `GET /api/v1/system/history/reconciliation`, `POST .../reconciliation/preview`, `POST .../reconciliation/apply` and `GET .../reconciliation/receipts/{operationId}`. Preview accepts an empty object or one generation or operation identifier. Apply requires its live plan identifier and explicit confirmation. Status is bounded to 4 KiB and plans and completed receipts to 64 KiB; references and digests describe closed metadata stages, never client-selected paths. Public failures use fixed reconciliation categories, including policy denial, expired or changed reviews, pending operations and unavailable storage. Read failure never fabricates a completed receipt. These source contracts and synthetic desktop interactions are separate from native deployment qualification.

The CLI exposes the same inspection and review boundaries:

```text
system history reconciliation [status]
system history reconciliation preview [--generation GENERATION | --operation OPERATION]
system history reconciliation receipt OPERATION
system history reconciliation apply OPERATION --review-revision SHA256 --confirm
```

A fresh CLI invocation can apply only a safely resumable durable operation: it creates a new preview of that operation, compares the supplied stable review revision, and applies the new in-memory plan in that same invocation. It cannot reuse another invocation's plan identifier or invent a live original-owner witness. Preview the known operation, inspect its complete plan, and supply its `reviewRevision` with explicit confirmation. After a lost response, read `receipt OPERATION` before reviewing any further resumption. A refusal preserves the evidence and does not fall back to a force action.

## Freshness and exact bytes

A cooperating workflow changes the store revision before attempting a record write. Existing inventory page cursors then fail with an explicit stale result, including when that write later fails. Capture again after the operation finishes. Refresh publishes a new inventory and invalidates references from the previous one. A page never silently drops or adds records to continue an old cursor.

A selected record is reread and SHA-256 checked before output begins. An unchanged selected record can still be inspected or exported after an unrelated store write, while the same captured inventory remains current. A changed selected file fails rather than being substituted under an old revision. Raw downloads preserve the original bytes, including malformed JSON, unknown fields, invalid UTF-8 and whitespace. The browser checks the returned revision before offering the download.

The desktop skips JSON preview for source records above 2 MiB and reads at most 4 MiB for a small-record preview. A record that exceeds this preview budget keeps its captured metadata and complete private raw download. API and CLI typed detail preserve complete supported job values. Records that cannot be safely decoded or embedded remain available as raw evidence where readable; they are not silently clipped or rewritten. Historical detail has a separate display from current-job status. A recorded `succeeded` state is a reported outcome, not proof of publisher identity, successful lease release, rollback completeness or permission to retire evidence. These checks provide freshness and consistency for cooperating processes, not authentication of user-writable records against a hostile account.

## Limits and ownership

Pages default to 64 entries and accept at most 128. They read a bounded set of slots from the captured index without rereading the complete results or rescanning the directory. Opaque references and cursors are limited to 256 bytes. Legacy full history retains its 4,096-entry and 64 MiB aggregate read limits.

Explicit capture can enumerate at most 65,536 entries and read at most 8 GiB of source data. A readable individual record is limited to 64 MiB. The single current index is limited to 128 MiB plus its 4 KiB header; capture also needs space for its sibling staging file. Capacity failure preserves source evidence and does not publish a partial inventory as complete. This permits bounded browsing above the legacy full-export limit without changing that export's guard.

Capture retains at most one staging slot for an unfinished derived inventory. A durable reservation binds that slot before index bytes are written; an uncertain write, publication or closure preserves its evidence and prevents another capture from accumulating another stage. A fresh process or an available OS lock is not proof that retained metadata is safe to discard. This bounds capture staging growth; it is not a total history-storage quota or permission to remove evidence.

The named capture pool allows a current index and one reserved data stage of at most 134,221,824 bytes each. The current reservation and its publication stage are limited to 4 KiB each. A failed 49-byte store-revision bootstrap also prevents another capture from accumulating more startup stages. These are logical lengths of named objects; other history, working files, filesystem overhead and native writers require separate capacity controls.

Publication checks the intended bytes after the owned writer closes and after promotion. Native identity and modification time detect conflicts across the short store transactions; they do not establish permission, owner release or immutable storage. Coordination covers writers using the AccessWeaver leases. Selected record reads still verify their exact SHA-256 revisions. This protocol does not provide atomic integrity against arbitrary external writers that restore timestamps.

A retained-stage refusal uses HTTP 409 with the fixed `history-staging-pending` code. The desktop keeps no old result payload for recovery: it rereads the prior snapshot and page, then checks the selected record's exact revision before restoring fresh detail and private-export readiness. If the page is stale or a selected read changes, fails or exceeds the existing desktop preview budget, unverified detail and raw-export readiness stay cleared. History inspection and current-job cancellation remain available. No capture POST, download, deletion, repair or cleanup is replayed automatically; an explicit new capture can remain refused while retained evidence is unresolved.

Raw selected-record transfers are limited to 64 MiB; typed detail has a 128 MiB encoded-response ceiling. Status and workflow cancellation use independent admission. Slow exports hold the history read slot until output finishes or fails, so concurrent exports cannot retain independent large copies. Capture uses the shared data-directory active lease and takes the store transaction lock for initialization/publication, without holding the manager status mutex across filesystem work.

The derived `.workflow-history.index` and `.workflow-store-revision` live beside the `workflows` directory. Clean cancellation or capacity refusal closes and verifies its own staging object before removing that derived temporary file. Uncertain write, flush, close or promotion failures preserve their staging objects for review. Persistent lock files stay in place. Index publication and byte checks do not establish a physical power-loss guarantee, global disk quota or hard serialization-memory budget.

The separate Windows `recover` operation reads a selected machine journal through one held read-only stream, with an 8 MiB input limit and actual EOF, length and byte-count checks. It closes that stream successfully before strict UTF-8 decoding and JSON parsing; one leading UTF-8 BOM is accepted, with no UTF-16 or locale fallback. Oversized, incomplete, length-changing, unreadable or malformed input is refused with a fixed private error. The selected journal and adjacent staging files remain untouched, and the existing administrator, protected-path, undo-resource and expected-hash checks still govern recovery.

Machine initialization can create a fresh current journal before the selected older journal is read. A refusal therefore does not mean the entire operation made no writes. This receiver limit does not bound journal production, backups, copies, native writers, parser memory or total storage; the controller's `workerJournalBounded` capability remains false. It provides no cleanup, retirement or vendor-completion proof.

## Access and remaining work

All new HTTP routes require the ordinary loopback host, session header and same-origin checks. Profile-audited desktop mode continues to deny system history routes. History inspection remains available to an authenticated session when unrelated profile loading fails. Private history stays separate from metadata-only support summaries and is cleared from the page when its session or mode changes.

The additive routes are `POST /api/v1/system/history/inventory`, `GET /api/v1/system/history/page`, and `GET /api/v1/system/history/records/{ref}` with an optional `/export` suffix. Capture accepts only an empty JSON object. Query fields are closed and bounded; selected reads require an explicitly supplied revision. Public errors use fixed categories without copying operating-system paths or record payloads.

Full storage quotas, durable cleanup classification, reviewed retirement and restart-safe retirement receipts remain separate required work. There are no age/count deletion controls or automatic pruning. Administrative machine journals and application backup paths require their own dependency and authority checks; an ordinary history inventory never follows their paths as deletion authority. Full installed-product, ordinary-user, managed-deployment and physical endpoint acceptance remains necessary. See [workflow ownership and recovery](WINDOWS_WORKFLOWS.md).
