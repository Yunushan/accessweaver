# Protected Windows installer registration

The native installer currently reaches uninstall with a registry entry that
inherits a write ACE from the machine Add/Remove Programs tree. The uninstaller
correctly refuses it. The
[AMD64 and ARM64 failure receipts](qualification/ed049b12e54e-installer-terminal-server-refusal.json)
identify the same inherited write class. Pinned Inno Setup 6.7.1 deletes the
previous leaf and supplies no security descriptor when it creates the new one.

The intended correction owns the 64-bit product leaf from creation through
retirement. The [CreateUninstallRegKey directive](https://jrsoftware.org/inno-setup/documentation/topic_setup_createuninstallregkey.htm)
can turn off Inno's Add/Remove Programs write while preserving creation and
maintenance of its uninstaller and data file. Setup must supply the same
consumer contract: display metadata, installed version and directory, the
exact quoted uninstall command, and its silent counterpart. ARP, the managed
deployment detector, setup's downgrade checks, and the uninstaller must see a
single canonical registration. The alternate 32-bit view must remain absent.

The [isolated ownership primitive](../scripts/windows-installer-registry-owned.iss)
creates a single child beneath a held parent with a protected DACL, an explicit
Administrators owner, full control for Administrators and SYSTEM, and read
access for Users. It does not reopen an existing object as if the creation
succeeded. An exact separate retry path checks the owner, DACL, stable class
tag, bounded inventory and absence of the symbolic-link value on the held
handle. The class tag identifies an expected layout; it is not a secret and
is insufficient without the other checks. The
[registry-only hosted fixture](../scripts/test-windows-installer-registry-owned.iss)
tests this primitive under an inheritable foreign-writer parent, including
registry links to existing and missing targets. It does not use the AccessWeaver
product registration or run the production installer.

Publication must follow payload, runtime notice, uninstaller and uninstaller
data verification while their exact handles and the installation lifecycle
lock remain held. Required version, location and command values must become
visible together, with the protected descriptor already in place. The isolated
fixture now covers a bounded local registry transaction for new registration
and updates to a verified owned leaf. Production setup must verify visibility
after committing, and keep the pending installation record until file,
registration and temporary uninstaller cleanup are confirmed. A close or
commit result that leaves the outcome uncertain must return an installation
failure and retain the existing recovery barrier. Never retry a commit
blindly. A registry transaction does not make Inno's filesystem changes atomic.

| Boundary | Required observation |
| --- | --- |
| Before the registration operation | A complete prior owned registration or no leaf, and the matching durable pending install record. |
| Aborted or interrupted registry transaction | The committed prior record is unchanged, or a previously absent leaf is still absent. No partial new command is discoverable. |
| Commit succeeds before the pending record is retired | The new record is complete; recovery of the same candidate can verify it without a second publication. |
| Retry sees a different class, writable ACL, symbolic link, divergent version/location, foreign data, or a second registry view | Refuse with the conflicting record unchanged. |
| Normal uninstall | Bind the exact registration to the running uninstaller, verify its controller and restoration, and retire only the owned leaf through the normal removal lifecycle. |

Legacy registrations need explicit compatibility coverage. Editing an insecure
leaf in place cannot revoke previously granted handles. A supported migration
must use independently verified installed package identity, account for handles
and unknown values, and either replace the owned legacy object safely or leave
it untouched with an actionable refusal. Neither a class tag alone nor a write
ACE allowlist can make a legacy leaf authoritative.

The [same-name replacement run](https://github.com/Yunushan/accessweaver/actions/runs/44003554389)
at `7bf36162cfd5a916f3bbb92ba5c8536bff3020e3` passed 40 of 43 cases on AMD64 and ARM64 and confirmed exact cleanup.
Both architectures staged deletion and restored the legacy entry on rollback.
The protected replacement failed to stage within that transaction. The AMD64
receipt is artifact `14294060325` with ZIP SHA-256 `6261b1b3bfc0bca774f67620f8a6f24b37591defa4ca0f616019271351fb8f8b`.
The ARM64 receipt is artifact `14293033280` with ZIP SHA-256 `ec650f5b007e5312bfa81d721f9617118fe36edee77ed06d823489721be400b3`.

The fixture now tests two transactions. It flushes and verifies a protected
pending record before retiring the approved prior entry. A new transaction
creates the protected replacement after independently observing the absent
name and the pending record. The retained legacy handle must refuse a write
after publication. Production migration will also need to bind the pending
record to the exact candidate setup and independently verified prior package.
An interruption between transactions leaves the registration absent and the
durable install recovery record present.

Setup, the standalone managed detector, and the embedded Windows controller
open each recovery registry component without following links. Setup mutates
the recovery values and flushes pending-state changes on the same held key.
The existing version, destination, and approval-pin format remains compatible
with the detector. The disposable registry fixture checks ordinary marker
creation and refusal of a linked parent, including when creation is requested.

The [no-follow marker run](https://github.com/Yunushan/accessweaver/actions/runs/44006688562)
passed the installer and managed detector contracts and all 48 registry fixture
assertions on AMD64 and ARM64 at `5be66f439b7d9ba754397082aee352eac0f4d3ba`.
Each fixture reported exact cleanup. The AMD64 receipt is artifact `14294812607`
with ZIP SHA-256 `73e94165311949d1918862d8474dd38ded52e11ea2e5830f217cd97ea2f55a23`.
The ARM64 receipt is artifact `14295495053` with ZIP SHA-256
`41c73214b819a067715548ff410bd371978f6f4881f72faacc849f0f2ec4c154`.

The [two-transaction recovery run](https://github.com/Yunushan/accessweaver/actions/runs/44004076267)
passed all 46 assertions and confirmed exact fixture cleanup on AMD64 and ARM64
at `7d6833963933598a0cc84106f83d09f7c8505f91`. Recovery refused a mismatched
pending candidate and published the complete protected entry for the bound
candidate. The old writer could no longer mutate it. The AMD64 receipt is
artifact `14292984104` with ZIP SHA-256
`17494c38dd457d6cf7b38a74fbd1bb5bf93aa2bddd7c557ab616443202c93205`.
The ARM64 receipt is artifact `14292889163` with ZIP SHA-256
`ae1a097ca343c932d0b97a3564d7163a2e89c725c358430947fc8b9b52ca32ee`.

At source `2b875e4b698d51b650042e12f072b85268a2592c`, the
[hosted registry run](https://github.com/Yunushan/accessweaver/actions/runs/44001985316)
passed all 31 assertions with exact cleanup on AMD64 and ARM64 using Inno Setup
6.7.1. This covers ACL and class roundtrip, no-follow registry access, and
visibility, rollback and commit of typed registration values. The AMD64 receipt
is artifact `14292996503` with ZIP SHA-256
`0a69f22be7f7b65017e8aad786bffd4806e3d51b51cbe92cd48b3fb89c31e4bd`.
The ARM64 receipt is artifact `14293001337` with ZIP SHA-256
`229b25be8d412ad072bdfa701b54b56e7a231076e738a770a5d7251be91684fe`.

The interrupted transaction case closes the last transaction handle without
committing. Process termination and reboot still require separate acceptance.
Production publication, legacy upgrade and uninstall retirement still need
integration. The disposable fixture stages retirement from an exact transacted
handle after checking the ownership descriptor, class and complete metadata.
The ordinary committed record must remain readable before commit and after
rollback. A successful commit must remove only that registration, and a held
prior handle must refuse writes. Linked names and mismatched versions are
covered by separate refusal cases.

The [retirement run](https://github.com/Yunushan/accessweaver/actions/runs/44002912817)
passed all 37 assertions and exact fixture cleanup on both architectures at
`41b265e3a0747d98d1f8ba2a4998a51049e0961c`.
The AMD64 receipt is artifact `14293820049` with ZIP SHA-256
`046fc6a1498aeb2ad54fd1b57907baf59f1489dc13ef72a74cd6b003d4e578ce`.
The ARM64 receipt is artifact `14292189894` with ZIP SHA-256
`107477a2b7f4f32ad6d4835b08083aff17f2d74f8d0e75eddc73a13be6d8bfa2`.

The installer registration reader now opens each fixed registry
component without following symbolic links. A linked or unreadable path blocks
setup and uninstall, while an absent registration remains distinguishable.

The [descriptor comparison follow-up](https://github.com/Yunushan/accessweaver/actions/runs/43995959172)
reached `descriptor-format` on AMD64 and ARM64. Each architecture passed 11 of 24
fixture assertions and removed the disposable registry root. The source-pinned
receipts are artifacts 14290606526 and 14289808008. Validation now compares the
owner SID, DACL control bits and complete ordered ACE bytes on the held
descriptor. The fixture also requires the rejection of an unprotected DACL and
a protected DACL with the same layout but a write grant for Users.

The transaction fixture now stages and checks the Apps & Features fields used
by deployment and removal. It covers the display name, version, location, icon,
publisher, publisher URL, both uninstall commands, and the DWORD maintenance
flags. Readback requires that exact field inventory and types. Separate aborted
updates check that a foreign field or a string in place of a DWORD is refused
and the committed record remains intact. Production registration publication,
legacy migration, and behavior in Apps & Features still require native
qualification.

Both jobs in the [first binary descriptor run](https://github.com/Yunushan/accessweaver/actions/runs/43998040683)
failed before uploading receipts. That revision added an unprotected-descriptor
case to the executable while the launcher still admitted only its earlier case
catalog. The launcher now derives the expected identities and count from the
exact checked-in fixture before compiling it. If the launcher stops before it
can validate native results, it retains a source-bound stage receipt with the
fixed failing stage and numeric process exit when available. The stage receipt
leaves cleanup unknown and does not credit any case.


## Setup publication candidate

The qualification build selects `ProtectedRegistrationQualification` on the
normal Setup script. It disables Inno's Apps & Features write while retaining
the generated uninstaller and its data. Setup records the prior registration
before copying files. It accepts an absent 64-bit product key or a protected
key with the exact class, descriptor, destination and typed fields. A 32-bit
record, a registry link and a legacy key fail admission before file copy.

Setup waits until completion to stage the replacement, after checking the
installed package and holding its uninstaller and data. The transaction creates
the key only if the expected slot is still absent, or updates it only if every
captured field still matches. A fresh readback checks the descriptor, class and
fields and flushes the key before the pending installation record can be retired.
The record also supplies Inno's previous installation directory for repeat Setup.

The native registry fixture exercises the same staging routine under a
disposable key. The release builder still uses the existing Inno registration.

The qualification uninstaller writes and flushes a repair record after verified
system restoration, then retires only the exact protected product record in
KTM. After Inno processes the uninstall log, the uninstaller checks that the
shipped files, uninstaller, uninstall data and both registry views are absent
before clearing the repair record. Interrupted or incomplete removal retains the
directory and version for approved Setup recovery. Managed verification checks
the record because the Inno completion callback runs after its deletion log.

The manual protected-publication workflow exercises real Setup rollback before
publication, retry, same-version repair using the previous directory, controller
binding and owned uninstall. Native verification of managed migration, process
termination, reboot recovery, and signed installed-product acceptance remain
open.


The [first publication fixture run](https://github.com/Yunushan/accessweaver/actions/runs/44009212448)
passed 25 of 50 cases with exact cleanup on both architectures. The registry
writer had applied a child-key name check to `Inno Setup: App Path`. The
correction admits that exact value name and retains the child-key name check
for the other names.

At `91ed21af596621a70630b72d23526bfa66c3d778`, the
[corrected publication run](https://github.com/Yunushan/accessweaver/actions/runs/44009684626)
passed all 50 assertions on AMD64 and ARM64 with exact cleanup. Both receipts
matched their archive digests and all fixed source hashes. The AMD64 receipt
is artifact `14296072039` with ZIP SHA-256
`0843f21b38d5627939887529cbc6f8cb1940e4fea93aad502575b455dcb8c314`.
The ARM64 receipt is artifact `14296376305` with ZIP SHA-256
`563572f69d5f4f585272ac1db3dd5348f379b80c6e34a6331e80b04f310fb1c5`.


## Approved legacy migration candidate

The protected qualification build accepts an extended `/AWUpgradeFrom` argument
for the supported legacy Inno 6.7.1 record. Append the independently approved
SHA-256 values of the prior uninstaller executable and uninstall data to the
existing version, payload, SBOM and build metadata fields. The standard release
builder retains its existing four-field argument format.

Setup verifies the legacy App Path, both uninstall commands, version, publisher
and other expected product values, and refuses a foreign value or child key.
It checks the supported compiler and captures the remaining typed Inno metadata
without recording its contents in logs or receipts. The approved payload,
SBOM, build metadata, uninstaller and uninstall data stay held through registry
retirement. Inside the delete transaction, Setup compares the exact inventory
again and rejects changes before committing. Only after the existing pending
record is durable can Setup retire the old leaf. Publication after file
verification uses a separate transaction. A retry in the original directory
requires the same extended argument and can resume after the old leaf is gone.

The qualification build overwrites the legacy Inno uninstall log to discard
its original path-based registry deletion command. Its ownership test covers
opaque metadata changes, a foreign value, a held legacy writer and the
separate replacement transaction. Native migration of real older packages must
still verify retained files and shortcuts that the current package no longer
ships. [Inno registration and log source](https://github.com/jrsoftware/issrc/blob/is-6_7_1/Projects/Src/Setup.Install.pas#L263-L367) · [Uninstall log modes](https://jrsoftware.org/ishelp/topic_setup_uninstalllogmode.htm)
