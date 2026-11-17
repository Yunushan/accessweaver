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

The disposable fixture attempts a same-name transaction with a synthetic
legacy entry that grants Users write access. It holds the old writable handle
through both rollback and commit and requires the old entry to remain visible
until commit. A successful replacement must have the protected descriptor and
complete new values, and the retained old handle must refuse a write. This
exercises the Windows replacement boundary. The production migration still
needs to verify the prior package, registry values, and uninstaller identity
before it can use that operation.

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
