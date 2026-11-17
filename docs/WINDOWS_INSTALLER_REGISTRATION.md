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

The creation and transaction contracts compile for both Windows target runners
with Inno Setup 6.7.1. Hosted results are required for the exact ACL and class
roundtrip, visibility, rollback and complete commit assertions. The interrupted
transaction case closes the last transaction handle without committing; process
termination and reboot still require separate acceptance. Full production
metadata, legacy upgrade and uninstall retirement remain to be integrated and
qualified. The product installer and its registration checks are unchanged.
