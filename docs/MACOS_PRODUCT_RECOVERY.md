# Experimental macOS product recovery

This procedure covers the versioned, fixed-path product layout. It is an administrator procedure under qualification. Publisher signing/notarization, managed endpoint distribution, interrupted Installer/reboot/power-loss recovery and whole-product uninstall remain separate readiness requirements.

The existing helper deliberately preserves and refuses partial copies. Recovery explicitly abandons a matching preparation and installs a fresh copy. It does not overwrite, delete or activate the abandoned copy. User profiles are outside this authority.

## Authenticate the exact candidate

Use the externally approved source commit, workflow/ref, architecture and run identity with the verifier described in [release provenance](RELEASE_PROVENANCE.md). Authenticate every required candidate subject before inspecting its reports. A version string alone is insufficient: the pending identity includes both the manifest and payload SHA256.

The packaging helper must come from the exact authenticated core component for that pending identity. Place the helper and product in private root-owned staging and verify that the staged bytes still match the authenticated digests before executing them. Do not run the installed application, launcher or a retained core as root. Do not use a helper from another source build merely because its version is equal.

In the commands below, the deployment system supplies the absolute root-owned staged paths in the variables trusted_helper and verified_product. This document does not create those paths or authorize an unverified download.

## Preserve and inspect

Arrange a clean controller shutdown through its owner or management lifecycle. The serving lease must be released; a busy-helper refusal must not be bypassed.

Read the protected code-deployment record:

    /bin/cat '/Library/Application Support/AccessWeaver/state/deployment.json'

Record the active identity, pending identity/base generation, current generation and high-water version. Preserve diagnostics and all retained versions. Do not collect private launch HTML/session credentials with these diagnostics. Stop for review if identities do not match the authenticated candidate, state is ambiguous, a newer version is active, or the preparation is fenced.

Resolve the underlying resource/storage failure before retrying. Another complete independent slot requires space and remains subject to retained-slot/history limits. Capacity refusal is not permission to erase history or user data.

## Explicit recovery

Inspect the sealed helper identity:

    sudo "$trusted_helper" version --json

A retry of a matching complete preparation can activate that verified copy. An incomplete or changed copy must refuse and remain preserved:

    sudo "$trusted_helper" activate-deployment

After confirming an incomplete matching preparation and choosing to retain it, explicitly abandon that preparation:

    sudo "$trusted_helper" abandon-deployment

Require the structured result to report the expected version/seals, operation abandon-deployment, state abandoned and published operation record. Abandonment removes the matching pending record; it does not advance the generation or remove its files. The previous active core and high-water version must remain unchanged. Any refusal or unexpected state requires investigation.

Retry the whole authenticated product:

    sudo /usr/sbin/installer -pkg "$verified_product" -target /

Require a successful Installer result and a fresh active slot distinct from the abandoned copy. Validate the new active manifest/payload identity, complete public app and protected registration against the authenticated candidate. Verify the core, public application and exact registration receipts with pkgutil --pkg-info; the registration receipt identifier includes the authenticated record SHA256. Require the expected private user profile to remain available through the ordinary-user launcher.

Do not use pkgutil --forget or filesystem deletion as a repair operation. They do not implement product uninstall or safe reclamation. Leave the abandoned bytes and retained history intact.

## Qualification boundary

The disposable native fixture tests detached-metadata and controller write limits on the actual extracted package helper. It checks exact retained source-byte prefixes, refusal without mutation, explicit abandonment and whole-product retries. It also checks full public/previous-core inventories, registrations, receipts, private profiles and retained partial copies.

Per-process write limits are a controlled test mechanism. They are not a production workaround, an Installer-process crash or a power-loss simulation. Fresh source-bound native and independent provenance evidence must establish the actual tested scope; [testing records](TESTING.md) retain both successful and failed qualification attempts.
