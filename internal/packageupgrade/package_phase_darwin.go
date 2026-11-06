//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"errors"
	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"os"
)

// Package input directories are created only after an accepted prepare. Read
// existing input first, so unknown contents and downgrades refuse without
// replacing files or creating another incoming generation.
func packageIncoming(identity deploymentIdentity, create bool) error {
	parent, e := darwintrust.OpenRootDirectory(deploymentParent)
	if e != nil {
		return e
	}
	return packageIncomingAt(parent, identity, create, nativeRuntimeReads())
}

// This scope owns parent and every opened verifier descriptor. A clean absent
// input remains allowed, but failed cleanup never becomes clean absence.
func packageIncomingAt(parent *os.File, identity deploymentIdentity, create bool, r runtimeReadOps) (failure error) {
	var absent error
	defer func() {
		failure = r.finish(parent, failure)
		if failure != nil && absent != nil {
			failure = errors.Join(failure, absent)
		}
	}()
	incoming, e := r.deploymentDirectory(parent, deploymentIncoming, 0, create)
	if !create && darwintrust.IsReadAbsent(e) {
		absent = e
		return nil
	}
	if e != nil {
		return e
	}
	defer func() { failure = r.finish(incoming, failure) }()
	stage, e := r.deploymentDirectory(incoming, identity.ManifestSHA256, 0, create)
	if !create && darwintrust.IsReadAbsent(e) {
		absent = e
		return nil
	}
	if e != nil {
		return e
	}
	defer func() { failure = r.finish(stage, failure) }()
	entries, e := r.deploymentEntries(stage, 0, 3)
	if e != nil {
		return e
	}
	if len(entries) == 0 {
		return nil
	}
	if len(entries) != 3 {
		return errors.New("existing package input has unexpected contents; preserve and inspect")
	}
	app, encoded, sbom, embedded, e := r.openDeploymentBundle(stage)
	if e != nil {
		return e
	}
	defer func() { failure = r.finish(app, failure) }()
	if embedded || len(sbom) == 0 {
		return errors.New("new packages require detached inventory and payload SBOM")
	}
	_, _, e = r.verifyDeploymentInventory(app, identity, encoded, false, sbom)
	return e
}

// PackageOperation serves only Apple's fixed pre/post entry points. A package
// receipt owns incoming files, never the independent authority/version store.
// There is no removal, installed-code execution, target path or seal override.
func PackageOperation(phase string) (result DeploymentResult, err error) {
	if phase == "postinstall" {
		if os.Geteuid() != 0 {
			return result, errors.New("package operation requires root")
		}
		identity, e := compiledDeploymentIdentity()
		if e != nil {
			return result, e
		}
		if e = packageIncoming(identity, false); e != nil {
			return result, e
		}
		return DeploymentOperation("activate-deployment")
	}
	if phase != "preinstall" {
		return result, errors.New("unknown package phase")
	}
	if os.Geteuid() != 0 {
		return result, errors.New("package operation requires root")
	}
	identity, e := compiledDeploymentIdentity()
	if e != nil {
		return result, e
	}
	if e = legacyDeploymentAbsent(); e != nil {
		return result, e
	}
	if e = packageIncoming(identity, false); e != nil {
		return result, e
	}
	s, e := openDeployment(true)
	if e != nil {
		return result, e
	}
	defer func() { err = errors.Join(err, s.Close()) }()
	if e = packageIncoming(identity, false); e != nil {
		return result, e
	}
	slot, published, state, e := s.reconcileDeployment("prepare-deployment", identity, func() (*os.File, error) { return nil, errors.New("prepare cannot read or execute an incoming app") })
	if e == nil {
		e = packageIncoming(identity, true)
	}
	if e != nil && !published {
		state = "refused"
	}
	result = DeploymentResult{SchemaVersion: 1, Operation: "prepare-deployment", Generation: s.state.Generation, Version: identity.Version, ManifestSHA256: identity.ManifestSHA256, PayloadSHA256: identity.PayloadSHA256, SlotID: slot.ID, State: state, OperationRecordPublished: published}
	return result, e
}
