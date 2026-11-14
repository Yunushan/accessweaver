#!/usr/bin/env python3
"""Authenticate the two-version native Windows acceptance family. Never execute it."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tempfile

from sbom import WINDOWS_BUILD_INFO_PROPERTY, validate,prop_map
from verify_release_provenance import (BUNDLE_NAME, REPOSITORY, authenticate_run,
                                       validate_identity, validate_run_id, verification_command as portable_command)
from verify_release_rebuild import snapshot

WORKFLOW=REPOSITORY+"/.github/workflows/installer-lifecycle.yml"
DEFAULT_VERSIONS=("0.1.0-alpha","0.1.1-alpha")
RELEASE=re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")
SHA=re.compile(r"[a-f0-9]{64}")
PHASES=["baseline","after-install","after-upgrade","after-reinstall","after-active-setup-uninstall","after-lifecycle-locks","after-refused-downgrade","after-version-policy","after-registry-read-boundaries","after-registry-view-policy","after-registry-access-policy","after-restoration-launch-failures","after-restoration-ownership-contracts","before-uninstall","after-uninstall"]

def require(ok,message):
    if not ok:raise ValueError(message)

def digest(data):return hashlib.sha256(data).hexdigest()

def subject_names(arch,versions):
    require(arch in ("amd64","arm64") and len(versions)==2 and len(set(versions))==2,"Expected approved architecture and two distinct acceptance versions")
    names={arch+".json"}
    for version in versions:
        require(isinstance(version,str) and len(version)<=256,"Invalid approved release version")
        match=RELEASE.fullmatch(version)
        require(match is not None,"Expected canonical approved SemVer")
        require(not match[4] or all(not p.isdigit() or p=="0" or not p.startswith("0") for p in match[4].split(".")),"Numeric prerelease has a leading zero")
        name="accessweaver-"+version+"-windows-"+arch+"-setup.exe"
        require(len((name+".cdx.json").encode("utf-8"))<=255,"Installer subject name exceeds filesystem limit")
        names.update((name,name+".cdx.json"))
    return names

def verification_command(path,bundle,commit,ref,gh="gh"):
    command=portable_command(path,bundle,commit,ref,gh)
    command[command.index("--signer-workflow")+1]=WORKFLOW
    return command

def authenticate(path,bundle,commit,ref,gh,run_id):
    authenticate_run(verification_command(path,bundle,commit,ref,gh),run_id)

def load(root,name):
    data=(root/name).read_bytes();require(len(data)<=4<<20,"Installer metadata exceeds budget")
    return json.loads(data.decode("utf-8-sig"))

def validate_build(identity,commit,arch,version):
    require(set(identity)=={"version","commit","sourceState","builtAt","goVersion","platform","arch"},"Incomplete native payload build fields")
    require(all(identity.get(k)==v for k,v in {"version":version,"commit":commit,"sourceState":"clean","goVersion":"go1.27.4","platform":"windows","arch":arch}.items()),"Native payload build identity differs")
    require(isinstance(identity["builtAt"],str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",identity["builtAt"]) is not None,"Invalid canonical build timestamp")
    datetime.datetime.strptime(identity["builtAt"],"%Y-%m-%dT%H:%M:%SZ")


def validate_state_observations(observations):
    require(type(observations) is list and len(observations)==len(PHASES) and all(type(o) is dict for o in observations),"Incomplete native state checkpoints")
    require([o.get("phase") for o in observations]==PHASES,"Expected all fifteen ordered native state checkpoints")
    baseline=observations[0].get("comparison")
    require(type(baseline) is dict and type(baseline.get("domains")) is dict and set(baseline["domains"])=={"services","firewall","dns"},"Incomplete native state baseline")
    for observation in observations:
        require(set(observation)=={"phase","comparison","transition"},"Incomplete native state checkpoint envelope")
        for key in ("comparison","transition"):
            comparison=observation.get(key)
            require(type(comparison) is dict and set(comparison)=={"exactMatch","beforeSHA256","afterSHA256","domains"},"Incomplete native state comparison")
            require(comparison.get("exactMatch") is True and type(comparison.get("beforeSHA256")) is str and comparison.get("beforeSHA256")==comparison.get("afterSHA256")==baseline.get("beforeSHA256") and SHA.fullmatch(comparison["beforeSHA256"]) is not None,"Native state checkpoint changed")
            require(type(comparison.get("domains")) is dict and set(comparison["domains"])=={"services","firewall","dns"},"Incomplete native state domains")
            for name,domain in comparison["domains"].items():
                initial=baseline["domains"][name]
                require(type(domain) is dict and type(initial) is dict and set(domain)=={"beforeSHA256","afterSHA256","serializedEqual","beforeRows","afterRows","added","removed","changed","rowSerializationChanges","recordOrderingChanged","changes","changesTruncated"},"Invalid native state domain")
                require(domain.get("serializedEqual") is True and type(domain.get("beforeSHA256")) is str and domain.get("beforeSHA256")==domain.get("afterSHA256")==initial.get("beforeSHA256") and SHA.fullmatch(domain["beforeSHA256"]) is not None,"Native state domain changed")
                require(type(domain.get("beforeRows")) is int and type(domain.get("afterRows")) is int and domain["beforeRows"]==domain["afterRows"]==initial.get("beforeRows") and 0<=domain["beforeRows"]<=10000,"Native state row count differs")
                require(all(type(domain.get(k)) is int and domain[k]==0 for k in ("added","removed","changed","rowSerializationChanges")) and domain.get("recordOrderingChanged") is False and domain.get("changes")==[] and domain.get("changesTruncated") is False,"Native state diagnostics report a change")
    return {"nativeStateCheckpointsVerified":len(PHASES),"nativeStateComparisonsVerified":2*len(PHASES)}


def validate_firewall_origin_diagnostics(value):
    expected={"schemaVersion":1,"source":"captured-rule-properties","maxRecords":16,"maxPropertyBytes":4096,"records":[],"truncated":False,"unavailable":False,"extraNativeQueriesPerformed":False,"processOriginEstablished":False}
    require(type(value) is dict and set(value)==set(expected),"Incomplete captured firewall metadata envelope")
    for key,wanted in expected.items():
        require(type(value[key]) is type(wanted) and value[key]==wanted,"Qualified unchanged state must have complete empty captured firewall metadata")
    return {"nativeFirewallOriginRecordsVerified":0}


def validate_firewall_event_diagnostics(value):
    expected={"schemaVersion":1,"source":"existing-local-firewall-event-log","status":"not-needed","queryAttempted":False,"queryDeadlineMilliseconds":10000,"queryElapsedMilliseconds":0,"maxEvents":128,"maxRecords":16,"maxXmlBytes":65536,"maxFieldBytes":4096,"windowStartUtc":None,"windowEndUtc":None,"eventsExamined":0,"invalidEvents":0,"eventsLimitReached":False,"records":[],"recordsTruncated":False,"unavailable":False,"eventLogConfigurationChanged":False,"extraFirewallRuleQueriesPerformed":False,"processOriginEstablished":False}
    require(type(value) is dict and set(value)==set(expected),"Incomplete firewall event diagnostic envelope")
    for key,wanted in expected.items():
        require(type(value[key]) is type(wanted) and value[key]==wanted,"Qualified unchanged state must not run or claim event correlation")
    return {"nativeFirewallEventQueriesVerified":0}


def validate_native_attempt(value):
    expected={"schemaVersion","toolClass","timeoutMilliseconds","elapsedMilliseconds","invocationReturned","operationAccepted","exitCode","outputComplete","failureCategory"}
    require(type(value) is dict and set(value)==expected,"Incomplete native-attempt metadata")
    require(type(value.get("schemaVersion")) is int and value["schemaVersion"]==1 and value.get("toolClass")=="uninstaller","Final native attempt was not the uninstaller")
    require(type(value.get("timeoutMilliseconds")) is int and value["timeoutMilliseconds"]==180000 and type(value.get("elapsedMilliseconds")) is int and 0<=value["elapsedMilliseconds"]<180000,"Final native attempt exceeded its original deadline")
    require(value.get("invocationReturned") is True and value.get("operationAccepted") is True and type(value.get("exitCode")) is int and value["exitCode"]==0 and value.get("outputComplete") is True and value.get("failureCategory")=="none","Final native attempt did not complete successfully")
    return {"finalNativeAttemptVerified":True}

def validate_managed_detection(report):
    expected = [
        ("before-install", False), ("after-install", True), ("wrong-digest", False),
        ("after-upgrade", True), ("superseded-version", False), ("after-reinstall", True),
        ("after-refused-downgrade", True), ("after-refused-uninstall", True), ("after-uninstall", False),
    ]
    refusals = {"active-lifecycle-refused", "abandoned-lifecycle-refused"}
    if report.get("schemaVersion", 0) >= 17:
        expected[6:6] = [("active-lifecycle-refused", False), ("abandoned-lifecycle-refused", False),
                         ("after-lifecycle-locks", True)]
    if report.get("schemaVersion", 0) >= 18:
        refusals.add("pending-install-refused")
        expected[9:9] = [("pending-install-refused", False), ("after-pending-install-retry", True)]
    if report.get("schemaVersion", 0) >= 21:
        refusals.add("pending-marker-access-denied")
        expected.insert(10, ("pending-marker-access-denied", False))
    if report.get("schemaVersion", 0) >= 36:
        refusals.add("managed-upgrade-pending")
        expected.insert(3, ("managed-upgrade-pending", False))
    source = Path(__file__).with_name("detect-windows-installer.ps1")
    require(report.get("managedDetectionSourceSHA256") == digest(source.read_bytes()),
            "Managed detection differs from the approved source")
    cases = report.get("managedDetectionCases")
    require(isinstance(cases, list) and len(cases) == len(expected), "Incomplete managed detection coverage")
    for case, (phase, detected) in zip(cases, expected):
        expected_case = {"phase": phase, "detected": detected}
        if phase in refusals:
            expected_case["inspectionRefused"] = True
        require(isinstance(case, dict) and case.keys() == expected_case.keys()
                and case["phase"] == phase and case["detected"] is detected
                and (phase not in refusals or case["inspectionRefused"] is True),
                "Unexpected managed detection result")
    return {"managedDetectionChecksVerified": len(expected)}


def validate_architecture_refusal(report, arch):
    value = report.get("architectureRefusal")
    flags = {"platformRefusalLogged", "installationAbsent", "registrationsAbsent", "machineStateUnchanged"}
    keys = {"target", "fixtureSHA256", "exitCode", "elapsedMilliseconds", "deadlineMilliseconds"} | flags
    other_arch = {"amd64": "arm64", "arm64": "amd64"}[arch]
    require(isinstance(value, dict) and value.keys() == keys and value["target"] == "windows/" + other_arch,
            "Wrong-architecture installer observation is missing or inconsistent")
    require(isinstance(value["fixtureSHA256"], str) and SHA.fullmatch(value["fixtureSHA256"])
            and type(value["exitCode"]) is int and value["exitCode"] == 1
            and type(value["deadlineMilliseconds"]) is int and value["deadlineMilliseconds"] == 180000
            and type(value["elapsedMilliseconds"]) is int and 0 <= value["elapsedMilliseconds"] < 180000
            and all(value[key] is True for key in flags), "Wrong-architecture installer refusal was not verified")
    return {"wrongArchitectureRefusalVerified": True}


def validate_setup_completion_refusal(value):
    flags = {"refusalLogged", "installedFixtureVerified", "pendingMarkerRetained", "managedDetectionRefused",
             "machineStateUnchanged", "profilePreserved", "unrelatedFilePreserved", "genuineRetryVerified"}
    require(isinstance(value, dict)
            and value.keys() == flags | {"fixtureSHA256", "exitCode", "elapsedMilliseconds", "deadlineMilliseconds"}
            and isinstance(value["fixtureSHA256"], str) and SHA.fullmatch(value["fixtureSHA256"])
            and type(value["exitCode"]) is int and value["exitCode"] == 1603
            and type(value["deadlineMilliseconds"]) is int and value["deadlineMilliseconds"] == 180000
            and type(value["elapsedMilliseconds"]) is int and 0 <= value["elapsedMilliseconds"] < 180000
            and all(value[key] is True for key in flags), "Setup completion refusal and recovery were not verified")
    return {"setupCompletionRefusalVerified": True}


def validate_setup_upgrade_baseline(value, *, check_recovery=False):
    flags = {"installedStatePreserved", "profilePreserved", "pendingMarkerAbsent", "matchingUpgradeAccepted"}
    if check_recovery:
        flags.update({"copyCompletedBeforeRecovery", "changedRetryRefused", "matchingRetryRetiredMarker"})
    require(type(value) is dict and set(value) == flags | {
        "refusalExitCode", "refusalElapsedMilliseconds", "deadlineMilliseconds"
    }, "Incomplete managed Setup upgrade baseline evidence")
    require(type(value["refusalExitCode"]) is int and value["refusalExitCode"] == 7
            and type(value["deadlineMilliseconds"]) is int and value["deadlineMilliseconds"] == 180000
            and type(value["refusalElapsedMilliseconds"]) is int
            and 0 <= value["refusalElapsedMilliseconds"] < 180000
            and all(value[key] is True for key in flags), "Managed Setup baseline refusal or upgrade was not verified")
    verified = {"setupUpgradeBaselineVerified": True}
    if check_recovery:
        verified["setupUpgradeRecoveryVerified"] = True
    return verified


def validate_setup_uninstall_registration_refusal(value):
    flags = {"refusalLogged", "changedCommandPreserved", "installedPayloadVerified", "pendingMarkerRetained",
             "managedDetectionRefused", "unrelatedStatePreserved", "genuineRetryVerified"}
    require(type(value) is dict and set(value) == flags | {
        "fixtureSHA256", "exitCode", "elapsedMilliseconds", "deadlineMilliseconds"
    }, "Incomplete Setup uninstall registration refusal")
    require(isinstance(value["fixtureSHA256"], str) and SHA.fullmatch(value["fixtureSHA256"]),
            "Invalid Setup uninstall registration fixture digest")
    require(type(value["exitCode"]) is int and value["exitCode"] == 1603
            and type(value["deadlineMilliseconds"]) is int and value["deadlineMilliseconds"] == 180000
            and type(value["elapsedMilliseconds"]) is int and 0 <= value["elapsedMilliseconds"] < 180000,
            "Invalid Setup uninstall registration result")
    require(all(value[key] is True for key in flags), "Setup uninstall registration was not safely recovered")
    return {"setupUninstallRegistrationRefusalVerified": True}


def validate_setup_marker_replacement(value, check_subject_guards=False):
    flags = {"replacementPreserved", "completionRefusalLogged", "approvedPayloadVerified", "unrelatedStatePreserved"}
    if check_subject_guards:
        flags.add("subjectAndDirectoryGuardsVerified")
    require(isinstance(value, dict)
            and value.keys() == flags | {"exitCode", "elapsedMilliseconds", "deadlineMilliseconds"}
            and type(value["exitCode"]) is int and value["exitCode"] == 1603
            and type(value["deadlineMilliseconds"]) is int and value["deadlineMilliseconds"] == 180000
            and type(value["elapsedMilliseconds"]) is int and 0 <= value["elapsedMilliseconds"] < 180000
            and all(value[key] is True for key in flags), "Setup replacement marker refusal was not verified")
    verified = {"setupMarkerReplacementRefusalVerified": True}
    if check_subject_guards:
        verified["setupCompletionSubjectAndDirectoryGuardsVerified"] = True
    return verified


def validate_installation_path_refusals(values):
    kinds = ("leaf-junction", "ancestor-junction")
    flags = {"preflightRefusalLogged", "targetPreserved", "pendingMarkerAbsent",
             "registrationsAbsent", "machineStateUnchanged"}
    require(isinstance(values, list) and len(values) == len(kinds),
            "Installation path refusal coverage differs")
    for value, kind in zip(values, kinds):
        require(isinstance(value, dict)
                and value.keys() == flags | {"kind", "exitCode", "elapsedMilliseconds", "deadlineMilliseconds"}
                and value["kind"] == kind
                and type(value["exitCode"]) is int and value["exitCode"] == 7
                and type(value["deadlineMilliseconds"]) is int and value["deadlineMilliseconds"] == 180000
                and type(value["elapsedMilliseconds"]) is int and 0 <= value["elapsedMilliseconds"] < 180000
                and all(value[key] is True for key in flags), "Installation path refusal was not verified")
    return {"installationPathRefusalsVerified": len(kinds)}


def validate_redirected_upgrade(value):
    flags = {
        "preflightRefusalLogged", "alternateDestinationAbsent", "pendingMarkerAbsent",
        "installedFileTreePreserved", "completeRegistrationPreserved", "profilePreserved",
        "machineStateUnchanged",
    }
    require(isinstance(value, dict)
            and value.keys() == flags | {"operation", "exitCode", "elapsedMilliseconds", "deadlineMilliseconds"}
            and value["operation"] == "refused-redirected-upgrade"
            and type(value["exitCode"]) is int and value["exitCode"] == 7
            and type(value["deadlineMilliseconds"]) is int and value["deadlineMilliseconds"] == 180000
            and type(value["elapsedMilliseconds"]) is int and 0 <= value["elapsedMilliseconds"] < 180000
            and all(value[key] is True for key in flags), "Redirected upgrade refusal was not verified")
    return {"redirectedUpgradePreservationVerified": True}


def validate_locked_upgrade(value, *, operation="refused-locked-upgrade", marker_required=False):
    checks = {
        "refused-locked-upgrade": "lockedUpgradePreservationVerified",
        "refused-locked-build-info-upgrade": "lockedBuildInfoUpgradePreservationVerified",
        "refused-locked-sbom-upgrade": "lockedSBOMUpgradePreservationVerified",
    }
    flags = {"preflightRefusalLogged", "installedFileTreePreserved", "completeRegistrationPreserved",
             "profilePreserved", "machineStateUnchanged"}
    if marker_required:
        flags.add("pendingMarkerAbsent")
    require(isinstance(value, dict)
            and value.keys() == flags | {"operation", "exitCode", "elapsedMilliseconds", "deadlineMilliseconds"}
            and operation in checks and value["operation"] == operation
            and type(value["exitCode"]) is int and value["exitCode"] == 7
            and type(value["deadlineMilliseconds"]) is int and value["deadlineMilliseconds"] == 180000
            and type(value["elapsedMilliseconds"]) is int and 0 <= value["elapsedMilliseconds"] < 180000
            and all(value[key] is True for key in flags), "Locked upgrade refusal was not verified")
    return {checks[operation]: True}


def validate_failed_copy_recovery(value, *, controller_required=False, compatibility_file=False):
    flags = {
        "copyFailureLogged", "pendingRecordCreatedBySetup",
        "lockedCompatibilityFilePreserved" if compatibility_file else "lockedSBOMPreserved",
        "refusedOperationsPreservedInstallation", "profilePreserved",
        "approvedPackageDetectedAfterRetry", "pendingRecordClearedAfterRetry",
    }
    if controller_required:
        flags.add("controllerUninstallBindingRefused")
    require(isinstance(value, dict)
            and value.keys() == flags | {"operation", "exitCode", "elapsedMilliseconds", "deadlineMilliseconds"}
            and value["operation"] == "recover-failed-install-copy"
            and type(value["exitCode"]) is int and value["exitCode"] in (4, 5)
            and type(value["deadlineMilliseconds"]) is int and value["deadlineMilliseconds"] == 180000
            and type(value["elapsedMilliseconds"]) is int and 0 <= value["elapsedMilliseconds"] < 180000
            and all(value[key] is True for key in flags), "Native installer copy-failure recovery was not verified")
    return {"failedInstallCopyRecoveryVerified": True}


def validate_pending_marker_access(value):
    flags = {
        "discoveryReportedUnavailable", "managedDetectionRefused", "controllerUninstallBindingRefused",
        "nativeUninstallerRefusalLogged", "installationRegistrationAndMarkerPreserved", "profilePreserved",
        "fixtureDACLRestored", "pendingStateObservedAfterRestore",
    }
    require(isinstance(value, dict)
            and value.keys() == flags | {"nativeQueryStatus", "nativeUninstallExitCode"}
            and type(value["nativeQueryStatus"]) is int and value["nativeQueryStatus"] == 5
            and type(value["nativeUninstallExitCode"]) is int and value["nativeUninstallExitCode"] == 1
            and all(value[key] is True for key in flags), "Native Setup recovery marker access-denial behavior was not verified")
    return {"pendingMarkerAccessDenialVerified": True}


def validate_uninstall_registration_refusal(value, *, operation="refused-uninstall-registration"):
    flags = {
        "preflightRefusalLogged", "restorationStateAbsent", "installedFileTreePreserved",
        "completeRegistrationPreserved", "profilePreserved", "machineStateUnchanged",
    }
    require(isinstance(value, dict)
            and value.keys() == flags | {"operation", "exitCode", "elapsedMilliseconds", "deadlineMilliseconds"}
            and value["operation"] == operation
            and type(value["exitCode"]) is int and value["exitCode"] == 1
            and type(value["deadlineMilliseconds"]) is int and value["deadlineMilliseconds"] == 180000
            and type(value["elapsedMilliseconds"]) is int and 0 <= value["elapsedMilliseconds"] < 180000
            and all(value[key] is True for key in flags), "Uninstall registration refusal was not verified")
    key = ("uninstallRegistrationVersionRefusalVerified"
           if operation == "refused-uninstall-registration-version" else "uninstallRegistrationRefusalVerified")
    return {key: True}


def validate_restoration_controller_refusals(cases, *, require_hardlink=False):
    expected = [
        "missing-controller-refused", "truncated-controller-refused", "malformed-controller-refused",
        "same-size-controller-mismatch-refused", "execution-denied-controller-refused",
    ]
    if require_hardlink:
        expected.insert(-1, "hard-linked-controller-refused")
    require(isinstance(cases, list) and len(cases) == len(expected)
            and all(isinstance(case, dict) for case in cases)
            and [case.get("name") for case in cases] == expected,
            "Restoration controller refusal coverage differs")
    preserved = {
        "installedFileTreePreserved", "registrationValuesPreserved", "profilePreserved",
        "originalControllerAndDACLRestored", "restoredControllerRuntimeVerified",
    }
    for case in cases[:-1]:
        require(case.keys() == preserved | {
            "name", "failurePhase", "controllerVerificationRefusalLogged", "exitCode",
            "elapsedMilliseconds", "observationDeadlineMilliseconds",
        } and case["failurePhase"] == "verify-controller"
                and case["controllerVerificationRefusalLogged"] is True
                and all(case[key] is True for key in preserved)
                and type(case["exitCode"]) is int and case["exitCode"] == 1
                and type(case["observationDeadlineMilliseconds"]) is int
                and case["observationDeadlineMilliseconds"] == 180000
                and type(case["elapsedMilliseconds"]) is int and 0 <= case["elapsedMilliseconds"] < 180000,
                "Unverifiable controller was not refused before launch")
    denied = cases[-1]
    require(denied.get("failurePhase") == "launch-controller"
            and denied.get("nativeErrorLogVerified") is True
            and denied.get("independentProbeStarted") is False
            and type(denied.get("nativeError")) is int and denied["nativeError"] == 5
            and all(denied.get(key) is True for key in preserved),
            "Verified controller launch refusal differs")
    return {"restorationControllerVerificationRefusalsVerified": True}


def validate_post_restoration_refusal(value):
    flags = {
        "restorationSucceededBeforeRefusal", "registrationChangeObserved", "deletionRefused",
        "installedFileTreePreserved", "otherRegistrationValuesPreserved", "profilePreserved", "machineStateUnchanged",
    }
    require(isinstance(value, dict)
            and value.keys() == flags | {"exitCode", "elapsedMilliseconds", "deadlineMilliseconds"}
            and type(value["exitCode"]) is int and value["exitCode"] == 1
            and type(value["deadlineMilliseconds"]) is int and value["deadlineMilliseconds"] == 180000
            and type(value["elapsedMilliseconds"]) is int and 0 <= value["elapsedMilliseconds"] < 180000
            and all(value[key] is True for key in flags), "Post-restoration deletion refusal was not verified")
    return {"postRestorationRefusalVerified": True}


def validate_fixed_restoration(refused, removed):
    require(refused.get("workflowLockRefusalVerified") is True
            and refused.get("controllerAndRegistrationRetained") is True
            and refused.get("unrelatedStatePreserved") is True
            and removed.get("legacyRequestAbsent") is True
            and removed.get("recoveryJournalRetained") is True
            and removed.get("ownedPayloadAndRegistrationRemoved") is True,
            "Fixed installer restoration was not verified")
    return {"fixedRestorationCommandVerified": True}


def validate_contents(root,commit,ref,arch,versions):
    report=load(root,arch+".json")
    require(type(report.get("schemaVersion")) is int and report.get("schemaVersion") in (11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36) and report.get("sourceCommit")==commit and report.get("sourceRef")==ref and report.get("target")=="windows/"+arch,"Native lifecycle source/target differs")
    require(report.get("compilerVersion")=="6.7.1" and report.get("stage")=="cleanup" and report.get("failureType") is None and report.get("failureSourceLine") is None and report.get("assertionFailure") is None,"Native lifecycle did not finish cleanly")
    for key in ("passed","actualUserProfilePreservationVerified","childEnvironmentSanitized","selectedServiceFirewallDNSStateUnchanged","ownedFixturesRemoved","unsigned","downgradeTested"):
        require(report.get(key) is True,"Native lifecycle acceptance is incomplete")
    for key in ("publisherSignatureVerified","rebootTested","crashOrPowerLossTested","vendorDriverOrRoutingQualified","productionQualificationComplete"):
        require(report.get(key) is False,"Unqualified native scope changed")
    require(re.fullmatch(r"[1-9][0-9]{0,19}",str(report.get("runID",""))) is not None,"Missing native invocation identity")
    require(report.get("stateDiagnosticsSourceSHA256")==digest(Path(__file__).with_name("windows-installer-state.ps1").read_bytes()),"State diagnostics differ from approved verifier source")
    require(report.get("nativeDiagnosticsSourceSHA256")==digest(Path(__file__).with_name("windows-installer-native-state.ps1").read_bytes()),"Native-attempt diagnostics differ from approved verifier source")
    require(report.get("eventDiagnosticsSourceSHA256")==digest(Path(__file__).with_name("windows-installer-event-state.ps1").read_bytes()),"Event diagnostics differ from approved verifier source")
    detection_counts = validate_managed_detection(report) if report["schemaVersion"] >= 12 else {}
    marker_access = validate_pending_marker_access(report.get("pendingMarkerAccess")) if report["schemaVersion"] >= 21 else {}
    architecture = validate_architecture_refusal(report, arch) if report["schemaVersion"] >= 13 else {}
    path_refusals = validate_installation_path_refusals(report.get("installationPathRefusals")) if report["schemaVersion"] >= 24 else {}
    setup_readback = {}
    if report["schemaVersion"] >= 25:
        require(report.get("setupCompletionReadbackVerified") is True,
                "Setup completion readback was not verified")
        setup_readback["setupCompletionReadbackVerified"] = True
    if report["schemaVersion"] >= 26:
        setup_readback.update(validate_setup_completion_refusal(report.get("setupCompletionRefusal")))
    if report["schemaVersion"] >= 32:
        setup_readback.update(validate_setup_marker_replacement(
            report.get("setupMarkerReplacement"), check_subject_guards=report["schemaVersion"] >= 33))
    if report["schemaVersion"] >= 34:
        setup_readback.update(validate_setup_uninstall_registration_refusal(report.get("setupUninstallRegistrationRefusal")))
    if report["schemaVersion"] >= 35:
        setup_readback.update(validate_setup_upgrade_baseline(
            report.get("setupUpgradeBaseline"), check_recovery=report["schemaVersion"] >= 36))
    event_counts=validate_firewall_event_diagnostics(report.get("firewallEventDiagnostics"))
    attempt_counts=validate_native_attempt(report.get("lastNativeAttempt"))
    state_counts=validate_state_observations(report.get("stateObservations"))
    origin_counts=validate_firewall_origin_diagnostics(report.get("firewallOriginDiagnostics"))
    operations=report.get("operations",[])
    expected=["install","upgrade","reinstall","refused-downgrade","refused-uninstall","uninstall"]
    if report["schemaVersion"] >= 16:
        expected.insert(1, "refused-locked-upgrade")
    if report["schemaVersion"] >= 19:
        expected.insert(expected.index("refused-downgrade"), "recover-failed-install-copy")
    if report["schemaVersion"] >= 22:
        expected.insert(1, "refused-redirected-upgrade")
    if report["schemaVersion"] >= 23:
        expected.insert(expected.index("refused-uninstall"), "refused-uninstall-registration")
    if report["schemaVersion"] >= 28:
        expected.insert(expected.index("refused-uninstall"), "refused-uninstall-registration-version")
    locked_operations = {"refused-locked-upgrade"}
    if report["schemaVersion"] >= 27:
        metadata_refusals = ["refused-locked-build-info-upgrade", "refused-locked-sbom-upgrade"]
        upgrade_index = expected.index("upgrade")
        expected[upgrade_index:upgrade_index] = metadata_refusals
        locked_operations.update(metadata_refusals)
    require([o.get("operation") for o in operations]==expected,"Native lifecycle operation coverage differs")
    redirected_upgrade = {}
    locked_upgrade = {}
    failed_copy_recovery = {}
    uninstall_registration = {}
    for operation in operations:
        if operation["operation"] in {"refused-uninstall-registration", "refused-uninstall-registration-version"}:
            uninstall_registration.update(validate_uninstall_registration_refusal(operation, operation=operation["operation"]))
            continue
        if operation["operation"] == "refused-redirected-upgrade":
            redirected_upgrade = validate_redirected_upgrade(operation)
            continue
        if operation["operation"] in locked_operations:
            locked_upgrade.update(validate_locked_upgrade(
                operation, operation=operation["operation"], marker_required=report["schemaVersion"] >= 27,
            ))
            continue
        if operation["operation"] == "recover-failed-install-copy":
            failed_copy_recovery = validate_failed_copy_recovery(
                operation, controller_required=report["schemaVersion"] >= 20,
                compatibility_file=report["schemaVersion"] >= 27,
            )
            continue
        require(operation.get("exitCode")== (1 if operation["operation"].startswith("refused-") else 0) and operation.get("deadlineMilliseconds")==180000 and type(operation.get("elapsedMilliseconds")) is int and 0<=operation["elapsedMilliseconds"]<180000,"Native lifecycle operation failed")
    restoration = validate_fixed_restoration(*operations[-2:]) if report["schemaVersion"] >= 14 else {}
    if report["schemaVersion"] >= 29:
        restoration.update(validate_restoration_controller_refusals(
            report.get("restorationLaunchCases"), require_hardlink=report["schemaVersion"] >= 30,
        ))
    if report["schemaVersion"] >= 31:
        restoration.update(validate_post_restoration_refusal(report.get("postRestorationRefusal")))
    if report["schemaVersion"] >= 15:
        require(operations[-2].get("registeredUninstallerBindingVerified") is True,
                "Registered workflow uninstaller binding was not verified")
        restoration["registeredUninstallerBindingVerified"] = True
    builds=report.get("builds",[]);require([b.get("version") for b in builds]==list(versions),"Authenticated family differs from independently approved versions")
    candidates=[]
    for build,version in zip(builds,versions):
        name="accessweaver-"+version+"-windows-"+arch+"-setup.exe";binary=(root/name).read_bytes()
        require(64<=len(binary)<=64<<20 and build.get("installerName")==name and build.get("installerBytes")==len(binary) and build.get("installerSHA256")==digest(binary) and binary[:2]==b"MZ","Installer bytes differ from native report")
        offset=struct.unpack_from("<I",binary,0x3c)[0]
        require(64<=offset<=len(binary)-6 and binary[offset:offset+4]==b"PE\0\0" and struct.unpack_from("<H",binary,offset+4)[0]==0x14c,"Expected the qualified x86 Inno bootstrap")
        identity=build["payloadBuild"]
        validate_build(identity,commit,arch,version)
        require(SHA.fullmatch(build["payloadSha256"]) is not None and SHA.fullmatch(build["compilerSHA256"]) is not None,"Native payload/compiler subject is missing")
        bom=load(root,name+".cdx.json");validate(bom,binary,identity)
        require(bom["metadata"].get("timestamp")==identity["builtAt"],"Installer SBOM build timestamp differs")
        installer_properties=prop_map(bom["metadata"]["component"])
        if WINDOWS_BUILD_INFO_PROPERTY in installer_properties:
            pin=installer_properties[WINDOWS_BUILD_INFO_PROPERTY]
            require(isinstance(pin,str) and SHA.fullmatch(pin) and pin==build.get("identityFileSHA256"),
                    "Installer SBOM build metadata differs from native readback")
        components={c["bom-ref"]:c for c in bom["components"]};payload=components.get("payload-application",{});compiler=components.get("inno-setup",{})
        require(payload.get("version")==version and payload.get("hashes")==[{"alg":"SHA-256","content":build["payloadSha256"]}],"Installer SBOM payload subject differs")
        require(compiler.get("version")=="6.7.1" and prop_map(compiler).get("accessweaver:compiler-sha256")==build["compilerSHA256"],"Installer SBOM compiler subject differs")
        candidates.append({"file":name,"sha256":digest(binary),"bytes":len(binary),"payloadSHA256":build["payloadSha256"],"payloadTarget":"windows/"+arch,"bootstrapPEMachine":"0x014c","sbomSHA256":digest((root/(name+".cdx.json")).read_bytes())})
    return {"candidates":candidates,**detection_counts,**architecture,**restoration,**uninstall_registration,**redirected_upgrade,**path_refusals,**setup_readback,**locked_upgrade,**failed_copy_recovery,**marker_access,**state_counts,**origin_counts,**event_counts,**attempt_counts,"nativeLifecycleOperationsVerified":len(expected),"nativeRunID":str(report["runID"]),"nativeDependencyClosureComplete":False}

def stage(build_root,destination,commit,ref,arch,versions,run_id=None):
    validate_identity(commit,ref);names=subject_names(arch,versions)
    require(not destination.exists() and not destination.is_symlink(),"Staging destination must be new")
    destination.mkdir(parents=True,mode=0o700)
    for name in sorted(names):
        source=build_root/("installer-lifecycle-checks/"+name if name==arch+".json" else name)
        before=source.lstat();maximum=(64<<20) if name.endswith(".exe") else (4<<20)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and not getattr(before,"st_file_attributes",0)&0x400 and 0<before.st_size<=maximum,"Expected bounded regular native subject")
        flags=os.O_RDONLY|getattr(os,"O_BINARY",0)|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_NONBLOCK",0)
        descriptor=os.open(source,flags)
        try:
            identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_nlink)
            require(identity(os.fstat(descriptor))==identity(before),"Native subject changed before staging")
            with os.fdopen(descriptor,"rb",closefd=False) as stream:data=stream.read(maximum+1)
            require(len(data)==before.st_size and identity(os.fstat(descriptor))==identity(before),"Native subject changed during staging")
        finally:os.close(descriptor)
        with (destination/name).open("xb") as stream:stream.write(data)
    # Producer validation precedes signing; it is not cryptographic authentication.
    result=validate_contents(destination,commit,ref,arch,versions)
    if run_id is not None:require(result["nativeRunID"]==run_id,"Native producer run differs from caller expectation")
    return result

def check_rejections(path,bundle,commit,ref,gh):
    base=verification_command(path,bundle,commit,ref,gh)
    def run(command,success):
        result=subprocess.run(command,capture_output=True,timeout=120)
        require((result.returncode==0)==success,"Unexpected Windows provenance rejection result")
    run(base,True);rejected=[]
    for flag,value in (("--source-digest","0"*len(commit)),("--source-ref","refs/tags/invalid-installer-probe"),("--signer-workflow",REPOSITORY+"/.github/workflows/ci.yml"),("--repo","octocat/Hello-World")):
        command=list(base);command[command.index(flag)+1]=value;run(command,False);rejected.append(flag)
    with tempfile.TemporaryDirectory(prefix="accessweaver-installer-negative-") as temporary:
        changed=Path(temporary)/path.name;changed.write_bytes(path.read_bytes()+b"changed")
        command=list(base);command[3]=str(changed.resolve());run(command,False);rejected.append("changed-subject-digest")
    run(base,True);return {"rejected":rejected,"realBundleVerifiedBeforeAndAfter":True}

def verify(directory,commit,ref,arch,versions=DEFAULT_VERSIONS,gh="gh",rejections=False,*,run_id):
    validate_identity(commit,ref);validate_run_id(run_id);names=subject_names(arch,versions)
    with tempfile.TemporaryDirectory(prefix="accessweaver-installer-auth-") as temporary:
        root=Path(temporary);require(snapshot(Path(directory),root,6)==names|{BUNDLE_NAME},"Expected five native subjects and one provenance bundle")
        for name in names|{BUNDLE_NAME}:
            maximum=(64<<20) if name.endswith(".exe") else (16<<20) if name==BUNDLE_NAME else (4<<20)
            require((root/name).stat().st_size<=maximum,"Native subject exceeds its type limit")
        for name in sorted(names):authenticate(root/name,root/BUNDLE_NAME,commit,ref,gh,run_id)
        contents=validate_contents(root,commit,ref,arch,versions)
        require(contents["nativeRunID"]==run_id,"Authenticated native run differs from caller expectation")
        result={"schemaVersion":1,"repository":REPOSITORY,"workflow":WORKFLOW,"sourceCommit":commit,"sourceRef":ref,"target":"windows/"+arch,"approvedVersions":list(versions),"subjectsVerified":5,"hostedRunnerRequired":True,"attestationRunID":run_id,"authenticatedBeforeParsing":True,"subjects":[{"file":name,"sha256":digest((root/name).read_bytes())} for name in sorted(names)],"nativeAcceptance":contents,"publisherSignatureVerified":False,"targetExecutionPerformedByVerifier":False,"productionQualificationComplete":False}
        if rejections:result["rejectionChecks"]=check_rejections(root/(arch+".json"),root/BUNDLE_NAME,commit,ref,gh)
        return result

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("directory",type=Path)
    parser.add_argument("--source-commit",required=True);parser.add_argument("--source-ref",required=True);parser.add_argument("--architecture",required=True)
    parser.add_argument("--versions",nargs=2,default=DEFAULT_VERSIONS);parser.add_argument("--gh",default="gh");parser.add_argument("--check-rejections",action="store_true");parser.add_argument("--stage-build-root",type=Path);parser.add_argument("--run-id",required=True)
    args=parser.parse_args()
    try:
        if args.stage_build_root is not None:
            result=stage(args.stage_build_root,args.directory,args.source_commit,args.source_ref,args.architecture,args.versions,args.run_id)
            print(json.dumps({"producerContentsValidatedBeforeSigning":True,"cryptographicProvenanceAuthenticated":False,"publisherSignatureVerified":False,"productionQualificationComplete":False,"nativeAcceptance":result}));return 0
        print(json.dumps(verify(args.directory,args.source_commit,args.source_ref,args.architecture,args.versions,args.gh,args.check_rejections,run_id=args.run_id)));return 0
    except (ValueError,OSError,KeyError,TypeError,RecursionError,subprocess.SubprocessError,struct.error) as error:
        print("Windows installer provenance verification failed ("+type(error).__name__+")",file=sys.stderr);return 1

if __name__=="__main__":sys.exit(main())
