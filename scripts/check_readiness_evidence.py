#!/usr/bin/env python3
"""Validate tracked readiness evidence references and summarize the gate register."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


GATE_STATUSES = ("passed", "partial", "failed")
COMMIT = r"(?:[0-9a-f]{40}|[0-9a-f]{64})"
SHA256 = r"[0-9a-f]{64}"


def verify_qualification(gate, root, candidate_commit):
    gate_id = gate["id"]
    qualification = gate.get("qualification")
    fields = {"sourceCommit", "environment", "procedure", "result", "evidenceSHA256"}
    if not isinstance(qualification, dict) or qualification.keys() != fields:
        raise ValueError(f"{gate_id} needs a qualification record before it can pass")
    if not candidate_commit or qualification["sourceCommit"] != candidate_commit:
        raise ValueError(f"{gate_id} qualification source differs from the assessed candidate")
    if any(not isinstance(qualification[key], str) or not qualification[key].strip()
           for key in ("environment", "procedure", "result")):
        raise ValueError(f"{gate_id} qualification needs an environment, procedure and result")
    evidence = qualification["evidenceSHA256"]
    if not isinstance(evidence, dict) or not evidence or evidence.keys() - set(gate["evidence"]):
        raise ValueError(f"{gate_id} qualification must pin one or more cited evidence files")
    for path, expected in evidence.items():
        source = root / path
        if (not isinstance(expected, str) or not re.fullmatch(SHA256, expected)
                or Path(path).anchor or source.resolve() != source):
            raise ValueError(f"{gate_id} has an invalid qualification evidence pin")
        digest = hashlib.sha256()
        with source.open("rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected:
            raise ValueError(f"{gate_id} qualification evidence digest differs for {path}")


def summarize(register, root, tracked, *, candidate_commit=None):
    root = root.resolve()
    areas = register["areas"]
    gates = [gate for area in areas for gate in area["gates"]]
    scoring = register["scoring"]
    weight = scoring["gateWeight"]
    total = scoring["total"]
    if type(total) is not int or total != 100 or type(weight) is not int or weight <= 0 or weight * len(gates) != total:
        raise ValueError("Readiness gate weights must total 100")

    assessed_commit = register.get("candidateCommit")
    for value in (assessed_commit, candidate_commit):
        if value is not None and (not isinstance(value, str) or not re.fullmatch(COMMIT, value)):
            raise ValueError("Expected a full lowercase readiness candidate commit")
    if candidate_commit is not None and assessed_commit != candidate_commit:
        raise ValueError("Readiness register was not assessed against the requested candidate")

    counts = dict.fromkeys(GATE_STATUSES, 0)
    failed = []
    gate_ids = set()
    for gate in gates:
        gate_id = gate["id"]
        if not isinstance(gate_id, str) or not re.fullmatch(r"[a-z]+\.[a-z0-9-]+", gate_id) or gate_id in gate_ids:
            raise ValueError("Duplicate or invalid readiness gate identifier")
        gate_ids.add(gate_id)

        status = gate["status"]
        if status not in GATE_STATUSES:
            raise ValueError(f"{gate_id} has an invalid readiness status")
        counts[status] += 1
        if status == "failed":
            failed.append(gate_id)
        evidence = gate["evidence"]
        if not isinstance(evidence, list) or not evidence:
            raise ValueError(f"{gate_id} has no evidence references")
        seen = set()
        for path in evidence:
            if not isinstance(path, str) or path not in tracked or not (root / path).is_file():
                raise ValueError(f"{gate_id} has an evidence reference missing from the checkout")
            if path in seen:
                raise ValueError(f"{gate_id} has a duplicate evidence reference")
            seen.add(path)
        if status == "passed":
            verify_qualification(gate, root, assessed_commit)

    score = weight * counts["passed"]
    assessment = register["assessmentState"]
    expected = "complete" if score == total else "in-progress"
    if assessment != expected:
        raise ValueError("Readiness assessment state disagrees with gate statuses")
    return {
        "assessmentState": assessment,
        "candidateCommit": assessed_commit,
        "score": score,
        "total": total,
        "counts": counts,
        "failedGates": failed,
    }


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="The score reflects recorded gate statuses. Review each cited artifact before passing a gate.",
    )
    parser.add_argument("--json", action="store_true", help="print the score and gate counts as JSON")
    parser.add_argument("--candidate-commit", help="require the assessment to match this full commit")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    register = json.loads((root / "docs/readiness-gates.json").read_text(encoding="utf-8"))
    tracked = set(subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=root, encoding="utf-8", timeout=30
    ).split("\0"))
    summary = summarize(register, root, tracked, candidate_commit=args.candidate_commit)
    if args.json:
        print(json.dumps(summary))
        return
    counts = summary["counts"]
    print(f"Verified tracked evidence references for {sum(counts.values())} readiness gates.")
    if summary["candidateCommit"] is not None:
        print(f"Assessed candidate {summary['candidateCommit']}.")
    print(f"Recorded readiness score {summary['score']}/{summary['total']} "
          f"({counts['passed']} passed, {counts['partial']} partial, {counts['failed']} failed).")
    for gate_id in summary["failedGates"]:
        print(f"Failed gate {gate_id}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"Readiness evidence check failed. {error}", file=sys.stderr)
        sys.exit(1)
