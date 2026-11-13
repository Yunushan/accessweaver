#!/usr/bin/env python3
"""Check that the readiness register links to files in a clean checkout."""
import json
from pathlib import Path
import re
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[1]
    register = json.loads((root / "docs/readiness-gates.json").read_text(encoding="utf-8"))
    tracked = set(subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=root, encoding="utf-8", timeout=30
    ).split("\0"))
    gates = [gate for area in register["areas"] for gate in area["gates"]]
    scoring = register["scoring"]
    if scoring["total"] != 100 or scoring["gateWeight"] * len(gates) != scoring["total"]:
        raise ValueError("Readiness gate weights must total 100")

    gate_ids = set()
    for gate in gates:
        gate_id = gate["id"]
        if gate_id in gate_ids or not re.fullmatch(r"[a-z]+\.[a-z0-9-]+", gate_id):
            raise ValueError("Duplicate or invalid readiness gate identifier")
        gate_ids.add(gate_id)
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
    print(f"Verified tracked evidence references for {len(gates)} readiness gates.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"Readiness evidence check failed. {error}", file=sys.stderr)
        sys.exit(1)
