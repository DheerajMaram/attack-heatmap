"""
Build a technique co-occurrence matrix (JSON) from the public CTID TIE dataset.

Output format matches mapper.TIERanker: nested dict T_a -> T_b -> float (counts).

Source data:
  https://github.com/center-for-threat-informed-defense/technique-inference-engine
  blob main/data/combined_dataset_full_frequency.json

Usage (from repo root):
  python scripts/build_tie_cooccurrence.py
  python scripts/build_tie_cooccurrence.py --input path/to/combined_dataset_full_frequency.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, DefaultDict, Dict
import requests

DEFAULT_URL = (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/"
    "technique-inference-engine/main/data/combined_dataset_full_frequency.json"
)


def build_matrix(raw: Dict[str, Any]) -> Dict[str, Dict[str, float]]:
    reports = raw.get("reports")
    if not isinstance(reports, list):
        raise ValueError("expected top-level 'reports' list")

    acc: DefaultDict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))

    for rep in reports:
        if not isinstance(rep, dict):
            continue
        mt = rep.get("mitre_techniques")
        if not isinstance(mt, dict):
            continue
        techs = sorted({str(k).strip().upper() for k in mt if k})
        n = len(techs)
        for i in range(n):
            for j in range(i + 1, n):
                a, b = techs[i], techs[j]
                acc[a][b] += 1.0
                acc[b][a] += 1.0

    return {k: dict(v) for k, v in acc.items()}


def main() -> int:
    p = argparse.ArgumentParser(description="Build TIE co-occurrence matrix JSON.")
    p.add_argument(
        "--input",
        type=Path,
        help="Local combined_dataset_full_frequency.json (default: download)",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=Path("data/tie_cooccurrence_matrix.json"),
        help="Output path (default: data/tie_cooccurrence_matrix.json)",
    )
    p.add_argument(
        "--url",
        default=DEFAULT_URL,
        help="Download URL if --input not set",
    )
    args = p.parse_args()

    if args.input:
        text = args.input.read_text(encoding="utf-8")
    else:
        r = requests.get(args.url, timeout=120)
        r.raise_for_status()
        text = r.text

    raw = json.loads(text)
    matrix = build_matrix(raw)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(matrix, indent=0), encoding="utf-8")

    n_t = len(matrix)
    n_e = sum(len(v) for v in matrix.values()) // 2  # undirected edges counted twice
    print(f"Wrote {args.output} ({n_t} techniques, ~{n_e} undirected co-occurrence pairs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
