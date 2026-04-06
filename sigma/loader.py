"""
Sigma rule loader — scans the rules directory and extracts ATT&CK technique coverage.

Tag normalization examples:
    "attack.t1059"       → "T1059"
    "attack.t1059.001"   → "T1059.001"
    "attack.t1059_001"   → "T1059.001"   (underscore separator)
    "attack.discovery"   → (ignored — tactic, not technique)
"""
import re
from pathlib import Path
from typing import Dict, List, Optional, Set

import yaml

from config import SIGMA_RULES_DIR


_TECHNIQUE_PATTERN = re.compile(r"^t\d{4}([\._]\d{3})?$")


def _parse_technique_tag(tag: str) -> Optional[str]:
    """
    Convert a Sigma attack tag to a canonical ATT&CK technique ID, or None
    if the tag does not represent a technique (e.g. it's a tactic name).
    """
    tag = tag.lower().strip()
    if not tag.startswith("attack."):
        return None
    suffix = tag[len("attack."):]
    if not _TECHNIQUE_PATTERN.match(suffix):
        return None
    # Normalize: replace underscore sub-technique separator with dot
    canonical = suffix.upper().replace("_", ".")
    # Replace first dot after T\d{4} pattern — already dot-separated from above
    return canonical


def load_sigma_coverage(rules_dir: Path = SIGMA_RULES_DIR) -> Set[str]:
    """
    Recursively scan rules_dir for .yml Sigma rules.
    Extract ATT&CK technique IDs from tags.

    Returns:
        Set of covered technique IDs, e.g. {"T1059.001", "T1566.001", "T1071"}
    """
    covered: Set[str] = set()
    for rule_file in rules_dir.rglob("*.yml"):
        try:
            with open(rule_file, encoding="utf-8") as fh:
                rule = yaml.safe_load(fh)
            if not isinstance(rule, dict):
                continue
            tags = rule.get("tags") or []
            for tag in tags:
                tech_id = _parse_technique_tag(str(tag))
                if tech_id:
                    covered.add(tech_id)
        except Exception:
            continue
    return covered


def load_sigma_rules_metadata(rules_dir: Path = SIGMA_RULES_DIR) -> List[Dict]:
    """
    Load full metadata for every Sigma rule.
    Returns a list of dicts with: title, id, status, techniques, path.
    """
    rules = []
    for rule_file in rules_dir.rglob("*.yml"):
        try:
            with open(rule_file, encoding="utf-8") as fh:
                rule = yaml.safe_load(fh)
            if not isinstance(rule, dict):
                continue
            tags = rule.get("tags") or []
            techniques = []
            for tag in tags:
                t = _parse_technique_tag(str(tag))
                if t is not None:
                    techniques.append(t)
            rules.append(
                {
                    "title": rule.get("title", ""),
                    "id": rule.get("id", ""),
                    "status": rule.get("status", ""),
                    "techniques": techniques,
                    "path": str(rule_file),
                }
            )
        except Exception:
            continue
    return rules
