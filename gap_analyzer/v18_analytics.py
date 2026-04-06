"""
Structured detection strategies and AN-series analytics from a MITRE enterprise-attack STIX bundle.

Expects objects and fields introduced in recent ATT&CK releases (validated against v18.x bundles).
Parses a MITRE STIX 2.1 bundle (enterprise-attack) for:
  - attack-pattern: x_mitre_detection / description → detection_strategy
  - Objects referencing AN- external_ids → analytic_ids
"""
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

_AN_RE = re.compile(r"^AN\d+$", re.I)


@dataclass
class V18Analytic:
    """Structured detection metadata for a single ATT&CK technique (v18)."""
    technique_id: str
    detection_strategy: Optional[str] = None
    analytic_ids: List[str] = field(default_factory=list)
    analytic_descriptions: List[str] = field(default_factory=list)


def _bundle_objects(raw: Any) -> List[Dict[str, Any]]:
    if isinstance(raw, dict) and "objects" in raw:
        return [x for x in raw["objects"] if isinstance(x, dict)]
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    return []


def load_v18_analytics(stix_bundle_path: str) -> Dict[str, V18Analytic]:
    path = Path(stix_bundle_path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    objs = _bundle_objects(raw)
    by_id: Dict[str, V18Analytic] = {}

    def ensure(tid: str) -> V18Analytic:
        u = tid.strip().upper()
        if u not in by_id:
            by_id[u] = V18Analytic(technique_id=u)
        return by_id[u]

    for obj in objs:
        typ = obj.get("type") or ""
        refs = obj.get("external_references") or []

        if typ == "attack-pattern":
            tid = None
            for r in refs:
                if not isinstance(r, dict):
                    continue
                if r.get("source_name") == "mitre-attack":
                    eid = r.get("external_id")
                    if isinstance(eid, str) and eid.upper().startswith("T"):
                        tid = eid.upper()
                        break
            if not tid:
                continue
            rec = ensure(tid)
            strat = (
                obj.get("x_mitre_detection")
                or obj.get("x_mitre_detection_strategy")
                or obj.get("description")
            )
            if strat and not rec.detection_strategy:
                rec.detection_strategy = str(strat)[:4000]
            continue

        an_list: List[str] = []
        for r in refs:
            if not isinstance(r, dict):
                continue
            eid = r.get("external_id")
            if isinstance(eid, str) and _AN_RE.match(eid.strip()):
                an_list.append(eid.strip().upper())
        if not an_list:
            continue

        tid: Optional[str] = None
        xt = obj.get("x_mitre_technique_id")
        if isinstance(xt, str) and xt.upper().startswith("T"):
            tid = xt.upper()
        if not tid:
            for r in refs:
                if not isinstance(r, dict):
                    continue
                if r.get("source_name") == "mitre-attack":
                    eid = r.get("external_id")
                    if isinstance(eid, str) and eid.upper().startswith("T"):
                        tid = eid.upper()
                        break
        if not tid:
            continue

        rec = ensure(tid)
        for aid in an_list:
            if aid not in rec.analytic_ids:
                rec.analytic_ids.append(aid)
        desc = obj.get("description")
        if isinstance(desc, str) and desc.strip():
            snippet = desc.strip()[:800]
            if snippet not in rec.analytic_descriptions:
                rec.analytic_descriptions.append(snippet)

    return by_id


def get_analytic_summary(analytics: Dict[str, V18Analytic], technique_id: str) -> str:
    """Return a human-readable summary of available analytics for a technique."""
    tid = technique_id.strip().upper()
    if tid not in analytics:
        return "No v18 analytics available"
    a = analytics[tid]
    ids = ", ".join(a.analytic_ids) if a.analytic_ids else "none"
    return f"Strategy: {a.detection_strategy or 'N/A'} | Analytics: {ids}"
