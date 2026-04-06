"""
Optional enrichment layer — supplements ATT&CK mapper with external lookups.

- Malpedia: https://malpedia.caad.fkie.fraunhofer.de/api (APIToken auth)
- MISP Galaxy: local mitre-attack-pattern.json (MISP_GALAXY_ATTACK_PATTERN_PATH)
"""
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from config import (
    MALPEDIA_API_KEY,
    MISP_GALAXY_ATTACK_PATTERN_PATH,
    REQUEST_TIMEOUT,
)

_TID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.I)


def _malpedia_headers() -> Dict[str, str]:
    # Official client uses "APIToken"; docs also show "apitoken"
    tok = MALPEDIA_API_KEY.strip()
    return {"Authorization": f"APIToken {tok}"}


def _extract_technique_ids(obj: Any, seen: Optional[set] = None) -> List[str]:
    """Recursively collect ATT&CK technique IDs from Malpedia JSON."""
    if seen is None:
        seen = set()
    out: List[str] = []
    if isinstance(obj, dict):
        chunk = obj.get("ATT&CK")
        if isinstance(chunk, list):
            for row in chunk:
                if isinstance(row, dict):
                    tid = row.get("tid") or row.get("technique_id") or row.get("id")
                    if tid:
                        nt = str(tid).strip().upper()
                        if _TID_RE.match(nt) and nt not in seen:
                            seen.add(nt)
                            out.append(nt)
        for k, v in obj.items():
            if k == "ATT&CK":
                continue
            out.extend(_extract_technique_ids(v, seen))
    elif isinstance(obj, list):
        for x in obj:
            out.extend(_extract_technique_ids(x, seen))
    return out


class Enricher:
    def __init__(self):
        self._malpedia_base = "https://malpedia.caad.fkie.fraunhofer.de/api"
        self._misp_cache: Optional[List[Dict[str, Any]]] = None

    def _load_misp_values(self) -> List[Dict[str, Any]]:
        if self._misp_cache is not None:
            return self._misp_cache
        path = (MISP_GALAXY_ATTACK_PATTERN_PATH or "").strip()
        if not path or not Path(path).is_file():
            self._misp_cache = []
            return self._misp_cache
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        self._misp_cache = list(raw.get("values") or [])
        return self._misp_cache

    def malpedia_family_techniques(self, family_slug: str) -> List[str]:
        """Fetch ATT&CK technique IDs for a malware family (Malpedia slug, e.g. win.emotet)."""
        if not MALPEDIA_API_KEY:
            return []

        slug = family_slug.strip()
        headers = _malpedia_headers()
        base = self._malpedia_base

        def get_family(s: str) -> Optional[Dict[str, Any]]:
            url = f"{base}/get/family/{s}"
            r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json()

        data = get_family(slug)
        if data is None:
            r2 = requests.get(
                f"{base}/find/family/{slug}",
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            r2.raise_for_status()
            found = r2.json()
            if isinstance(found, list) and found:
                first = found[0].get("name")
                if isinstance(first, str):
                    data = get_family(first)
            if data is None:
                return []

        tids = _extract_technique_ids(data)
        return sorted(set(tids))

    def misp_galaxy_techniques(self, cluster_name: str) -> List[str]:
        """
        Match MISP Galaxy attack-pattern cluster `value` fields against cluster_name
        (substring, case-insensitive) and return external_id technique IDs.
        """
        needle = cluster_name.strip().lower()
        if not needle:
            return []
        out: List[str] = []
        for v in self._load_misp_values():
            val = (v.get("value") or "").lower()
            if needle not in val:
                continue
            meta = v.get("meta") or {}
            eid = meta.get("external_id")
            if eid and _TID_RE.match(str(eid)):
                out.append(str(eid).upper())
        return sorted(set(out))

    def enrich(self, malware_family: str) -> List[str]:
        """Merge Malpedia + MISP lookups for one family label."""
        techniques: List[str] = []
        try:
            techniques.extend(self.malpedia_family_techniques(malware_family))
        except Exception:
            pass
        try:
            techniques.extend(self.misp_galaxy_techniques(malware_family))
        except Exception:
            pass
        return sorted(set(techniques))
