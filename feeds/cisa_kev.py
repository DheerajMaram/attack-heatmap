"""
CISA Known Exploited Vulnerabilities (KEV) feed.

Fetches the CISA KEV catalogue JSON and the companion ATT&CK mapping from
the CTID mappings-explorer project. Entries carry ATT&CK technique IDs
directly in `technique_ids`, bypassing the STIX malware-family mapper.

No API key required — both sources are public.

References:
  KEV catalogue:  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  ATT&CK mapping: https://raw.githubusercontent.com/center-for-threat-informed-defense/
                  mappings-explorer/main/src/mappings/cisa_kev_attack/enterprise_attack/
                  cisa-kev-attack-enterprise-attack.json
"""
from __future__ import annotations

import re
from typing import Dict, List, Set

import requests

from config import REQUEST_TIMEOUT
from feeds.base import BaseFeed, FeedEntry

# Public CISA KEV catalogue (no auth)
_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

# CTID mappings-explorer: KEV → ATT&CK enterprise mapping
_CTID_KEV_ATTACK_MAP_URL = (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/"
    "mappings-explorer/main/src/mappings/cisa_kev_attack/enterprise_attack/"
    "cisa-kev-attack-enterprise-attack.json"
)

# Regex for bare technique / sub-technique IDs in free-text fields
_TECH_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")


def _fetch_json(url: str, timeout: int) -> dict | list | None:
    """GET a JSON URL; return parsed body or None on failure."""
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


def _build_cve_technique_map(mapping_data: dict | None) -> Dict[str, Set[str]]:
    """
    Parse the CTID KEV-ATT&CK mapping JSON into {cve_id: {technique_ids}}.

    The CTID mappings-explorer format is:
        {
          "mapping_objects": [
            {
              "capability_id": "CVE-2021-44228",
              "attack_object_id": "T1190",
              ...
            },
            ...
          ]
        }

    Falls back to an empty dict if the data is unavailable or malformed.
    """
    result: Dict[str, Set[str]] = {}
    if not isinstance(mapping_data, dict):
        return result

    objects = mapping_data.get("mapping_objects") or []
    for obj in objects:
        cve = (obj.get("capability_id") or "").strip().upper()
        tech = (obj.get("attack_object_id") or "").strip().upper()
        if cve.startswith("CVE-") and _TECH_RE.match(tech):
            result.setdefault(cve, set()).add(tech)

    return result


class CISAKEVFeed(BaseFeed):
    """
    CISA Known Exploited Vulnerabilities feed.

    Each KEV entry is emitted as a FeedEntry keyed by CVE ID.
    When the CTID ATT&CK mapping is available the entry carries ATT&CK
    technique IDs directly in `technique_ids` — no STIX mapper lookup needed.
    Entries without a mapping are still included (technique_ids=[]) so the
    full KEV catalogue is represented in feed counts.
    """

    name = "cisa_kev"

    def fetch(self) -> List[FeedEntry]:
        # 1. Download the CTID KEV → ATT&CK mapping (best-effort)
        mapping_data = _fetch_json(_CTID_KEV_ATTACK_MAP_URL, REQUEST_TIMEOUT)
        cve_map = _build_cve_technique_map(mapping_data)
        mapped_count = len(cve_map)
        if mapped_count == 0:
            # Mapping unavailable — KEV entries will still be ingested without
            # technique IDs so they appear in feed counts.
            pass

        # 2. Download the KEV catalogue
        kev_data = _fetch_json(_KEV_URL, REQUEST_TIMEOUT)
        if not isinstance(kev_data, dict):
            raise RuntimeError(
                f"CISA KEV: unexpected response format from {_KEV_URL}"
            )

        vulns = kev_data.get("vulnerabilities") or []
        entries: List[FeedEntry] = []

        for v in vulns:
            cve_id = (v.get("cveID") or "").strip().upper()
            if not cve_id:
                continue

            # Collect technique IDs from the CTID mapping
            tech_ids = sorted(cve_map.get(cve_id, set()))

            # Also scrape any bare technique IDs from the notes field as fallback
            notes = v.get("notes") or ""
            scraped = _TECH_RE.findall(notes)
            for t in scraped:
                if t not in tech_ids:
                    tech_ids.append(t)

            entries.append(
                FeedEntry(
                    ioc=cve_id,
                    ioc_type="cve",
                    malware_family=None,      # KEV entries don't carry family names
                    threat_type="known_exploited_vulnerability",
                    source=self.name,
                    tags=[v.get("vendorProject", ""), v.get("product", "")],
                    raw=v,
                    technique_ids=tech_ids,
                )
            )

        return entries
