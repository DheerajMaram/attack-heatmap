"""
MITRE D3FEND countermeasure lookup.

For each ATT&CK gap technique, queries the public D3FEND knowledge base API
and returns defensive countermeasure recommendations.

D3FEND covers 309 ATT&CK techniques mapped to 3,109 countermeasures.
No API key required.

Reference:
  https://d3fend.mitre.org/
  API: https://d3fend.mitre.org/api/offensive-technique/attack/{technique_id}.json
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

from config import REQUEST_TIMEOUT

_D3FEND_API = (
    "https://d3fend.mitre.org/api/offensive-technique/attack/{tech_id}.json"
)

# Pause between requests to be polite to the public API
_REQUEST_DELAY_SEC = 0.4


@dataclass
class D3FENDCountermeasure:
    """A single D3FEND defensive technique mapped to an ATT&CK technique."""
    d3fend_id: str            # e.g. "D3-IAA"
    label: str                # Human-readable name, e.g. "Inbound Traffic Analysis"
    definition: str           # Short description
    d3fend_url: str           # Direct link to D3FEND entry


@dataclass
class D3FENDResult:
    """D3FEND lookup result for a single ATT&CK technique."""
    attack_technique_id: str
    countermeasures: List[D3FENDCountermeasure] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def has_coverage(self) -> bool:
        return len(self.countermeasures) > 0


def _parse_d3fend_response(technique_id: str, data: dict) -> D3FENDResult:
    """
    Parse the D3FEND API JSON response for one ATT&CK technique.

    The API returns a SPARQL-style JSON structure:
    {
      "off_to_def": {
        "results": {
          "bindings": [
            {
              "def_tech_label": {"value": "Inbound Traffic Analysis"},
              "def_artifact_rel_label": {"value": "analyzes"},
              "def_tech": {"value": "https://d3fend.mitre.org/technique/d3f:InboundTrafficAnalysis"},
              "def_tech_kb_article_url": {"value": "https://d3fend.mitre.org/technique/d3f:InboundTrafficAnalysis"},
              "def_tech_id": {"value": "D3-ITA"},
              "short_description": {"value": "..."}
            }
          ]
        }
      }
    }
    """
    result = D3FENDResult(attack_technique_id=technique_id)
    try:
        bindings = (
            data.get("off_to_def", {})
            .get("results", {})
            .get("bindings", [])
        )
        seen: set[str] = set()
        for b in bindings:
            d3_id = b.get("def_tech_id", {}).get("value", "").strip()
            label = b.get("def_tech_label", {}).get("value", "").strip()
            definition = b.get("short_description", {}).get("value", "").strip()
            url = b.get("def_tech_kb_article_url", {}).get("value", "").strip()

            if not d3_id or d3_id in seen:
                continue
            seen.add(d3_id)

            result.countermeasures.append(
                D3FENDCountermeasure(
                    d3fend_id=d3_id,
                    label=label,
                    definition=definition,
                    d3fend_url=url or f"https://d3fend.mitre.org/technique/d3f:{label.replace(' ', '')}",
                )
            )
    except Exception as exc:
        result.error = f"parse error: {exc}"
    return result


def lookup_countermeasures(
    technique_ids: List[str],
    max_techniques: int = 20,
    delay_sec: float = _REQUEST_DELAY_SEC,
) -> Dict[str, D3FENDResult]:
    """
    Query D3FEND for countermeasures covering each ATT&CK technique.

    Args:
        technique_ids:  List of ATT&CK technique IDs (e.g. ["T1071", "T1059.001"]).
        max_techniques: Cap to avoid hammering the public API. Only the first N
                        techniques are looked up; remainder are skipped.
        delay_sec:      Pause between requests (rate-limit courtesy).

    Returns:
        Dict mapping technique_id → D3FENDResult.
        Techniques with no D3FEND mapping return a result with empty countermeasures.
    """
    results: Dict[str, D3FENDResult] = {}

    for i, tech_id in enumerate(technique_ids[:max_techniques]):
        # D3FEND uses dot notation (T1059.001) — same as ATT&CK
        url = _D3FEND_API.format(tech_id=tech_id)
        try:
            resp = requests.get(url, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 404:
                # Technique exists in ATT&CK but D3FEND has no mapping yet
                results[tech_id] = D3FENDResult(attack_technique_id=tech_id)
            else:
                resp.raise_for_status()
                results[tech_id] = _parse_d3fend_response(tech_id, resp.json())
        except Exception as exc:
            results[tech_id] = D3FENDResult(
                attack_technique_id=tech_id,
                error=str(exc),
            )

        if i < len(technique_ids) - 1:
            time.sleep(delay_sec)

    return results
