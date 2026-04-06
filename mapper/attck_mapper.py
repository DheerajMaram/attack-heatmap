"""
Core ATT&CK mapper — resolves malware family names to ATT&CK technique IDs.

Uses mitreattack-python (MitreAttackData) to:
  1. Search the ATT&CK STIX bundle for Software objects matching a family name
  2. Retrieve all techniques used by that software
  3. Return a list of external technique IDs (e.g. ["T1059.001", "T1071.001"])

The STIX bundle is downloaded on first run and cached at data/enterprise-attack.json.
"""
import re
from typing import Dict, List, Optional

from mitreattack.stix20 import MitreAttackData

from config import STIX_BUNDLE_PATH
from mapper.stix_downloader import download


def _normalize(name: str) -> str:
    """Lower-case, strip punctuation for fuzzy family-name matching."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


class ATTCKMapper:
    def __init__(self):
        if not STIX_BUNDLE_PATH.exists():
            download()
        self.attack_data = MitreAttackData(str(STIX_BUNDLE_PATH))

        # Pre-build a lookup: normalized_name → stix_id for all Software objects
        self._software_index: Dict[str, str] = {}
        self._build_software_index()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_software_index(self) -> None:
        """
        Index all Software objects (malware + tool) by normalized name.

        mitreattack-python returns STIX objects; we pull:
            obj["name"]                   → primary name
            obj.get("x_mitre_aliases", []) → alternate names
        """
        softwares = self.attack_data.get_software()
        for sw in softwares:
            name = sw.get("name", "")
            aliases = sw.get("x_mitre_aliases", []) or []
            stix_id = sw["id"]
            for alias in [name] + aliases:
                key = _normalize(alias)
                if key:
                    self._software_index[key] = stix_id

    def _stix_id_for_family(self, malware_family: str) -> Optional[str]:
        """Return the STIX ID for a malware family name, or None if not found."""
        return self._software_index.get(_normalize(malware_family))

    def _techniques_for_stix_id(self, stix_id: str) -> List[str]:
        """
        Retrieve ATT&CK technique IDs for a Software STIX object.

        Steps:
          1. get_techniques_used_by_software → list of relationship/technique dicts
          2. Extract external_id from each technique's external_references
        """
        # TODO: resolve mitreattack-python API — method signature varies by version.
        # mitreattack-python ≥ 2.0 returns a list of dicts with keys
        # "object" (technique STIX obj) and "relationship" (use relationship).
        # Earlier versions may return plain STIX objects.
        try:
            uses = self.attack_data.get_techniques_used_by_software(stix_id)
        except Exception:
            return []

        tech_ids: List[str] = []
        for entry in uses:
            # Handle both v2 dict format and plain STIX object
            technique = entry.get("object", entry) if isinstance(entry, dict) else entry
            for ref in technique.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tech_ids.append(ref["external_id"])
        return tech_ids

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def family_to_techniques(self, malware_family: str) -> List[str]:
        """
        Return a list of ATT&CK technique IDs for the given malware family name.

        Example:
            mapper.family_to_techniques("Emotet")
            → ["T1059.001", "T1071.001", "T1566.001", ...]

        Raises:
            ValueError: if the family is not found in the ATT&CK STIX bundle.
        """
        stix_id = self._stix_id_for_family(malware_family)
        if stix_id is None:
            raise ValueError(f"Malware family not found in ATT&CK STIX: {malware_family!r}")
        return self._techniques_for_stix_id(stix_id)

    def bulk_map(self, families: List[str]) -> Dict[str, List[str]]:
        """
        Map a list of malware family names to their ATT&CK technique IDs.

        Unknown families are silently skipped (logged, empty list).

        Returns:
            {family_name: [technique_id, ...]}
        """
        results: Dict[str, List[str]] = {}
        for family in sorted(set(f for f in families if f)):
            try:
                results[family] = self.family_to_techniques(family)
            except ValueError:
                results[family] = []
            except Exception as exc:
                print(f"    [mapper] Unexpected error for {family!r}: {exc}")
                results[family] = []
        return results
