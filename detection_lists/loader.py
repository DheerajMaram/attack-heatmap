"""
mthcht detection-list coverage loader.

Fetches curated detection lists from github.com/mthcht/awesome-lists and maps
each list to the ATT&CK techniques whose behaviour it can detect. The result
supplements the Sigma coverage set so gaps.md can show:

    Source: sigma, detection-lists

rather than just Sigma rules.

All lists are public CSVs — no API key required.

Reference: https://github.com/mthcht/awesome-lists
"""
from __future__ import annotations

import csv
import io
from typing import Dict, NamedTuple, Optional, Set

import requests

from config import REQUEST_TIMEOUT


class DetectionList(NamedTuple):
    name: str                # human-readable label shown in the report
    url: str                 # raw GitHub CSV URL
    techniques: list[str]    # ATT&CK technique IDs this list covers


# ---------------------------------------------------------------------------
# Mapping: mthcht list → ATT&CK technique IDs
#
# Sources for the mappings:
#   - mthcht/ThreatHunting-Keywords column headers include ATT&CK tags
#   - MITRE ATT&CK technique descriptions cross-referenced with list contents
#   - Technique IDs without sub-technique cover all variants (T1071 ⊇ T1071.001)
# ---------------------------------------------------------------------------
_BASE = "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists"

DETECTION_LISTS: list[DetectionList] = [
    DetectionList(
        name="Suspicious Named Pipes",
        url=f"{_BASE}/suspicious_named_pipe_list.csv",
        techniques=["T1071", "T1090", "T1559.001"],
        # Named pipes used by C2 frameworks (Cobalt Strike, Metasploit)
        # T1071: App Layer Protocol, T1090: Proxy, T1559.001: IPC - Component Object Model
    ),
    DetectionList(
        name="Suspicious Windows Services",
        url=f"{_BASE}/suspicious_windows_services_names_list.csv",
        techniques=["T1543.003", "T1569.002"],
        # Malicious/renamed services → Create/Modify System Process: Windows Service
    ),
    DetectionList(
        name="Suspicious Scheduled Tasks",
        url=f"{_BASE}/suspicious_windows_tasks_list.csv",
        techniques=["T1053.005"],
        # Scheduled Task/Job: Scheduled Task
    ),
    DetectionList(
        name="Suspicious HTTP User-Agents",
        url=f"{_BASE}/suspicious_http_user_agents_list.csv",
        techniques=["T1071.001"],
        # Web Protocols — malware/C2 UA strings
    ),
    DetectionList(
        name="Suspicious Mutex Names",
        url=f"{_BASE}/suspicious_mutex_names_list.csv",
        techniques=["T1055", "T1027"],
        # Process Injection, Obfuscated Files/Information — mutex fingerprints
    ),
    DetectionList(
        name="Suspicious Hostnames",
        url=f"{_BASE}/suspicious_hostnames_list.csv",
        techniques=["T1071.001", "T1568"],
        # Web Protocols, Dynamic Resolution — malware-associated hostnames
    ),
    DetectionList(
        name="Ransomware Extensions",
        url=f"{_BASE}/ransomware_extensions_list.csv",
        techniques=["T1486"],
        # Data Encrypted for Impact
    ),
    DetectionList(
        name="Ransomware Ransom Notes",
        url=f"{_BASE}/ransomware_notes_list.csv",
        techniques=["T1486", "T1491"],
        # Data Encrypted for Impact, Defacement
    ),
    DetectionList(
        name="LOLDrivers (BYOVD hashes)",
        url=f"{_BASE}/Drivers/loldrivers_only_hashes_list.csv",
        techniques=["T1068", "T1562.001"],
        # Exploitation for Privilege Escalation, Disable or Modify Tools
    ),
    DetectionList(
        name="Malicious Bootloaders",
        url=f"{_BASE}/Drivers/malicious_bootloaders_only_hashes_list.csv",
        techniques=["T1542.003"],
        # Bootkit
    ),
    DetectionList(
        name="HijackLibs (DLL hijacking)",
        url=f"{_BASE}/Hijacklibs/hijacklibs_list.csv",
        techniques=["T1574.001", "T1574.002"],
        # Hijack Execution Flow: DLL Search Order / Side-Loading
    ),
    DetectionList(
        name="DNS-over-HTTPS Servers",
        url=f"{_BASE}/dns_over_https_servers_list.csv",
        techniques=["T1071.004"],
        # Application Layer Protocol: DNS
    ),
    DetectionList(
        name="Offensive Tool Keywords",
        url="https://raw.githubusercontent.com/mthcht/ThreatHunting-Keywords/main/offensive_tool_keyword.csv",
        techniques=["T1059", "T1027", "T1036", "T1105"],
        # Command/Scripting, Obfuscation, Masquerading, Ingress Tool Transfer
    ),
    DetectionList(
        name="Greyware Tool Keywords",
        url="https://raw.githubusercontent.com/mthcht/ThreatHunting-Keywords/main/greyware_tool_keyword.csv",
        techniques=["T1219", "T1078", "T1021"],
        # Remote Access Software, Valid Accounts, Remote Services
    ),
    DetectionList(
        name="Malicious SSL Certificates",
        url=f"{_BASE}/SSL CERTS/ssl_certificates_malicious_list.csv",
        techniques=["T1071.001", "T1573"],
        # Web Protocols, Encrypted Channel — C2 over TLS with known-bad certs
    ),
]


def _fetch_csv_row_count(url: str, timeout: int) -> Optional[int]:
    """Download a CSV and return data-row count (header excluded). None on failure."""
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        reader = csv.reader(io.StringIO(resp.text))
        rows = list(reader)
        # Subtract 1 for header row
        return max(0, len(rows) - 1)
    except Exception:
        return None


def load_detection_list_coverage(
    lists: list[DetectionList] | None = None,
    verbose: bool = False,
) -> tuple[Set[str], Dict[str, list[str]]]:
    """
    Fetch each detection list and return:
        (covered_techniques, source_map)

    covered_techniques: set of ATT&CK technique IDs covered by at least one list.
    source_map: {technique_id: [list names that cover it]}

    Lists that fail to download are skipped with a warning (non-fatal).
    """
    if lists is None:
        lists = DETECTION_LISTS

    covered: Set[str] = set()
    source_map: Dict[str, list[str]] = {}
    loaded = 0

    for dl in lists:
        row_count = _fetch_csv_row_count(dl.url, REQUEST_TIMEOUT)
        if row_count is None:
            if verbose:
                print(f"  [detection-lists] SKIP {dl.name} — download failed")
            continue

        loaded += 1
        if verbose:
            print(f"  [detection-lists] OK   {dl.name} ({row_count:,} entries)")

        for tech_id in dl.techniques:
            covered.add(tech_id)
            source_map.setdefault(tech_id, [])
            if dl.name not in source_map[tech_id]:
                source_map[tech_id].append(dl.name)

    if verbose:
        print(
            f"  [detection-lists] {loaded}/{len(lists)} lists loaded, "
            f"{len(covered)} technique IDs covered"
        )

    return covered, source_map
