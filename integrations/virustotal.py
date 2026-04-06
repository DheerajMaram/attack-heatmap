"""
VirusTotal API v3 — file/URL reports for enrichment and gap-report context.

Docs: https://docs.virustotal.com/reference/overview
"""
from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

from feeds.base import FeedEntry

VT_API_BASE = "https://www.virustotal.com/api/v3"

_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


@dataclass
class VtContextRow:
    """One row for gaps.md VirusTotal section."""
    ioc: str
    ioc_type: str
    suggested_family: str
    malicious: int
    harmless: int
    undetected: int
    suspicious: int
    link: str
    enriched_family: bool = False


@dataclass
class VtEnrichmentStats:
    """Counters for CLI diagnostics after VT enrichment."""

    candidates_queued: int
    hash_candidate_slots: int
    url_candidate_slots: int
    dedup_skipped: int
    lookups: int
    ok: int
    not_found: int
    errors: int
    capped_remaining: int

    def summary_line(self, report_rows: int) -> str:
        c = f"{self.candidates_queued} candidates"
        if self.dedup_skipped:
            c += f" ({self.dedup_skipped} duplicate IOCs skipped)"
        parts = [
            c,
            f"{self.lookups} lookups",
            f"{self.ok} ok",
            f"{self.not_found} 404",
            f"{self.errors} errors",
            f"{report_rows} report rows",
        ]
        base = "VT: " + ", ".join(parts)
        if self.capped_remaining > 0:
            base += f" ({self.capped_remaining} not tried — lookup cap)"
        if self.candidates_queued == 0:
            base += " — no sha256/URL IOCs missing malware_family (URLs need VT_INCLUDE_URLS or paid tier)"
        return base


def _url_to_vt_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.strip().encode()).decode().rstrip("=")


def _extract_family(attrs: Dict[str, Any]) -> Optional[str]:
    """Deterministic primary label from VT attributes."""
    ptc = attrs.get("popular_threat_classification") or {}
    label = ptc.get("suggested_threat_label") or ptc.get("popular_threat_name")
    if label and str(label).strip():
        return str(label).strip()
    mn = attrs.get("meaningful_name")
    if mn and str(mn).strip():
        return str(mn).strip()
    names = attrs.get("names")
    if isinstance(names, list) and names:
        n = names[0]
        if n and str(n).strip():
            return str(n).strip()
    return None


def _stats(attrs: Dict[str, Any]) -> Tuple[int, int, int, int]:
    s = attrs.get("last_analysis_stats") or {}
    return (
        int(s.get("malicious") or 0),
        int(s.get("harmless") or 0),
        int(s.get("undetected") or 0),
        int(s.get("suspicious") or 0),
    )


def _file_gui_link(sha256: str) -> str:
    return f"https://www.virustotal.com/gui/file/{sha256}"


def _url_gui_link(url: str) -> str:
    return f"https://www.virustotal.com/gui/url/{_url_to_vt_id(url)}"


def enrich_feed_entries(
    entries: List[FeedEntry],
    api_key: str,
    max_lookups: int,
    min_interval_sec: float,
    include_urls: bool,
    report_cap: int = 30,
    on_progress: Optional[Callable[[str, int, int], None]] = None,
) -> Tuple[List[FeedEntry], List[VtContextRow], VtEnrichmentStats]:
    """
    Lookup VT for IOCs missing malware_family (hashes first, then URLs if allowed).

    Mutates entries in place (sets malware_family when empty). Respects max_lookups
    and sleeps min_interval_sec between requests (unless 429 Retry-After).
    """
    headers = {"x-apikey": api_key}
    session = requests.Session()
    rows: List[VtContextRow] = []
    performed = 0
    first_request = True
    dedup_skipped = 0
    n_ok = 0
    n_404 = 0
    n_err = 0
    capped_remaining = 0

    def backoff(resp: requests.Response) -> None:
        ra = resp.headers.get("Retry-After")
        if ra:
            try:
                time.sleep(float(ra))
            except ValueError:
                time.sleep(min_interval_sec)
        else:
            time.sleep(min_interval_sec)

    # Candidates: (priority, entry_index) — no family first
    hash_candidates: List[int] = []
    url_candidates: List[int] = []
    for i, e in enumerate(entries):
        if e.malware_family and str(e.malware_family).strip():
            continue
        ioc = (e.ioc or "").strip()
        it = (e.ioc_type or "").lower()
        if it == "sha256" and _SHA256_RE.match(ioc):
            hash_candidates.append(i)
        elif it == "md5" and len(ioc) == 32:
            # VT file id is sha256; skip md5-only unless we resolve elsewhere
            continue
        elif include_urls and it == "url" and ioc.lower().startswith(("http://", "https://")):
            url_candidates.append(i)

    order = hash_candidates + url_candidates
    seen_ioc: set = set()

    for slot, idx in enumerate(order):
        if performed >= max_lookups:
            capped_remaining = len(order) - slot
            break
        e = entries[idx]
        ioc = e.ioc.strip()
        it = e.ioc_type.lower()
        key = f"{it}:{ioc}"
        if key in seen_ioc:
            dedup_skipped += 1
            continue
        seen_ioc.add(key)

        if on_progress:
            on_progress(ioc, performed + 1, max_lookups)

        if not first_request:
            time.sleep(min_interval_sec)
        first_request = False

        try:
            if it == "sha256":
                url = f"{VT_API_BASE}/files/{ioc.lower()}"
                r = session.get(url, headers=headers, timeout=60)
                if r.status_code == 429:
                    backoff(r)
                    r = session.get(url, headers=headers, timeout=60)
                if r.status_code == 404:
                    performed += 1
                    n_404 += 1
                    continue
                r.raise_for_status()
                data = r.json()
                attrs = data.get("data", {}).get("attributes") or {}
            elif it == "url" and include_urls:
                uid = _url_to_vt_id(ioc)
                url = f"{VT_API_BASE}/urls/{uid}"
                r = session.get(url, headers=headers, timeout=60)
                if r.status_code == 429:
                    backoff(r)
                    r = session.get(url, headers=headers, timeout=60)
                if r.status_code == 404:
                    performed += 1
                    n_404 += 1
                    continue
                r.raise_for_status()
                data = r.json()
                attrs = data.get("data", {}).get("attributes") or {}
            else:
                continue
        except requests.RequestException:
            performed += 1
            n_err += 1
            continue

        performed += 1
        n_ok += 1
        fam = _extract_family(attrs)
        mal, harm, und, sus = _stats(attrs)
        link = _file_gui_link(ioc.lower()) if it == "sha256" else _url_gui_link(ioc)
        enriched = False
        if fam and not (e.malware_family and str(e.malware_family).strip()):
            e.malware_family = fam
            enriched = True
        e.raw = dict(e.raw) if e.raw else {}
        e.raw["virustotal"] = {
            "last_analysis_stats": attrs.get("last_analysis_stats"),
            "popular_threat_classification": attrs.get("popular_threat_classification"),
        }
        if len(rows) < report_cap:
            rows.append(
                VtContextRow(
                    ioc=ioc[:120] + ("…" if len(ioc) > 120 else ""),
                    ioc_type=it,
                    suggested_family=fam or "—",
                    malicious=mal,
                    harmless=harm,
                    undetected=und,
                    suspicious=sus,
                    link=link,
                    enriched_family=enriched,
                )
            )

    stats = VtEnrichmentStats(
        candidates_queued=len(order),
        hash_candidate_slots=len(hash_candidates),
        url_candidate_slots=len(url_candidates),
        dedup_skipped=dedup_skipped,
        lookups=n_ok + n_404 + n_err,
        ok=n_ok,
        not_found=n_404,
        errors=n_err,
        capped_remaining=capped_remaining,
    )
    return entries, rows, stats
