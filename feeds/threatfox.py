"""
ThreatFox feed — abuse.ch IOC database.
API docs: https://threatfox.abuse.ch/api/
"""
import requests
from typing import List

from .base import BaseFeed, FeedEntry
import config as _cfg
from config import THREATFOX_API_URL, REQUEST_TIMEOUT, THREATFOX_AUTH_KEY

# ThreatFox get_iocs accepts days 1–7 (API default 3).
_THREATFOX_MAX_DAYS = 7


class ThreatFoxFeed(BaseFeed):
    name = "threatfox"

    def fetch(self) -> List[FeedEntry]:
        """Fetch recent IOCs from ThreatFox (last N days, capped at API max 7)."""
        if not THREATFOX_AUTH_KEY:
            raise ValueError(
                "ThreatFox requires THREATFOX_AUTH_KEY in .env (HTTP header Auth-Key). "
                "Obtain a free key: https://auth.abuse.ch/"
            )
        days = max(1, min(_cfg.FEED_DAYS_BACK, _THREATFOX_MAX_DAYS))
        payload = {"query": "get_iocs", "days": days}
        headers = {"Auth-Key": THREATFOX_AUTH_KEY}
        resp = requests.post(
            THREATFOX_API_URL,
            json=payload,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        entries: List[FeedEntry] = []
        for item in data.get("data", []):
            entries.append(
                FeedEntry(
                    ioc=item.get("ioc", ""),
                    ioc_type=item.get("ioc_type", ""),
                    malware_family=item.get("malware") or None,
                    threat_type=item.get("threat_type") or None,
                    source=self.name,
                    tags=item.get("tags") or [],
                    raw=item,
                )
            )
        return entries
