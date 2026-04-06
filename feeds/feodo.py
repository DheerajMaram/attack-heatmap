"""
Feodo Tracker feed — abuse.ch botnet C2 IP blocklist.
API docs: https://feodotracker.abuse.ch/blocklist/
"""
import requests
from typing import List

from .base import BaseFeed, FeedEntry
from config import FEODO_TRACKER_URL, REQUEST_TIMEOUT


class FeodoFeed(BaseFeed):
    name = "feodo"

    def fetch(self) -> List[FeedEntry]:
        """
        Fetch the Feodo Tracker JSON IP blocklist.

        Each record contains:
            ip_address, port, status, hostname, as_number, as_name,
            country, first_seen, last_online, malware (malware_family)
        """
        resp = requests.get(FEODO_TRACKER_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        records = resp.json()

        entries: List[FeedEntry] = []
        for item in records:
            entries.append(
                FeedEntry(
                    ioc=item.get("ip_address", ""),
                    ioc_type="ip",
                    malware_family=item.get("malware") or None,
                    threat_type="botnet_cc",
                    source=self.name,
                    tags=[item.get("malware", "")]
                    if item.get("malware")
                    else [],
                    raw=item,
                )
            )
        return entries
