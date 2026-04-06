"""
URLhaus feed — abuse.ch malware distribution URL tracker.
API docs: https://urlhaus-api.abuse.ch/
"""
import requests
from typing import Any, Dict, List

from .base import BaseFeed, FeedEntry
from config import URLHAUS_API_URL, URLHAUS_AUTH_KEY, REQUEST_TIMEOUT


def _as_tag_list(val: Any) -> List[str]:
    if val is None:
        return []
    if isinstance(val, list):
        return [str(x) for x in val if x is not None]
    if isinstance(val, str):
        return [t.strip() for t in val.split(",") if t.strip()]
    return [str(val)]


class URLHausFeed(BaseFeed):
    name = "urlhaus"

    def fetch(self) -> List[FeedEntry]:
        """Recent malware URLs (last ~3 days, max 1000) + Auth-Key header."""
        if not URLHAUS_AUTH_KEY:
            raise ValueError(
                "URLhaus requires URLHAUS_AUTH_KEY (or shared abuse.ch key). "
                "https://auth.abuse.ch/"
            )
        url = f"{URLHAUS_API_URL.rstrip('/')}/urls/recent/"
        headers = {"Auth-Key": URLHAUS_AUTH_KEY}
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data: Dict[str, Any] = resp.json()
        if data.get("query_status") not in (None, "ok"):
            raise ValueError(f"URLhaus API: {data.get('query_status')}")

        entries: List[FeedEntry] = []
        for item in data.get("urls") or []:
            if not isinstance(item, dict):
                continue
            u = item.get("url")
            if not u:
                continue
            threat = item.get("threat") or "malware_download"
            tags = _as_tag_list(item.get("tags"))
            fam = None
            for t in tags:
                if "." not in t and len(t) > 2:
                    fam = t
                    break
            entries.append(
                FeedEntry(
                    ioc=str(u),
                    ioc_type="url",
                    malware_family=fam,
                    threat_type=str(threat),
                    source=self.name,
                    tags=tags,
                    raw=item,
                )
            )
        return entries
