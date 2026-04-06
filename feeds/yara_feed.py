"""
YARAify feed — abuse.ch YARA rule hit tracker.
API docs: https://yaraify.abuse.ch/api/

Uses list_tasks for a private identifier (create via query=generate_identifier).
"""
import json
from typing import Any, Dict, List

import requests

from .base import BaseFeed, FeedEntry
from config import (
    REQUEST_TIMEOUT,
    YARAIFY_API_URL,
    YARAIFY_AUTH_KEY,
    YARAIFY_IDENTIFIER,
)


class YARAifyFeed(BaseFeed):
    name = "yaraify"

    def fetch(self) -> List[FeedEntry]:
        """
        Recent processed scan tasks for YARAIFY_IDENTIFIER (max 250 / 24h window).
        """
        if not YARAIFY_AUTH_KEY:
            raise ValueError(
                "YARAify requires YARAIFY_AUTH_KEY (or shared abuse.ch key). "
                "https://auth.abuse.ch/"
            )
        if not YARAIFY_IDENTIFIER:
            raise ValueError(
                "YARAify list_tasks requires YARAIFY_IDENTIFIER in .env "
                '(create one: POST {"query": "generate_identifier"} to the YARAify API).'
            )
        headers = {"Auth-Key": YARAIFY_AUTH_KEY, "Content-Type": "application/json"}
        body = {
            "query": "list_tasks",
            "identifier": YARAIFY_IDENTIFIER,
            "task_status": "processed",
        }
        resp = requests.post(
            YARAIFY_API_URL,
            data=json.dumps(body),
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        payload: Dict[str, Any] = resp.json()
        if payload.get("query_status") not in (None, "ok"):
            raise ValueError(f"YARAify API: {payload.get('query_status')}")

        rows = payload.get("data") or []
        entries: List[FeedEntry] = []
        for item in rows:
            if not isinstance(item, dict):
                continue
            h = item.get("sha256_hash") or item.get("sha256")
            if not h:
                continue
            name = item.get("file_name") or ""
            entries.append(
                FeedEntry(
                    ioc=str(h).lower(),
                    ioc_type="sha256",
                    malware_family=None,
                    threat_type="yaraify_scan",
                    source=self.name,
                    tags=[str(name)] if name else [],
                    raw=item,
                )
            )
        return entries
