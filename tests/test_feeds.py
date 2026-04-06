"""
Tests for feed normalization logic.

Uses the `responses` library to mock HTTP calls so tests run offline.
Fixture JSON files live in tests/fixtures/.
"""
import json
from pathlib import Path

import pytest
import responses as responses_lib

from feeds.base import FeedEntry
from feeds.threatfox import ThreatFoxFeed
from feeds.feodo import FeodoFeed

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# ThreatFox
# ---------------------------------------------------------------------------

@responses_lib.activate
def test_threatfox_fetch_normalizes_entries():
    fixture = json.loads((FIXTURES_DIR / "threatfox_response.json").read_text())
    responses_lib.add(
        responses_lib.POST,
        "https://threatfox-api.abuse.ch/api/v1/",
        json=fixture,
        status=200,
    )
    feed = ThreatFoxFeed()
    entries = feed.fetch()
    assert len(entries) > 0
    for e in entries:
        assert isinstance(e, FeedEntry)
        assert e.source == "threatfox"
        assert e.ioc_type == e.ioc_type.lower()


@responses_lib.activate
def test_threatfox_handles_empty_response():
    responses_lib.add(
        responses_lib.POST,
        "https://threatfox-api.abuse.ch/api/v1/",
        json={"query_status": "no_results", "data": []},
        status=200,
    )
    feed = ThreatFoxFeed()
    entries = feed.fetch()
    assert entries == []


# ---------------------------------------------------------------------------
# Feodo
# ---------------------------------------------------------------------------

@responses_lib.activate
def test_feodo_fetch_normalizes_entries():
    fixture = json.loads((FIXTURES_DIR / "feodo_response.json").read_text())
    responses_lib.add(
        responses_lib.GET,
        "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        json=fixture,
        status=200,
    )
    feed = FeodoFeed()
    entries = feed.fetch()
    assert len(entries) > 0
    for e in entries:
        assert e.ioc_type == "ip"
        assert e.source == "feodo"
        assert e.threat_type == "botnet_cc"


# ---------------------------------------------------------------------------
# FeedEntry dataclass
# ---------------------------------------------------------------------------

def test_feed_entry_normalizes_ioc_type():
    entry = FeedEntry(
        ioc="1.2.3.4",
        ioc_type="IP",
        malware_family="TestMalware",
        threat_type=None,
        source="test",
    )
    assert entry.ioc_type == "ip"


def test_feed_entry_strips_malware_family():
    entry = FeedEntry(
        ioc="abc",
        ioc_type="sha256",
        malware_family="  Emotet  ",
        threat_type=None,
        source="test",
    )
    assert entry.malware_family == "Emotet"
