"""VirusTotal enrichment and CLI tier validation."""
import os
import subprocess
import sys
from pathlib import Path
import pytest
import responses

from feeds.base import FeedEntry
from gap_analyzer.analyzer import GapResult
from gap_analyzer.reporter import render_gaps_md
from integrations.virustotal import enrich_feed_entries


ROOT = Path(__file__).resolve().parents[1]


@responses.activate
def test_enrich_feed_sha256_sets_family():
    h = "a" * 64
    responses.get(
        f"https://www.virustotal.com/api/v3/files/{h}",
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 40,
                        "harmless": 5,
                        "undetected": 10,
                        "suspicious": 0,
                    },
                    "popular_threat_classification": {
                        "suggested_threat_label": "trojan.emotet",
                    },
                }
            }
        },
        status=200,
    )
    entries = [
        FeedEntry(
            ioc=h,
            ioc_type="sha256",
            malware_family=None,
            threat_type=None,
            source="test",
            tags=[],
            raw={},
        )
    ]
    out, rows, stats = enrich_feed_entries(
        entries,
        api_key="dummy",
        max_lookups=5,
        min_interval_sec=0,
        include_urls=False,
    )
    assert out[0].malware_family == "trojan.emotet"
    assert len(rows) == 1
    assert rows[0].malicious == 40
    assert stats.candidates_queued == 1
    assert stats.lookups == 1
    assert stats.ok == 1
    assert stats.not_found == 0
    assert stats.errors == 0
    assert "1 ok" in stats.summary_line(len(rows))


@responses.activate
def test_enrich_feed_sha256_404_counts_stats():
    h = "b" * 64
    responses.get(
        f"https://www.virustotal.com/api/v3/files/{h}",
        status=404,
    )
    entries = [
        FeedEntry(
            ioc=h,
            ioc_type="sha256",
            malware_family=None,
            threat_type=None,
            source="test",
            tags=[],
            raw={},
        )
    ]
    _out, rows, stats = enrich_feed_entries(
        entries,
        api_key="dummy",
        max_lookups=5,
        min_interval_sec=0,
        include_urls=False,
    )
    assert len(rows) == 0
    assert stats.lookups == 1
    assert stats.ok == 0
    assert stats.not_found == 1
    assert stats.errors == 0


def test_render_gaps_md_vt_section():
    from integrations.virustotal import VtContextRow

    r = GapResult(
        active_techniques={"T1059.001"},
        covered_techniques={"T1059.001"},
        gap_techniques=set(),
        ranked_gaps=[],
    )
    vt = [
        VtContextRow(
            ioc="abc",
            ioc_type="sha256",
            suggested_family="x",
            malicious=1,
            harmless=2,
            undetected=3,
            suspicious=0,
            link="https://virustotal.com/gui/file/abc",
            enriched_family=True,
        )
    ]
    md = render_gaps_md(r, vt_context=vt)
    assert "VirusTotal context" in md
    assert "x" in md


def test_main_exits_when_vt_key_without_tier():
    env = os.environ.copy()
    env["VIRUSTOTAL_API_KEY"] = "test-key-please-ignore"
    # Block .env from supplying VT_TIER (load_dotenv does not override existing keys).
    env["VT_TIER"] = ""
    r = subprocess.run(
        [sys.executable, str(ROOT / "main.py"), "--no-tie"],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert r.returncode != 0
    assert "VT tier" in r.stderr or "VT tier" in r.stdout


def test_main_ok_with_no_vt_key():
    env = os.environ.copy()
    env["VIRUSTOTAL_API_KEY"] = ""
    env.pop("VT_TIER", None)
    r = subprocess.run(
        [
            sys.executable,
            str(ROOT / "main.py"),
            "--no-tie",
            "--feeds",
            "feodo",
            "--quiet",
        ],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert r.returncode == 0
