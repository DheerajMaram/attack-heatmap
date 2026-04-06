"""
Tests for the three new features:
  1. CISA KEV feed (direct technique IDs, no STIX mapper needed)
  2. mthcht detection-list coverage loader
  3. D3FEND countermeasure integration
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Feature 1: CISA KEV feed
# ---------------------------------------------------------------------------

class TestCISAKEVFeed:
    """Tests for feeds/cisa_kev.py"""

    def _make_kev_payload(self):
        return {
            "catalogVersion": "2024.04.01",
            "dateReleased": "2024-04-01T00:00:00Z",
            "count": 2,
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "vulnerabilityName": "Log4Shell",
                    "dateAdded": "2021-12-10",
                    "shortDescription": "Log4j RCE",
                    "requiredAction": "Apply update",
                    "dueDate": "2021-12-24",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "T1190",
                },
                {
                    "cveID": "CVE-2017-0144",
                    "vendorProject": "Microsoft",
                    "product": "Windows SMB",
                    "vulnerabilityName": "EternalBlue",
                    "dateAdded": "2022-03-28",
                    "shortDescription": "SMB RCE used by WannaCry",
                    "requiredAction": "Apply update",
                    "dueDate": "2022-04-15",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "",
                },
            ],
        }

    def _make_ctid_mapping(self):
        return {
            "mapping_objects": [
                {
                    "capability_id": "CVE-2021-44228",
                    "attack_object_id": "T1190",
                    "mapping_type": "primary_impact",
                },
                {
                    "capability_id": "CVE-2017-0144",
                    "attack_object_id": "T1210",
                    "mapping_type": "primary_impact",
                },
            ]
        }

    @patch("feeds.cisa_kev._fetch_json")
    def test_fetch_returns_entries(self, mock_fetch):
        """KEV feed returns one FeedEntry per CVE."""
        mock_fetch.side_effect = [
            self._make_ctid_mapping(),  # first call: CTID mapping
            self._make_kev_payload(),   # second call: KEV catalogue
        ]
        from feeds.cisa_kev import CISAKEVFeed
        feed = CISAKEVFeed()
        entries = feed.fetch()
        assert len(entries) == 2

    @patch("feeds.cisa_kev._fetch_json")
    def test_technique_ids_from_ctid_mapping(self, mock_fetch):
        """Technique IDs from CTID mapping appear on the FeedEntry."""
        mock_fetch.side_effect = [
            self._make_ctid_mapping(),
            self._make_kev_payload(),
        ]
        from feeds.cisa_kev import CISAKEVFeed
        feed = CISAKEVFeed()
        entries = feed.fetch()
        cve_map = {e.ioc: e for e in entries}
        assert "T1190" in cve_map["CVE-2021-44228"].technique_ids
        assert "T1210" in cve_map["CVE-2017-0144"].technique_ids

    @patch("feeds.cisa_kev._fetch_json")
    def test_technique_ids_scraped_from_notes(self, mock_fetch):
        """If CTID mapping unavailable, bare technique IDs in notes field are scraped."""
        mock_fetch.side_effect = [
            None,                       # CTID mapping unavailable
            self._make_kev_payload(),   # KEV catalogue still works
        ]
        from feeds.cisa_kev import CISAKEVFeed
        feed = CISAKEVFeed()
        entries = feed.fetch()
        cve_map = {e.ioc: e for e in entries}
        # CVE-2021-44228 notes contain "T1190"
        assert "T1190" in cve_map["CVE-2021-44228"].technique_ids

    @patch("feeds.cisa_kev._fetch_json")
    def test_ioc_type_is_cve(self, mock_fetch):
        """All KEV entries have ioc_type 'cve'."""
        mock_fetch.side_effect = [self._make_ctid_mapping(), self._make_kev_payload()]
        from feeds.cisa_kev import CISAKEVFeed
        entries = CISAKEVFeed().fetch()
        assert all(e.ioc_type == "cve" for e in entries)

    @patch("feeds.cisa_kev._fetch_json")
    def test_malware_family_is_none(self, mock_fetch):
        """KEV entries carry no malware_family (bypasses STIX mapper by design)."""
        mock_fetch.side_effect = [self._make_ctid_mapping(), self._make_kev_payload()]
        from feeds.cisa_kev import CISAKEVFeed
        entries = CISAKEVFeed().fetch()
        assert all(e.malware_family is None for e in entries)

    @patch("feeds.cisa_kev._fetch_json")
    def test_kev_api_failure_raises(self, mock_fetch):
        """If the KEV catalogue call fails entirely, fetch() raises RuntimeError."""
        mock_fetch.side_effect = [self._make_ctid_mapping(), None]
        from feeds.cisa_kev import CISAKEVFeed
        with pytest.raises(RuntimeError, match="CISA KEV"):
            CISAKEVFeed().fetch()


# ---------------------------------------------------------------------------
# Feature 2: mthcht detection-list coverage loader
# ---------------------------------------------------------------------------

class TestDetectionListLoader:
    """Tests for detection_lists/loader.py"""

    @patch("detection_lists.loader._fetch_csv_row_count")
    def test_returns_covered_techniques(self, mock_count):
        """Successfully loaded lists contribute their technique IDs."""
        mock_count.return_value = 100  # all lists download fine
        from detection_lists.loader import load_detection_list_coverage, DETECTION_LISTS
        covered, source_map = load_detection_list_coverage()
        # Every list has at least one technique; covered set must be non-empty
        assert len(covered) > 0

    @patch("detection_lists.loader._fetch_csv_row_count")
    def test_failed_lists_are_skipped(self, mock_count):
        """Lists that fail to download are skipped; rest succeed."""
        # First list fails, all others succeed
        mock_count.side_effect = [None] + [50] * 100
        from detection_lists.loader import load_detection_list_coverage
        covered, _ = load_detection_list_coverage()
        # Should still return coverage from the non-failing lists
        assert len(covered) > 0

    @patch("detection_lists.loader._fetch_csv_row_count")
    def test_source_map_populated(self, mock_count):
        """source_map keys are technique IDs; values are list names."""
        mock_count.return_value = 10
        from detection_lists.loader import load_detection_list_coverage
        _, source_map = load_detection_list_coverage()
        for tech_id, names in source_map.items():
            assert tech_id.startswith("T")
            assert isinstance(names, list)
            assert len(names) > 0

    @patch("detection_lists.loader._fetch_csv_row_count")
    def test_all_lists_fail_returns_empty(self, mock_count):
        """If every list download fails, return empty sets."""
        mock_count.return_value = None
        from detection_lists.loader import load_detection_list_coverage
        covered, source_map = load_detection_list_coverage()
        assert covered == set()
        assert source_map == {}

    @patch("detection_lists.loader._fetch_csv_row_count")
    def test_custom_list_subset(self, mock_count):
        """Passing a custom list subset only loads those lists."""
        mock_count.return_value = 5
        from detection_lists.loader import DetectionList, load_detection_list_coverage
        subset = [
            DetectionList(
                name="Test List",
                url="http://example.com/test.csv",
                techniques=["T1059", "T1071"],
            )
        ]
        covered, _ = load_detection_list_coverage(lists=subset)
        assert "T1059" in covered
        assert "T1071" in covered


# ---------------------------------------------------------------------------
# Feature 3: D3FEND countermeasure integration
# ---------------------------------------------------------------------------

class TestD3FENDIntegration:
    """Tests for integrations/d3fend.py"""

    def _make_d3fend_response(self, tech_id: str):
        return {
            "off_to_def": {
                "results": {
                    "bindings": [
                        {
                            "def_tech_id": {"value": "D3-ITA"},
                            "def_tech_label": {"value": "Inbound Traffic Analysis"},
                            "short_description": {"value": "Analyzes inbound network traffic."},
                            "def_tech_kb_article_url": {
                                "value": "https://d3fend.mitre.org/technique/d3f:InboundTrafficAnalysis"
                            },
                        },
                        {
                            "def_tech_id": {"value": "D3-NTF"},
                            "def_tech_label": {"value": "Network Traffic Filtering"},
                            "short_description": {"value": "Filters network traffic."},
                            "def_tech_kb_article_url": {
                                "value": "https://d3fend.mitre.org/technique/d3f:NetworkTrafficFiltering"
                            },
                        },
                    ]
                }
            }
        }

    @patch("integrations.d3fend.requests.get")
    def test_returns_countermeasures(self, mock_get):
        """Successful D3FEND response is parsed into D3FENDCountermeasure objects."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = self._make_d3fend_response("T1071")
        mock_get.return_value = mock_resp

        from integrations.d3fend import lookup_countermeasures
        results = lookup_countermeasures(["T1071"], delay_sec=0)
        assert "T1071" in results
        assert results["T1071"].has_coverage
        assert len(results["T1071"].countermeasures) == 2
        assert results["T1071"].countermeasures[0].d3fend_id == "D3-ITA"

    @patch("integrations.d3fend.requests.get")
    def test_404_returns_empty_result(self, mock_get):
        """404 from D3FEND (no mapping) returns result with empty countermeasures."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        from integrations.d3fend import lookup_countermeasures
        results = lookup_countermeasures(["T9999"], delay_sec=0)
        assert "T9999" in results
        assert not results["T9999"].has_coverage
        assert results["T9999"].countermeasures == []

    @patch("integrations.d3fend.requests.get")
    def test_network_error_stored_as_error_field(self, mock_get):
        """Network errors are captured in result.error, not re-raised."""
        mock_get.side_effect = Exception("connection refused")

        from integrations.d3fend import lookup_countermeasures
        results = lookup_countermeasures(["T1059"], delay_sec=0)
        assert results["T1059"].error is not None
        assert not results["T1059"].has_coverage

    @patch("integrations.d3fend.requests.get")
    def test_max_techniques_cap(self, mock_get):
        """Only max_techniques IDs are queried regardless of input length."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        from integrations.d3fend import lookup_countermeasures
        tech_ids = [f"T{1000 + i}" for i in range(20)]
        results = lookup_countermeasures(tech_ids, max_techniques=5, delay_sec=0)
        assert len(results) == 5

    @patch("integrations.d3fend.requests.get")
    def test_deduplicates_countermeasure_ids(self, mock_get):
        """Duplicate D3FEND IDs in the response are deduplicated."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "off_to_def": {
                "results": {
                    "bindings": [
                        {
                            "def_tech_id": {"value": "D3-ITA"},
                            "def_tech_label": {"value": "Inbound Traffic Analysis"},
                            "short_description": {"value": "desc"},
                            "def_tech_kb_article_url": {"value": "https://d3fend.mitre.org/"},
                        },
                        {
                            "def_tech_id": {"value": "D3-ITA"},  # duplicate
                            "def_tech_label": {"value": "Inbound Traffic Analysis"},
                            "short_description": {"value": "desc again"},
                            "def_tech_kb_article_url": {"value": "https://d3fend.mitre.org/"},
                        },
                    ]
                }
            }
        }
        mock_get.return_value = mock_resp

        from integrations.d3fend import lookup_countermeasures
        results = lookup_countermeasures(["T1071"], delay_sec=0)
        assert len(results["T1071"].countermeasures) == 1


# ---------------------------------------------------------------------------
# Feature integration: reporter renders new sections
# ---------------------------------------------------------------------------

class TestReporterNewSections:
    """Verify gaps.md output includes D3FEND and detection-list sections."""

    def _base_gap_result(self):
        from gap_analyzer.analyzer import GapResult
        return GapResult(
            active_techniques={"T1071", "T1059"},
            covered_techniques={"T1059"},
            gap_techniques={"T1071"},
            ranked_gaps=[("T1071", 0.85)],
            technique_sources={"T1071": {"feodo"}, "T1059": {"threatfox"}},
        )

    def test_d3fend_section_rendered(self):
        from gap_analyzer.reporter import render_gaps_md
        from integrations.d3fend import D3FENDResult, D3FENDCountermeasure

        d3fend_results = {
            "T1071": D3FENDResult(
                attack_technique_id="T1071",
                countermeasures=[
                    D3FENDCountermeasure(
                        d3fend_id="D3-ITA",
                        label="Inbound Traffic Analysis",
                        definition="Analyzes inbound traffic.",
                        d3fend_url="https://d3fend.mitre.org/technique/d3f:InboundTrafficAnalysis",
                    )
                ],
            )
        }
        md = render_gaps_md(self._base_gap_result(), d3fend_results=d3fend_results)
        assert "D3FEND Countermeasures" in md
        assert "D3-ITA" in md
        assert "Inbound Traffic Analysis" in md

    def test_detection_list_coverage_source_shown(self):
        from gap_analyzer.reporter import render_gaps_md

        detection_list_source_map = {"T1059": ["Suspicious Named Pipes"]}
        md = render_gaps_md(
            self._base_gap_result(),
            detection_list_source_map=detection_list_source_map,
        )
        assert "Detection Coverage" in md
        assert "Suspicious Named Pipes" in md

    def test_no_d3fend_no_section(self):
        from gap_analyzer.reporter import render_gaps_md

        md = render_gaps_md(self._base_gap_result())
        assert "D3FEND Countermeasures" not in md

    def test_summary_label_updated_with_detection_lists(self):
        from gap_analyzer.reporter import render_gaps_md

        md = render_gaps_md(
            self._base_gap_result(),
            detection_list_source_map={"T1059": ["LOLDrivers (BYOVD hashes)"]},
        )
        assert "detection lists" in md
