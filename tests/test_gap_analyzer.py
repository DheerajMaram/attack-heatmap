"""
Tests for gap_analyzer — analyzer, reporter, and Navigator layer builder.
"""
import json
from pathlib import Path

import pytest

from gap_analyzer.analyzer import GapResult, analyze_gaps
from gap_analyzer.reporter import render_gaps_md
from navigator.layer_builder import build_navigator_layer


# ---------------------------------------------------------------------------
# analyze_gaps
# ---------------------------------------------------------------------------

def test_analyze_gaps_basic():
    active = {"T1059.001", "T1071.001", "T1566.001"}
    covered = {"T1059.001"}
    result = analyze_gaps(active, covered)

    assert result.gap_techniques == {"T1071.001", "T1566.001"}
    assert result.covered_active == {"T1059.001"}
    assert result.coverage_ratio == pytest.approx(1 / 3)


def test_analyze_gaps_no_gaps():
    active = {"T1059.001", "T1566.001"}
    covered = {"T1059.001", "T1566.001", "T1003.001"}
    result = analyze_gaps(active, covered)

    assert result.gap_techniques == set()
    assert result.coverage_ratio == 1.0


def test_analyze_gaps_empty_active():
    result = analyze_gaps(set(), {"T1059.001"})
    assert result.gap_techniques == set()
    assert result.coverage_ratio == 1.0


def test_analyze_gaps_with_ranker():
    from mapper.tie_ranker import TIERanker
    ranker = TIERanker()
    active = {"T1059.001", "T1071.001", "T1003.001"}
    covered = {"T1059.001"}
    result = analyze_gaps(active, covered, ranker=ranker, top_n=5)
    assert len(result.ranked_gaps) <= 5
    ranked_ids = {t for t, _ in result.ranked_gaps}
    assert ranked_ids.issubset(result.gap_techniques)


# ---------------------------------------------------------------------------
# render_gaps_md
# ---------------------------------------------------------------------------

def test_render_gaps_md_contains_expected_sections():
    result = GapResult(
        active_techniques={"T1059.001", "T1071.001"},
        covered_techniques={"T1059.001"},
        gap_techniques={"T1071.001"},
        ranked_gaps=[("T1071.001", 0.0)],
        technique_sources={"T1059.001": {"threatfox"}, "T1071.001": {"feodo", "urlhaus"}},
    )
    md = render_gaps_md(result)
    assert "# ATT&CK Coverage Gap Report" in md
    assert "T1071.001" in md
    assert "T1059.001" in md  # covered active section
    assert "Priority" in md
    assert "feodo, urlhaus" in md


def test_render_gaps_md_no_gaps():
    result = GapResult(
        active_techniques={"T1059.001"},
        covered_techniques={"T1059.001"},
        gap_techniques=set(),
        ranked_gaps=[],
        technique_sources={"T1059.001": {"threatfox"}},
    )
    md = render_gaps_md(result)
    assert "0" in md
    assert "threatfox" in md


# ---------------------------------------------------------------------------
# build_navigator_layer
# ---------------------------------------------------------------------------

def test_layer_schema_keys():
    result = GapResult(
        active_techniques={"T1059.001", "T1071.001"},
        covered_techniques={"T1059.001"},
        gap_techniques={"T1071.001"},
        ranked_gaps=[],
    )
    layer = build_navigator_layer(result, attck_version="14")

    required_keys = {"name", "versions", "domain", "techniques", "gradient", "legendItems"}
    assert required_keys.issubset(layer.keys())
    assert layer["versions"]["attack"] == "14"
    assert layer["versions"]["layer"] == "4.5"


def test_layer_technique_colors():
    result = GapResult(
        active_techniques={"T1059.001", "T1071.001"},
        covered_techniques={"T1059.001"},
        gap_techniques={"T1071.001"},
        ranked_gaps=[],
    )
    layer = build_navigator_layer(result)
    tech_map = {t["techniqueID"]: t for t in layer["techniques"]}

    assert tech_map["T1071.001"]["color"] == "#ff6666"  # gap → red
    assert tech_map["T1071.001"]["score"] == 100
    assert tech_map["T1059.001"]["color"] == "#66ff66"  # covered → green
    assert tech_map["T1059.001"]["score"] == 50


def test_layer_is_json_serializable():
    result = GapResult(
        active_techniques={"T1059.001"},
        covered_techniques=set(),
        gap_techniques={"T1059.001"},
        ranked_gaps=[],
    )
    layer = build_navigator_layer(result)
    serialized = json.dumps(layer)
    assert len(serialized) > 0
