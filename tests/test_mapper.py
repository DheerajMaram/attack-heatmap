"""
Tests for the ATT&CK mapper and related utilities.

ATTCKMapper requires a local STIX bundle — tests use a minimal stub
to avoid downloading the full 30 MB bundle during CI.
"""
import pytest
from unittest.mock import Mock, patch

from mapper.attck_mapper import ATTCKMapper, _normalize
from mapper.tie_ranker import TIERanker


# ---------------------------------------------------------------------------
# _normalize helper
# ---------------------------------------------------------------------------

def test_normalize_strips_punctuation():
    assert _normalize("Cobalt Strike") == "cobaltstrike"
    assert _normalize("Emotet.v2") == "emotetv2"
    assert _normalize("TA505") == "ta505"


# ---------------------------------------------------------------------------
# ATTCKMapper (mocked STIX bundle)
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_mapper():
    """ATTCKMapper with a mocked MitreAttackData instance."""
    bundle = Mock()
    bundle.exists.return_value = True
    bundle.__str__ = Mock(return_value="tests/fixtures/enterprise-attack.json")

    with patch("mapper.attck_mapper.STIX_BUNDLE_PATH", bundle), \
         patch("mapper.attck_mapper.MitreAttackData") as MockMAD:
        instance = MockMAD.return_value
        # Simulate two software objects
        instance.get_software.return_value = [
            {
                "id": "malware--abc123",
                "name": "Emotet",
                "x_mitre_aliases": ["Geodo", "Heodo"],
                "external_references": [],
            },
            {
                "id": "tool--def456",
                "name": "Cobalt Strike",
                "x_mitre_aliases": ["CS"],
                "external_references": [],
            },
        ]
        # Simulate technique lookup for Emotet
        emotet_technique = {
            "id": "attack-pattern--xyz",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}],
        }
        instance.get_techniques_used_by_software.return_value = [
            {"object": emotet_technique, "relationship": {}}
        ]

        mapper = ATTCKMapper()
        yield mapper


def test_family_to_techniques_known(mock_mapper):
    techs = mock_mapper.family_to_techniques("Emotet")
    assert "T1059.001" in techs


def test_family_to_techniques_alias(mock_mapper):
    techs = mock_mapper.family_to_techniques("Geodo")
    assert "T1059.001" in techs


def test_family_to_techniques_unknown_raises(mock_mapper):
    with pytest.raises(ValueError, match="not found"):
        mock_mapper.family_to_techniques("UnknownMalware999")


def test_bulk_map_skips_unknown(mock_mapper):
    result = mock_mapper.bulk_map(["Emotet", "UnknownMalware999"])
    assert "T1059.001" in result.get("Emotet", [])
    assert result.get("UnknownMalware999") == []


# ---------------------------------------------------------------------------
# TIERanker (no model)
# ---------------------------------------------------------------------------

def test_tie_ranker_fallback_no_model():
    ranker = TIERanker(tie_model_path="")
    ranked = ranker.rank_gaps(
        observed_techniques=["T1059.001"],
        gap_techniques=["T1071.001", "T1566.001", "T1003.001"],
        top_n=5,
    )
    assert len(ranked) <= 5
    for tech_id, score in ranked:
        assert isinstance(tech_id, str)
        assert score == 0.0


def test_tie_ranker_respects_top_n():
    ranker = TIERanker()
    gaps = [f"T{1000 + i}" for i in range(50)]
    ranked = ranker.rank_gaps([], gaps, top_n=10)
    assert len(ranked) == 10
