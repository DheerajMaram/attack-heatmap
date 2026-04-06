"""TIE matrix loading and v18 STIX parsing."""
from pathlib import Path

from gap_analyzer.v18_analytics import load_v18_analytics
from mapper.tie_ranker import TIERanker

FIXTURES = Path(__file__).parent / "fixtures"


def test_tie_ranker_loads_json_matrix():
    path = FIXTURES / "tie_mini.json"
    ranker = TIERanker(tie_model_path=str(path))
    assert ranker.model is not None
    ranked = ranker.rank_gaps(
        observed_techniques=["T1071.001"],
        gap_techniques=["T1003.001", "T1566.001"],
        top_n=5,
    )
    assert ranked[0][0] == "T1003.001"
    assert ranked[0][1] > ranked[1][1]


def test_load_v18_analytics_mini_bundle():
    path = FIXTURES / "v18_mini_bundle.json"
    by_t = load_v18_analytics(str(path))
    assert "T1059.001" in by_t
    rec = by_t["T1059.001"]
    assert rec.detection_strategy and "command-line" in rec.detection_strategy.lower()
    assert "AN1234" in rec.analytic_ids
