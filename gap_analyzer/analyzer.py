"""
Gap analyzer — diffs live ATT&CK technique coverage against Sigma rule library.

The core function analyze_gaps() produces a GapResult which is the central
data structure consumed by the reporter and Navigator layer builder.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class GapResult:
    """Result of the gap analysis between live threat techniques and Sigma coverage."""
    active_techniques: Set[str]       # Observed in live threat feeds
    covered_techniques: Set[str]      # Covered by at least one Sigma rule
    gap_techniques: Set[str]          # Active but NOT covered — critical gaps
    ranked_gaps: List[Tuple[str, float]] = field(default_factory=list)
    technique_sources: Dict[str, Set[str]] = field(default_factory=dict)
    # ranked_gaps: [(technique_id, tie_probability_score), ...] sorted descending

    @property
    def covered_active(self) -> Set[str]:
        """Active techniques that DO have Sigma coverage."""
        return self.active_techniques & self.covered_techniques

    @property
    def coverage_ratio(self) -> float:
        """Fraction of active techniques covered by Sigma (0.0 – 1.0)."""
        if not self.active_techniques:
            return 1.0
        return len(self.covered_active) / len(self.active_techniques)


def analyze_gaps(
    active: Set[str],
    covered: Set[str],
    ranker=None,
    top_n: int = 20,
    technique_sources: Optional[Dict[str, Set[str]]] = None,
) -> GapResult:
    """
    Compute the gap between observed ATT&CK techniques and Sigma coverage.

    Args:
        active:   Technique IDs observed in live threat feeds.
        covered:  Technique IDs covered by at least one Sigma rule.
        ranker:   Optional TIERanker instance for kill-chain probability ranking.
        top_n:    Maximum number of ranked gaps to include.

    Returns:
        GapResult with all sets populated and ranked_gaps filled.
    """
    gaps = active - covered

    if ranker is not None:
        ranked = ranker.rank_gaps(list(active), list(gaps), top_n=top_n)
    else:
        # No TIE model: sort alphabetically, zero probability scores
        ranked = [(t, 0.0) for t in sorted(gaps)[:top_n]]

    return GapResult(
        active_techniques=active,
        covered_techniques=covered,
        gap_techniques=gaps,
        ranked_gaps=ranked,
        technique_sources=technique_sources or {},
    )
