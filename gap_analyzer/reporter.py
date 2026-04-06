"""
Output renderer — writes gaps.md and layer.json to the outputs/ directory.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional

from gap_analyzer.analyzer import GapResult
from gap_analyzer.v18_analytics import V18Analytic

if TYPE_CHECKING:
    from integrations.virustotal import VtContextRow
    from integrations.d3fend import D3FENDResult
from navigator.layer_builder import build_navigator_layer
from config import ATTCK_VERSION, OUTPUTS_DIR


def _priority_label(score: float, max_score: float) -> str:
    """Translate numeric TIE scores into analyst-friendly buckets."""
    if score <= 0 or max_score <= 0:
        return "Unranked"
    relative = score / max_score
    if relative >= 0.67:
        return "High"
    if relative >= 0.34:
        return "Medium"
    return "Low"


def _format_sources(gap_result: GapResult, tech_id: str) -> str:
    sources = sorted(gap_result.technique_sources.get(tech_id, set()))
    return ", ".join(sources) if sources else "—"


def _format_coverage_sources(
    tech_id: str,
    detection_list_source_map: Optional[Dict[str, list]],
) -> str:
    """Return detection source labels for a covered technique."""
    sources = []
    if detection_list_source_map and tech_id in detection_list_source_map:
        sources.extend(detection_list_source_map[tech_id])
    if not sources:
        sources = ["sigma"]
    return ", ".join(sources)


def render_gaps_md(
    gap_result: GapResult,
    v18_analytics: Optional[Dict[str, "V18Analytic"]] = None,
    vt_context: Optional[List["VtContextRow"]] = None,
    d3fend_results: Optional[Dict[str, "D3FENDResult"]] = None,
    detection_list_source_map: Optional[Dict[str, list]] = None,
) -> str:
    """
    Render the gap report as a Markdown string.

    Sections:
      - Summary statistics
      - Critical gaps table (ranked by TIE score, with v18 AN-series IDs)
      - D3FEND countermeasures (when --d3fend was used)
      - Covered active techniques with detection-source attribution
      - VirusTotal context (when VT enrichment was used)
    """
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    covered_active = gap_result.covered_active

    # Coverage source label for the summary
    coverage_label = "Sigma rules"
    if detection_list_source_map:
        coverage_label = "Sigma rules + detection lists"

    lines = [
        "# ATT&CK Coverage Gap Report",
        f"\n> Generated: {ts}  |  ATT&CK version: {ATTCK_VERSION}",
        "\n## Summary\n",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Active techniques (observed in feeds) | {len(gap_result.active_techniques)} |",
        f"| Covered by {coverage_label} | {len(covered_active)} |",
        f"| **Gaps (active, no detection)** | **{len(gap_result.gap_techniques)}** |",
        f"| Coverage ratio | {gap_result.coverage_ratio:.1%} |",
        "\n## Critical Gaps — Active Threats with No Detection\n",
        "_Ranked using TIE-derived co-occurrence scores from the public CTID dataset. "
        "Higher scores indicate stronger relative overlap with observed techniques in this run._\n",
        "_Priority labels are relative to the highest ranked TIE score in this run._\n",
        "| Rank | Technique ID | Priority | TIE Relevance Score | Source Feeds | ATT&CK v18 Analytics |",
        "|------|-------------|----------|---------------------|--------------|----------------------|",
    ]

    max_ranked_score = max((score for _, score in gap_result.ranked_gaps), default=0.0)
    for rank, (tech_id, score) in enumerate(gap_result.ranked_gaps, 1):
        analytics_str = ""
        if v18_analytics and tech_id in v18_analytics:
            ids = v18_analytics[tech_id].analytic_ids
            analytics_str = ", ".join(ids) if ids else "—"
        else:
            analytics_str = "—"
        score_str = f"{score:.4f}" if score > 0 else "N/A"
        priority = _priority_label(score, max_ranked_score)
        sources = _format_sources(gap_result, tech_id)
        lines.append(
            f"| {rank} | [{tech_id}](https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}) | "
            f"{priority} | {score_str} | {sources} | {analytics_str} |"
        )

    # Show remaining gaps not in ranked list
    unranked = gap_result.gap_techniques - {t for t, _ in gap_result.ranked_gaps}
    if unranked:
        lines += [
            f"\n<details><summary>Additional {len(unranked)} gaps (not ranked)</summary>\n",
            "| Technique ID | Source Feeds |",
            "|-------------|--------------|",
        ]
        for tech_id in sorted(unranked):
            lines.append(f"| {tech_id} | {_format_sources(gap_result, tech_id)} |")
        lines.append("\n</details>")

    # ------------------------------------------------------------------ #
    # D3FEND countermeasures section                                      #
    # ------------------------------------------------------------------ #
    if d3fend_results:
        mapped = {tid: r for tid, r in d3fend_results.items() if r.has_coverage}
        lines += [
            "\n## D3FEND Countermeasures for Top Gaps\n",
            "_Defensive techniques from [MITRE D3FEND](https://d3fend.mitre.org/) "
            "mapped to the highest-priority uncovered ATT&CK techniques. "
            "Use these to guide detection rule development or control selection._\n",
        ]
        if not mapped:
            lines.append(
                "_No D3FEND mappings found for the queried techniques. "
                "D3FEND coverage is still growing — check directly at "
                "[d3fend.mitre.org](https://d3fend.mitre.org/)._"
            )
        else:
            for tech_id, result in mapped.items():
                tech_url = f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}"
                lines.append(f"\n### [{tech_id}]({tech_url})\n")
                lines += [
                    "| D3FEND ID | Countermeasure | Description |",
                    "|-----------|---------------|-------------|",
                ]
                for cm in result.countermeasures[:8]:  # cap per-technique to keep report tidy
                    label = cm.label or "—"
                    defn = (cm.definition or "—")[:120].replace("|", "\\|")
                    if cm.d3fend_url:
                        label_link = f"[{label}]({cm.d3fend_url})"
                    else:
                        label_link = label
                    lines.append(f"| `{cm.d3fend_id}` | {label_link} | {defn} |")

    # ------------------------------------------------------------------ #
    # Covered techniques with detection-source attribution                #
    # ------------------------------------------------------------------ #
    lines += [
        "\n## Active Techniques with Detection Coverage\n",
        "| Technique ID | Feed Sources | Detection Source |",
        "|-------------|--------------|-----------------|",
    ]
    for tech_id in sorted(covered_active):
        feed_src = _format_sources(gap_result, tech_id)
        det_src = _format_coverage_sources(tech_id, detection_list_source_map)
        lines.append(f"| {tech_id} | {feed_src} | {det_src} |")

    if vt_context:
        lines += [
            "\n## VirusTotal context (sampled)\n",
            "_IOC lookups used for enrichment / triage; stats from last VT analysis._\n",
            "| IOC | Type | Suggested family | Malicious | Harmless | Undetected | Enriched | Link |",
            "|-----|------|------------------|-----------|----------|------------|----------|------|",
        ]
        for row in vt_context:
            enr = "yes" if row.enriched_family else "—"
            lines.append(
                f"| `{row.ioc}` | {row.ioc_type} | {row.suggested_family} | "
                f"{row.malicious} | {row.harmless} | {row.undetected} | {enr} | [VT]({row.link}) |"
            )

    return "\n".join(lines)


def write_outputs(
    gap_result: GapResult,
    v18_analytics: Optional[Dict[str, V18Analytic]] = None,
    vt_context: Optional[List] = None,
    d3fend_results: Optional[Dict] = None,
    detection_list_source_map: Optional[Dict[str, list]] = None,
) -> None:
    """Write gaps.md and layer.json to the configured outputs directory."""
    gaps_path = OUTPUTS_DIR / "gaps.md"
    layer_path = OUTPUTS_DIR / "layer.json"

    # gaps.md
    md = render_gaps_md(
        gap_result,
        v18_analytics,
        vt_context=vt_context,
        d3fend_results=d3fend_results,
        detection_list_source_map=detection_list_source_map,
    )
    gaps_path.write_text(md, encoding="utf-8")
    print(f"[+] gaps.md    -> {gaps_path}")

    # Navigator layer JSON
    layer = build_navigator_layer(gap_result, attck_version=ATTCK_VERSION)
    layer_path.write_text(json.dumps(layer, indent=2), encoding="utf-8")
    print(f"[+] layer.json -> {layer_path}")
