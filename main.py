"""
attack-heatmap — ATT&CK Coverage Gap Analyzer CLI

Pipeline:
  1. Fetch live threat feeds (+ optional CISA KEV + optional VirusTotal enrichment)
  2. Map malware families → ATT&CK techniques via mitreattack-python
     (CISA KEV entries bypass the mapper — technique IDs are embedded directly)
  3. Load Sigma rule coverage + optional mthcht detection-list coverage
  4. Diff gaps, optional TIE ranking
  5. Optional D3FEND countermeasure lookup for top gaps
  6. outputs/gaps.md + outputs/layer.json

Usage:
    python main.py
    python main.py --no-tie --top-n 10 --feeds threatfox feodo
    python main.py --kev                          # add CISA KEV feed
    python main.py --detection-lists              # add mthcht coverage layer
    python main.py --d3fend                       # add D3FEND countermeasures
    python main.py --quiet
    python main.py -i
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Dict, List, Optional

import config as app_config
from cli_ui import PipelineUI
from gap_analyzer.analyzer import analyze_gaps
from gap_analyzer.reporter import write_outputs
from mapper.attck_mapper import ATTCKMapper
from mapper.tie_ranker import TIERanker
from sigma.loader import load_sigma_coverage

DEFAULT_FEEDS = ["threatfox", "feodo", "malwarebazaar", "urlhaus"]
FEED_CHOICES = ["threatfox", "feodo", "malwarebazaar", "urlhaus", "yaraify"]
# Note: cisa_kev is enabled via --kev flag (not a positional feed choice) because
# it bypasses the STIX mapper and needs separate pipeline handling.


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="attack-heatmap",
        description="Map live threat feeds to ATT&CK and surface Sigma coverage gaps.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--feeds",
        nargs="*",
        default=None,
        choices=FEED_CHOICES,
        metavar="NAME",
        help="Feeds to ingest (default: threatfox feodo malwarebazaar urlhaus).",
    )
    p.add_argument(
        "--no-tie",
        action="store_true",
        help="Disable CTID TIE relevance-score ranking.",
    )
    p.add_argument(
        "--top-n",
        type=int,
        default=None,
        help="Override TIE_TOP_N — number of gaps to rank (default from config).",
    )
    p.add_argument(
        "--refresh-stix",
        action="store_true",
        help="Force re-download of the ATT&CK STIX bundle.",
    )
    p.add_argument(
        "--stix-bundle",
        type=str,
        default=None,
        help="Path to a local ATT&CK STIX bundle (skips auto-download).",
    )
    p.add_argument(
        "--v18-analytics",
        type=str,
        default=None,
        metavar="PATH",
        help=(
            "Path to enterprise-attack STIX JSON for AN-series / detection-strategy column "
            "(use data/enterprise-attack.json after refresh when on default v18.1 bundle)."
        ),
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Minimal output (errors and artifact paths only).",
    )
    p.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Prompt for missing VT tier / feeds (requires a TTY).",
    )
    p.add_argument(
        "--vt-tier",
        choices=["free", "paid"],
        default=None,
        help="VirusTotal quota tier (overrides VT_TIER env). Required if API key is set.",
    )
    p.add_argument(
        "--no-vt",
        action="store_true",
        help="Skip VirusTotal even if VIRUSTOTAL_API_KEY is set.",
    )
    p.add_argument(
        "--vt-max-lookups",
        type=int,
        default=None,
        metavar="N",
        help="Override VT_MAX_LOOKUPS for this run.",
    )
    p.add_argument(
        "--feed-days-back",
        type=int,
        default=None,
        metavar="N",
        help="Override FEED_DAYS_BACK (e.g. ThreatFox window, capped at API max).",
    )
    p.add_argument(
        "--no-enrich",
        action="store_true",
        help="Skip Malpedia/MISP enrichment step.",
    )

    # ------------------------------------------------------------------ #
    # New features: KEV feed, detection-list coverage, D3FEND             #
    # ------------------------------------------------------------------ #
    p.add_argument(
        "--kev",
        action="store_true",
        help=(
            "Add CISA Known Exploited Vulnerabilities (KEV) as an additional feed. "
            "Entries carry ATT&CK technique IDs directly from the CTID KEV-ATT&CK "
            "mapping — no malware-family lookup needed. No API key required."
        ),
    )
    p.add_argument(
        "--detection-lists",
        action="store_true",
        help=(
            "Supplement Sigma coverage with mthcht/awesome-lists detection lists "
            "(suspicious named pipes, Windows services, scheduled tasks, user-agents, "
            "LOLDrivers, HijackLibs, ransomware extensions, and more). "
            "Technique IDs covered by these lists are marked as detected even if "
            "no local Sigma rule exists. No API key required."
        ),
    )
    p.add_argument(
        "--d3fend",
        action="store_true",
        help=(
            "Query MITRE D3FEND for defensive countermeasures covering the top gap "
            "techniques. Adds a countermeasures section to gaps.md. "
            "Caps at --d3fend-max lookups to respect the public API. No API key required."
        ),
    )
    p.add_argument(
        "--d3fend-max",
        type=int,
        default=15,
        metavar="N",
        help="Max ATT&CK techniques to look up in D3FEND (default: 15).",
    )
    return p


def _resolve_vt_config(args: argparse.Namespace) -> Optional[Dict]:
    """Return VT settings dict, or None if VT disabled / no key."""
    key = app_config.VIRUSTOTAL_API_KEY.strip()
    if args.no_vt or not key:
        return None
    tier = (args.vt_tier or app_config.VT_TIER or "").strip().lower()
    if tier not in ("free", "paid"):
        return None
    if tier == "free":
        max_l, interval, urls = 50, 15.0, False
    else:
        max_l, interval, urls = 500, 1.0, True
    ev_ml = os.getenv("VT_MAX_LOOKUPS")
    if ev_ml and str(ev_ml).strip():
        max_l = max(1, int(ev_ml))
    ev_int = os.getenv("VT_MIN_INTERVAL_SEC")
    if ev_int and str(ev_int).strip():
        interval = float(ev_int)
    ev_u = os.getenv("VT_INCLUDE_URLS")
    if ev_u is not None and str(ev_u).strip():
        urls = str(ev_u).lower() in ("1", "true", "yes")
    if args.vt_max_lookups is not None:
        max_l = max(1, int(args.vt_max_lookups))
    return {
        "api_key": key,
        "max_lookups": max_l,
        "min_interval": interval,
        "include_urls": urls,
        "tier": tier,
    }


def _require_vt_tier_if_needed(args: argparse.Namespace) -> None:
    key = app_config.VIRUSTOTAL_API_KEY.strip()
    if not key or args.no_vt:
        return
    tier = (args.vt_tier or app_config.VT_TIER or "").strip().lower()
    if tier in ("free", "paid"):
        return
    sys.exit(
        "VirusTotal API key is set but VT tier is missing.\n"
        "Set VT_TIER=free or VT_TIER=paid in .env, or pass --vt-tier free|paid, "
        "or run with --interactive to choose.\n"
        "Use --no-vt to skip VirusTotal for this run."
    )


def _build_feeds(selected: List[str], include_kev: bool = False):
    from feeds.feodo import FeodoFeed
    from feeds.malwarebazaar import MalwareBazaarFeed
    from feeds.threatfox import ThreatFoxFeed
    from feeds.urlhaus import URLHausFeed
    from feeds.yara_feed import YARAifyFeed

    registry = {
        "threatfox": ThreatFoxFeed,
        "feodo": FeodoFeed,
        "malwarebazaar": MalwareBazaarFeed,
        "urlhaus": URLHausFeed,
        "yaraify": YARAifyFeed,
    }
    feeds = [registry[name]() for name in selected if name in registry]

    if include_kev:
        from feeds.cisa_kev import CISAKEVFeed
        feeds.append(CISAKEVFeed())

    return feeds


def run_pipeline(args: argparse.Namespace, ui: PipelineUI, vt_cfg: Optional[Dict]) -> None:
    from integrations.virustotal import enrich_feed_entries

    top_n = args.top_n if args.top_n is not None else app_config.TIE_TOP_N
    tie_enabled = app_config.TIE_ENABLED and not args.no_tie

    if args.feed_days_back is not None:
        app_config.FEED_DAYS_BACK = max(1, int(args.feed_days_back))

    feeds = _build_feeds(args.feeds, include_kev=getattr(args, "kev", False))
    all_entries = []

    ui.rule("Step 1: Ingesting threat feeds")
    ui.panel(
        f"Feeds: {', '.join(args.feeds)}\n"
        f"FEED_DAYS_BACK={app_config.FEED_DAYS_BACK}",
        title="Feed run",
        style="dim",
    )

    from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

    if not ui.quiet:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=ui.console,
        ) as progress:
            task = progress.add_task("feeds", total=len(feeds))
            for feed in feeds:
                progress.update(task, description=f"[cyan]{feed.name}[/cyan]")
                try:
                    entries = feed.fetch()
                    all_entries.extend(entries)
                    ui.print(f"  [green]OK[/green] [{feed.name}]  {len(entries):,} entries")
                except NotImplementedError:
                    ui.print(f"  [yellow]--[/yellow] [{feed.name}]  not implemented (skipped)")
                except Exception as exc:
                    ui.print(f"  [red]!![/red] [{feed.name}]  FAILED: {exc}")
                progress.advance(task)
    else:
        for feed in feeds:
            try:
                entries = feed.fetch()
                all_entries.extend(entries)
            except NotImplementedError:
                pass
            except Exception as exc:
                ui.info_always(f"[red]{feed.name}[/red] FAILED: {exc}")

    ui.print(f"\n  Total entries ingested: [bold]{len(all_entries):,}[/bold]")

    vt_rows = []
    if vt_cfg:
        ui.rule("Step 1b: VirusTotal enrichment")

        def on_prog(ioc: str, cur: int, mx: int) -> None:
            ui.print(f"  [dim]VT {cur}/{mx}[/dim] {ioc[:80]}")

        all_entries, vt_rows, vt_stats = enrich_feed_entries(
            all_entries,
            api_key=vt_cfg["api_key"],
            max_lookups=vt_cfg["max_lookups"],
            min_interval_sec=vt_cfg["min_interval"],
            include_urls=vt_cfg["include_urls"],
            on_progress=on_prog if not ui.quiet else None,
        )
        vt_diag = vt_stats.summary_line(len(vt_rows))
        if ui.quiet:
            ui.info_always(vt_diag)
        else:
            ui.print(f"  [dim]{vt_diag}[/dim]")

    ui.rule("Step 2: Mapping malware families -> ATT&CK techniques")

    if args.refresh_stix:
        from mapper.stix_downloader import download

        download(force=True)

    mapper = ATTCKMapper()
    families = [e.malware_family for e in all_entries if e.malware_family]
    ui.print(f"  Unique malware families: [bold]{len(set(families)):,}[/bold]")

    family_map = mapper.bulk_map(families)
    family_sources = {}
    for entry in all_entries:
        family = entry.malware_family
        if not family:
            continue
        family_sources.setdefault(family, set()).add(entry.source)

    enricher_on = (
        app_config.ENRICHER_ENABLED
        and not args.no_enrich
        and (
            app_config.MALPEDIA_API_KEY.strip()
            or app_config.MISP_GALAXY_ATTACK_PATTERN_PATH.strip()
        )
    )
    if enricher_on:
        from mapper.enricher import Enricher

        enricher = Enricher()
        enriched = 0
        for fam, techs in list(family_map.items()):
            if techs:
                continue
            extra = enricher.enrich(fam)
            if extra:
                family_map[fam] = extra
                enriched += 1
        if enriched:
            ui.print(f"  Malpedia/MISP enrichment: [bold]{enriched:,}[/bold] additional families")

    active_techniques = {t for techs in family_map.values() for t in techs}
    technique_sources = {}
    for family, techniques in family_map.items():
        for tech_id in techniques:
            technique_sources.setdefault(tech_id, set()).update(family_sources.get(family, set()))

    # Collect technique IDs contributed directly by feeds (e.g. CISA KEV)
    # that bypassed the STIX mapper.
    kev_direct_count = 0
    for entry in all_entries:
        direct_ids = entry.technique_ids or []
        if not direct_ids:
            continue
        kev_direct_count += len(direct_ids)
        for tech_id in direct_ids:
            active_techniques.add(tech_id)
            technique_sources.setdefault(tech_id, set()).add(entry.source)

    if kev_direct_count:
        ui.print(
            f"  Direct technique IDs from feed entries (e.g. KEV): "
            f"[bold]{kev_direct_count:,}[/bold]"
        )

    ui.print(f"  Unique ATT&CK techniques observed: [bold]{len(active_techniques):,}[/bold]")

    ui.rule("Step 3: Loading Sigma rule coverage")
    covered_techniques = load_sigma_coverage()
    ui.print(f"  Techniques covered by Sigma rules: [bold]{len(covered_techniques):,}[/bold]")

    # Optional: supplement coverage with mthcht detection lists
    detection_list_source_map: Dict[str, list] = {}
    if getattr(args, "detection_lists", False):
        ui.rule("Step 3b: Loading mthcht detection-list coverage")
        from detection_lists.loader import load_detection_list_coverage
        dl_covered, detection_list_source_map = load_detection_list_coverage(
            verbose=not ui.quiet
        )
        new_from_lists = dl_covered - covered_techniques
        covered_techniques = covered_techniques | dl_covered
        ui.print(
            f"  Detection lists: [bold]{len(dl_covered):,}[/bold] technique IDs covered "
            f"([bold]{len(new_from_lists):,}[/bold] not already in Sigma)"
        )

    ui.rule("Step 4: Analyzing coverage gaps")
    ranker = TIERanker(silent=ui.quiet) if tie_enabled else None
    gap_result = analyze_gaps(
        active_techniques,
        covered_techniques,
        ranker=ranker,
        top_n=top_n,
        technique_sources=technique_sources,
    )

    from rich.table import Table

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="dim")
    table.add_column("Count", justify="right")
    table.add_row("Active techniques", str(len(gap_result.active_techniques)))
    table.add_row("Covered by Sigma", str(len(gap_result.covered_active)))
    table.add_row(
        "[bold red]Gaps (critical)[/bold red]",
        f"[bold red]{len(gap_result.gap_techniques)}[/bold red]",
    )
    table.add_row("Coverage ratio", f"{gap_result.coverage_ratio:.1%}")
    ui.print(table)

    v18_analytics = None
    if args.v18_analytics:
        ui.rule("Step 5: Loading STIX detection analytics (AN-series)")
        try:
            from gap_analyzer.v18_analytics import load_v18_analytics

            v18_analytics = load_v18_analytics(args.v18_analytics)
            ui.print(f"  Loaded detection analytics for {len(v18_analytics):,} techniques")
        except Exception as exc:
            ui.print(f"  [red]Failed to load STIX detection analytics:[/red] {exc}")

    # Optional: D3FEND countermeasure lookup for top gap techniques
    d3fend_results = None
    if getattr(args, "d3fend", False):
        ui.rule("Step 5b: Querying D3FEND for countermeasures")
        from integrations.d3fend import lookup_countermeasures
        max_d3fend = getattr(args, "d3fend_max", 15)
        top_gap_ids = [t for t, _ in gap_result.ranked_gaps[:max_d3fend]]
        if not top_gap_ids:
            top_gap_ids = sorted(gap_result.gap_techniques)[:max_d3fend]
        ui.print(
            f"  Querying D3FEND for [bold]{len(top_gap_ids)}[/bold] gap techniques "
            f"(cap: {max_d3fend}) ..."
        )
        d3fend_results = lookup_countermeasures(top_gap_ids, max_techniques=max_d3fend)
        covered_count = sum(1 for r in d3fend_results.values() if r.has_coverage)
        ui.print(
            f"  D3FEND: [bold]{covered_count}[/bold] / {len(d3fend_results)} "
            f"techniques have mapped countermeasures"
        )

    ui.rule("Step 6: Writing outputs")
    write_outputs(
        gap_result,
        v18_analytics=v18_analytics,
        vt_context=vt_rows or None,
        d3fend_results=d3fend_results,
        detection_list_source_map=detection_list_source_map or None,
    )

    ui.rule("[bold green]Done")

    ui.summary_table(
        [
            ("Active techniques", str(len(gap_result.active_techniques))),
            ("Gaps", str(len(gap_result.gap_techniques))),
            ("Outputs", str(app_config.OUTPUTS_DIR)),
            ("VirusTotal", "on" if vt_cfg else "off"),
        ]
    )

    ui.info_always(
        f"[green]Artifacts:[/green] {app_config.OUTPUTS_DIR / 'gaps.md'}, "
        f"{app_config.OUTPUTS_DIR / 'layer.json'}"
    )


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.quiet and args.interactive:
        sys.exit("Cannot combine --quiet and --interactive.")

    if args.interactive:
        import cli_prompts

        cli_prompts.ensure_tty()
        if args.feeds is None:
            args.feeds = cli_prompts.prompt_feeds(None)
        if app_config.VIRUSTOTAL_API_KEY.strip() and not args.no_vt:
            t = (args.vt_tier or app_config.VT_TIER or "").strip().lower()
            if t not in ("free", "paid"):
                args.vt_tier = cli_prompts.prompt_vt_tier()

    if not args.feeds:
        args.feeds = list(DEFAULT_FEEDS)

    _require_vt_tier_if_needed(args)
    vt_cfg = _resolve_vt_config(args)

    if args.interactive and vt_cfg:
        import cli_prompts

        ml, inv, urls = cli_prompts.prompt_vt_confirm(
            vt_cfg["max_lookups"], vt_cfg["min_interval"], vt_cfg["include_urls"]
        )
        vt_cfg["max_lookups"] = ml
        vt_cfg["min_interval"] = inv
        vt_cfg["include_urls"] = urls

    ui = PipelineUI(quiet=args.quiet)
    run_pipeline(args, ui, vt_cfg)


if __name__ == "__main__":
    main()
