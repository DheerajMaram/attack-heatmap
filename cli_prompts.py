"""Interactive CLI prompts (--interactive)."""
import sys
from typing import List, Optional

from rich.prompt import Confirm, Prompt

FEED_CHOICES = ["threatfox", "feodo", "malwarebazaar", "urlhaus", "yaraify"]
DEFAULT_FEEDS = ["threatfox", "feodo", "malwarebazaar", "urlhaus"]


def ensure_tty() -> None:
    if not sys.stdin.isatty():
        sys.exit(
            "Cannot use --interactive without a TTY. "
            "Set options via flags or .env instead."
        )


def prompt_vt_tier() -> str:
    return Prompt.ask(
        "VirusTotal tier",
        choices=["free", "paid"],
        default="free",
    )


def prompt_feeds(current: Optional[List[str]]) -> List[str]:
    if current is not None:
        return current
    mode = Prompt.ask(
        "Feeds preset",
        choices=["default", "minimal", "custom"],
        default="default",
    )
    if mode == "default":
        return list(DEFAULT_FEEDS)
    if mode == "minimal":
        return ["threatfox", "feodo"]
    raw = Prompt.ask("Comma-separated feeds", default="threatfox,feodo")
    parts = [p.strip().lower() for p in raw.split(",") if p.strip()]
    bad = [p for p in parts if p not in FEED_CHOICES]
    if bad:
        sys.exit(f"Unknown feed(s): {bad}. Valid: {FEED_CHOICES}")
    if not parts:
        sys.exit("No feeds selected.")
    return parts


def prompt_vt_confirm(max_lookups: int, interval: float, include_urls: bool) -> tuple:
    """Returns (max_lookups, interval, include_urls) possibly adjusted."""
    print(
        f"\nVirusTotal: max lookups={max_lookups}, "
        f"min interval={interval}s, include URLs={include_urls}\n"
    )
    if not Confirm.ask("Proceed with these settings?", default=True):
        ml = Prompt.ask("VT_MAX_LOOKUPS for this run", default=str(max_lookups))
        try:
            max_lookups = max(1, int(ml))
        except ValueError:
            pass
        include_urls = Confirm.ask("Include URL lookups?", default=include_urls)
    return max_lookups, interval, include_urls
