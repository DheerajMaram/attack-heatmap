"""
Central configuration — all magic strings and paths live here.
Override via environment variables or a .env file.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent
SIGMA_RULES_DIR = BASE_DIR / "sigma" / "rules"
OUTPUTS_DIR = BASE_DIR / "outputs"
DATA_DIR = BASE_DIR / "data"

OUTPUTS_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)

# ATT&CK version and domain (label for reports / Navigator — match your STIX bundle)
ATTCK_VERSION = os.getenv("ATTCK_VERSION", "18.1")
ATTCK_DOMAIN = "enterprise-attack"
STIX_BUNDLE_PATH = DATA_DIR / "enterprise-attack.json"
# Pinned MITRE release by default (not moving `master`). Override with STIX_BUNDLE_URL.
_STIX_DEFAULT_URL = (
    "https://raw.githubusercontent.com/mitre/cti/"
    "ATT%26CK-v18.1/enterprise-attack/enterprise-attack.json"
)
STIX_BUNDLE_URL = os.getenv("STIX_BUNDLE_URL", _STIX_DEFAULT_URL).strip()

# Feed URLs
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
FEODO_TRACKER_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/"

# Optional API keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
# VT_TIER: free | paid (required when VIRUSTOTAL_API_KEY is set, unless --no-vt / prompt)
VT_TIER = os.getenv("VT_TIER", "").strip().lower()
MALPEDIA_API_KEY = os.getenv("MALPEDIA_API_KEY", "")

# ThreatFox (abuse.ch) — required for get_iocs; free key: https://auth.abuse.ch/
# Accept THREATFOX_API_KEY as alias (same Auth-Key from the portal).
THREATFOX_AUTH_KEY = (
    os.getenv("THREATFOX_AUTH_KEY") or os.getenv("THREATFOX_API_KEY") or ""
).strip()


def _env_first(*names: str) -> str:
    for n in names:
        v = os.getenv(n, "").strip()
        if v:
            return v
    return ""


# abuse.ch Auth-Key per product (falls back to ThreatFox key — often the same key works for all)
MALWAREBAZAAR_AUTH_KEY = (
    _env_first("MALWAREBAZAAR_AUTH_KEY", "MALWAREBAZAAR_API_KEY") or THREATFOX_AUTH_KEY
)
URLHAUS_AUTH_KEY = _env_first("URLHAUS_AUTH_KEY", "URLHAUS_API_KEY") or THREATFOX_AUTH_KEY
YARAIFY_AUTH_KEY = _env_first("YARAIFY_AUTH_KEY", "YARAIFY_API_KEY") or THREATFOX_AUTH_KEY
YARAIFY_API_URL = "https://yaraify-api.abuse.ch/api/v1/"
# From YARAify API: POST {"query": "generate_identifier"} then set here for list_tasks
YARAIFY_IDENTIFIER = os.getenv("YARAIFY_IDENTIFIER", "").strip()

# Optional: path to misp-galaxy/clusters/mitre-attack-pattern.json (clone MISP/misp-galaxy)
MISP_GALAXY_ATTACK_PATTERN_PATH = os.getenv("MISP_GALAXY_ATTACK_PATTERN_PATH", "").strip()

# Merge Malpedia / MISP enrichment for families missing from ATT&CK STIX
ENRICHER_ENABLED = os.getenv("ENRICHER_ENABLED", "true").lower() == "true"

# TIE (Technique Inference Engine) config
# Source: https://github.com/center-for-threat-informed-defense/technique-inference-engine
TIE_ENABLED = os.getenv("TIE_ENABLED", "true").lower() == "true"
TIE_TOP_N = int(os.getenv("TIE_TOP_N", "20"))  # rank top N uncovered techniques

# Feed fetch settings
FEED_DAYS_BACK = int(os.getenv("FEED_DAYS_BACK", "7"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
