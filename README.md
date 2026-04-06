# ATT&CK Heatmap

Python CLI that ingests live threat feeds, maps malware families to MITRE ATT&CK techniques, checks Sigma coverage, and writes a prioritized gap report plus an ATT&CK Navigator layer.

Three optional extensions add depth without changing the core workflow: CISA KEV data (no API key, ATT&CK mappings included), mthcht detection lists as a second coverage layer alongside Sigma, and MITRE D3FEND countermeasure suggestions for the top uncovered techniques.

---

## Why this exists

It answers one question: which ATT&CK techniques are showing up in current threat data but have no Sigma detection in your repo?

The output is two files. `gaps.md` gives a ranked list of uncovered techniques with source-feed context and priority labels. `layer.json` is an ATT&CK Navigator layer you can open immediately.

For a stable example of the output, see [`docs/sample-gaps.md`](docs/sample-gaps.md). Files under `outputs/` are local run artifacts and are gitignored.

---

## Pipeline

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          ATT&CK Heatmap pipeline                             │
│                                                                              │
│  ┌─────────────────────┐   ┌──────────────┐   ┌────────────────────────┐    │
│  │ Live feeds          │   │ ATT&CK       │   │ Sigma rules            │    │
│  │                     │──►│ STIX mapper  │   │ sigma/rules/**/*.yml   │    │
│  │ ThreatFox           │   │ + opt.       │   │ attack.tXXXX tags      │    │
│  │ Feodo               │   │ Malpedia /   │   │                        │    │
│  │ MalwareBazaar       │   │ MISP enrich  │   ├────────────────────────┤    │
│  │ URLhaus / YARAify   │   └──────┬───────┘   │ mthcht detection lists │    │
│  ├─────────────────────┤          │   (opt.)  │ (--detection-lists)    │    │
│  │ CISA KEV  (--kev)   │──────────┘           └───────────┬────────────┘    │
│  │ (ATT&CK IDs direct) │    bypasses mapper               │                 │
│  └─────────────────────┘                                  │                 │
│           + optional VirusTotal enrichment                │                 │
│                                    ▼                      ▼                 │
│                        ┌───────────────────────────────────────┐            │
│                        │ Gap analyzer + TIE ranker             │            │
│                        └──────────────────┬────────────────────┘            │
│                                           ▼                                 │
│                    outputs/gaps.md            outputs/layer.json            │
│                    (+ D3FEND section          (Navigator heatmap)           │
│                     with --d3fend)                                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Features

| Feature | Status |
|---------|--------|
| ThreatFox (`Auth-Key`) | Implemented |
| Feodo Tracker C2 blocklist | Implemented |
| MalwareBazaar (`recent_detections`) | Implemented |
| URLhaus (`urls/recent`) | Implemented |
| YARAify (`list_tasks` + identifier) | Implemented |
| **CISA KEV feed** (`--kev`, no API key) | **New** |
| Optional VirusTotal v3 (file/URL, tiered limits) | Implemented |
| mitreattack-python STIX mapper | Implemented |
| Optional Malpedia / MISP Galaxy enrichment | Implemented |
| Sigma coverage loader (`attack.*` tags) | Implemented |
| **mthcht detection lists** (`--detection-lists`, no API key) | **New** |
| Gap ranking via TIE co-occurrence matrix | Implemented |
| ATT&CK v18 AN-series column (`--v18-analytics`) | Implemented |
| **D3FEND countermeasures** (`--d3fend`, no API key) | **New** |
| Navigator layer JSON (schema v4.5) | Implemented |
| Rich CLI (`--quiet`, `--interactive`, progress) | Implemented |

---

## Setup

### 1. Clone and install

```bash
git clone <your-repo-url>
cd attack-heatmap

python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

If creating `.venv` under OneDrive gives permission errors, create it elsewhere (e.g. `%LOCALAPPDATA%\venvs\attack-heatmap`) and install from the project root.

### 2. Configure

```bash
cp .env.example .env
```

| Variable | Purpose |
|----------|---------|
| `THREATFOX_AUTH_KEY` / `THREATFOX_API_KEY` | abuse.ch [Auth-Key](https://auth.abuse.ch/) for ThreatFox |
| `MALWAREBAZAAR_*`, `URLHAUS_*` | Same portal — often the same key works for all abuse.ch products |
| `VIRUSTOTAL_API_KEY` | Optional; also set `VT_TIER=free` or `paid` when using this |
| `VT_INCLUDE_URLS` | `true` to query URL IOCs on free tier (quota-aware) |
| `TIE_MODEL_PATH` | Default: `data/tie_cooccurrence_matrix.json` |
| `FEED_DAYS_BACK` | Feed lookback window (ThreatFox API max 7 days) |

Minimal run with no abuse.ch keys: `python main.py --feeds feodo`. The three new flags (KEV, detection lists, D3FEND) also require no API key.

### 3. TIE matrix

The repo ships `data/tie_cooccurrence_matrix.json` — technique co-occurrence counts derived from the public [CTID Technique Inference Engine](https://github.com/center-for-threat-informed-defense/technique-inference-engine) dataset. Regenerate after upstream changes:

```bash
python scripts/build_tie_cooccurrence.py
```

### 4. Sigma rules

Drop `.yml` rules under `sigma/rules/` at any depth. The loader scans for `attack.tXXXX` tags.

Bulk SigmaHQ rules:

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma sigma/rules/sigmahq
```

A small curated set ships under `sigma/rules/` for demos.

---

## Usage

```bash
# Default feeds: threatfox, feodo, malwarebazaar, urlhaus
python main.py

# Subset of feeds (no API keys needed for feodo)
python main.py --feeds feodo

# Add CISA KEV — no API key needed, ATT&CK mappings come from CTID
python main.py --kev

# Add mthcht detection lists as a second coverage layer
python main.py --detection-lists

# Add D3FEND countermeasure suggestions for top gap techniques
python main.py --d3fend

# Cap D3FEND lookups (default 15)
python main.py --d3fend --d3fend-max 10

# Full run: KEV + detection lists + D3FEND + VirusTotal
python main.py --kev --detection-lists --d3fend --vt-tier free

# No TIE ranking
python main.py --no-tie --top-n 30

# Quiet output
python main.py --quiet

# Interactive mode (prompts for VT tier)
python main.py -i

# Feed window override
python main.py --feed-days-back 3

# Force re-download ATT&CK STIX bundle
python main.py --refresh-stix

# AN-series detection-strategy column
python main.py --v18-analytics data/enterprise-attack.json

# Skip Malpedia/MISP enrichment
python main.py --no-enrich
```

**First run:** the pipeline downloads the ATT&CK v18.1 enterprise STIX bundle (~8 MB) to `data/enterprise-attack.json` and caches it. Use `--refresh-stix` or delete the cache to force an update.

**VirusTotal:** only queries IOCs missing `malware_family` that are sha256 hashes, or URLs when `VT_INCLUDE_URLS=true`. The CLI prints a one-line diagnostic (candidates, lookups, 404s, report rows).

---

## New features

### CISA KEV (`--kev`)

CISA's Known Exploited Vulnerabilities catalogue is publicly available and requires no authentication. The feed also carries ATT&CK technique IDs from the [CTID KEV-ATT&CK mapping](https://github.com/center-for-threat-informed-defense/mappings-explorer) — so KEV entries bypass the STIX malware-family mapper entirely and contribute technique IDs directly to the active set.

If the CTID mapping is temporarily unavailable, the feed falls back to scraping bare technique IDs (e.g. `T1190`) from the KEV notes field. Either way, entries still appear in feed counts.

```bash
python main.py --feeds feodo --kev --no-vt
```

### mthcht detection lists (`--detection-lists`)

Fetches 15 curated detection lists from [mthcht/awesome-lists](https://github.com/mthcht/awesome-lists) and maps each one to its ATT&CK technique coverage. Lists that fail to download are skipped; the rest still contribute.

Covered lists include: suspicious named pipes, Windows services, scheduled tasks, HTTP user-agents, mutex names, LOLDrivers hashes, HijackLibs DLL hijacking paths, DNS-over-HTTPS servers, ransomware extensions, ransomware ransom notes, offensive tool keywords, greyware tool keywords, and malicious SSL certificates.

The `gaps.md` covered-techniques table gains a "Detection Source" column showing which layer covered each technique — `sigma`, a specific list name, or both.

```bash
python main.py --detection-lists
```

### D3FEND countermeasures (`--d3fend`)

Queries the public [MITRE D3FEND](https://d3fend.mitre.org/) API for each of the top gap techniques and adds a countermeasures section to `gaps.md`. D3FEND maps 309 ATT&CK techniques to 3,109 defensive techniques.

Use `--d3fend-max N` to control how many techniques get queried (default 15). The API is public and rate-limited by a small delay between requests.

```bash
python main.py --d3fend --d3fend-max 10
```

---

## Outputs

### `outputs/gaps.md`

- Summary table: active techniques, covered, gaps, coverage ratio (label updates to "Sigma rules + detection lists" when `--detection-lists` is active).
- Critical gaps table: ranked by TIE relevance score, with priority labels (High/Medium/Low), source feeds, and optional v18 AN-series IDs.
- D3FEND countermeasures section (when `--d3fend` is used): per-technique defensive technique suggestions linked to d3fend.mitre.org.
- Covered techniques table: now includes a "Detection Source" column showing whether coverage came from Sigma, a detection list, or both.
- VirusTotal context section (when VT enrichment ran).

### `outputs/layer.json`

ATT&CK Navigator layer (schema v4.5):

| Color | Meaning |
|-------|---------|
| Red `#ff6666` | Active in feeds — no detection coverage |
| Green `#66ff66` | Active in feeds — Sigma or detection-list coverage present |
| (uncolored) | Not observed in the current feed window |

Open in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/): Open Existing Layer → upload `outputs/layer.json`.

---

## Project structure

```
├── main.py                    # CLI entrypoint
├── config.py                  # Env-driven URLs, keys, paths
├── cli_ui.py                  # Rich panels / progress / quiet
├── cli_prompts.py             # Interactive prompts
├── feeds/                     # ThreatFox, Feodo, MalwareBazaar, URLhaus, YARAify
│   └── cisa_kev.py            # CISA KEV + CTID ATT&CK mapping (new)
├── detection_lists/           # mthcht detection-list coverage loader (new)
│   └── loader.py
├── integrations/
│   ├── virustotal.py          # VirusTotal v3 enrichment
│   └── d3fend.py              # MITRE D3FEND countermeasure lookup (new)
├── mapper/                    # STIX mapper, enricher, TIE ranker, STIX download
├── sigma/                     # Rule loader + rules/
├── gap_analyzer/              # Diff, reporter, v18 analytics
├── navigator/                 # layer_builder.py
├── scripts/                   # e.g. build_tie_cooccurrence.py
├── data/                      # STIX cache (ignored), tie_cooccurrence_matrix.json
├── docs/                      # sample-gaps.md (stable example for GitHub browsing)
├── outputs/                   # gaps.md, layer.json (run artifacts, gitignored)
└── tests/                     # pytest (48 tests)
```

---

## Development

```bash
pytest -q
pytest tests/ -v
pytest tests/test_new_features.py -v   # KEV, detection lists, D3FEND tests only
```

---

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE D3FEND](https://d3fend.mitre.org/)
- [CISA KEV Catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CTID KEV-ATT&CK Mapping](https://github.com/center-for-threat-informed-defense/mappings-explorer)
- [mthcht/awesome-lists](https://github.com/mthcht/awesome-lists)
- [mitreattack-python](https://github.com/mitre-attack/mitreattack-python)
- [CTID Technique Inference Engine](https://github.com/center-for-threat-informed-defense/technique-inference-engine)
- [abuse.ch](https://abuse.ch/) / [auth.abuse.ch](https://auth.abuse.ch/)
- [VirusTotal API v3](https://docs.virustotal.com/reference/overview)
- [SigmaHQ](https://github.com/SigmaHQ/sigma)
- [ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator)
