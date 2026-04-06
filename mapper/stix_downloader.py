"""
STIX bundle downloader and cache manager.

Downloads the ATT&CK STIX JSON bundle on first run and caches it at
data/enterprise-attack.json. Subsequent runs use the cached file.
Default source is pinned to MITRE tag ATT&CK-v18.1 (see config.STIX_BUNDLE_URL).

To force a refresh, delete data/enterprise-attack.json or call download(force=True).
"""
import sys
from pathlib import Path

import requests

from config import STIX_BUNDLE_PATH, STIX_BUNDLE_URL, REQUEST_TIMEOUT


def download(force: bool = False) -> Path:
    """
    Ensure the ATT&CK STIX bundle is present locally.

    Args:
        force: Re-download even if the cached file exists.

    Returns:
        Path to the local STIX bundle JSON file.
    """
    if STIX_BUNDLE_PATH.exists() and not force:
        return STIX_BUNDLE_PATH

    print(f"[*] Downloading ATT&CK STIX bundle from {STIX_BUNDLE_URL} ...", flush=True)
    print(
        "    (30–90s typical; JSON on disk is tens of MiB — progress is decompressed bytes, "
        "so % vs Content-Length is unreliable and omitted)",
        flush=True,
    )

    # Stream the download so we can show progress without loading into RAM.
    # Note: iter_content() yields decoded bytes while Content-Length is often the gzip
    # payload size — never divide by that for a percentage.
    with requests.get(STIX_BUNDLE_URL, stream=True, timeout=REQUEST_TIMEOUT * 4) as resp:
        resp.raise_for_status()
        downloaded = 0
        STIX_BUNDLE_PATH.parent.mkdir(parents=True, exist_ok=True)

        with open(STIX_BUNDLE_PATH, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=65536):
                fh.write(chunk)
                downloaded += len(chunk)
                mib = downloaded / (1024 * 1024)
                print(f"\r    {mib:,.1f} MiB written ...", end="", flush=True)

    print(f"\n[+] Saved to {STIX_BUNDLE_PATH}")
    return STIX_BUNDLE_PATH


if __name__ == "__main__":
    force = "--force" in sys.argv
    download(force=force)
