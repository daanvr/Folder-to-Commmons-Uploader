#!/usr/bin/env python3
"""
Check local files against Wikimedia Commons by SHA-1 (scales without prebuilt indices)

What it does
------------
For each file in a local folder:
  1) Compute SHA-1 over the bytes (HEX digest).
  2) Ask Commons: list=allimages&aisha1=<HEX> → any exact byte-identical files?
  3) (Optional) If a target category is given, check whether any of the matches
     are members of that category (prop=categories&clcategories=Category:…).
  4) If no hash match is found, do a fallback "name exists?" check:
     - prop=imageinfo&iiprop=sha1 on File:<local filename>
     - If it exists but has a different SHA-1, report “exists by title, different content”.

Why this scales
---------------
- One API lookup per file (plus a title check only for negative results).
- No need to download full JSONs or build/maintain local indices.

Examples
--------
# Check existence anywhere on Commons:
python wmc_check_local_by_sha1.py --files-dir "files/Category_Binnenhofrenovatie"

# Check specifically within a category:
python wmc_check_local_by_sha1.py \
  --files-dir "files/Category_Binnenhofrenovatie" \
  --category "Category:Binnenhofrenovatie"

# Save a CSV report:
python wmc_check_local_by_sha1.py --files-dir ... --output-csv out/report.csv
"""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# =========================
# Config
# =========================

COMMONS_API = "https://commons.wikimedia.org/w/api.php"
USER_AGENT = "WMC SHA1 checker - User:OlafJanssen - Contact: olaf.janssen@kb.nl)"
TIMEOUT_SECS = 20
RETRIES_TOTAL = 5
RETRIES_BACKOFF = 0.6
ALLIMAGES_LIMIT = "500"  # API cap for non-bot


# =========================
# HTTP session
# =========================

def build_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=RETRIES_TOTAL,
        connect=RETRIES_TOTAL,
        read=RETRIES_TOTAL,
        status=RETRIES_TOTAL,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        backoff_factor=RETRIES_BACKOFF,
        raise_on_status=False,
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
    return s


# =========================
# Local hashing helpers
# =========================

def to_base36(n: int) -> str:
    if n == 0:
        return "0"
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    out = []
    while n:
        n, r = divmod(n, 36)
        out.append(digits[r])
    return "".join(reversed(out))

def sha1_hex(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    """Return SHA-1 hex digest of file bytes."""
    h = hashlib.sha1()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def sha_hex_to_base36(sha_hex: str) -> str:
    """Convert hex SHA-1 to MediaWiki-style base-36 (for display only)."""
    try:
        val = int(sha_hex, 16)
    except Exception:
        return ""
    return to_base36(val).lstrip("0") or "0"


# =========================
# Commons API helpers
# =========================

def list_allimages_by_sha1_hex(session: requests.Session, sha1_hex: str) -> List[str]:
    """
    Return *all* File: titles on Commons that have exactly this SHA-1 (hex).
    Handles continuation (there can be multiple exact duplicates).
    """
    titles: List[str] = []
    params: Dict[str, str] = {
        "action": "query",
        "format": "json",
        "list": "allimages",
        "aisha1": sha1_hex.lower(),
        "aiprop": "sha1|timestamp|user|mime|size|url",
        "ailimit": ALLIMAGES_LIMIT,
    }
    cont = None
    while True:
        if cont:
            params.update(cont)
        r = session.get(COMMONS_API, params=params, timeout=TIMEOUT_SECS)
        r.raise_for_status()
        data = r.json()
        ai = (data.get("query") or {}).get("allimages") or []
        for item in ai:
            t = item.get("title")
            if t:
                titles.append(str(t))
        cont = data.get("continue")
        if not cont:
            break
    return titles

def normalize_category(cat: str) -> str:
    """Ensure 'Category:' prefix and replace underscores with spaces."""
    c = (cat or "").strip().replace("_", " ")
    if not c:
        return ""
    return c if c.lower().startswith("category:") else f"Category:{c}"

def which_titles_are_in_category(
    session: requests.Session, titles: List[str], category_title: str, batch: int = 50
) -> Set[str]:
    """
    Given a list of File: titles, return the subset that are in 'category_title'.
    Uses prop=categories with clcategories=Category:Name in batches.
    """
    category_title = normalize_category(category_title)
    hits: Set[str] = set()
    for i in range(0, len(titles), batch):
        chunk = titles[i : i + batch]
        if not chunk:
            continue
        params = {
            "action": "query",
            "format": "json",
            "prop": "categories",
            "titles": "|".join(chunk),
            "clcategories": category_title,
            "cllimit": "500",
        }
        r = session.get(COMMONS_API, params=params, timeout=TIMEOUT_SECS)
        r.raise_for_status()
        data = r.json()
        pages = (data.get("query") or {}).get("pages") or {}
        for _, page in pages.items():
            # If the page has a 'categories' array, it matched the filter
            if page.get("categories"):
                t = page.get("title")
                if t:
                    hits.add(str(t))
    return hits

def get_remote_sha1_hex_for_title(session: requests.Session, title: str) -> str:
    """
    Return hex SHA-1 for current version of File:title ('' if page missing or not a file).
    formatversion=2 for simpler shape.
    """
    r = session.get(
        COMMONS_API,
        params={
            "action": "query",
            "format": "json",
            "formatversion": "2",
            "prop": "imageinfo",
            "iiprop": "sha1",
            "titles": title,
        },
        timeout=TIMEOUT_SECS,
    )
    r.raise_for_status()
    data = r.json()
    pages = (data.get("query") or {}).get("pages") or []
    if not pages:
        return ""
    page = pages[0]
    if page.get("missing"):
        return ""
    info = page.get("imageinfo") or []
    if not info:
        return ""
    return (info[0].get("sha1") or "").lower()


# =========================
# File iteration
# =========================

def iter_local_files(files_dir: Path, exts: Iterable[str]) -> Iterable[Path]:
    exts_norm = {e.lower().lstrip(".") for e in exts}
    for p in sorted(files_dir.iterdir()):
        if p.is_file():
            if not exts_norm:
                yield p
            elif p.suffix.lower().lstrip(".") in exts_norm:
                yield p


# =========================
# CLI
# =========================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Check local files against Wikimedia Commons by SHA-1, optionally within a specific category."
    )
    p.add_argument(
        "--files-dir",
        required=True,
        help="Local folder with files to check, e.g. 'files/Category_Binnenhofrenovatie'.",
    )
    p.add_argument(
        "--category",
        help="Optional Commons category to test membership, e.g. 'Category:Binnenhofrenovatie'. "
             "If omitted, the script only checks existence anywhere on Commons.",
    )
    p.add_argument(
        "--extensions",
        default="jpg,jpeg,png,tif,tiff,svg,gif,webm,ogv,ogg,pdf",
        help="Comma-separated list of file extensions to include (default common media). "
             "Use empty string to include all files.",
    )
    p.add_argument(
        "--output-csv",
        help="Optional CSV path to write a report.",
    )
    return p.parse_args()


# =========================
# Main
# =========================

def main() -> None:
    args = parse_args()
    files_dir = Path(args.files_dir)
    if not files_dir.exists():
        raise FileNotFoundError(f"--files-dir not found: {files_dir}")

    exts = [] if args.extensions.strip() == "" else [e.strip() for e in args.extensions.split(",") if e.strip()]
    session = build_session()

    total = 0
    found_any = 0
    found_in_cat = 0
    exists_name_diff = 0

    rows_for_csv: List[Tuple[str, str, str, str]] = []  # (filename, sha1_hex, status, matches_or_note)

    print(f"Scanning: {files_dir}")
    if args.category:
        print(f"Checking within category: {normalize_category(args.category)}")
    else:
        print("Checking existence anywhere on Commons.")

    for path in iter_local_files(files_dir, exts):
        total += 1

        try:
            sha_hex = sha1_hex(path)
            sha_b36 = sha_hex_to_base36(sha_hex)
        except Exception as e:
            print(f"[ERROR] {path.name}: failed to compute SHA-1 ({e})")
            rows_for_csv.append((path.name, "", "ERROR_HASH", ""))
            continue

        try:
            titles = list_allimages_by_sha1_hex(session, sha_hex)
        except requests.RequestException as e:
            print(f"[ERROR] {path.name}: API error while searching by SHA-1 ({e})")
            rows_for_csv.append((path.name, sha_hex, "ERROR_API", "search_by_hash"))
            continue

        if titles:
            found_any += 1
            if args.category:
                try:
                    in_cat = which_titles_are_in_category(session, titles, args.category)
                except requests.RequestException as e:
                    print(f"[ERROR] {path.name}: API error while checking category ({e})")
                    rows_for_csv.append((path.name, sha_hex, "ERROR_API", "category_check"))
                    continue

                if in_cat:
                    found_in_cat += 1
                    match_list = ", ".join(sorted(in_cat))
                    print(f"[FOUND_IN_CATEGORY] {path.name} → sha1(hex)={sha_hex} (base36={sha_b36}) → {match_list}")
                    rows_for_csv.append((path.name, sha_hex, "FOUND_IN_CATEGORY", "; ".join(sorted(in_cat))))
                else:
                    sample = ", ".join(titles[:5]) + ("..." if len(titles) > 5 else "")
                    print(f"[FOUND_OUTSIDE_CATEGORY] {path.name} → sha1(hex)={sha_hex} (base36={sha_b36}) → {sample}")
                    rows_for_csv.append((path.name, sha_hex, "FOUND_OUTSIDE_CATEGORY", "; ".join(titles)))
            else:
                sample = ", ".join(titles[:5]) + ("..." if len(titles) > 5 else "")
                print(f"[FOUND_ANYWHERE] {path.name} → sha1(hex)={sha_hex} (base36={sha_b36}) → {sample}")
                rows_for_csv.append((path.name, sha_hex, "FOUND_ANYWHERE", "; ".join(titles)))
            continue

        # No exact hash match — try a by-title check to distinguish “absent” vs “exists with different bytes”
        candidate_title = f"File:{path.name.replace(' ', '_')}"
        try:
            remote_hex = get_remote_sha1_hex_for_title(session, candidate_title)
        except requests.RequestException as e:
            print(f"[ERROR] {path.name}: API error while checking by title ({e})")
            rows_for_csv.append((path.name, sha_hex, "ERROR_API", "title_check"))
            continue

        if remote_hex:
            exists_name_diff += 1
            remote_b36 = sha_hex_to_base36(remote_hex)
            print(
                f"[EXISTS_BY_TITLE_DIFFERENT_CONTENT] {path.name} "
                f"→ local sha1(hex)={sha_hex} (b36={sha_b36}); "
                f"remote sha1(hex)={remote_hex} (b36={remote_b36})"
            )
            rows_for_csv.append((path.name, sha_hex, "EXISTS_BY_TITLE_DIFFERENT_CONTENT", candidate_title))
        else:
            print(f"[NOT_ON_COMMONS] {path.name} → sha1(hex)={sha_hex} (base36={sha_b36})")
            rows_for_csv.append((path.name, sha_hex, "NOT_ON_COMMONS", ""))

    # Summary
    print("\nSummary")
    print(f"  Scanned files: {total}")
    print(f"  Exact hash matches anywhere on Commons: {found_any}")
    if args.category:
        print(f"  Exact hash matches inside target category: {found_in_cat}")
    print(f"  Exists by title but different content: {exists_name_diff}")

    # CSV (optional)
    if args.output_csv:
        out = Path(args.output_csv)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Filename", "SHA1_Hex", "Status", "MatchesOrNote"])
            for r in rows_for_csv:
                w.writerow(r)
        print(f"CSV written: {out}")


if __name__ == "__main__":
    main()
