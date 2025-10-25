#!/usr/bin/env python3
"""
Check local files against Wikimedia Commons by SHA-1 and detect scaled variants,
with clear stdout showing LOCAL vs REMOTE SHA-1 (hex only) and Commons FILE URLs.
Also emits a machine-readable JSON report (see --output-json).

Run on one folder (--files-dir) or all immediate subfolders (--files-root).

Usage
-----
Show help:
    python wmc_check_local_by_sha1.py -h

Examples
--------
# 1) Check a single directory
python wmc_check_local_by_sha1.py --files-dir "files/Category_Binnenhofrenovatie"

# 2) Check ALL immediate subfolders under 'files/'
python wmc_check_local_by_sha1.py --files-root "files"

# 3) Restrict to matches inside a specific Commons category
python wmc_check_local_by_sha1.py --files-root "files" --category "Category:Binnenhofrenovatie"

# 4) Disable scaled-variant detection (fast exact SHA-1 only)
python wmc_check_local_by_sha1.py --files-dir "files/Category_Binnenhofrenovatie" --no-detect-scaled

# 5) Tune scaled-variant detection (tighter threshold, smaller thumbs, larger candidate cap)
python wmc_check_local_by_sha1.py \
  --files-dir "files/Category_Binnenhofrenovatie" \
  --fuzzy-threshold 8 --fuzzy-thumb-width 192 --fuzzy-max-candidates 500

# 6) Export a CSV report
python wmc_check_local_by_sha1.py --files-root "files" --output-csv out/report.csv

# 7) Export a JSON report (machine-readable)
python wmc_check_local_by_sha1.py --files-root "files" --output-json out/report.json

# 8) Include ALL files (ignore extension filter)
python wmc_check_local_by_sha1.py --files-dir "files/Category_Maps_of_the_Binnenhof" --extensions ""

Notes
-----
- On macOS/Linux you might use `python3 …`; on Windows you can use `py …`.
- Quote paths that contain spaces.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple, Optional, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from PIL import Image, ImageOps
from io import BytesIO
from urllib.parse import quote


# =========================
# Config
# =========================

COMMONS_API = "https://commons.wikimedia.org/w/api.php"
USER_AGENT = "WMC checker + scaled-variant detection - User:OlafJanssen - Contact: olaf.janssen@kb.nl)"
TIMEOUT_SECS = 20
RETRIES_TOTAL = 5
RETRIES_BACKOFF = 0.6
ALLIMAGES_LIMIT = "500"
CATEGORY_PAGE_LIMIT = "500"

# Scaled-variant detection
FUZZY_DEFAULT_THRESHOLD = 10
FUZZY_DEFAULT_THUMB_WIDTH = 256
FUZZY_DEFAULT_MAX_CANDIDATES = 300


# =========================
# HTTP session
# =========================

def build_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=RETRIES_TOTAL,
        connect=RETRIES_TOTAL,
        read=RETRIES_TOTAL,           # ← fix: no walrus operator here
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
# Local hashing
# =========================

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


def commons_file_url_from_title(title: str) -> str:
    """
    Build a canonical Commons URL from a MediaWiki title like 'File:Foo bar.jpg'.
    - Replaces spaces with underscores
    - Percent-encodes other characters safely
    """
    t = (title or "").strip().replace(" ", "_")
    return f"https://commons.wikimedia.org/wiki/{quote(t, safe=':/')}"


def print_hash_block(local_hex: str, remote_hex: Optional[str] = None, title: Optional[str] = None, indent: str = "    ") -> None:
    """Pretty-print local vs remote SHA-1 (hex) aligned, show equality, and include Commons URL."""
    equal = (remote_hex is not None and local_hex.lower() == remote_hex.lower())
    if title:
        print(f"{indent}Commons URL   : {commons_file_url_from_title(title)}")
    print(f"{indent}SHA1 (hex)     local  : {local_hex}")
    if remote_hex is not None:
        print(f"{indent}               remote : {remote_hex}  [{'EQUAL' if equal else 'DIFFERENT'}]")


# =========================
# Perceptual hash (dHash) for scaled detection
# =========================

def image_dhash(img: Image.Image, hash_size: int = 8) -> int:
    img = ImageOps.exif_transpose(img)
    img = img.convert("L").resize((hash_size + 1, hash_size), Image.BILINEAR)
    w, h = img.size
    bits = 0
    bit_index = 0
    px = img.load()
    for y in range(h):
        for x in range(w - 1):
            if px[x, y] > px[x + 1, y]:
                bits |= (1 << bit_index)
            bit_index += 1
    return bits

def dhash_from_path(path: Path) -> Optional[int]:
    try:
        with Image.open(path) as im:
            return image_dhash(im, hash_size=8)
    except Exception:
        return None

def dhash_from_bytes(data: bytes) -> Optional[int]:
    try:
        with Image.open(BytesIO(data)) as im:
            return image_dhash(im, hash_size=8)
    except Exception:
        return None

def hamming_distance(a: int, b: int) -> int:
    return (a ^ b).bit_count()


# =========================
# Commons API helpers
# =========================

def list_allimages_by_sha1_hex(session: requests.Session, sha1_hex: str) -> List[str]:
    """Return *all* File: titles on Commons that have exactly this SHA-1 (hex)."""
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
    c = (cat or "").strip().replace("_", " ")
    if not c:
        return ""
    return c if c.lower().startswith("category:") else f"Category:{c}"

def list_category_files_depth0(session: requests.Session, category_title: str, max_items: int) -> List[str]:
    """Return up to max_items direct file members (depth 0) of a category."""
    category_title = normalize_category(category_title)
    params: Dict[str, str] = {
        "action": "query",
        "format": "json",
        "list": "categorymembers",
        "cmtitle": category_title,
        "cmtype": "file",
        "cmnamespace": "6",
        "cmprop": "title",
        "cmlimit": CATEGORY_PAGE_LIMIT,
    }
    out: List[str] = []
    cont = None
    while True:
        if cont:
            params.update(cont)
        r = session.get(COMMONS_API, params=params, timeout=TIMEOUT_SECS)
        r.raise_for_status()
        data = r.json()
        members = (data.get("query") or {}).get("categorymembers") or []
        for m in members:
            t = str(m.get("title") or "")
            if t:
                out.append(t)
                if len(out) >= max_items:
                    return out
        cont = data.get("continue")
        if not cont:
            break
    return out

def which_titles_are_in_category(session: requests.Session, titles: List[str], category_title: str, batch: int = 50) -> Set[str]:
    """Filter titles to those listed in category_title."""
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
            if page.get("categories"):
                t = page.get("title")
                if t:
                    hits.add(str(t))
    return hits

def get_remote_sha1_hex_for_title(session: requests.Session, title: str) -> str:
    """Return hex SHA-1 for current version of File:title ('' if page missing)."""
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

def get_thumb_urls_for_titles(session: requests.Session, titles: List[str], width: int) -> Dict[str, str]:
    """Fetch thumbnail URLs for a batch of File: titles (thumb or original)."""
    urls: Dict[str, str] = {}
    for i in range(0, len(titles), 50):
        chunk = titles[i : i + 50]
        if not chunk:
            continue
        r = session.get(
            COMMONS_API,
            params={
                "action": "query",
                "format": "json",
                "formatversion": "2",
                "prop": "imageinfo",
                "iiprop": "url",
                "iiurlwidth": str(width),
                "titles": "|".join(chunk),
            },
            timeout=TIMEOUT_SECS,
        )
        r.raise_for_status()
        data = r.json()
        pages = (data.get("query") or {}).get("pages") or []
        for p in pages:
            t = p.get("title")
            info = p.get("imageinfo") or []
            if t and info:
                u = info[0].get("thumburl") or info[0].get("url")
                if u:
                    urls[str(t)] = str(u)
    return urls


# =========================
# File / folder iteration
# =========================

def iter_local_files(files_dir: Path, exts: Iterable[str]) -> Iterable[Path]:
    exts_norm = {e.lower().lstrip(".") for e in exts}
    for p in sorted(files_dir.iterdir()):
        if p.is_file():
            if not exts_norm:
                yield p
            elif p.suffix.lower().lstrip(".") in exts_norm:
                yield p

def iter_subfolders(root: Path) -> List[Path]:
    return sorted([p for p in root.iterdir() if p.is_dir()])

def infer_category_from_folder_name(folder: Path) -> Optional[str]:
    name = folder.name.strip()
    if not name:
        return None
    name = name.replace("_", " ")
    return normalize_category(name)


# =========================
# JSON report helpers
# =========================

def new_json_record(
    *,
    folder: str,
    filename: str,
    sha1_hex_local: str,
    status: str,
    category_context: Optional[str] = None,
    details: str = "",
    matches: Optional[List[Dict[str, Any]]] = None,
    fuzzy_distance: Optional[int] = None,
    fuzzy_thumb_width: Optional[int] = None,
) -> Dict[str, Any]:
    rec: Dict[str, Any] = {
        "folder": folder,
        "filename": filename,
        "sha1_hex_local": sha1_hex_local,
        "status": status,
        "category_context": category_context or "",
        "details": details or "",
        "matches": matches or [],
    }
    if fuzzy_distance is not None or fuzzy_thumb_width is not None:
        rec["fuzzy"] = {
            "distance": fuzzy_distance,
            "thumb_width": fuzzy_thumb_width,
        }
    return rec


# =========================
# Processing (per folder)
# =========================

def process_one_folder(
    session: requests.Session,
    folder: Path,
    exts: List[str],
    category: Optional[str],
    detect_scaled: bool,
    fuzzy_threshold: int,
    fuzzy_thumb_width: int,
    fuzzy_max_candidates: int,
) -> Tuple[int, int, int, int, int, List[Tuple[str, str, str, str, str, str]], List[Dict[str, Any]]]:
    """
    Returns:
      totals..., rows_for_csv, json_records
    """
    total = 0
    found_any = 0
    found_in_cat = 0
    exists_name_diff = 0
    scaled_warnings = 0

    rows: List[Tuple[str, str, str, str, str, str]] = []
    json_records: List[Dict[str, Any]] = []

    category_ctx = normalize_category(category) if category else infer_category_from_folder_name(folder)

    print(f"\n== Folder: {folder} ==")
    if category_ctx:
        print(f"Category context: {category_ctx}")
    else:
        print("No category context inferred/provided.")

    for path in iter_local_files(folder, exts):
        total += 1

        try:
            sha_hex = sha1_hex(path)
        except Exception as e:
            msg = f"failed to compute SHA-1 ({e})"
            print(f"[ERROR] {path.name}: {msg}")
            rows.append((folder.name, path.name, "", "ERROR_HASH", "", category_ctx or ""))
            json_records.append(new_json_record(
                folder=folder.name, filename=path.name, sha1_hex_local="",
                status="ERROR_HASH", category_context=category_ctx, details=msg
            ))
            continue

        # 1) Exact hash match
        try:
            titles = list_allimages_by_sha1_hex(session, sha_hex)
        except requests.RequestException as e:
            msg = f"API error (search by SHA-1) — {e}"
            print(f"[ERROR] {path.name}: {msg}")
            rows.append((folder.name, path.name, sha_hex, "ERROR_API", "search_by_hash", category_ctx or ""))
            json_records.append(new_json_record(
                folder=folder.name, filename=path.name, sha1_hex_local=sha_hex,
                status="ERROR_API", category_context=category_ctx, details="search_by_hash"
            ))
            continue

        if titles:
            found_any += 1
            rep_title = titles[0]
            try:
                remote_hex_rep = get_remote_sha1_hex_for_title(session, rep_title)
            except requests.RequestException:
                remote_hex_rep = ""

            url_list = [commons_file_url_from_title(t) for t in titles]
            url_sample = ", ".join(url_list[:5]) + ("..." if len(url_list) > 5 else "")

            # For exact hash matches, remote sha1 == local sha1, so we can fill it without extra calls
            matches_payload = [{"title": t, "url": commons_file_url_from_title(t), "sha1_hex_remote": sha_hex} for t in titles]

            if category_ctx:
                try:
                    in_cat = which_titles_are_in_category(session, titles, category_ctx)
                except requests.RequestException as e:
                    msg = f"API error (category check) — {e}"
                    print(f"[ERROR] {path.name}: {msg}")
                    rows.append((folder.name, path.name, sha_hex, "ERROR_API", "category_check", category_ctx))
                    json_records.append(new_json_record(
                        folder=folder.name, filename=path.name, sha1_hex_local=sha_hex,
                        status="ERROR_API", category_context=category_ctx, details="category_check"
                    ))
                    continue

                if in_cat:
                    found_in_cat += 1
                    in_cat_urls = ", ".join(sorted(commons_file_url_from_title(t) for t in in_cat))
                    print(f"[FOUND_IN_CATEGORY] {path.name} → {in_cat_urls}")
                    print_hash_block(sha_hex, remote_hex_rep or None, rep_title)

                    # Mark which are in the category
                    in_cat_set = set(in_cat)
                    for m in matches_payload:
                        m["in_category"] = (m["title"] in in_cat_set)

                    rows.append((folder.name, path.name, sha_hex, "FOUND_IN_CATEGORY", "; ".join(sorted(in_cat)), category_ctx))
                    json_records.append(new_json_record(
                        folder=folder.name, filename=path.name, sha1_hex_local=sha_hex,
                        status="FOUND_IN_CATEGORY", category_context=category_ctx,
                        matches=matches_payload
                    ))
                else:
                    print(f"[FOUND_OUTSIDE_CATEGORY] {path.name} → {url_sample}")
                    print_hash_block(sha_hex, remote_hex_rep or None, rep_title)

                    for m in matches_payload:
                        m["in_category"] = False

                    rows.append((folder.name, path.name, sha_hex, "FOUND_OUTSIDE_CATEGORY", "; ".join(titles), category_ctx))
                    json_records.append(new_json_record(
                        folder=folder.name, filename=path.name, sha1_hex_local=sha_hex,
                        status="FOUND_OUTSIDE_CATEGORY", category_context=category_ctx,
                        matches=matches_payload
                    ))
            else:
                print(f"[FOUND_ANYWHERE] {path.name} → {url_sample}")
                print_hash_block(sha_hex, remote_hex_rep or None, rep_title)

                rows.append((folder.name, path.name, sha_hex, "FOUND_ANYWHERE", "; ".join(titles), ""))
                json_records.append(new_json_record(
                    folder=folder.name, filename=path.name, sha1_hex_local=sha_hex,
                    status="FOUND_ANYWHERE", matches=matches_payload
                ))
            continue

        # 2) No hash match — try by-title & scaled checks
        title_candidate = f"File:{path.name.replace(' ', '_')}"
        title_candidate_url = commons_file_url_from_title(title_candidate)

        # Scaled-variant by title (thumb + dHash)
        if detect_scaled:
            try:
                thumb_map = get_thumb_urls_for_titles(session, [title_candidate], fuzzy_thumb_width)
                url = thumb_map.get(title_candidate)
                if url:
                    resp = session.get(url, timeout=TIMEOUT_SECS)
                    if resp.ok:
                        local_dh = dhash_from_path(path)
                        remote_dh = dhash_from_bytes(resp.content)
                        if local_dh is not None and remote_dh is not None:
                            dist = hamming_distance(local_dh, remote_dh)
                            if dist <= fuzzy_threshold:
                                scaled_warnings += 1
                                print(f"[POSSIBLE_SCALED_VARIANT_BY_TITLE] {path.name} ↔ {title_candidate_url} (dHash distance={dist} ≤ {fuzzy_threshold})")
                                # Show local vs remote hex for that title
                                try:
                                    remote_hex = get_remote_sha1_hex_for_title(session, title_candidate)
                                except requests.RequestException:
                                    remote_hex = ""
                                print_hash_block(sha_hex, remote_hex or None, title_candidate)

                                rows.append((folder.name, path.name, sha_hex, "POSSIBLE_SCALED_VARIANT_BY_TITLE",
                                             f"{title_candidate} (d={dist})", category_ctx or ""))
                                json_records.append(new_json_record(
                                    folder=folder.name, filename=path.name, sha1_hex_local=sha_hex,
                                    status="POSSIBLE_SCALED_VARIANT_BY_TITLE",
                                    category_context=category_ctx,
                                    details=f"{title_candidate} (d={dist})",
                                    matches=[{
                                        "title": title_candidate,
                                        "url": title_candidate_url,
                                        "sha1_hex_remote": remote_hex or "",
                                    }],
                                    fuzzy_distance=dist, fuzzy_thumb_width=fuzzy_thumb_width
                                ))
                                continue
            except requests.RequestException:
                pass
            except Exception:
                pass

        # Exists by title but different content?
        try:
            remote_hex = get_remote_sha1_hex_for_title(session, title_candidate)
        except requests.RequestException as e:
            msg = f"API error (title check) — {e}"
            print(f"[ERROR] {path.name}: {msg}")
            rows.append((folder.name, path.name, sha_hex, "ERROR_API", "title_check", category_ctx or ""))
            json_records.append(new_json_record(
                folder=folder.name, filename=path.name, sha1_hex_local=sha_hex,
                status="ERROR_API", category_context=category_ctx, details="title_check"
            ))
            continue

        if remote_hex:
            exists_name_diff += 1
            print(f"[EXISTS_BY_TITLE_DIFFERENT_CONTENT] {path.name}")
            print_hash_block(sha_hex, remote_hex, title_candidate)

            rows.append((folder.name, path.name, sha_hex, "EXISTS_BY_TITLE_DIFFERENT_CONTENT",
                         title_candidate, category_ctx or ""))
            json_records.append(new_json_record(
                folder=folder.name, filename=path.name, sha1_hex_local=sha_hex,
                status="EXISTS_BY_TITLE_DIFFERENT_CONTENT", category_context=category_ctx,
                matches=[{
                    "title": title_candidate,
                    "url": title_candidate_url,
                    "sha1_hex_remote": remote_hex
                }]
            ))
            continue

        # Category-scoped fuzzy search (bounded)
        if detect_scaled and category_ctx:
            try:
                cand_titles = list_category_files_depth0(session, category_ctx, fuzzy_max_candidates)
                if cand_titles:
                    thumb_map = get_thumb_urls_for_titles(session, cand_titles, fuzzy_thumb_width)
                    local_dh = dhash_from_path(path)
                    if local_dh is not None:
                        best_hit: Tuple[str, int] | None = None
                        for title, url in thumb_map.items():
                            try:
                                r = session.get(url, timeout=TIMEOUT_SECS)
                                if not r.ok:
                                    continue
                                dh = dhash_from_bytes(r.content)
                                if dh is None:
                                    continue
                                dist = hamming_distance(local_dh, dh)
                                if dist <= fuzzy_threshold:
                                    if best_hit is None or dist < best_hit[1]:
                                        best_hit = (title, dist)
                            except requests.RequestException:
                                continue
                        if best_hit:
                            scaled_warnings += 1
                            title, dist = best_hit
                            best_url = commons_file_url_from_title(title)
                            print(f"[POSSIBLE_SCALED_VARIANT_IN_CATEGORY] {path.name} ↔ {best_url} (dHash distance={dist} ≤ {fuzzy_threshold})")
                            try:
                                remote_hex2 = get_remote_sha1_hex_for_title(session, title)
                            except requests.RequestException:
                                remote_hex2 = ""
                            print_hash_block(sha_hex, remote_hex2 or None, title)

                            rows.append((folder.name, path.name, sha_hex, "POSSIBLE_SCALED_VARIANT_IN_CATEGORY",
                                         f"{title} (d={dist})", category_ctx))
                            json_records.append(new_json_record(
                                folder=folder.name, filename=path.name, sha1_hex_local=sha_hex,
                                status="POSSIBLE_SCALED_VARIANT_IN_CATEGORY", category_context=category_ctx,
                                details=f"{title} (d={dist})",
                                matches=[{
                                    "title": title,
                                    "url": best_url,
                                    "sha1_hex_remote": remote_hex2 or ""
                                }],
                                fuzzy_distance=dist, fuzzy_thumb_width=fuzzy_thumb_width
                            ))
                            continue
            except requests.RequestException as e:
                msg = f"API error (category fuzzy) — {e}"
                print(f"[ERROR] {path.name}: {msg}")
                rows.append((folder.name, path.name, sha_hex, "ERROR_API", "category_fuzzy", category_ctx))
                json_records.append(new_json_record(
                    folder=folder.name, filename=path.name, sha1_hex_local=sha_hex,
                    status="ERROR_API", category_context=category_ctx, details="category_fuzzy"
                ))
                # fall through

        # 3) Nothing found
        print(f"[NOT_ON_COMMONS] {path.name}")
        print_hash_block(sha_hex, None)

        rows.append((folder.name, path.name, sha_hex, "NOT_ON_COMMONS", "", category_ctx or ""))
        json_records.append(new_json_record(
            folder=folder.name, filename=path.name, sha1_hex_local=sha_hex,
            status="NOT_ON_COMMONS", category_context=category_ctx
        ))

    print(f"-- Folder summary: scanned={total}, found_any={found_any},"
          f"{' found_in_cat=' + str(found_in_cat) if category_ctx else ''} "
          f"exists_by_title_diff={exists_name_diff}, scaled_warnings={scaled_warnings}")
    return total, found_any, found_in_cat, exists_name_diff, scaled_warnings, rows, json_records


# =========================
# CLI
# =========================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Check local files against Wikimedia Commons by SHA-1 and detect scaled variants, "
                    "printing clear LOCAL vs REMOTE SHA-1 (hex only), Commons file URLs, "
                    "and optionally writing CSV/JSON reports."
    )
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--files-dir", help="Path to one folder, e.g. 'files/Category_Binnenhofrenovatie'.")
    group.add_argument("--files-root", help="Path whose immediate subfolders are scanned, e.g. 'files'.")

    p.add_argument("--category",
                   help="Commons category context (overrides folder inference), e.g. 'Category:Binnenhofrenovatie'.")

    p.add_argument("--extensions",
                   default="jpg,jpeg,png,tif,tiff,gif",
                   help="Comma-separated raster types to include (default common raster). "
                        "Use empty string to include all files.")

    p.add_argument("--output-csv",
                   help="Optional CSV path to write a tabular report.")

    p.add_argument("--output-json",
                   help="Optional JSON path to write a machine-readable report.")

    p.add_argument("--detect-scaled", dest="detect_scaled", action="store_true", default=True,
                   help="Enable scaled-variant detection (default).")
    p.add_argument("--no-detect-scaled", dest="detect_scaled", action="store_false",
                   help="Disable scaled-variant detection.")
    p.add_argument("--fuzzy-threshold", type=int, default=FUZZY_DEFAULT_THRESHOLD,
                   help=f"Hamming distance threshold for dHash similarity (default {FUZZY_DEFAULT_THRESHOLD}).")
    p.add_argument("--fuzzy-thumb-width", type=int, default=FUZZY_DEFAULT_THUMB_WIDTH,
                   help=f"Width for server-side thumbnails (default {FUZZY_DEFAULT_THUMB_WIDTH}px).")
    p.add_argument("--fuzzy-max-candidates", type=int, default=FUZZY_DEFAULT_MAX_CANDIDATES,
                   help=f"Max category candidates to scan per folder (default {FUZZY_DEFAULT_MAX_CANDIDATES}).")

    return p.parse_args()


# =========================
# Main
# =========================

def main() -> None:
    args = parse_args()
    exts = [] if args.extensions.strip() == "" else [e.strip() for e in args.extensions.split(",") if e.strip()]
    session = build_session()

    grand_total = 0
    grand_found_any = 0
    grand_found_in_cat = 0
    grand_exists_name_diff = 0
    grand_scaled_warnings = 0

    all_rows: List[Tuple[str, str, str, str, str, str]] = []
    all_json_records: List[Dict[str, Any]] = []
    folders_scanned = 0

    if args.files_dir:
        folder = Path(args.files_dir)
        if not folder.exists():
            raise FileNotFoundError(f"--files-dir not found: {folder}")
        folders_scanned += 1
        t, fa, fic, end, sw, rows, json_recs = process_one_folder(
            session, folder, exts, args.category, args.detect_scaled,
            args.fuzzy_threshold, args.fuzzy_thumb_width, args.fuzzy_max_candidates
        )
        grand_total += t
        grand_found_any += fa
        grand_found_in_cat += fic
        grand_exists_name_diff += end
        grand_scaled_warnings += sw
        all_rows.extend(rows)
        all_json_records.extend(json_recs)

    else:
        root = Path(args.files_root)
        if not root.exists():
            raise FileNotFoundError(f"--files-root not found: {root}")
        subfolders = iter_subfolders(root)
        if not subfolders:
            print(f"No subfolders found under {root}. Nothing to do.")
        else:
            print(f"Scanning ALL immediate subfolders under: {root}")
            for folder in subfolders:
                folders_scanned += 1
                t, fa, fic, end, sw, rows, json_recs = process_one_folder(
                    session, folder, exts, args.category, args.detect_scaled,
                    args.fuzzy_threshold, args.fuzzy_thumb_width, args.fuzzy_max_candidates
                )
                grand_total += t
                grand_found_any += fa
                grand_found_in_cat += fic
                grand_exists_name_diff += end
                grand_scaled_warnings += sw
                all_rows.extend(rows)
                all_json_records.extend(json_recs)

    # Grand summary (stdout)
    print("\n=== Grand summary ===")
    print(f"  Folders scanned: {folders_scanned}")
    print(f"  Files scanned: {grand_total}")
    print(f"  Exact hash matches anywhere on Commons: {grand_found_any}")
    if grand_found_in_cat:
        print(f"  Exact hash matches inside target category: {grand_found_in_cat}")
    print(f"  Exists by title but different content: {grand_exists_name_diff}")
    print(f"  Possible scaled/variant warnings: {grand_scaled_warnings}")

    # CSV (optional)
    if args.output_csv:
        out = Path(args.output_csv)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Folder", "Filename", "SHA1_Hex", "Status", "Details", "CategoryContext"])
            for r in all_rows:
                w.writerow(r)
        print(f"CSV written: {out}")

    # JSON (optional)
    if args.output_json:
        outj = Path(args.output_json)
        outj.parent.mkdir(parents=True, exist_ok=True)

        report = {
            "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "args": {
                "files_dir": args.files_dir,
                "files_root": args.files_root,
                "category": args.category,
                "extensions": args.extensions,
                "detect_scaled": args.detect_scaled,
                "fuzzy_threshold": args.fuzzy_threshold,
                "fuzzy_thumb_width": args.fuzzy_thumb_width,
                "fuzzy_max_candidates": args.fuzzy_max_candidates,
            },
            "summary": {
                "folders_scanned": folders_scanned,
                "files_scanned": grand_total,
                "exact_hash_matches": grand_found_any,
                "exact_hash_matches_in_category": grand_found_in_cat,
                "exists_by_title_different_content": grand_exists_name_diff,
                "possible_scaled_variant_warnings": grand_scaled_warnings,
            },
            "results": all_json_records,
        }

        with outj.open("w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"JSON written: {outj}")


if __name__ == "__main__":
    main()