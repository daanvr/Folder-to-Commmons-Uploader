#!/usr/bin/env python3
"""
Flask Web UI for MacOS-to-Commons-Uploader
Displays detected files, their status, and metadata.

What this app does
------------------
• Watches a "watch" folder (e.g. watch/Category_Binnenhofrenovatie) for JPG/JPEG.
• Tracks files in data/processed_files.json.
• Background "Commons duplicate check" so items don’t stay stuck on PENDING.
• For files NOT on Commons, suggests a Commons filename:
    <CategorySlug>_<yyyymmdd-hhmmss><ext>
  where CategorySlug is the part after "Category_" in the folder name.
• Upload to Commons via /api/upload using credentials in .env.
• Routes accept either absolute paths or filenames relative to the watch folder.

Prereqs
-------
pip install flask pillow watchdog python-dotenv requests urllib3
"""

from __future__ import annotations

import json
import os
import re
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any

from flask import (
    Flask, render_template, jsonify, request, redirect, url_for, flash, send_file
)
from PIL import Image
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from html import unescape

CONNECT_TIMEOUT = 25
READ_TIMEOUT = 240
API_TIMEOUT = (CONNECT_TIMEOUT, READ_TIMEOUT)

# ---- watchdog: use polling on Windows to be robust ----
if os.name == "nt":
    from watchdog.observers.polling import PollingObserver as Observer
else:
    from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ---- Import Commons duplicate checker (optional) ----
try:
    from lib.commons_duplicate_checker import check_file_on_commons, build_session as build_checker_session
except Exception as e:
    print("Warning: Could not import lib.commons_duplicate_checker. Duplicate checking disabled.")
    print(f"  Import error: {e}")
    check_file_on_commons = None  # type: ignore
    build_checker_session = None  # type: ignore

# ---- dotenv: robust, on-demand loading ----
from dotenv import load_dotenv, find_dotenv

def get_commons_creds() -> tuple[str, str, str]:
    """
    Load .env from the repo root (or nearest parent) every time.
    Returns (username, password, user_agent).
    """
    dotenv_path = find_dotenv(usecwd=True)
    # You can uncomment the next line to see where it loads from:
    # print(f".env found: {dotenv_path or '(none)'}")
    load_dotenv(dotenv_path=dotenv_path, override=False)

    username = os.getenv("COMMONS_USERNAME", "").strip()
    password = os.getenv("COMMONS_PASSWORD", "").strip()
    # Optional override for UA
    user_agent_from_env = (os.getenv("COMMONS_USER_AGENT", "") or "").strip()
    return username, password, user_agent_from_env


COMMONS_API = "https://commons.wikimedia.org/w/api.php"
DEFAULT_USER_AGENT = "KB Folder-to-Commons Uploader (App UI)"
TIMEOUT_SECS = 25
RETRIES_TOTAL = 5
RETRIES_BACKOFF = 0.6

app = Flask(__name__)
app.secret_key = 'dev-secret-key-change-in-production'


# ========================
# Utilities
# ========================

def login_with_botpassword(session: requests.Session, username: str, password: str) -> None:
    """
    Login using legacy action=login (recommended for BotPasswords).
    Raises on failure.
    """
    print("[UPLOAD] (fallback) Getting login token for action=login…")
    r = session.get(COMMONS_API, params={
        "action": "query", "meta": "tokens", "type": "login", "format": "json"
    }, timeout=API_TIMEOUT)
    r.raise_for_status()
    login_token = r.json()["query"]["tokens"]["logintoken"]

    print("[UPLOAD] (fallback) action=login …")
    r2 = session.post(COMMONS_API, data={
        "action": "login", "format": "json",
        "lgname": username, "lgpassword": password, "lgtoken": login_token,
    }, timeout=API_TIMEOUT)
    r2.raise_for_status()
    data2 = r2.json()
    status = (data2.get("login") or {}).get("result")
    print(f"[UPLOAD] (fallback) login result = {status}")
    if status != "Success":
        raise RuntimeError(f"BotPassword login failed: {json.dumps(data2, ensure_ascii=False)}")


def build_requests_session(user_agent: str | None = None) -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=RETRIES_TOTAL,
        connect=RETRIES_TOTAL,
        read=RETRIES_TOTAL,
        status=RETRIES_TOTAL,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "POST"}),
        backoff_factor=RETRIES_BACKOFF,
        raise_on_status=False,
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    ua = (user_agent or DEFAULT_USER_AGENT).strip()
    s.headers.update({"User-Agent": ua, "Accept": "application/json"})
    return s


def resolve_ref_to_path(ref: str, settings: dict) -> Path:
    """
    Accepts either:
      - a bare filename like '20240409_173917.jpg' (resolved under watch_folder), or
      - an absolute path like 'D:\\...\\20240409_173917.jpg' or '/Users/.../file.jpg'.
    """
    # Windows absolute path like C:\ or D:\
    is_win_abs = bool(re.match(r"^[A-Za-z]:[\\/]", ref))
    p = Path(ref)
    if p.is_absolute() or is_win_abs:
        return p
    return Path(settings['watch_folder']).resolve() / ref


def slug_from_category_folder(folder_name: str) -> str:
    """From 'Category_Binnenhofrenovatie' -> 'Binnenhofrenovatie' (safe)."""
    base = folder_name.strip()
    m = re.match(r"^Category[_\s]+(.+)$", base, flags=re.IGNORECASE)
    core = m.group(1) if m else base
    core = core.replace(" ", "_")
    core = re.sub(r'[<>:"/\\|?*#]', "_", core)
    return core


TS_PATTERN = re.compile(r"(?P<date>\d{8})[-_](?P<time>\d{6})")  # yyyymmdd-hhmmss / yyyymmdd_hhmmss

def extract_timestamp_token(filename: str) -> Optional[str]:
    m = TS_PATTERN.search(filename)
    if not m:
        return None
    date = m.group("date")
    tim = m.group("time")
    return f"{date}-{tim}"


def suggest_commons_filename(local_path: Path, watch_folder: Path) -> str:
    """
    Suggested filename: "<CategorySlug>_<yyyymmdd-hhmmss><ext>"
    If no timestamp found, fall back to "<CategorySlug>_<stem><ext>".
    """
    parent = local_path.parent.name
    slug = slug_from_category_folder(parent)
    ts = extract_timestamp_token(local_path.name)
    stem = local_path.stem
    ext = local_path.suffix.lower()
    namecore = f"{slug}_{ts}" if ts else f"{slug}_{stem}"
    namecore = re.sub(r'[<>:"/\\|?*#]', "_", namecore)
    return f"{namecore}{ext}"


def wikitext_from_settings_and_category(settings: Dict[str, Any], category_slug: str) -> str:
    """Build initial page text and categories."""
    author = settings.get("author", "")
    source = settings.get("source", "")
    own_work = settings.get("own_work", True)
    default_categories = settings.get("default_categories", []) or []

    lines = [
        "=={{int:filedesc}}==",
        "{{Information",
        "|description={{en|1=Uploaded via KB Folder-to-Commons Uploader}}",
        "|date=",
        "|source={{own}}" if own_work else f"|source={source}",
        f"|author={author}",
        "}}",
        "=={{int:license-header}}==",
        "{{self|cc-by-sa-4.0}}",
        f"[[Category:{category_slug}]]",
    ]
    for c in default_categories:
        c = str(c).strip()
        if not c:
            continue
        cat_name = c.split(":", 1)[1] if c.lower().startswith("category:") else c
        lines.append(f"[[Category:{cat_name}]]")
    return "\n".join(lines) + "\n"


def commons_login_and_get_csrf(session: requests.Session, username: str, password: str) -> str:
    """
    Try clientlogin first (works for non-2FA accounts).
    If that fails (e.g., 2FA or wrong flow), fall back to action=login (BotPassword).
    Returns a CSRF token on success.
    """
    # First attempt: clientlogin
    try:
        print("[UPLOAD] Getting login token (clientlogin)…")
        r = session.get(COMMONS_API, params={
            "action": "query", "meta": "tokens", "type": "login", "format": "json"
        }, timeout=API_TIMEOUT)
        r.raise_for_status()
        login_token = r.json()["query"]["tokens"]["logintoken"]

        print(f"[UPLOAD] clientlogin as {username!r} …")
        r2 = session.post(COMMONS_API, data={
            "action": "clientlogin", "format": "json",
            "username": username, "password": password,
            "loginreturnurl": "https://commons.wikimedia.org/wiki/Special:BlankPage",
            "logintoken": login_token,
        }, timeout=API_TIMEOUT)
        r2.raise_for_status()
        data2 = r2.json()
        status = (data2.get("clientlogin") or {}).get("status")
        print(f"[UPLOAD] clientlogin status = {status}")

        if status == "PASS":
            # get CSRF
            print("[UPLOAD] Getting CSRF token…")
            r3 = session.get(COMMONS_API, params={
                "action": "query", "meta": "tokens", "type": "csrf", "format": "json"
            }, timeout=API_TIMEOUT)
            r3.raise_for_status()
            csrf = r3.json()["query"]["tokens"]["csrftoken"]
            if not csrf or csrf == "+\\":
                raise RuntimeError("Empty CSRF token")
            return csrf

        # If clientlogin FAILED (e.g., wrongpassword, 2FA), try BotPassword flow next.
        print(f"[UPLOAD] clientlogin failed ({status}). Falling back to action=login (BotPassword).")

    except Exception as e:
        print(f"[UPLOAD] clientlogin exception: {e}. Will try action=login (BotPassword).")

    # Fallback: BotPassword (action=login)
    login_with_botpassword(session, username, password)

    # After login, fetch CSRF token
    print("[UPLOAD] (fallback) Getting CSRF token…")
    r4 = session.get(COMMONS_API, params={
        "action": "query", "meta": "tokens", "type": "csrf", "format": "json"
    }, timeout=API_TIMEOUT)
    r4.raise_for_status()
    csrf = r4.json()["query"]["tokens"]["csrftoken"]
    if not csrf or csrf == "+\\":
        raise RuntimeError("Empty CSRF token after fallback login")
    return csrf




def upload_to_commons(
    local_path: Path,
    target_filename: str,
    category_slug: str,
    settings: dict,
    username: str,
    password: str,
    user_agent: str,
) -> Dict[str, Any]:
    """Upload file to Commons with initial wikitext that includes Category:<slug>."""
    if not username or not password:
        raise RuntimeError("Missing COMMONS_USERNAME/COMMONS_PASSWORD in .env")

    session = build_requests_session(user_agent or DEFAULT_USER_AGENT)
    csrf = commons_login_and_get_csrf(session, username, password)

    with local_path.open("rb") as f:
        files = {"file": (target_filename, f, "application/octet-stream")}
        data = {
            "action": "upload",
            "format": "json",
            "filename": target_filename,          # no 'File:' prefix here
            "comment": "Upload via KB Folder-to-Commons Uploader",
            "text": wikitext_from_settings_and_category(settings, category_slug),
            "token": csrf,
            "ignorewarnings": "1",
        }
        r = session.post(COMMONS_API, data=data, files=files, timeout=TIMEOUT_SECS)
        r.raise_for_status()
        resp = r.json()

    if "error" in resp:
        return {"ok": False, "details": resp["error"]}

    up = resp.get("upload", {})
    if up.get("result") == "Success":
        title = up.get("filename") or f"File:{target_filename}"
        url = f"https://commons.wikimedia.org/wiki/{title.replace(' ', '_')}"
        return {"ok": True, "title": title, "url": url, "details": up}
    return {"ok": False, "details": resp}


# ========================
# File tracking / storage
# ========================

class FileTracker:
    """Tracks files and their Commons-check status in a JSON DB."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self.processed_files: Dict[str, Dict[str, Any]] = self._load()

    def _load(self) -> Dict[str, Dict[str, Any]]:
        if self.db_path.exists():
            with self.db_path.open('r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, list):
                return {str(p): self._create_file_record(p) for p in data}
            if isinstance(data, dict):
                return data
        return {}

    def _save(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.db_path.open('w', encoding='utf-8') as f:
            json.dump(self.processed_files, f, indent=2)

    def _create_file_record(self, file_path: str, **kwargs) -> Dict[str, Any]:
        return {
            "file_path": str(file_path),
            "detected_at": kwargs.get("detected_at", datetime.now().isoformat()),
            "sha1_local": kwargs.get("sha1_local", ""),
            "commons_check_status": kwargs.get("commons_check_status", "PENDING"),
            "commons_matches": kwargs.get("commons_matches", []),
            "checked_at": kwargs.get("checked_at", ""),
            "check_details": kwargs.get("check_details", ""),
        }

    def is_processed(self, file_path: Path) -> bool:
        with self._lock:
            return str(file_path) in self.processed_files

    def mark_processed(self, file_path: Path, **kwargs) -> None:
        file_key = str(file_path)
        with self._lock:
            if file_key in self.processed_files:
                self.processed_files[file_key].update(kwargs)
            else:
                self.processed_files[file_key] = self._create_file_record(file_key, **kwargs)
            self._save()

    def update_commons_check(self, file_path: str | Path, check_result: Dict[str, Any]) -> None:
        file_key = str(file_path)
        with self._lock:
            if file_key not in self.processed_files:
                self.processed_files[file_key] = self._create_file_record(file_key)
            rec = self.processed_files[file_key]
            rec.update({
                "sha1_local": check_result.get("sha1_local", rec.get("sha1_local", "")),
                "commons_check_status": check_result.get("status", "ERROR"),
                "commons_matches": check_result.get("matches", []),
                "checked_at": check_result.get("checked_at", datetime.now().isoformat()),
                "check_details": check_result.get("details", rec.get("check_details", "")),
            })
            self._save()

    def get_file_record(self, file_path: str | Path) -> Optional[Dict[str, Any]]:
        return self.processed_files.get(str(file_path))

    def get_all_files(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.processed_files.values())


# ========================
# Watchdog handler
# ========================

class NewFileHandler(FileSystemEventHandler):
    """Handles new files arriving in the watch folder."""

    def __init__(self, tracker: FileTracker, watch_folder: Path, settings: Dict[str, Any], commons_session=None):
        self.tracker = tracker
        self.watch_folder = Path(watch_folder)
        self.settings = settings
        self.commons_session = commons_session

    def on_created(self, event):
        if event.is_directory:
            return
        file_path = Path(event.src_path)
        if file_path.suffix.lower() not in ('.jpg', '.jpeg'):
            return
        if self.tracker.is_processed(file_path):
            return
        print(f"[NEW FILE DETECTED] {file_path.name}")
        self.tracker.mark_processed(file_path, commons_check_status="PENDING")
        print("  • Status: Tracked; Commons check scheduled.\n")


# ========================
# Boot helpers
# ========================

def scan_existing_files(watch_folder: Path, tracker: FileTracker) -> None:
    watch_folder.mkdir(parents=True, exist_ok=True)
    print(f"Scanning existing files in: {watch_folder}")
    existing_count = 0
    for p in watch_folder.glob('*'):
        if p.is_file() and p.suffix.lower() in ('.jpg', '.jpeg'):
            if not tracker.is_processed(p):
                tracker.mark_processed(p, commons_check_status="PENDING")
                existing_count += 1
    if existing_count:
        print(f"Marked {existing_count} existing file(s) as pending for Commons check.\n")


def commons_checker_loop(tracker: FileTracker, settings: Dict[str, Any], commons_session) -> None:
    enabled = settings.get('enable_duplicate_check', False)
    if not enabled or check_file_on_commons is None:
        # convert PENDING -> DISABLED so UI isn't stuck
        for rec in tracker.get_all_files():
            if rec.get("commons_check_status", "PENDING") == "PENDING":
                tracker.update_commons_check(
                    rec["file_path"],
                    {
                        "status": "DISABLED",
                        "details": "Duplicate checking disabled or checker module not available.",
                        "sha1_local": rec.get("sha1_local", ""),
                        "checked_at": datetime.now().isoformat()
                    }
                )
        return

    print("Commons checker loop: started.")
    while True:
        pendings = [
            r for r in tracker.get_all_files()
            if r.get("commons_check_status", "PENDING") in ("PENDING", "IN_PROGRESS")
        ]
        for rec in pendings:
            fp = rec["file_path"]
            tracker.update_commons_check(fp, {
                "status": "IN_PROGRESS",
                "check_details": "Running Commons duplicate check…",
                "checked_at": datetime.now().isoformat()
            })
            try:
                result = check_file_on_commons(
                    Path(fp),
                    session=commons_session,
                    check_scaled=settings.get('check_scaled_variants', False),
                    fuzzy_threshold=settings.get('fuzzy_threshold', 10),
                )
                tracker.update_commons_check(fp, result)
            except Exception as e:
                tracker.update_commons_check(fp, {
                    "status": "ERROR",
                    "details": f"{type(e).__name__}: {e}",
                    "checked_at": datetime.now().isoformat()
                })
        time.sleep(2)


def start_monitoring() -> None:
    settings = load_settings()
    watch_folder = Path(settings['watch_folder']).resolve()
    db_path = Path(settings['processed_files_db']).resolve()

    print("=" * 60)
    print("Starting File Monitor")
    print("=" * 60)
    print(f"Watch folder: {watch_folder}")
    print(f"Tracking database: {db_path}")

    if settings.get('enable_duplicate_check', False):
        print("Duplicate checking: ENABLED")
        print(f"  • Scaled-variant detection: {'ENABLED' if settings.get('check_scaled_variants', False) else 'DISABLED'}"
              + (f" (threshold={settings.get('fuzzy_threshold', 10)})" if settings.get('check_scaled_variants', False) else ""))
    else:
        print("Duplicate checking: DISABLED")
    print()

    tracker = FileTracker(db_path)

    commons_session = None
    if settings.get('enable_duplicate_check', False) and build_checker_session is not None:
        try:
            commons_session = build_checker_session()
            print("Commons API session (checker): ready.")
        except Exception as e:
            print(f"Commons checker session init failed: {e}")

    scan_existing_files(watch_folder, tracker)

    event_handler = NewFileHandler(tracker, watch_folder, settings, commons_session)
    observer = Observer()
    observer.schedule(event_handler, str(watch_folder), recursive=False)
    try:
        observer.start()
    except Exception as e:
        print(f"Observer start failed ({e}); falling back to PollingObserver.")
        from watchdog.observers.polling import PollingObserver
        observer = PollingObserver()
        observer.schedule(event_handler, str(watch_folder), recursive=False)
        observer.start()

    threading.Thread(
        target=commons_checker_loop,
        args=(tracker, settings, commons_session),
        daemon=True
    ).start()

    print("File monitoring started.\n")


# ========================
# Settings + helpers
# ========================

def load_settings() -> Dict[str, Any]:
    with open('settings.json', 'r', encoding='utf-8') as f:
        return json.load(f)

def save_settings(settings: Dict[str, Any]) -> None:
    with open('settings.json', 'w', encoding='utf-8') as f:
        json.dump(settings, f, indent=2)

def get_file_info(file_path: str) -> Optional[Dict[str, Any]]:
    p = Path(file_path)
    if not p.exists():
        return None
    st = p.stat()
    return {
        'path': str(p),
        'name': p.name,
        'size': st.st_size,
        'size_mb': round(st.st_size / (1024 * 1024), 2),
        'created': datetime.fromtimestamp(st.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
        'modified': datetime.fromtimestamp(getattr(st, "st_mtime", st.st_mtime)).strftime('%Y-%m-%d %H:%M:%S'),
        'exists': True,
        'status': 'Detected'
    }


# ========================
# Routes (UI + API)
# ========================

@app.route('/')
def index():
    """Main list with suggestions and pre-built URLs attached."""
    settings = load_settings()
    tracker = FileTracker(Path(settings['processed_files_db']))
    records = tracker.get_all_files()
    watch_folder = Path(settings['watch_folder']).resolve()

    files_info: List[Dict[str, Any]] = []
    for rec in records:
        info = get_file_info(rec.get('file_path', ''))
        if not info:
            continue

        # add relative path (for convenience in templates)
        try:
            if str(info['path']).lower().startswith(str(watch_folder).lower()):
                info['relative_path'] = os.path.relpath(info['path'], watch_folder)
            else:
                info['relative_path'] = info['name']
        except Exception:
            info['relative_path'] = info['name']

        # Derive category from parent folder if it starts with Category_
        parent_name = Path(info['path']).parent.name
        if parent_name.lower().startswith("category_"):
            info['category'] = slug_from_category_folder(parent_name)

        # pre-built URLs so templates don't need to know param names
        info['urls'] = {
            "detail": url_for('file_detail', ref=info['path']),
            "thumb": url_for('serve_thumbnail', ref=info['path']),
            "image": url_for('serve_image', ref=info['path']),
        }

        status = rec.get('commons_check_status', 'PENDING')
        info['commons_check_status'] = status
        info['commons_matches'] = rec.get('commons_matches', [])
        info['check_details'] = rec.get('check_details', '')
        info['sha1_local'] = rec.get('sha1_local', '')

        if status == "NOT_ON_COMMONS":
            local_path = Path(rec['file_path'])
            suggested = suggest_commons_filename(local_path, watch_folder)
            cat_slug = slug_from_category_folder(local_path.parent.name)
            info['upload_suggestion'] = {
                "suggested_filename": suggested,
                "category_slug": cat_slug,
                "post_url": url_for('api_upload')
            }
        files_info.append(info)

    files_info.sort(key=lambda x: x['created'], reverse=True)

    # Fresh creds -> enable/disable upload UI
    u, p, _ua = get_commons_creds()
    can_upload = bool(u and p)

    return render_template(
        'index.html',
        files=files_info,
        total_files=len(files_info),
        settings=settings,
        upload_enabled=can_upload
    )


@app.route('/file/<path:ref>')
def file_detail(ref: str):
    """Detail page for one file (accepts filename or absolute path)."""
    settings = load_settings()
    p = resolve_ref_to_path(ref, settings)

    info = get_file_info(str(p))
    if not info:
        return "File not found", 404

    # Derive category display (optional)
    parent_name = p.parent.name
    if parent_name.lower().startswith("category_"):
        info['category'] = slug_from_category_folder(parent_name)

    tracker = FileTracker(Path(settings['processed_files_db']))
    rec = tracker.get_file_record(str(p))
    if rec:
        status = rec.get('commons_check_status', 'PENDING')
        info['commons_check_status'] = status
        info['commons_matches'] = rec.get('commons_matches', [])
        info['check_details'] = rec.get('check_details', '')
        info['sha1_local'] = rec.get('sha1_local', '')
        if status == "NOT_ON_COMMONS":
            suggested = suggest_commons_filename(p, Path(settings['watch_folder']).resolve())
            cat_slug = slug_from_category_folder(p.parent.name)
            info['upload_suggestion'] = {
                "suggested_filename": suggested,
                "category_slug": cat_slug,
                "post_url": url_for('api_upload')
            }

    # URLs for the detail template
    info['urls'] = {
        "thumb": url_for('serve_thumbnail', ref=str(p)),
        "image": url_for('serve_image', ref=str(p)),
    }

    # Fresh creds control upload UI
    u, pword, _ua = get_commons_creds()
    can_upload = bool(u and pword)

    exif = extract_exif_safe(str(p))
    return render_template('file_detail.html', file=info, exif=exif, settings=settings, upload_enabled=can_upload)


@app.route('/api/files')
def api_files():
    """JSON list of tracked files (with suggestions when applicable)."""
    settings = load_settings()
    tracker = FileTracker(Path(settings['processed_files_db']))
    watch_folder = Path(settings['watch_folder']).resolve()
    out = []
    for rec in tracker.get_all_files():
        info = get_file_info(rec.get('file_path', ''))
        if not info:
            continue
        status = rec.get('commons_check_status', 'PENDING')
        info['commons_check_status'] = status
        info['commons_matches'] = rec.get('commons_matches', [])
        info['check_details'] = rec.get('check_details', '')
        info['sha1_local'] = rec.get('sha1_local', '')
        if status == "NOT_ON_COMMONS":
            p = Path(rec['file_path'])
            info['upload_suggestion'] = {
                "suggested_filename": suggest_commons_filename(p, watch_folder),
                "category_slug": slug_from_category_folder(p.parent.name),
                "post_url": url_for('api_upload')
            }
        # include URLs in API too (handy for frontend JS)
        info['urls'] = {
            "detail": url_for('file_detail', ref=info['path']),
            "thumb": url_for('serve_thumbnail', ref=info['path']),
            "image": url_for('serve_image', ref=info['path']),
        }
        # Optional category field for UI/API clients
        parent_name = Path(info['path']).parent.name
        if parent_name.lower().startswith("category_"):
            info['category'] = slug_from_category_folder(parent_name)
        out.append(info)
    return jsonify(out)


@app.route('/api/file/<path:ref>')
def api_file_detail(ref: str):
    """JSON details for a single file (accepts filename or absolute path)."""
    settings = load_settings()
    p = resolve_ref_to_path(ref, settings)

    info = get_file_info(str(p))
    if not info:
        return jsonify({"error": "File not found"}), 404

    exif = extract_exif_safe(str(p))
    return jsonify({"file": info, "exif": exif})


@app.route('/image/<path:ref>')
def serve_image(ref: str):
    """Serve the original image bytes (accepts filename or absolute path)."""
    settings = load_settings()
    p = resolve_ref_to_path(ref, settings)
    if not p.exists() or not p.is_file():
        return "Image not found", 404
    return send_file(str(p), mimetype='image/jpeg')


@app.route('/thumbnail/<path:ref>')
def serve_thumbnail(ref: str):
    """Serve a resized thumbnail (JPEG). Accepts filename or absolute path."""
    settings = load_settings()
    p = resolve_ref_to_path(ref, settings)
    if not p.exists() or not p.is_file():
        return "Image not found", 404

    try:
        from io import BytesIO
        img = Image.open(p)
        img.thumbnail((300, 300))
        bio = BytesIO()
        img.save(bio, 'JPEG', quality=85)
        bio.seek(0)
        return send_file(bio, mimetype='image/jpeg')
    except Exception as e:
        return str(e), 500


@app.route('/api/suggestion/<path:ref>')
def api_suggestion(ref: str):
    """Return JSON suggestion for a single file."""
    settings = load_settings()
    p = resolve_ref_to_path(ref, settings)
    if not p.exists():
        return jsonify({"error": "file not found"}), 404
    return jsonify({
        "suggested_filename": suggest_commons_filename(p, Path(settings['watch_folder']).resolve()),
        "category_slug": slug_from_category_folder(p.parent.name)
    })


@app.route('/api/upload', methods=['POST'])
def api_upload():
    """
    Upload endpoint.
    Expects JSON body:
      {
        "filename": "local filename under watch folder OR absolute path",
        "target": "TargetOnCommons.jpg",
        "category_slug": "Binnenhofrenovatie"   // optional; inferred from folder if missing
      }
    """
    settings = load_settings()
    data = request.get_json(force=True, silent=True) or {}
    local_name = data.get("filename", "")
    target = data.get("target", "")
    category_slug = data.get("category_slug", "")

    # NEW: de-HTML-escape any windows backslashes etc.
    local_name = unescape(local_name)

    if not local_name or not target:
        return jsonify({"ok": False, "error": "Missing 'filename' or 'target'"}), 400

    p = resolve_ref_to_path(local_name, settings)
    if not p.exists():
        return jsonify({"ok": False, "error": "Local file not found"}), 404

    if not category_slug:
        category_slug = slug_from_category_folder(p.parent.name)

    # Load creds fresh each request
    username, password, user_agent = get_commons_creds()

    try:
        result = upload_to_commons(p, target, category_slug, settings, username, password, user_agent)
        if result.get("ok"):
            tracker = FileTracker(Path(settings['processed_files_db']))
            tracker.update_commons_check(str(p), {
                "status": "UPLOADED",
                "details": "Uploaded via app UI",
                "checked_at": datetime.now().isoformat(),
                "matches": [{"title": result.get("title", ""), "url": result.get("url", "")}]
            })
            return jsonify({"ok": True, "title": result.get("title"), "url": result.get("url")}), 200
        else:
            return jsonify({"ok": False, "error": result.get("details")}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 500


@app.route('/settings', methods=['GET', 'POST'])
def settings_view():
    """View/update settings.json; includes duplicate check and author/source defaults."""
    if request.method == 'POST':
        s = load_settings()
        s['watch_folder'] = request.form.get('watch_folder', s.get('watch_folder', 'watch'))
        s['processed_files_db'] = request.form.get('processed_files_db', s.get('processed_files_db', 'data/processed_files.json'))
        # Duplicate checker options
        s['enable_duplicate_check'] = request.form.get('enable_duplicate_check') == 'on'
        s['check_scaled_variants'] = request.form.get('check_scaled_variants') == 'on'
        try:
            s['fuzzy_threshold'] = int(request.form.get('fuzzy_threshold', s.get('fuzzy_threshold', 10)))
        except Exception:
            s['fuzzy_threshold'] = 10
        # Metadata defaults
        s['author'] = request.form.get('author', s.get('author', ''))
        s['copyright'] = request.form.get('copyright', s.get('copyright', ''))
        s['source'] = request.form.get('source', s.get('source', ''))
        s['own_work'] = request.form.get('own_work') == 'on'
        cats = request.form.get('default_categories', '')
        s['default_categories'] = [c.strip() for c in cats.split(',') if c.strip()]

        save_settings(s)
        flash('Settings saved.', 'success')
        return redirect(url_for('settings_view'))

    return render_template('settings.html', settings=load_settings(), upload_enabled=bool(get_commons_creds()[0] and get_commons_creds()[1]))


# ========================
# Minimal EXIF helper (safe)
# ========================

def extract_exif_safe(file_path: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        img = Image.open(file_path)
        out['Image Size'] = f"{img.width} x {img.height}"
        out['Format'] = img.format
        out['Mode'] = img.mode
        exif = img.getexif()
        if exif:
            from PIL.ExifTags import TAGS
            for tag_id, value in exif.items():
                tag = TAGS.get(tag_id, str(tag_id))
                if isinstance(value, bytes):
                    if len(value) > 100:
                        continue
                    try:
                        value = value.decode('utf-8', errors='ignore').strip()
                    except Exception:
                        continue
                out[str(tag)] = value
    except Exception as e:
        out['error'] = str(e)
    return out


# ========================
# Main
# ========================

def start_monitoring_thread():
    t = threading.Thread(target=start_monitoring, daemon=True)
    t.start()

if __name__ == '__main__':
    # Start file monitoring + background checker
    start_monitoring_thread()
    # Start Flask app (stat reloader avoids watchdog reloader issues on Windows)
    app.run(debug=True, host='0.0.0.0', port=5001, use_reloader=True, reloader_type="stat")
