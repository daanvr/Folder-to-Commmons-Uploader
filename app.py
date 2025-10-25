#!/usr/bin/env python3
"""
Flask Web UI for MacOS-to-Commons-Uploader
Displays detected files, their status, and metadata.
Also runs a background "Commons duplicate check" worker so items never get stuck
in "Pending Check"—even for files that already existed when the app starts.

Notes
-----
- On Windows we use watchdog's PollingObserver to avoid backend issues.
- The duplicate checker is provided by: lib/commons_duplicate_checker.py
  and should expose:
    - build_session() -> requests.Session
    - check_file_on_commons(path: Path, session, check_scaled: bool, fuzzy_threshold: int) -> dict
      (returns a dict with keys like: status, sha1_local, matches, details, checked_at)
"""

import json
import os
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any

from flask import (
    Flask, render_template, jsonify, request, redirect, url_for, flash, send_file
)
from PIL import Image

# ---- watchdog: use polling on Windows to be robust ----
if os.name == "nt":
    from watchdog.observers.polling import PollingObserver as Observer
else:
    from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


def extract_category_from_path(file_path, watch_folder):
    """
    Extract category from directory name if file is in a subdirectory starting with 'category_'.

    Args:
        file_path: Path to the file
        watch_folder: Path to the watch folder

    Returns:
        Category name if found, None otherwise
    """
    file_path = Path(file_path)
    watch_folder = Path(watch_folder)

    try:
        # Get relative path from watch folder
        relative_path = file_path.relative_to(watch_folder)

        # Check if file is in a subdirectory
        if len(relative_path.parts) > 1:
            # Get the immediate parent directory name
            parent_dir = relative_path.parts[0]

            # Check if it starts with 'category_' (case-insensitive)
            if parent_dir.lower().startswith('category_'):
                # Extract category name (everything after 'category_')
                category_name = parent_dir[9:]  # len('category_') = 9
                return category_name if category_name else None
    except (ValueError, IndexError):
        pass

    return None


# ---- Import Commons duplicate checker (optional) ----
try:
    from lib.commons_duplicate_checker import check_file_on_commons, build_session
except Exception as e:
    print("Warning: Could not import lib.commons_duplicate_checker. Duplicate checking disabled.")
    print(f"  Import error: {e}")
    check_file_on_commons = None  # type: ignore
    build_session = None          # type: ignore

app = Flask(__name__)
app.secret_key = 'dev-secret-key-change-in-production'


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
        """Load the DB; accepts old format (list of paths) or new (dict by path)."""
        if self.db_path.exists():
            with self.db_path.open('r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, list):
                # migrate old -> new
                return {str(p): self._create_file_record(p) for p in data}
            if isinstance(data, dict):
                return data
        return {}

    def _save(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.db_path.open('w', encoding='utf-8') as f:
            json.dump(self.processed_files, f, indent=2)

    def _create_file_record(self, file_path: str, **kwargs) -> Dict[str, Any]:
        """Create a canonical record structure for a file."""
        return {
            "file_path": str(file_path),
            "detected_at": kwargs.get("detected_at", datetime.now().isoformat()),
            "sha1_local": kwargs.get("sha1_local", ""),
            "commons_check_status": kwargs.get("commons_check_status", "PENDING"),
            "commons_matches": kwargs.get("commons_matches", []),
            "checked_at": kwargs.get("checked_at", ""),
            "check_details": kwargs.get("check_details", ""),
            "category": kwargs.get("category", None),
        }

    def is_processed(self, file_path: Path) -> bool:
        with self._lock:
            return str(file_path) in self.processed_files

    def mark_processed(self, file_path: Path, **kwargs) -> None:
        """Create or update a record; defaults status to PENDING for checker loop."""
        file_key = str(file_path)
        with self._lock:
            if file_key in self.processed_files:
                self.processed_files[file_key].update(kwargs)
            else:
                self.processed_files[file_key] = self._create_file_record(file_key, **kwargs)
            self._save()

    def update_commons_check(self, file_path: str | Path, check_result: Dict[str, Any]) -> None:
        """Merge checker results into the record."""
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
        try:
            size = file_path.stat().st_size
            ctime = time.ctime(file_path.stat().st_ctime)
            print(f"  • Full path: {file_path}")
            print(f"  • Size: {size} bytes")
            print(f"  • Created: {ctime}")
        except Exception:
            pass

        # Extract category from directory path if present
        category = extract_category_from_path(file_path, self.watch_folder)
        if category:
            print(f"  • Category: {category}")

        # Mark as tracked (pending commons check) with category
        self.tracker.mark_processed(file_path, commons_check_status="PENDING", category=category)
        print("  • Status: Tracked; Commons check scheduled.\n")


# ========================
# Boot helpers
# ========================

def scan_existing_files(watch_folder: Path, tracker: FileTracker, settings: Dict[str, Any]) -> None:
    """Ensure existing JPG/JPEG files are tracked (as PENDING), including subdirectories."""
    watch_folder.mkdir(parents=True, exist_ok=True)
    print(f"Scanning existing files in: {watch_folder}")

    existing_count = 0
    # Use rglob to scan recursively through subdirectories
    for p in watch_folder.rglob('*'):
        if p.is_file() and p.suffix.lower() in ('.jpg', '.jpeg'):
            if not tracker.is_processed(p):
                # Extract category from directory path if present
                category = extract_category_from_path(p, watch_folder)
                tracker.mark_processed(p, commons_check_status="PENDING", category=category)
                existing_count += 1
    if existing_count:
        print(f"Marked {existing_count} existing file(s) as pending for Commons check.\n")


def commons_checker_loop(tracker: FileTracker, settings: Dict[str, Any], commons_session) -> None:
    """
    Background loop that resolves any items with status PENDING/IN_PROGRESS.
    """
    enabled = settings.get('enable_duplicate_check', False)
    if not enabled or check_file_on_commons is None:
        # Convert lingering PENDING → DISABLED so UI doesn't look stuck
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
            # mark in-progress to avoid repeated picking in this cycle
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
        time.sleep(2)  # polite periodic scan


def start_monitoring() -> None:
    """Launch file observer and the background Commons checker."""
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

    # Prepare Commons session if checker is enabled
    commons_session = None
    if settings.get('enable_duplicate_check', False) and build_session is not None:
        try:
            commons_session = build_session()
            print("Commons API session: ready.")
        except Exception as e:
            print(f"Commons session init failed: {e}")

    # Track existing files (recursive scan)
    scan_existing_files(watch_folder, tracker, settings)

    # Set up watcher for NEW files (recursive monitoring)
    event_handler = NewFileHandler(tracker, watch_folder, settings, commons_session)
    observer = Observer()
    observer.schedule(event_handler, str(watch_folder), recursive=True)
    try:
        observer.start()
    except Exception as e:
        # As a last resort (very rare), downgrade to polling at runtime
        print(f"Observer start failed ({e}); falling back to PollingObserver.")
        from watchdog.observers.polling import PollingObserver
        observer = PollingObserver()
        observer.schedule(event_handler, str(watch_folder), recursive=True)
        observer.start()

    # Start background checker for PENDING items
    threading.Thread(
        target=commons_checker_loop,
        args=(tracker, settings, commons_session),
        daemon=True
    ).start()

    print("File monitoring started.")
    print(f"Watching for new JPEG files in: {watch_folder}\n")


# ========================
# Settings + helpers
# ========================

def load_settings() -> Dict[str, Any]:
    with open('settings.json', 'r', encoding='utf-8') as f:
        return json.load(f)

def save_settings(settings: Dict[str, Any]) -> None:
    with open('settings.json', 'w', encoding='utf-8') as f:
        json.dump(settings, f, indent=2)

def get_file_info(file_path: str, watch_folder: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Get detailed information about a file."""
    p = Path(file_path)
    if not p.exists():
        return None
    st = p.stat()
    info = {
        'path': str(p),
        'name': p.name,
        'size': st.st_size,
        'size_mb': round(st.st_size / (1024 * 1024), 2),
        'created': datetime.fromtimestamp(st.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
        'modified': datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
        'exists': True,
        'status': 'Detected'
    }

    # Add relative path for URL generation
    if watch_folder:
        try:
            rel_path = p.relative_to(watch_folder)
            info['relative_path'] = str(rel_path)
        except ValueError:
            info['relative_path'] = p.name
    else:
        info['relative_path'] = p.name

    return info


# ========================
# Routes (UI + API)
# ========================

@app.route('/')
def index():
    """Main page showing all tracked files + Commons status."""
    settings = load_settings()
    watch_folder = Path(settings['watch_folder']).resolve()
    tracker = FileTracker(Path(settings['processed_files_db']))
    records = tracker.get_all_files()

    files_info: List[Dict[str, Any]] = []
    for rec in records:
        info = get_file_info(rec.get('file_path', ''), watch_folder)
        if not info:
            continue
        # enrich with Commons checker fields
        info['commons_check_status'] = rec.get('commons_check_status', 'PENDING')
        info['commons_matches'] = rec.get('commons_matches', [])
        info['check_details'] = rec.get('check_details', '')
        info['sha1_local'] = rec.get('sha1_local', '')
        info['category'] = rec.get('category')
        files_info.append(info)

    files_info.sort(key=lambda x: x['created'], reverse=True)
    return render_template('index.html', files=files_info, total_files=len(files_info), settings=settings)


@app.route('/file/<path:filename>')
def file_detail(filename: str):
    """Detail page for a specific file (supports subdirectories)."""
    settings = load_settings()
    watch_folder = Path(settings['watch_folder']).resolve()

    # Support both direct filenames and paths with subdirectories
    file_path = watch_folder / filename

    file_info = get_file_info(str(file_path), watch_folder)
    if not file_info:
        return "File not found", 404

    # Pull checker fields
    tracker = FileTracker(Path(settings['processed_files_db']))
    rec = tracker.get_file_record(str(file_path))
    if rec:
        file_info['commons_check_status'] = rec.get('commons_check_status', 'PENDING')
        file_info['commons_matches'] = rec.get('commons_matches', [])
        file_info['check_details'] = rec.get('check_details', '')
        file_info['sha1_local'] = rec.get('sha1_local', '')
        file_info['category'] = rec.get('category')

    # Minimal EXIF (safe subset)
    exif = extract_exif_safe(str(file_path))
    return render_template('file_detail.html', file=file_info, exif=exif, settings=settings)


@app.route('/api/files')
def api_files():
    """JSON list of tracked files."""
    settings = load_settings()
    watch_folder = Path(settings['watch_folder']).resolve()
    tracker = FileTracker(Path(settings['processed_files_db']))
    out = []
    for rec in tracker.get_all_files():
        info = get_file_info(rec.get('file_path', ''), watch_folder)
        if not info:
            continue
        info['commons_check_status'] = rec.get('commons_check_status', 'PENDING')
        info['commons_matches'] = rec.get('commons_matches', [])
        info['check_details'] = rec.get('check_details', '')
        info['sha1_local'] = rec.get('sha1_local', '')
        info['category'] = rec.get('category')
        out.append(info)
    return jsonify(out)


@app.route('/api/file/<path:filename>')
def api_file_detail(filename: str):
    """JSON details for a single file (supports subdirectories)."""
    settings = load_settings()
    watch_folder = Path(settings['watch_folder']).resolve()
    p = watch_folder / filename

    info = get_file_info(str(p), watch_folder)
    if not info:
        return jsonify({"error": "File not found"}), 404

    # Pull checker fields
    tracker = FileTracker(Path(settings['processed_files_db']))
    rec = tracker.get_file_record(str(p))
    if rec:
        info['commons_check_status'] = rec.get('commons_check_status', 'PENDING')
        info['commons_matches'] = rec.get('commons_matches', [])
        info['check_details'] = rec.get('check_details', '')
        info['sha1_local'] = rec.get('sha1_local', '')
        info['category'] = rec.get('category')

    exif = extract_exif_safe(str(p))
    return jsonify({"file": info, "exif": exif})


@app.route('/image/<path:filename>')
def serve_image(filename: str):
    """Serve image file (supports subdirectories)."""
    settings = load_settings()
    p = Path(settings['watch_folder']).resolve() / filename
    if not p.exists() or not p.is_file():
        return "Image not found", 404
    return send_file(str(p), mimetype='image/jpeg')


@app.route('/thumbnail/<path:filename>')
def serve_thumbnail(filename: str):
    """Serve thumbnail version of image (supports subdirectories)."""
    settings = load_settings()
    p = Path(settings['watch_folder']).resolve() / filename
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


@app.route('/settings', methods=['GET', 'POST'])
def settings_view():
    """View/update settings.json (also supports duplicate-check options)."""
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

        save_settings(s)
        flash('Settings saved.', 'success')
        return redirect(url_for('settings_view'))

    return render_template('settings.html', settings=load_settings())


# ---- Optional endpoints to kick checks from UI/JS ----

@app.route('/api/commons-check/run', methods=['POST'])
def api_run_commons_check():
    """Process current PENDING items once (best-effort)."""
    s = load_settings()
    tracker = FileTracker(Path(s['processed_files_db']))
    if not (s.get('enable_duplicate_check') and check_file_on_commons and build_session):
        # mark pendings as DISABLED so UI isn't stuck
        pending = [r for r in tracker.get_all_files() if r.get('commons_check_status', 'PENDING') == 'PENDING']
        for rec in pending:
            tracker.update_commons_check(rec['file_path'], {
                "status": "DISABLED",
                "details": "Duplicate checking disabled or checker unavailable.",
                "checked_at": datetime.now().isoformat()
            })
        return jsonify({"processed": 0, "note": "disabled"}), 200

    session = build_session()
    processed = 0
    for rec in tracker.get_all_files():
        if rec.get('commons_check_status', 'PENDING') == 'PENDING':
            try:
                res = check_file_on_commons(
                    Path(rec['file_path']),
                    session=session,
                    check_scaled=s.get('check_scaled_variants', False),
                    fuzzy_threshold=s.get('fuzzy_threshold', 10),
                )
                tracker.update_commons_check(rec['file_path'], res)
                processed += 1
            except Exception as e:
                tracker.update_commons_check(rec['file_path'], {
                    "status": "ERROR",
                    "details": f"{type(e).__name__}: {e}",
                    "checked_at": datetime.now().isoformat()
                })
    return jsonify({"processed": processed}), 200


@app.route('/api/commons-check/<path:filename>', methods=['POST'])
def api_check_single(filename: str):
    """Run a Commons check for a single file by filename (supports subdirectories)."""
    s = load_settings()
    p = Path(s['watch_folder']).resolve() / filename
    tracker = FileTracker(Path(s['processed_files_db']))
    if not p.exists():
        return jsonify({"error": "file not found"}), 404

    if not (s.get('enable_duplicate_check') and check_file_on_commons and build_session):
        tracker.update_commons_check(str(p), {
            "status": "DISABLED",
            "details": "Duplicate checking disabled or checker unavailable.",
            "checked_at": datetime.now().isoformat()
        })
        return jsonify({"status": "DISABLED"}), 200

    try:
        session = build_session()
        res = check_file_on_commons(
            p,
            session=session,
            check_scaled=s.get('check_scaled_variants', False),
            fuzzy_threshold=s.get('fuzzy_threshold', 10),
        )
        tracker.update_commons_check(str(p), res)
        return jsonify(res), 200
    except Exception as e:
        tracker.update_commons_check(str(p), {
            "status": "ERROR",
            "details": f"{type(e).__name__}: {e}",
            "checked_at": datetime.now().isoformat()
        })
        return jsonify({"status": "ERROR", "details": str(e)}), 500


# ========================
# Minimal EXIF helper (safe)
# ========================

def extract_exif_safe(file_path: str) -> Dict[str, Any]:
    """Small, safe EXIF extractor for display (avoids huge/binary fields)."""
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

if __name__ == '__main__':
    # Start file monitoring + background checker
    threading.Thread(target=start_monitoring, daemon=True).start()

    # Start Flask app
    # Use reloader_type="stat" to avoid watchdog-based reloader conflicts on Windows
    app.run(debug=True, host='0.0.0.0', port=5001, use_reloader=True, reloader_type="stat")
