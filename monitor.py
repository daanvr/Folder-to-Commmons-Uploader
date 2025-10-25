#!/usr/bin/env python3
"""
MacOS-to-Commons-Uploader - Folder Monitor
Monitors a folder for new files and tracks them for upload to Wikimedia Commons
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
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

            # Check if it starts with 'category_'
            if parent_dir.startswith('category_'):
                # Extract category name (everything after 'category_')
                category_name = parent_dir[9:]  # len('category_') = 9
                return category_name if category_name else None
    except (ValueError, IndexError):
        pass

    return None


# Import Commons duplicate checker
try:
    from lib.commons_duplicate_checker import check_file_on_commons, build_session
except ImportError:
    print("Warning: Could not import commons_duplicate_checker. Duplicate checking disabled.")
    check_file_on_commons = None
    build_session = None


class FileTracker:
    """Tracks processed files to avoid duplicate processing"""

    def __init__(self, db_path):
        self.db_path = Path(db_path)
        self.processed_files = self._load()

    def _load(self):
        """Load processed files database"""
        if self.db_path.exists():
            with open(self.db_path, 'r') as f:
                data = json.load(f)
                # Handle old format (list of strings) or new format (dict)
                if isinstance(data, list):
                    # Convert old format to new format
                    return {str(path): self._create_file_record(path) for path in data}
                return data
        return {}

    def _create_file_record(self, file_path, **kwargs):
        """Create a new file record with metadata"""
        record = {
            "file_path": str(file_path),
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "sha1_local": kwargs.get("sha1_local", ""),
            "commons_check_status": kwargs.get("commons_check_status", "PENDING"),
            "commons_matches": kwargs.get("commons_matches", []),
            "checked_at": kwargs.get("checked_at", ""),
            "check_details": kwargs.get("check_details", ""),
            "category": kwargs.get("category", None),
        }
        return record

    def _save(self):
        """Save processed files database"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.db_path, 'w') as f:
            json.dump(self.processed_files, f, indent=2)

    def is_processed(self, file_path):
        """Check if file has been processed"""
        return str(file_path) in self.processed_files

    def mark_processed(self, file_path, **kwargs):
        """Mark file as processed with optional metadata"""
        file_key = str(file_path)
        if file_key in self.processed_files:
            # Update existing record
            self.processed_files[file_key].update(kwargs)
        else:
            # Create new record
            self.processed_files[file_key] = self._create_file_record(file_path, **kwargs)
        self._save()

    def update_commons_check(self, file_path, check_result):
        """Update Commons check results for a file"""
        file_key = str(file_path)
        if file_key in self.processed_files:
            self.processed_files[file_key].update({
                "sha1_local": check_result.get("sha1_local", ""),
                "commons_check_status": check_result.get("status", "ERROR"),
                "commons_matches": check_result.get("matches", []),
                "checked_at": check_result.get("checked_at", ""),
                "check_details": check_result.get("details", ""),
            })
            self._save()

    def get_file_record(self, file_path):
        """Get full record for a file"""
        return self.processed_files.get(str(file_path))

    def get_all_files(self):
        """Get all tracked files"""
        return list(self.processed_files.values())


class NewFileHandler(FileSystemEventHandler):
    """Handles file system events"""

    def __init__(self, tracker, watch_folder, settings, commons_session=None):
        self.tracker = tracker
        self.watch_folder = Path(watch_folder)
        self.settings = settings
        self.commons_session = commons_session

    def on_created(self, event):
        """Called when a file is created"""
        if event.is_directory:
            return

        file_path = Path(event.src_path)

        # Only process JPEG files for now
        if file_path.suffix.lower() not in ['.jpg', '.jpeg']:
            return

        # Check if already processed
        if self.tracker.is_processed(file_path):
            return

        print(f"[NEW FILE DETECTED] {file_path.name}")
        print(f"  - Full path: {file_path}")
        print(f"  - Size: {file_path.stat().st_size} bytes")
        print(f"  - Created: {time.ctime(file_path.stat().st_ctime)}")

        # Extract category from directory path if present
        category = extract_category_from_path(file_path, self.watch_folder)
        if category:
            print(f"  - Category: {category}")

        # Mark as detected (not yet uploaded, but tracked)
        self.tracker.mark_processed(file_path, category=category)

        # Check for duplicates on Commons if enabled
        if self.settings.get('enable_duplicate_check', False) and check_file_on_commons:
            print(f"  - Checking for duplicates on Wikimedia Commons...")
            try:
                check_result = check_file_on_commons(
                    file_path,
                    session=self.commons_session,
                    check_scaled=self.settings.get('check_scaled_variants', False),
                    fuzzy_threshold=self.settings.get('fuzzy_threshold', 10)
                )

                # Update tracker with results
                self.tracker.update_commons_check(file_path, check_result)

                # Display results
                status = check_result.get('status', 'ERROR')
                if status == 'EXACT_MATCH':
                    matches = check_result.get('matches', [])
                    print(f"  - ⚠️  DUPLICATE FOUND: File already exists on Commons!")
                    for match in matches[:3]:  # Show first 3 matches
                        print(f"    • {match.get('url', 'N/A')}")
                    if len(matches) > 3:
                        print(f"    • ... and {len(matches) - 3} more")
                elif status == 'POSSIBLE_SCALED_VARIANT':
                    matches = check_result.get('matches', [])
                    print(f"  - ⚠️  Possible scaled variant found on Commons")
                    if matches:
                        print(f"    • {matches[0].get('url', 'N/A')}")
                elif status == 'EXISTS_DIFFERENT_CONTENT':
                    print(f"  - ⚠️  File with same name but different content exists on Commons")
                elif status == 'NOT_ON_COMMONS':
                    print(f"  - ✓ File not found on Commons - safe to upload")
                else:
                    print(f"  - Status: {status}")
                    if check_result.get('error'):
                        print(f"    Error: {check_result.get('error')}")

                print(f"  - SHA-1: {check_result.get('sha1_local', 'N/A')}")
            except Exception as e:
                print(f"  - Error checking Commons: {e}")

        print(f"  - Status: Tracked for upload\n")


def load_settings(settings_file='settings.json'):
    """Load settings from JSON file"""
    settings_path = Path(settings_file)
    if not settings_path.exists():
        print(f"Error: Settings file not found: {settings_path}")
        sys.exit(1)

    with open(settings_path, 'r') as f:
        return json.load(f)


def scan_existing_files(watch_folder, tracker):
    """Scan and track existing files in the watch folder"""
    watch_path = Path(watch_folder)
    if not watch_path.exists():
        watch_path.mkdir(parents=True, exist_ok=True)
        print(f"Created watch folder: {watch_path}")
        return

    print(f"Scanning existing files in: {watch_path}")
    existing_count = 0

    # Scan files in root and subdirectories (recursive)
    for file_path in watch_path.rglob('*'):
        if file_path.is_file() and file_path.suffix.lower() in ['.jpg', '.jpeg']:
            if not tracker.is_processed(file_path):
                # Extract category from directory path if present
                category = extract_category_from_path(file_path, watch_folder)
                tracker.mark_processed(file_path, category=category)
                existing_count += 1

    if existing_count > 0:
        print(f"Marked {existing_count} existing file(s) as already present\n")


def main():
    """Main entry point"""
    print("=" * 60)
    print("MacOS-to-Commons-Uploader - Folder Monitor")
    print("=" * 60)
    print()

    # Load settings
    settings = load_settings()
    watch_folder = Path(settings['watch_folder']).resolve()
    db_path = Path(settings['processed_files_db']).resolve()

    print(f"Watch folder: {watch_folder}")
    print(f"Tracking database: {db_path}")

    # Show duplicate check status
    if settings.get('enable_duplicate_check', False):
        print(f"Duplicate checking: ENABLED")
        if settings.get('check_scaled_variants', False):
            print(f"  - Scaled variant detection: ENABLED (threshold={settings.get('fuzzy_threshold', 10)})")
        else:
            print(f"  - Scaled variant detection: DISABLED")
    else:
        print(f"Duplicate checking: DISABLED")
    print()

    # Initialize file tracker
    tracker = FileTracker(db_path)

    # Build Commons API session if duplicate checking is enabled
    commons_session = None
    if settings.get('enable_duplicate_check', False) and build_session:
        print("Initializing Commons API session...")
        commons_session = build_session()

    # Scan existing files
    scan_existing_files(watch_folder, tracker)

    # Set up file system observer
    event_handler = NewFileHandler(tracker, watch_folder, settings, commons_session)
    observer = Observer()
    observer.schedule(event_handler, str(watch_folder), recursive=True)
    observer.start()

    print("Monitoring started. Press Ctrl+C to stop.")
    print(f"Watching for new JPEG files in: {watch_folder}\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        observer.stop()
        observer.join()
        print("Monitor stopped.")


if __name__ == '__main__':
    main()
