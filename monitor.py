#!/usr/bin/env python3
"""
MacOS-to-Commons-Uploader - Folder Monitor
Monitors a folder for new files and tracks them for upload to Wikimedia Commons
"""

import json
import os
import sys
import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class FileTracker:
    """Tracks processed files to avoid duplicate processing"""

    def __init__(self, db_path):
        self.db_path = Path(db_path)
        self.processed_files = self._load()

    def _load(self):
        """Load processed files database"""
        if self.db_path.exists():
            with open(self.db_path, 'r') as f:
                return set(json.load(f))
        return set()

    def _save(self):
        """Save processed files database"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.db_path, 'w') as f:
            json.dump(list(self.processed_files), f, indent=2)

    def is_processed(self, file_path):
        """Check if file has been processed"""
        return str(file_path) in self.processed_files

    def mark_processed(self, file_path):
        """Mark file as processed"""
        self.processed_files.add(str(file_path))
        self._save()


class NewFileHandler(FileSystemEventHandler):
    """Handles file system events"""

    def __init__(self, tracker, watch_folder):
        self.tracker = tracker
        self.watch_folder = Path(watch_folder)

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

        # Mark as detected (not yet uploaded, but tracked)
        self.tracker.mark_processed(file_path)
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

    for file_path in watch_path.glob('*'):
        if file_path.is_file() and file_path.suffix.lower() in ['.jpg', '.jpeg']:
            if not tracker.is_processed(file_path):
                tracker.mark_processed(file_path)
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
    print()

    # Initialize file tracker
    tracker = FileTracker(db_path)

    # Scan existing files
    scan_existing_files(watch_folder, tracker)

    # Set up file system observer
    event_handler = NewFileHandler(tracker, watch_folder)
    observer = Observer()
    observer.schedule(event_handler, str(watch_folder), recursive=False)
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
