#!/usr/bin/env python3
"""
Flask Web UI for MacOS-to-Commons-Uploader
Displays detected files, their status, and metadata
"""

import json
import os
import time
import threading
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, send_file
from PIL import Image
from PIL.ExifTags import TAGS
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


# Import Commons duplicate checker
try:
    from lib.commons_duplicate_checker import check_file_on_commons, build_session
except ImportError:
    print("Warning: Could not import commons_duplicate_checker. Duplicate checking disabled.")
    check_file_on_commons = None
    build_session = None

app = Flask(__name__)
app.secret_key = 'dev-secret-key-change-in-production'


# File monitoring classes
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
            "detected_at": datetime.now().isoformat(),
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


def start_monitoring():
    """Start file monitoring in background thread"""
    settings = load_settings()
    watch_folder = Path(settings['watch_folder']).resolve()
    db_path = Path(settings['processed_files_db']).resolve()

    print("=" * 60)
    print("Starting File Monitor")
    print("=" * 60)
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

    print("File monitoring started")
    print(f"Watching for new JPEG files in: {watch_folder}\n")


def load_settings():
    """Load settings from JSON file"""
    with open('settings.json', 'r') as f:
        return json.load(f)


def save_settings(settings):
    """Save settings to JSON file"""
    with open('settings.json', 'w') as f:
        json.dump(settings, f, indent=2)


def load_processed_files():
    """Load processed files database"""
    settings = load_settings()
    db_path = Path(settings['processed_files_db'])
    tracker = FileTracker(db_path)
    return tracker.get_all_files()


def get_file_info(file_path, watch_folder=None):
    """Get detailed information about a file"""
    path = Path(file_path)
    if not path.exists():
        return None

    stat = path.stat()
    info = {
        'path': str(path),
        'name': path.name,
        'size': stat.st_size,
        'size_mb': round(stat.st_size / (1024 * 1024), 2),
        'created': datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
        'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
        'exists': True,
        'status': 'Detected'  # Will be updated when we add upload functionality
    }

    # Add relative path for URL generation
    if watch_folder:
        try:
            rel_path = path.relative_to(Path(watch_folder))
            info['relative_path'] = str(rel_path)
        except ValueError:
            info['relative_path'] = path.name
    else:
        info['relative_path'] = path.name

    return info


def get_exif_data(file_path):
    """Extract comprehensive EXIF data from image"""
    try:
        from PIL.ExifTags import TAGS, GPSTAGS

        image = Image.open(file_path)
        exif_data = {}

        # Tags to skip (non-useful or binary data)
        SKIP_TAGS = {
            'ExifOffset', 'GPSInfo', 'MakerNote', 'UserComment',
            'ComponentsConfiguration', 'SceneType', 'Padding',
            'OffsetTime', 'OffsetTimeOriginal', 'OffsetTimeDigitized',
            'PrintImageMatching', 'DNGPrivateData', 'ApplicationNotes',
            'ImageUniqueID', 'BodySerialNumber'
        }

        # Tags that contain large binary data to skip by ID
        SKIP_TAG_IDS = {
            59932,  # Padding
            37500,  # MakerNote
        }

        # Get basic image info
        exif_data['Image Size'] = f"{image.width} x {image.height}"
        exif_data['Image Format'] = image.format
        exif_data['Image Mode'] = image.mode
        exif_data['Megapixels'] = round((image.width * image.height) / 1_000_000, 2)

        # Get EXIF tags
        exifdata = image.getexif()
        if exifdata:
            for tag_id, value in exifdata.items():
                tag = TAGS.get(tag_id, tag_id)

                # Skip unwanted tags
                if tag in SKIP_TAGS or tag_id in SKIP_TAG_IDS:
                    continue

                # Skip unknown numeric tags (not in TAGS dictionary)
                if isinstance(tag, int):
                    continue

                # Skip large binary data
                if isinstance(value, bytes) and len(value) > 100:
                    continue

                # Convert bytes to string for display
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8', errors='ignore').strip()
                        if not value or not value.isprintable():
                            continue
                    except:
                        continue

                exif_data[tag] = value

            # Get IFD (Image File Directory) data for more detailed info
            ifd = exifdata.get_ifd(0x8769)  # ExifOffset
            if ifd:
                for tag_id, value in ifd.items():
                    tag = TAGS.get(tag_id, tag_id)

                    # Skip unwanted tags
                    if tag in SKIP_TAGS or tag_id in SKIP_TAG_IDS:
                        continue

                    # Skip unknown numeric tags
                    if isinstance(tag, int):
                        continue

                    # Skip large binary data
                    if isinstance(value, bytes) and len(value) > 100:
                        continue

                    # Handle special value types
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore').strip()
                            if not value or not value.isprintable():
                                continue
                        except:
                            continue
                    elif isinstance(value, tuple) and len(value) == 2:
                        # Rational number (like exposure time)
                        if value[1] != 0:
                            if tag in ['ExposureTime', 'ShutterSpeedValue']:
                                value = f"{value[0]}/{value[1]} sec"
                            elif tag in ['FNumber', 'ApertureValue']:
                                value = f"f/{round(value[0]/value[1], 1)}"
                            elif tag in ['FocalLength']:
                                value = f"{round(value[0]/value[1], 1)} mm"
                            else:
                                value = round(value[0] / value[1], 3)

                    exif_data[tag] = value

            # Get GPS data if available
            gps_ifd = exifdata.get_ifd(0x8825)  # GPSInfo
            if gps_ifd:
                gps_data = {}
                for tag_id, value in gps_ifd.items():
                    tag = GPSTAGS.get(tag_id, tag_id)
                    gps_data[tag] = value

                # Parse GPS coordinates
                if 'GPSLatitude' in gps_data and 'GPSLongitude' in gps_data:
                    lat = gps_data['GPSLatitude']
                    lon = gps_data['GPSLongitude']
                    lat_ref = gps_data.get('GPSLatitudeRef', 'N')
                    lon_ref = gps_data.get('GPSLongitudeRef', 'E')

                    # Convert to decimal degrees
                    def to_decimal(coord):
                        if isinstance(coord, tuple) and len(coord) == 3:
                            d = coord[0] if isinstance(coord[0], (int, float)) else coord[0][0] / coord[0][1]
                            m = coord[1] if isinstance(coord[1], (int, float)) else coord[1][0] / coord[1][1]
                            s = coord[2] if isinstance(coord[2], (int, float)) else coord[2][0] / coord[2][1]
                            return d + (m / 60.0) + (s / 3600.0)
                        return 0

                    lat_decimal = to_decimal(lat)
                    lon_decimal = to_decimal(lon)

                    if lat_ref == 'S':
                        lat_decimal = -lat_decimal
                    if lon_ref == 'W':
                        lon_decimal = -lon_decimal

                    exif_data['GPS Coordinates'] = f"{lat_decimal:.6f}, {lon_decimal:.6f}"
                    exif_data['GPS Latitude'] = f"{lat_decimal:.6f}° {lat_ref}"
                    exif_data['GPS Longitude'] = f"{lon_decimal:.6f}° {lon_ref}"

                # Add altitude if available
                if 'GPSAltitude' in gps_data:
                    alt = gps_data['GPSAltitude']
                    if isinstance(alt, tuple) and len(alt) == 2:
                        alt_m = alt[0] / alt[1]
                        exif_data['GPS Altitude'] = f"{alt_m:.1f} m"

        return exif_data
    except Exception as e:
        return {'error': str(e)}


@app.route('/')
def index():
    """Main page showing all detected files"""
    processed_files = load_processed_files()
    settings = load_settings()
    watch_folder = Path(settings['watch_folder']).resolve()

    files_info = []
    for file_record in processed_files:
        file_path = file_record.get('file_path', '')
        info = get_file_info(file_path, watch_folder)
        if info:
            # Add Commons check information to file info
            info['commons_check_status'] = file_record.get('commons_check_status', 'PENDING')
            info['commons_matches'] = file_record.get('commons_matches', [])
            info['check_details'] = file_record.get('check_details', '')
            info['sha1_local'] = file_record.get('sha1_local', '')
            info['category'] = file_record.get('category')
            files_info.append(info)

    # Sort by creation date (newest first)
    files_info.sort(key=lambda x: x['created'], reverse=True)

    return render_template('index.html',
                         files=files_info,
                         total_files=len(files_info),
                         settings=settings)


@app.route('/file/<path:filename>')
def file_detail(filename):
    """Detail page for a specific file"""
    settings = load_settings()
    watch_folder = Path(settings['watch_folder']).resolve()

    # Support both direct filenames and paths with subdirectories
    file_path = watch_folder / filename

    file_info = get_file_info(str(file_path), watch_folder)
    if not file_info:
        return "File not found", 404

    # Get Commons check information from tracker
    db_path = Path(settings['processed_files_db'])
    tracker = FileTracker(db_path)
    file_record = tracker.get_file_record(str(file_path))

    if file_record:
        file_info['commons_check_status'] = file_record.get('commons_check_status', 'PENDING')
        file_info['commons_matches'] = file_record.get('commons_matches', [])
        file_info['check_details'] = file_record.get('check_details', '')
        file_info['sha1_local'] = file_record.get('sha1_local', '')
        file_info['category'] = file_record.get('category')

    exif_data = get_exif_data(str(file_path))

    return render_template('file_detail.html',
                         file=file_info,
                         exif=exif_data,
                         settings=settings)


@app.route('/api/files')
def api_files():
    """API endpoint for file list"""
    processed_files = load_processed_files()
    settings = load_settings()
    watch_folder = Path(settings['watch_folder']).resolve()
    files_info = []

    for file_record in processed_files:
        file_path = file_record.get('file_path', '')
        info = get_file_info(file_path, watch_folder)
        if info:
            # Add Commons check information to file info
            info['commons_check_status'] = file_record.get('commons_check_status', 'PENDING')
            info['commons_matches'] = file_record.get('commons_matches', [])
            info['check_details'] = file_record.get('check_details', '')
            info['sha1_local'] = file_record.get('sha1_local', '')
            info['category'] = file_record.get('category')
            files_info.append(info)

    return jsonify(files_info)


@app.route('/api/file/<path:filename>')
def api_file_detail(filename):
    """API endpoint for file details"""
    settings = load_settings()
    watch_folder = Path(settings['watch_folder']).resolve()
    file_path = watch_folder / filename

    file_info = get_file_info(str(file_path), watch_folder)
    if not file_info:
        return jsonify({'error': 'File not found'}), 404

    exif_data = get_exif_data(str(file_path))

    return jsonify({
        'file': file_info,
        'exif': exif_data
    })


@app.route('/image/<path:filename>')
def serve_image(filename):
    """Serve image file"""
    settings = load_settings()
    watch_folder = Path(settings['watch_folder']).resolve()
    file_path = watch_folder / filename

    if not file_path.exists() or not file_path.is_file():
        return "Image not found", 404

    return send_file(str(file_path), mimetype='image/jpeg')


@app.route('/thumbnail/<path:filename>')
def serve_thumbnail(filename):
    """Serve thumbnail version of image"""
    settings = load_settings()
    watch_folder = Path(settings['watch_folder']).resolve()
    file_path = watch_folder / filename

    if not file_path.exists() or not file_path.is_file():
        return "Image not found", 404

    # Create thumbnail
    try:
        img = Image.open(file_path)
        img.thumbnail((300, 300))

        # Save to a temporary BytesIO object
        from io import BytesIO
        img_io = BytesIO()
        img.save(img_io, 'JPEG', quality=85)
        img_io.seek(0)

        return send_file(img_io, mimetype='image/jpeg')
    except Exception as e:
        return str(e), 500


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    """Settings page for viewing and editing configuration"""
    if request.method == 'POST':
        # Get form data and update settings
        settings_data = load_settings()

        settings_data['watch_folder'] = request.form.get('watch_folder', '')
        settings_data['author'] = request.form.get('author', '')
        settings_data['copyright'] = request.form.get('copyright', '')
        settings_data['source'] = request.form.get('source', '')
        settings_data['own_work'] = request.form.get('own_work') == 'on'

        # Handle categories (comma-separated)
        categories_str = request.form.get('default_categories', '')
        settings_data['default_categories'] = [c.strip() for c in categories_str.split(',') if c.strip()]

        # Save settings
        save_settings(settings_data)
        flash('Settings saved successfully!', 'success')
        return redirect(url_for('settings'))

    # GET request - display settings
    settings_data = load_settings()
    return render_template('settings.html', settings=settings_data)


if __name__ == '__main__':
    # Start file monitoring in background thread
    monitor_thread = threading.Thread(target=start_monitoring, daemon=True)
    monitor_thread.start()

    # Start Flask app
    app.run(debug=True, host='0.0.0.0', port=5001)
