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
    if db_path.exists():
        with open(db_path, 'r') as f:
            return json.load(f)
    return []


def get_file_info(file_path):
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

    files_info = []
    for file_path in processed_files:
        info = get_file_info(file_path)
        if info:
            files_info.append(info)

    # Sort by creation date (newest first)
    files_info.sort(key=lambda x: x['created'], reverse=True)

    return render_template('index.html',
                         files=files_info,
                         total_files=len(files_info),
                         settings=settings)


@app.route('/file/<path:filepath>')
def file_detail(filepath):
    """Detail page for a specific file"""
    # Add leading slash if missing (happens with absolute paths in URLs)
    if not filepath.startswith('/'):
        filepath = '/' + filepath

    file_info = get_file_info(filepath)
    if not file_info:
        return "File not found", 404

    exif_data = get_exif_data(filepath)
    settings = load_settings()

    return render_template('file_detail.html',
                         file=file_info,
                         exif=exif_data,
                         settings=settings)


@app.route('/api/files')
def api_files():
    """API endpoint for file list"""
    processed_files = load_processed_files()
    files_info = []

    for file_path in processed_files:
        info = get_file_info(file_path)
        if info:
            files_info.append(info)

    return jsonify(files_info)


@app.route('/api/file/<path:filepath>')
def api_file_detail(filepath):
    """API endpoint for file details"""
    # Add leading slash if missing (happens with absolute paths in URLs)
    if not filepath.startswith('/'):
        filepath = '/' + filepath

    file_info = get_file_info(filepath)
    if not file_info:
        return jsonify({'error': 'File not found'}), 404

    exif_data = get_exif_data(filepath)

    return jsonify({
        'file': file_info,
        'exif': exif_data
    })


@app.route('/image/<path:filepath>')
def serve_image(filepath):
    """Serve image file"""
    # Add leading slash if missing
    if not filepath.startswith('/'):
        filepath = '/' + filepath

    path = Path(filepath)
    if not path.exists() or not path.is_file():
        return "Image not found", 404

    return send_file(filepath, mimetype='image/jpeg')


@app.route('/thumbnail/<path:filepath>')
def serve_thumbnail(filepath):
    """Serve thumbnail version of image"""
    # Add leading slash if missing
    if not filepath.startswith('/'):
        filepath = '/' + filepath

    path = Path(filepath)
    if not path.exists() or not path.is_file():
        return "Image not found", 404

    # Create thumbnail
    try:
        img = Image.open(path)
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
