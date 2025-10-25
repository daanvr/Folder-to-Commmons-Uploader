#!/usr/bin/env python3
"""
Flask Web UI for MacOS-to-Commons-Uploader
Displays detected files, their status, and metadata
"""

import json
import os
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, send_file
from PIL import Image
from PIL.ExifTags import TAGS

app = Flask(__name__)
app.secret_key = 'dev-secret-key-change-in-production'


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
    """Extract EXIF data from image"""
    try:
        image = Image.open(file_path)
        exif_data = {}

        # Get basic image info
        exif_data['Image Size'] = f"{image.width} x {image.height}"
        exif_data['Image Format'] = image.format
        exif_data['Image Mode'] = image.mode

        # Get EXIF tags
        exifdata = image.getexif()
        if exifdata:
            for tag_id, value in exifdata.items():
                tag = TAGS.get(tag_id, tag_id)
                # Convert bytes to string for display
                if isinstance(value, bytes):
                    try:
                        value = value.decode()
                    except:
                        value = str(value)
                exif_data[tag] = value

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
    app.run(debug=True, host='0.0.0.0', port=5001)
