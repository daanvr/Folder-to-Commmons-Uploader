#!/usr/bin/env python3
"""
Flask Web UI for MacOS-to-Commons-Uploader
Displays detected files, their status, and metadata
"""

import json
import os
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, jsonify
from PIL import Image
from PIL.ExifTags import TAGS

app = Flask(__name__)


def load_settings():
    """Load settings from JSON file"""
    with open('settings.json', 'r') as f:
        return json.load(f)


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
    file_info = get_file_info(filepath)
    if not file_info:
        return jsonify({'error': 'File not found'}), 404

    exif_data = get_exif_data(filepath)

    return jsonify({
        'file': file_info,
        'exif': exif_data
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
