# MacOS-to-Commons-Uploader

A cross-platform Python tool that monitors a folder for new files and automatically uploads them to Wikimedia Commons with appropriate file titles, license templates, categories and other metadata.

## Features

- Monitors a folder for new JPEG files
- Tracks processed files to avoid duplicates
- Web UI to view detected files and their metadata
- EXIF data extraction and display
- Configurable metadata defaults
- Cross-platform support (macOS and Windows)

## Requirements

- Python 3.7 or higher
- pip (Python package installer)

## Setup

### macOS/Linux

1. Clone or download this repository
2. Navigate to the project directory
3. Run the setup script:
   ```bash
   ./setup.sh
   ```
4. Activate the virtual environment:
   ```bash
   source venv/bin/activate
   ```

### Windows

1. Clone or download this repository
2. Navigate to the project directory
3. Run the setup script:
   ```cmd
   setup.bat
   ```
4. Activate the virtual environment:
   ```cmd
   venv\Scripts\activate.bat
   ```

## Configuration

Edit `settings.json` to configure:
- `watch_folder`: Path to the folder to monitor (default: `./watch`)
- `own_work`: Whether uploads are your own work
- `copyright`: Default license (e.g., CC-BY-SA-4.0)
- `author`: Your name
- `default_categories`: Default categories for uploads
- `source`: Source of the files

## Running

### Option 1: Web UI (Recommended)

View detected files with full metadata and EXIF data in a web browser.

**macOS/Linux:**
```bash
source venv/bin/activate && python app.py
```

**Windows:**
```cmd
venv\Scripts\activate.bat && python app.py
```

Then open your browser to: `http://localhost:5001`

The web interface shows:
- List of all detected files
- File status and metadata
- Complete EXIF data for each image
- Configuration settings

### Option 2: Command Line Monitor

**macOS/Linux:**
```bash
source venv/bin/activate && python monitor.py
```

**Windows:**
```cmd
venv\Scripts\activate.bat && python monitor.py
```

This will monitor the configured folder and log when new JPEG files are detected. Press `Ctrl+C` to stop monitoring.

## Usage

1. Start the monitor with `python monitor.py`
2. Add JPEG files to the watched folder (default: `./watch`)
3. The monitor will detect and log new files
4. Currently tracks files for future upload functionality

## Project Structure

```
.
├── app.py                 # Flask web UI application
├── monitor.py             # Command-line monitoring script
├── settings.json          # Configuration file
├── requirements.txt       # Python dependencies
├── setup.sh              # Setup script for macOS/Linux
├── setup.bat             # Setup script for Windows
├── templates/            # HTML templates for web UI
│   ├── index.html        # File list view
│   └── file_detail.html  # File detail view
├── watch/                # Watched folder (configurable)
└── data/                 # Tracking database
    └── processed_files.json
```
