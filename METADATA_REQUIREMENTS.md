# Metadata Requirements for Wikimedia Commons Photo Uploads

## Overview
This document outlines the metadata requirements for uploading photos to Wikimedia Commons through the macOS uploader tool. Understanding these requirements is crucial for ensuring successful uploads and proper content organization on Commons.

## Essential Metadata (Required)

### 1. Licensing Information
**Status:** REQUIRED
**Description:** Every file must have a valid license compatible with Commons.
**Implementation:** User must select from predefined license options or provide custom license text.

**Common license options:**
- CC BY 4.0 (Creative Commons Attribution 4.0)
- CC BY-SA 4.0 (Creative Commons Attribution-ShareAlike 4.0)
- CC0 (Public Domain Dedication)
- Public Domain (for works in public domain)
- Own work (for creator's original content)

### 2. Source Information
**Status:** REQUIRED
**Description:** Clear indication of where the image originated.
**Implementation:** Text field with validation.

**Examples:**
- "Own work" (for original photography)
- "Derived from [filename]" (for edited versions)
- URL or citation for external sources (with proper permissions)

### 3. Author/Creator Information
**Status:** REQUIRED
**Description:** Person or entity who created the work.
**Implementation:** Text field, can be pre-filled with user's Commons username.

**Format:** Commons username, real name, or "Unknown" if genuinely unknown

### 4. Description
**Status:** REQUIRED
**Description:** Clear, descriptive text explaining what the image shows.
**Implementation:** Multi-line text field with character limit guidance.

**Best practices:**
- Use clear, objective language
- Include relevant context
- Mention notable features or subjects
- Support multiple languages when possible

## Important Metadata (Highly Recommended)

### 5. Categories
**Status:** HIGHLY RECOMMENDED
**Description:** Hierarchical classification system for organizing content.
**Implementation:** Category picker with search functionality and suggestions.

**Examples:**
- Geographic categories: "Images of Paris", "France"
- Subject categories: "Flowers", "Architecture", "Portraits"
- Technical categories: "Taken with Canon EOS", "Black and white photographs"

### 6. Date Information
**Status:** RECOMMENDED
**Description:** When the photograph was taken.
**Implementation:** Date picker, can extract from EXIF data automatically.

**Formats:**
- Specific date: "2024-01-15"
- Approximate: "circa 2024"
- Date ranges: "between 2023 and 2024"

### 7. Location Information
**Status:** RECOMMENDED
**Description:** Where the photograph was taken.
**Implementation:** GPS coordinates from EXIF, manual entry, or map picker.

**Components:**
- GPS coordinates (latitude/longitude)
- Location name (city, landmark, address)
- Geographic hierarchy (country, state/province, city)

## Technical Metadata

### 8. EXIF Data
**Status:** AUTOMATIC EXTRACTION
**Description:** Technical camera and shooting information.
**Implementation:** Automatically extracted from image files.

**Key EXIF fields:**
- Camera make and model
- Lens information
- Shooting settings (ISO, aperture, shutter speed)
- GPS coordinates
- Timestamp
- Camera orientation

### 9. File Information
**Status:** AUTOMATIC
**Description:** Technical file characteristics.
**Implementation:** Automatically determined during upload.

**Components:**
- File format (JPEG, PNG, TIFF, etc.)
- File size
- Image dimensions (width × height)
- Color space (sRGB, Adobe RGB, etc.)
- Compression quality

## Legal and Rights Metadata

### 10. Copyright Status
**Status:** REQUIRED
**Description:** Legal status of the image rights.
**Implementation:** Checkbox confirmations and legal text display.

**Requirements:**
- Confirmation of copyright ownership or permissions
- Declaration of license terms
- Acknowledgment of Commons terms of use

### 11. Model/Property Releases
**Status:** CONDITIONAL
**Description:** Required for identifiable people or copyrighted property.
**Implementation:** Checkbox with file upload for release documents.

**When required:**
- Recognizable people in photos
- Copyrighted buildings or artwork
- Trademarked logos or products

## Additional Descriptive Metadata

### 12. Keywords/Tags
**Status:** OPTIONAL
**Description:** Additional searchable terms.
**Implementation:** Tag input field with suggestions.

**Examples:**
- Subject matter: "sunset", "portrait", "architecture"
- Techniques: "HDR", "black and white", "macro"
- Events: "wedding", "concert", "festival"

### 13. Related Files
**Status:** OPTIONAL
**Description:** Connection to other related media.
**Implementation:** File picker or URL input.

**Types:**
- Other views of same subject
- Before/after images
- Different resolutions of same image

### 14. WikiData Integration
**Status:** OPTIONAL
**Description:** Structured data connections.
**Implementation:** WikiData item search and selection.

**Uses:**
- Link to people, places, or objects depicted
- Connect to events or concepts
- Provide multilingual labels

## Implementation Considerations for macOS App

### Automatic Metadata Extraction
- **EXIF Data:** Use Core Image or ImageIO frameworks
- **GPS Coordinates:** Extract from EXIF when available
- **File Properties:** Use NSFileManager for technical details
- **Timestamp:** Prefer EXIF date over file creation date

### User Interface Design
- **Progressive Disclosure:** Show required fields first, expand for optional
- **Smart Defaults:** Pre-fill fields when possible (username, extracted EXIF)
- **Validation:** Real-time validation with helpful error messages
- **Templates:** Save common metadata combinations for reuse

### Data Validation
- **License Compatibility:** Validate license selection against Commons requirements
- **File Format:** Ensure supported formats (JPEG, PNG, TIFF, SVG, etc.)
- **Size Limits:** Check file size constraints (100MB standard limit)
- **Content Policy:** Basic checks for potential policy violations

### Batch Upload Support
- **Common Metadata:** Apply shared metadata to multiple files
- **Individual Overrides:** Allow per-file customization
- **Progress Tracking:** Show upload status for each file
- **Error Handling:** Clear error reporting with correction suggestions

## Validation Checklist

Before upload, verify:
- [ ] Valid license selected
- [ ] Source information provided
- [ ] Author/creator specified
- [ ] Description written
- [ ] Categories assigned (recommended)
- [ ] Legal requirements met (releases if needed)
- [ ] Technical requirements satisfied (format, size)
- [ ] Content policy compliance confirmed

## Resources and References

### Commons Documentation
- Upload requirements and policies
- License compatibility guidelines
- Category structure and naming conventions
- Content policies and restrictions

### Technical Standards
- Supported file formats and specifications
- Maximum file size limits
- Image quality recommendations
- Metadata format standards

### Legal Considerations
- Copyright law basics
- Fair use limitations
- Model and property release requirements
- International copyright variations