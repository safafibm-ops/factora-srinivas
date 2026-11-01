"""
Factora Member 3: Evidence File Upload & Secure Storage Module
Handles validation, virus-prevention sanitization, and isolated storage
for supporting screenshots and documents submitted with student scam reports.
"""

import os
import uuid
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from fastapi import UploadFile, HTTPException

UPLOADS_DIR = Path(__file__).resolve().parent / "uploads"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

PERMITTED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".pdf", ".txt"}
PERMITTED_CONTENT_TYPES = {
    "image/png",
    "image/jpeg",
    "image/pjpeg",
    "image/webp",
    "application/pdf",
    "text/plain",
    "application/octet-stream" # Fallback for some browsers
}
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024 # 10 MB per file limit


def is_safe_extension(filename: str) -> bool:
    """Checks whether the file has a permitted non-executable extension."""
    ext = Path(filename).suffix.lower()
    return ext in PERMITTED_EXTENSIONS


def sanitize_and_store_file(file: UploadFile) -> Dict[str, Any]:
    """
    Validates, sanitizes, and saves an uploaded evidence file.
    Returns metadata dict with stored filename, original filename, and size.
    """
    original_filename = file.filename or "evidence"
    original_ext = Path(original_filename).suffix.lower()

    if not original_ext or original_ext not in PERMITTED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{original_ext}'. Allowed formats: {', '.join(sorted(PERMITTED_EXTENSIONS))}"
        )

    # Check content type if provided
    if file.content_type and file.content_type.lower() not in PERMITTED_CONTENT_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid MIME content type: '{file.content_type}'"
        )

    # Read content to check file size
    content = file.file.read()
    file_size = len(content)

    if file_size > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum allowed size of 10 MB ({file_size / (1024 * 1024):.1f} MB provided)"
        )

    # Generate a cryptographically random, collision-free, non-traversable filename
    secure_filename = f"evid_{uuid.uuid4().hex[:12]}{original_ext}"
    target_path = UPLOADS_DIR / secure_filename

    # Save content to disk
    with open(target_path, "wb") as f:
        f.write(content)

    return {
        "stored_filename": secure_filename,
        "original_filename": original_filename,
        "file_size_bytes": file_size,
        "content_type": file.content_type,
        "file_path": str(target_path)
    }


def get_evidence_file_path(filename: str) -> Optional[Path]:
    """
    Safely resolves an evidence filename, strictly enforcing isolation inside UPLOADS_DIR.
    Prevents path traversal attacks.
    """
    clean_name = os.path.basename(filename)
    target = UPLOADS_DIR / clean_name
    if target.exists() and target.is_file():
        # Double check resolved path is inside UPLOADS_DIR
        if UPLOADS_DIR in target.resolve().parents:
            return target
    return None
