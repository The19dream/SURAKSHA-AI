"""
Upload hardening for /api/note/check.

Nothing here trusts the client: the filename is only ever sanitised for display/audit
(it is never used as a filesystem path), the MIME type is derived from the file's own
bytes, and the image is held in memory, so no temp file exists to leak or clean up.
"""
from __future__ import annotations

import io
import re
from dataclasses import dataclass
from typing import Optional

from fastapi import HTTPException, UploadFile

ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "image/webp"}
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
MAX_PIXELS = 40_000_000  # reject decompression bombs
DEFAULT_FILENAME = "uploaded_banknote_image"
_SAFE_CHARS = re.compile(r"[^A-Za-z0-9._ -]")


@dataclass(frozen=True)
class ValidatedImage:
    data: bytes
    mime_type: str
    safe_filename: str


def sanitize_filename(name: Optional[str], max_len: int = 100) -> str:
    """Return a display-safe filename: no directories, no control/odd characters."""
    if not name:
        return DEFAULT_FILENAME
    base = re.split(r"[\\/]", name.replace("\x00", ""))[-1]  # strip any path, either separator
    base = _SAFE_CHARS.sub("_", base).strip(" .")
    base = re.sub(r"\.{2,}", ".", base)
    if not base or set(base) <= {"_", "."}:
        return DEFAULT_FILENAME
    if len(base) > max_len:
        stem, dot, ext = base.rpartition(".")
        base = (stem[: max_len - len(ext) - 1] + "." + ext) if dot and len(ext) <= 5 else base[:max_len]
    return base


def sniff_image_mime(data: bytes) -> Optional[str]:
    """Identify the real format from magic bytes (ignores the client's claims)."""
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def _ext(name: str) -> str:
    return ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""


async def read_and_validate_image(file: UploadFile, max_bytes: int) -> ValidatedImage:
    safe_name = sanitize_filename(file.filename)

    # 1. Cheap checks first: declared type and extension.
    declared = (file.content_type or "").split(";")[0].strip().lower()
    if declared not in ALLOWED_MIME_TYPES or _ext(safe_name) not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=415, detail="Unsupported file type. Upload a JPEG, PNG or WebP image.")

    # 2. Bounded read: never buffer more than max_bytes + 1.
    chunks, total = [], 0
    while True:
        chunk = await file.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum size is {max_bytes // (1024 * 1024)} MB.",
            )
        chunks.append(chunk)
    data = b"".join(chunks)
    if not data:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")

    # 3. Content must really be an allowed image, whatever the client claimed.
    mime = sniff_image_mime(data)
    if mime is None:
        raise HTTPException(status_code=415, detail="The file content is not a valid JPEG, PNG or WebP image.")

    # 4. Must actually decode (Pillow is a declared dependency) and not be absurdly large.
    try:
        from PIL import Image

        with Image.open(io.BytesIO(data)) as img:
            if img.width * img.height > MAX_PIXELS:
                raise HTTPException(status_code=413, detail="Image dimensions are too large.")
            img.verify()
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="The image file is corrupt or unreadable.") from None

    return ValidatedImage(data=data, mime_type=mime, safe_filename=safe_name)
