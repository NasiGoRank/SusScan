from __future__ import annotations

from pathlib import Path

from fastapi import HTTPException, UploadFile

from config import settings


SAFE_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


def sanitize_filename(filename: str) -> str:
    cleaned = "".join(ch if ch in SAFE_CHARS else "_" for ch in filename)
    return cleaned[:200] or "uploaded_file"


async def save_upload_file(upload: UploadFile, job_id: str) -> Path:
    safe_name = sanitize_filename(upload.filename or "uploaded_file")
    stored_name = f"{job_id}_{safe_name}"
    stored_path = settings.uploads_dir / stored_name

    stored_path.parent.mkdir(parents=True, exist_ok=True)

    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    written_bytes = 0

    try:
        with stored_path.open("wb") as f:
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break

                written_bytes += len(chunk)
                if written_bytes > max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Upload exceeds the maximum allowed size of {settings.max_upload_size_mb} MB.",
                    )

                f.write(chunk)

        return stored_path
    except Exception:
        try:
            stored_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise
    finally:
        await upload.close()