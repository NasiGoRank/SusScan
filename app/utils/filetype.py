from __future__ import annotations

from pathlib import Path


PE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl"}
APK_EXTENSIONS = {".apk"}


def classify_artifact_type(file_path: Path, mime_type: str | None = None) -> str:
    path = Path(file_path)
    ext = path.suffix.lower()
    mime = (mime_type or "").lower()

    try:
        header = path.read_bytes()[:8]
    except Exception:
        header = b""

    # PE / Windows executable
    if (
        ext in PE_EXTENSIONS
        or "application/x-dosexec" in mime
        or "portable executable" in mime
        or "application/vnd.microsoft.portable-executable" in mime
        or header.startswith(b"MZ")
    ):
        return "pe"

    # APK / Android package
    if (
        ext in APK_EXTENSIONS
        or "android.package-archive" in mime
        or "application/vnd.android.package-archive" in mime
    ):
        return "apk"

    return "unknown"