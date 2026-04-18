from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from androguard.core.apk import APK

from config import settings
from utils.process import run_command


PERMISSION_TOKEN_MAP: dict[str, list[str]] = {
    "android.permission.CAMERA": ["android.hardware.Camera", "CameraManager", "ACTION_IMAGE_CAPTURE"],
    "android.permission.RECORD_AUDIO": ["MediaRecorder", "AudioRecord"],
    "android.permission.READ_CONTACTS": ["ContactsContract"],
    "android.permission.SEND_SMS": ["SmsManager", "sendTextMessage"],
    "android.permission.RECEIVE_SMS": ["SmsMessage", "android.provider.Telephony"],
    "android.permission.RECEIVE_BOOT_COMPLETED": ["BOOT_COMPLETED", "android.intent.action.BOOT_COMPLETED"],
    "android.permission.REQUEST_INSTALL_PACKAGES": ["PackageInstaller", "ACTION_INSTALL_PACKAGE"],
    "android.permission.SYSTEM_ALERT_WINDOW": ["TYPE_APPLICATION_OVERLAY", "WindowManager"],
}

SENSITIVE_PERMISSIONS = set(PERMISSION_TOKEN_MAP.keys())
RANDOMISH_ISSUER_RE = re.compile(r"\b[A-Za-z0-9+/=_-]{20,}\b")


def _dir_contains_any_token(root: Path, tokens: list[str], *, max_files: int = 250, max_bytes: int = 1_000_000) -> bool:
    if not root.exists():
        return False

    files_checked = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".java", ".kt", ".xml", ".smali", ".txt"}:
            continue

        files_checked += 1
        if files_checked > max_files:
            break

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        if len(text) > max_bytes:
            text = text[:max_bytes]

        lowered = text.lower()
        for token in tokens:
            if token.lower() in lowered:
                return True

    return False


def _value_to_text(value: Any) -> str:
    if value is None:
        return ""
    human = getattr(value, "human_friendly", None)
    if isinstance(human, str):
        return human
    native = getattr(value, "native", None)
    if isinstance(native, (str, int)):
        return str(native)
    return str(value)


def _collect_certificates(apk: APK) -> tuple[list[Any], dict[str, int]]:
    certs: list[Any] = []
    source_counts: dict[str, int] = {}

    for method_name in ("get_certificates", "get_certificates_v3", "get_certificates_v2", "get_certificates_v1"):
        if not hasattr(apk, method_name):
            continue
        try:
            values = getattr(apk, method_name)() or []
        except Exception:
            continue
        source_counts[method_name] = len(values)
        certs.extend(values)

    unique: list[Any] = []
    seen: set[str] = set()

    for cert in certs:
        key = "|".join(
            [
                _value_to_text(getattr(cert, "issuer", None)),
                _value_to_text(getattr(cert, "subject", None)),
                _value_to_text(getattr(cert, "serial_number", None)),
            ]
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(cert)

    return unique, source_counts


def _build_certificate_triage(apk: APK) -> dict[str, Any]:
    try:
        certs, source_counts = _collect_certificates(apk)
    except Exception as exc:
        return {
            "status": f"error: {exc}",
            "cert_count": 0,
            "debug_certificate": False,
            "randomized_issuer": False,
            "signing_sources": {},
            "issuers": [],
            "subjects": [],
        }

    issuers: list[str] = []
    subjects: list[str] = []

    for cert in certs:
        issuers.append(_value_to_text(getattr(cert, "issuer", None)))
        subjects.append(_value_to_text(getattr(cert, "subject", None)))

    issuer_blob = " || ".join(issuers).lower()
    subject_blob = " || ".join(subjects).lower()

    debug_certificate = ("android debug" in issuer_blob) or ("android debug" in subject_blob)
    randomized_issuer = any(RANDOMISH_ISSUER_RE.search(text or "") for text in issuers)

    return {
        "status": "ok" if certs else "no_certificate_data",
        "cert_count": len(certs),
        "debug_certificate": debug_certificate,
        "randomized_issuer": randomized_issuer,
        "signing_sources": source_counts,
        "issuers": issuers[:5],
        "subjects": subjects[:5],
    }


def _build_permission_to_code_mismatch(metadata: dict[str, Any], jadx_dir: Path | None) -> dict[str, Any]:
    permissions = set(metadata.get("permissions", []))
    requested_permissions = sorted(permissions & SENSITIVE_PERMISSIONS)

    observed_usage: dict[str, bool | None] = {}
    api_tokens_checked: dict[str, list[str]] = {}
    mismatches: list[str] = []

    for permission, tokens in PERMISSION_TOKEN_MAP.items():
        if permission not in permissions:
            continue

        api_tokens_checked[permission] = tokens

        if jadx_dir and jadx_dir.exists():
            observed = _dir_contains_any_token(jadx_dir, tokens)
            observed_usage[permission] = observed
            if not observed:
                mismatches.append(permission)
        else:
            observed_usage[permission] = None

    return {
        "requested_permissions": requested_permissions,
        "api_tokens_checked": api_tokens_checked,
        "observed_usage": observed_usage,
        "mismatches": mismatches,
    }


def analyze_apk(path: Path, job_id: str) -> dict[str, Any]:
    try:
        apk_obj = APK(str(path))
        metadata = {
            "package_name": apk_obj.get_package(),
            "app_name": apk_obj.get_app_name(),
            "version_name": apk_obj.get_androidversion_name(),
            "version_code": apk_obj.get_androidversion_code(),
            "permissions": sorted(apk_obj.get_permissions()),
            "activities": apk_obj.get_activities(),
            "services": apk_obj.get_services(),
            "receivers": apk_obj.get_receivers(),
            "main_activity": apk_obj.get_main_activity(),
            "min_sdk": apk_obj.get_min_sdk_version(),
            "target_sdk": apk_obj.get_target_sdk_version(),
        }
    except Exception as exc:
        return {
            "metadata": {"error": f"androguard failed: {exc}"},
            "jadx": {"ok": False, "error": f"androguard failed before JADX: {exc}"},
            "structural_evidence": {},
        }

    result: dict[str, Any] = {"metadata": metadata}

    jadx_dir: Path | None = None
    if settings.enable_jadx_decompile:
        jadx_dir = settings.decompiled_dir / job_id
        jadx_dir.mkdir(parents=True, exist_ok=True)
        result["jadx"] = run_command(["jadx", "-d", str(jadx_dir), str(path)])
        result["jadx_output_dir"] = str(jadx_dir)
    else:
        result["jadx"] = {
            "ok": True,
            "skipped": True,
            "reason": "JADX decompilation disabled for this build.",
        }

    result["structural_evidence"] = {
        "permission_to_code_mismatch": _build_permission_to_code_mismatch(metadata, jadx_dir),
        "certificate_triage": _build_certificate_triage(apk_obj),
    }
    return result