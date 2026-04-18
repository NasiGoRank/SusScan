from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib import error, parse, request

from config import settings
from db import get_trust_cache, upsert_trust_cache, utcnow_iso


ProviderFn = Callable[[str], dict[str, Any]]


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _finalize_uncached(payload: dict[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    result["cached"] = False
    result.setdefault("cached_at", None)
    return result


def _should_cache_payload(payload: dict[str, Any]) -> bool:
    return payload.get("status") not in {"disabled", "error"}


def _cache_get(sha256: str, provider: str) -> dict[str, Any] | None:
    cached = get_trust_cache(sha256, provider)
    if not cached:
        return None

    expires_at = _parse_iso(cached.get("expires_at"))
    now = datetime.now(timezone.utc)
    if expires_at is not None and expires_at <= now:
        return None

    payload = dict(cached.get("response_json") or {})
    if payload.get("status") in {"disabled", "error"}:
        return None

    payload["cached"] = True
    payload["cached_at"] = cached.get("cached_at")
    return payload


def _cache_put(sha256: str, provider: str, artifact_type: str | None, payload: dict[str, Any]) -> dict[str, Any]:
    if not _should_cache_payload(payload):
        return _finalize_uncached(payload)

    now = datetime.now(timezone.utc)
    cached_at = utcnow_iso()
    expires_at = (now + timedelta(hours=settings.trust_cache_ttl_hours)).isoformat()

    upsert_trust_cache(
        sha256=sha256,
        provider=provider,
        artifact_type=artifact_type,
        response_json=payload,
        cached_at=cached_at,
        expires_at=expires_at,
    )

    saved = dict(payload)
    saved["cached"] = False
    saved["cached_at"] = cached_at
    return saved


def _json_request(
    *,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    form: dict[str, Any] | None = None,
    timeout: int | None = None,
) -> tuple[int, dict[str, Any] | list[Any] | None]:
    headers = dict(headers or {})
    timeout = timeout or settings.reputation_timeout_seconds

    if params:
        qs = parse.urlencode(params, doseq=True)
        url = f"{url}?{qs}" if "?" not in url else f"{url}&{qs}"

    data = None
    if form is not None:
        data = parse.urlencode(form).encode("utf-8")
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    req = request.Request(url, data=data, headers=headers, method=method.upper())

    try:
        with request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            payload = json.loads(body) if body.strip() else {}
            return resp.getcode(), payload
    except error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="ignore")
            payload = json.loads(body) if body.strip() else {}
        except Exception:
            payload = {}
        return exc.code, payload
    except Exception:
        raise


def _confidence_from_ratio(positives: int, total: int, *, base: int = 50, cap: int = 99) -> int:
    if total <= 0:
        return min(base + positives * 5, cap)
    ratio = positives / total
    return min(int(base + ratio * 100), cap)


def _disabled(provider: str, reason: str) -> dict[str, Any]:
    return {
        "provider": provider,
        "status": "disabled",
        "found": False,
        "confidence": None,
        "reason": reason,
    }


def _unknown(provider: str, reason: str) -> dict[str, Any]:
    return {
        "provider": provider,
        "status": "unknown",
        "found": False,
        "confidence": None,
        "reason": reason,
    }


def _error(provider: str, reason: str) -> dict[str, Any]:
    return {
        "provider": provider,
        "status": "error",
        "found": False,
        "confidence": None,
        "reason": reason,
    }


def _normalize_circl_payload(raw: dict[str, Any] | None, *, sha256: str) -> dict[str, Any]:
    raw = raw or {}
    trust = raw.get("hashlookup:trust")
    if trust is None:
        trust = raw.get("trust")

    try:
        trust_score = int(float(trust)) if trust is not None else None
    except Exception:
        trust_score = None

    source = raw.get("source") or raw.get("hashlookup:source") or raw.get("NSRL")
    found = bool(raw)

    if not found:
        status = "unknown"
        reason = "SHA-256 was not found in the CIRCL hash lookup source."
    elif trust_score is None:
        status = "known_neutral"
        reason = "SHA-256 was found in CIRCL, but no trust score was available."
    elif trust_score > 50:
        status = "trusted"
        reason = "SHA-256 was found in CIRCL and the trust score is above neutral."
    elif trust_score == 50:
        status = "known_neutral"
        reason = "SHA-256 was found in CIRCL, but the trust score is neutral."
    else:
        status = "known_low_trust"
        reason = "SHA-256 was found in CIRCL, but the trust score is below neutral."

    return {
        "provider": settings.hash_lookup_provider,
        "sha256": sha256,
        "status": status,
        "found": found,
        "trust_score": trust_score,
        "source": source,
        "raw": raw,
        "reason": reason,
    }


def lookup_circl_sha256(sha256: str, artifact_type: str | None = None) -> dict[str, Any]:
    provider = settings.hash_lookup_provider
    cached = _cache_get(sha256, provider)
    if cached:
        return cached

    if not settings.enable_hash_lookup:
        return _cache_put(
            sha256,
            provider,
            artifact_type,
            {
                "provider": provider,
                "sha256": sha256,
                "status": "disabled",
                "found": False,
                "trust_score": None,
                "reason": "Remote CIRCL hash lookup is disabled for this deployment.",
            },
        )

    base_url = settings.hash_lookup_url.rstrip("/") + "/"
    url = base_url + sha256
    req = request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "SusScan/phase1",
        },
    )

    try:
        with request.urlopen(req, timeout=settings.hash_lookup_timeout_seconds) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            raw = json.loads(body) if body.strip() else {}
        payload = _normalize_circl_payload(raw, sha256=sha256)
    except error.HTTPError as exc:
        if exc.code == 404:
            payload = {
                "provider": provider,
                "sha256": sha256,
                "status": "unknown",
                "found": False,
                "trust_score": None,
                "reason": "SHA-256 was not found in the CIRCL hash lookup source.",
            }
        else:
            payload = {
                "provider": provider,
                "sha256": sha256,
                "status": "error",
                "found": False,
                "trust_score": None,
                "reason": f"CIRCL hash lookup failed with HTTP {exc.code}.",
            }
    except Exception as exc:
        payload = {
            "provider": provider,
            "sha256": sha256,
            "status": "error",
            "found": False,
            "trust_score": None,
            "reason": f"CIRCL hash lookup failed: {exc}",
        }

    return _cache_put(sha256, provider, artifact_type, payload)

def _malwarebazaar_lookup(sha256: str) -> dict[str, Any]:
    provider = "malwarebazaar"
    if not settings.malwarebazaar_api_key:
        return _disabled(provider, "MalwareBazaar API key is not configured.")

    status_code, payload = _json_request(
        url=settings.malwarebazaar_url,
        method="POST",
        headers={
            "Accept": "application/json",
            "Auth-Key": settings.malwarebazaar_api_key,
            "User-Agent": "SusScan/phase1",
        },
        form={"query": "get_info", "hash": sha256},
    )

    if status_code == 404:
        return _unknown(provider, "Hash was not found in MalwareBazaar.")
    if status_code >= 400:
        return _error(provider, f"MalwareBazaar returned HTTP {status_code}.")

    if isinstance(payload, dict) and payload.get("query_status") == "ok":
        data = payload.get("data") or []
        first = data[0] if isinstance(data, list) and data else {}
        return {
            "provider": provider,
            "status": "malicious",
            "found": True,
            "confidence": 95,
            "reason": "Hash was found in MalwareBazaar malware intelligence.",
            "raw": {
                "query_status": payload.get("query_status"),
                "file_name": first.get("file_name"),
                "file_type": first.get("file_type"),
                "signature": first.get("signature"),
                "tags": first.get("tags"),
                "first_seen": first.get("first_seen"),
            },
        }

    return _unknown(provider, "Hash was not found in MalwareBazaar.")


def _hybrid_analysis_lookup(sha256: str) -> dict[str, Any]:
    provider = "hybrid_analysis"
    if not settings.hybrid_analysis_api_key:
        return _disabled(provider, "Hybrid Analysis API key is not configured.")

    status_code, payload = _json_request(
        url=settings.hybrid_analysis_search_url,
        headers={
            "Accept": "application/json",
            "api-key": settings.hybrid_analysis_api_key,
            "User-Agent": "Falcon Sandbox",
        },
        params={"hash": sha256},
    )

    if status_code == 404:
        return _unknown(provider, "Hash was not found in Hybrid Analysis.")
    if status_code >= 400:
        return _error(provider, f"Hybrid Analysis returned HTTP {status_code}.")

    if isinstance(payload, list):
        item = payload[0] if payload else {}
    elif isinstance(payload, dict):
        item = payload
    else:
        item = {}

    if not item:
        return _unknown(provider, "Hash was not found in Hybrid Analysis.")

    verdict = str(item.get("verdict") or item.get("threat_level") or "").lower()
    threat_score = item.get("threat_score")
    try:
        threat_score_int = int(threat_score) if threat_score is not None else None
    except Exception:
        threat_score_int = None

    if verdict in {"malicious", "malware"}:
        status = "malicious"
        confidence = max(75, threat_score_int or 75)
        reason = "Hybrid Analysis reported a malicious verdict."
    elif verdict in {"suspicious", "susp"}:
        status = "suspicious"
        confidence = max(65, threat_score_int or 65)
        reason = "Hybrid Analysis reported a suspicious verdict."
    else:
        status = "neutral"
        confidence = 55
        reason = "Hash was found in Hybrid Analysis without a malicious/suspicious verdict."

    return {
        "provider": provider,
        "status": status,
        "found": True,
        "confidence": confidence,
        "reason": reason,
        "raw": {
            "verdict": item.get("verdict"),
            "threat_score": threat_score_int,
            "analysis_start_time": item.get("analysis_start_time"),
            "vx_family": item.get("vx_family"),
        },
    }


def _metadefender_lookup(sha256: str) -> dict[str, Any]:
    provider = "metadefender"
    if not settings.metadefender_api_key:
        return _disabled(provider, "MetaDefender API key is not configured.")

    status_code, payload = _json_request(
        url=f"{settings.metadefender_hash_url.rstrip('/')}/{sha256}",
        headers={
            "Accept": "application/json",
            "apikey": settings.metadefender_api_key,
            "User-Agent": "SusScan/phase1",
        },
    )

    if status_code == 404:
        return _unknown(provider, "Hash was not found in MetaDefender Cloud.")
    if status_code >= 400:
        return _error(provider, f"MetaDefender returned HTTP {status_code}.")

    if not isinstance(payload, dict) or not payload:
        return _unknown(provider, "Hash was not found in MetaDefender Cloud.")

    scan_results = payload.get("scan_results") or {}
    detected = int(scan_results.get("total_detected_avs") or 0)
    total = int(scan_results.get("total_avs") or 0)

    if detected > 0:
        return {
            "provider": provider,
            "status": "malicious",
            "found": True,
            "confidence": _confidence_from_ratio(detected, total, base=55),
            "reason": f"MetaDefender reported {detected} engine detection(s).",
            "raw": {
                "total_detected_avs": detected,
                "total_avs": total,
                "file_type": payload.get("file_type"),
            },
        }

    return {
        "provider": provider,
        "status": "neutral",
        "found": True,
        "confidence": 55,
        "reason": "Hash was found in MetaDefender Cloud with no positive engine detections.",
        "raw": {
            "total_detected_avs": detected,
            "total_avs": total,
            "file_type": payload.get("file_type"),
        },
    }


def _virustotal_lookup(sha256: str) -> dict[str, Any]:
    provider = "virustotal"
    if not settings.virustotal_api_key:
        return _disabled(provider, "VirusTotal API key is not configured.")

    status_code, payload = _json_request(
        url=f"{settings.virustotal_file_url.rstrip('/')}/{sha256}",
        headers={
            "Accept": "application/json",
            "x-apikey": settings.virustotal_api_key,
            "User-Agent": "SusScan/phase1",
        },
    )

    if status_code == 404:
        return _unknown(provider, "Hash was not found in VirusTotal.")
    if status_code >= 400:
        return _error(provider, f"VirusTotal returned HTTP {status_code}.")

    data = payload.get("data") if isinstance(payload, dict) else None
    attrs = data.get("attributes") if isinstance(data, dict) else None
    if not isinstance(attrs, dict):
        return _unknown(provider, "Hash was not found in VirusTotal.")

    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    total = malicious + suspicious + harmless + undetected

    if malicious > 0:
        return {
            "provider": provider,
            "status": "malicious",
            "found": True,
            "confidence": _confidence_from_ratio(malicious + suspicious, max(total, 1), base=55),
            "reason": f"VirusTotal reported {malicious} malicious engine detection(s).",
            "raw": {
                "last_analysis_stats": stats,
                "type_description": attrs.get("type_description"),
                "popular_threat_classification": attrs.get("popular_threat_classification"),
            },
        }

    if suspicious > 0:
        return {
            "provider": provider,
            "status": "suspicious",
            "found": True,
            "confidence": _confidence_from_ratio(suspicious, max(total, 1), base=50),
            "reason": f"VirusTotal reported {suspicious} suspicious engine result(s).",
            "raw": {
                "last_analysis_stats": stats,
                "type_description": attrs.get("type_description"),
            },
        }

    return {
        "provider": provider,
        "status": "neutral",
        "found": True,
        "confidence": 55,
        "reason": "Hash was found in VirusTotal with no malicious/suspicious results.",
        "raw": {
            "last_analysis_stats": stats,
            "type_description": attrs.get("type_description"),
        },
    }


_PROVIDER_MAP: dict[str, ProviderFn] = {
    "malwarebazaar": _malwarebazaar_lookup,
    "hybrid_analysis": _hybrid_analysis_lookup,
    "metadefender": _metadefender_lookup,
    "virustotal": _virustotal_lookup,
}


def _enabled_provider_names() -> list[str]:
    raw = settings.enabled_reputation_providers or ""
    names = [part.strip().lower() for part in raw.split(",") if part.strip()]
    ordered = ["malwarebazaar", "hybrid_analysis", "metadefender", "virustotal"]
    requested = {name for name in names if name in _PROVIDER_MAP}
    return [name for name in ordered if name in requested]


def _lookup_one(provider: str, sha256: str, artifact_type: str | None) -> dict[str, Any]:
    cached = _cache_get(sha256, provider)
    if cached:
        return cached

    try:
        payload = _PROVIDER_MAP[provider](sha256)
    except Exception as exc:
        payload = _error(provider, f"{provider} lookup failed: {exc}")

    return _cache_put(sha256, provider, artifact_type, payload)


def _native_status_has_data(status: str | None) -> bool:
    return status in {"malicious", "suspicious", "neutral"}


def _normalize_provider_for_hash_lookup(item: dict[str, Any], sha256: str) -> dict[str, Any]:
    native_status = item.get("status")
    mapped_status = {
        "malicious": "known_malicious",
        "suspicious": "known_suspicious",
        "neutral": "known_neutral",
        "unknown": "unknown",
        "error": "error",
        "disabled": "disabled",
    }.get(native_status, "unknown")

    return {
        "provider": item.get("provider"),
        "sha256": sha256,
        "status": mapped_status,
        "found": bool(item.get("found")),
        "trust_score": item.get("confidence"),
        "source": item.get("provider"),
        "raw": item.get("raw"),
        "reason": item.get("reason"),
    }


def _final_no_match_result(sha256: str, attempts: list[dict[str, Any]]) -> dict[str, Any]:
    providers_tried = [item.get("provider") for item in attempts if item.get("provider")]
    unknown_seen = any(item.get("status") == "unknown" for item in attempts)

    if unknown_seen:
        status = "unknown"
        reason = "Hash was not found in any configured hash provider."
    else:
        status = "error"
        reason = "All configured hash providers were unavailable or disabled."

    return {
        "provider": providers_tried[-1] if providers_tried else settings.hash_lookup_provider,
        "sha256": sha256,
        "status": status,
        "found": False,
        "trust_score": None,
        "source": providers_tried[-1] if providers_tried else settings.hash_lookup_provider,
        "raw": {},
        "reason": reason,
        "fallback_used": len(attempts) > 1,
        "attempted_providers": providers_tried,
    }


def _build_chain_summary(selected_hash_lookup: dict[str, Any], attempts: list[dict[str, Any]]) -> dict[str, Any]:
    providers_tried = [item.get("provider") for item in attempts if item.get("provider")]
    return {
        "enabled": True,
        "attempt_count": len(attempts),
        "providers_tried": providers_tried,
        "selected_provider": selected_hash_lookup.get("provider"),
        "selected_status": selected_hash_lookup.get("status"),
        "fallback_used": bool(selected_hash_lookup.get("fallback_used")),
        "reason": selected_hash_lookup.get("reason"),
    }


def resolve_hash_lookup_chain(sha256: str, artifact_type: str | None = None) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []

    circl_result = lookup_circl_sha256(sha256, artifact_type=artifact_type)
    circl_attempt = dict(circl_result)
    circl_attempt["attempt_order"] = 1
    attempts.append(circl_attempt)

    if circl_result.get("status") not in {"unknown", "error", "disabled"}:
        selected = dict(circl_result)
        selected["fallback_used"] = False
        selected["attempted_providers"] = [circl_result.get("provider")]
        return {
            "selected_hash_lookup": selected,
            "provider_attempts": attempts,
            "summary": _build_chain_summary(selected, attempts),
        }

    for provider in _enabled_provider_names():
        provider_result = _lookup_one(provider, sha256, artifact_type)
        provider_attempt = dict(provider_result)
        provider_attempt["attempt_order"] = len(attempts) + 1
        attempts.append(provider_attempt)

        if _native_status_has_data(provider_result.get("status")):
            selected = _normalize_provider_for_hash_lookup(provider_result, sha256)
            selected["fallback_used"] = True
            selected["attempted_providers"] = [item.get("provider") for item in attempts if item.get("provider")]
            selected["reason"] = (
                f"Primary hash lookup did not return usable data, so fallback provider "
                f"'{provider_result.get('provider')}' was used. {provider_result.get('reason', '')}"
            ).strip()
            return {
                "selected_hash_lookup": selected,
                "provider_attempts": attempts,
                "summary": _build_chain_summary(selected, attempts),
            }

    selected = _final_no_match_result(sha256, attempts)
    return {
        "selected_hash_lookup": selected,
        "provider_attempts": attempts,
        "summary": _build_chain_summary(selected, attempts),
    }