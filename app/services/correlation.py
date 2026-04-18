from __future__ import annotations

import ast
import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any


IGNORED_RULE_NAMES = {
    "domain",
    "ip",
    "url",
    "contains_base64",
    "ispe32",
    "iswindowsgui",
    "ispacked",
    "hasoverlay",
    "hasdebugdata",
    "hasrichsignature",
}

IGNORED_NAMESPACE_PARTS = {
    "yara_rules__utils_",
    "yara_rules__packers_packer_compiler_signatures",
    "yara_rules__packers_peid",
}

IGNORED_TAGS = {
    "pecheck",
    "peid",
    "base64",
}

STRONG_YARA_TAGS = {"malware", "trojan", "ransomware", "backdoor", "loader", "stealer"}
SUSPICIOUS_YARA_TAGS = {"packer", "obfuscation", "anti_vm", "anti_debug"}

CRYPTO_KEYWORDS = {
    "crypto",
    "crypt",
    "aes",
    "rsa",
    "chacha",
    "xchacha",
    "salsa20",
    "ransom",
    "locker",
}

INJECTION_KEYWORDS = {
    "inject thread",
    "process injection",
    "writeprocessmemory",
    "createremotethread",
    "queueuserapc",
    "ntcreatethreadex",
    "setthreadcontext",
    "resume thread",
    "thread hijack",
    "dll injection",
}

DEBUGGER_KEYWORDS = {
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "outputdebugstring",
    "debugger",
    "anti-debug",
    "ntqueryinformationprocess",
    "beingdebugged",
}

VM_KEYWORDS = {
    "virtualbox",
    "vmware",
    "qemu",
    "xen",
    "hyper-v",
    "sandbox",
    "anti-vm",
    "anti sandbox",
}

SERVICE_PERSISTENCE_KEYWORDS = {
    "createservice",
    "openservice",
    "startservice",
    "controlservice",
    "service persistence",
    "windows service",
}


def _correlation_rules_root() -> Path:
    env_override = os.getenv("SUSSCAN_CORRELATION_RULES_DIR")
    if env_override:
        return Path(env_override)

    susscan_home = os.getenv("SUSSCAN_HOME", "/opt/susscan")
    return Path(susscan_home) / "rules" / "correlation"


def _normalize_tags(match: dict[str, Any]) -> list[str]:
    return [str(tag).lower() for tag in (match.get("tags") or [])]


def _normalize_meta(match: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v).lower() for k, v in (match.get("meta") or {}).items()}


def should_drop_yara_match(match: dict[str, Any], artifact_type: str) -> bool:
    rule = str(match.get("rule") or "").lower()
    namespace = str(match.get("namespace") or "").lower()
    tags = _normalize_tags(match)

    if not rule:
        return False
    if rule in IGNORED_RULE_NAMES:
        return True
    if any(tag in IGNORED_TAGS for tag in tags):
        return True
    if any(part in namespace for part in IGNORED_NAMESPACE_PARTS):
        return True
    if "maldoc" in tags and artifact_type in {"pe", "apk"}:
        return True
    if artifact_type == "apk" and ("pecheck" in tags or "peid" in tags):
        return True
    return False


def filter_yara_matches(yara_matches: list[dict[str, Any]], artifact_type: str) -> list[dict[str, Any]]:
    return [match for match in yara_matches if not should_drop_yara_match(match, artifact_type)]


def _score_yara_matches(yara_matches: list[dict[str, Any]]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    for match in yara_matches:
        rule = str(match.get("rule") or "")
        rule_l = rule.lower()
        tags = _normalize_tags(match)
        meta = _normalize_meta(match)
        namespace = str(match.get("namespace") or "").lower()

        if "test" in tags or "sample" in rule_l:
            continue

        if any(tag in tags for tag in STRONG_YARA_TAGS):
            score += 35
            reasons.append(f"Strong YARA hit: {rule}")
            continue

        if meta.get("severity") in {"critical", "high"}:
            score += 25
            reasons.append(f"High-severity YARA rule matched: {rule}")
            continue

        if any(tag in tags for tag in SUSPICIOUS_YARA_TAGS):
            score += 12
            reasons.append(f"Suspicious YARA hit: {rule}")
            continue

        if "antidebug" in namespace or "antivm" in namespace:
            score += 4
            reasons.append(f"Weak anti-debug/anti-VM indicator: {rule}")
            continue

    return score, reasons


def _score_pe_phase2(pe_analysis: dict[str, Any], reasons: list[str]) -> int:
    score = 0
    structural = pe_analysis.get("structural_evidence", {})

    rich = structural.get("rich_header_anomaly", {})
    if rich.get("anomaly") is True:
        score += 12
        reasons.append(rich.get("reason") or "Rich Header appears inconsistent with claimed build metadata.")

    iat = structural.get("iat_red_flags", {})
    if iat.get("red_flag"):
        score += 12
        reasons.append(iat.get("reason") or "IAT contains very few imported functions.")

    sec = structural.get("section_name_and_entropy", {})
    if sec.get("correlated_red_flag"):
        score += 18
        reasons.append(sec.get("reason") or "Suspicious section naming correlates with high entropy.")
    else:
        suspicious_names = sec.get("suspicious_section_names", [])
        high_entropy_sections = sec.get("high_entropy_sections", [])

        if suspicious_names:
            score += 6
            reasons.append(f"PE uses suspicious section names: {', '.join(suspicious_names[:5])}")

        if high_entropy_sections:
            section_names = [
                item.get("name", str(item))
                if isinstance(item, dict)
                else str(item)
                for item in high_entropy_sections[:5]
            ]
            score += min(len(high_entropy_sections) * 6, 18)
            reasons.append(f"PE contains high-entropy sections: {', '.join(section_names)}")

    return score


def _score_apk_phase2(apk_analysis: dict[str, Any], reasons: list[str]) -> int:
    score = 0
    structural = apk_analysis.get("structural_evidence", {})

    mismatch = structural.get("permission_to_code_mismatch", {})
    requested = mismatch.get("requested_permissions", [])
    mismatches = mismatch.get("mismatches", [])

    if requested:
        score += min(len(requested) * 4, 20)
        reasons.append(f"APK requests sensitive permissions: {', '.join(requested[:5])}")

    if mismatches:
        score += min(len(mismatches) * 10, 30)
        reasons.append(f"APK shows permission-to-code mismatches for: {', '.join(mismatches[:5])}")

    cert = structural.get("certificate_triage", {})
    if cert.get("debug_certificate"):
        score += 20
        reasons.append("APK appears to be signed with an Android debug certificate.")

    if cert.get("randomized_issuer"):
        score += 10
        reasons.append("APK certificate issuer appears randomized or machine-generated.")

    if cert.get("status") == "no_certificate_data":
        score += 6
        reasons.append("APK certificate data could not be recovered.")

    return score


def _contains_any_text(value: Any, needles: set[str]) -> bool:
    try:
        blob = json.dumps(value, ensure_ascii=False).lower()
    except Exception:
        blob = str(value).lower()
    return any(needle in blob for needle in needles)


def _has_strong_yara(yara_matches: list[dict[str, Any]]) -> bool:
    for match in yara_matches:
        tags = _normalize_tags(match)
        meta = _normalize_meta(match)
        if any(tag in tags for tag in STRONG_YARA_TAGS):
            return True
        if meta.get("severity") in {"critical", "high"}:
            return True
    return False


def _has_crypto_yara(yara_matches: list[dict[str, Any]]) -> bool:
    for match in yara_matches:
        rule = str(match.get("rule") or "").lower()
        namespace = str(match.get("namespace") or "").lower()
        tags = _normalize_tags(match)
        meta = _normalize_meta(match)
        haystack = " ".join([rule, namespace, " ".join(tags), " ".join(meta.values())])
        if any(word in haystack for word in CRYPTO_KEYWORDS):
            return True
    return False


def _has_packer_yara(yara_matches: list[dict[str, Any]]) -> bool:
    for match in yara_matches:
        rule = str(match.get("rule") or "").lower()
        namespace = str(match.get("namespace") or "").lower()
        tags = _normalize_tags(match)
        meta = _normalize_meta(match)

        if "packer" in tags:
            return True

        haystack = " ".join([rule, namespace, " ".join(meta.values())])
        if "packer" in haystack or "upx" in haystack or "themida" in haystack or "vmprotect" in haystack:
            return True

    return False


def _has_anti_debug_yara(yara_matches: list[dict[str, Any]]) -> bool:
    for match in yara_matches:
        rule = str(match.get("rule") or "").lower()
        namespace = str(match.get("namespace") or "").lower()
        tags = _normalize_tags(match)

        if "anti_debug" in tags:
            return True

        haystack = " ".join([rule, namespace, " ".join(tags)])
        if "antidebug" in haystack or "anti-debug" in haystack or "debugger" in haystack:
            return True

    return False


def _has_anti_vm_yara(yara_matches: list[dict[str, Any]]) -> bool:
    for match in yara_matches:
        rule = str(match.get("rule") or "").lower()
        namespace = str(match.get("namespace") or "").lower()
        tags = _normalize_tags(match)

        if "anti_vm" in tags:
            return True

        haystack = " ".join([rule, namespace, " ".join(tags)])
        if "antivm" in haystack or "anti-vm" in haystack or "sandbox" in haystack or "vmware" in haystack:
            return True

    return False


def _bool(value: Any) -> bool:
    return bool(value)


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def _derive_features(
    *,
    artifact_type: str,
    trust_analysis: dict[str, Any],
    common_analysis: dict[str, Any],
    pe_analysis: dict[str, Any],
    apk_analysis: dict[str, Any],
) -> dict[str, Any]:
    yara_matches = common_analysis.get("yara_matches", [])
    trust_decision = trust_analysis.get("trust_decision", {})
    signature = trust_analysis.get("signature_verification", {})
    trust_state = str(trust_decision.get("state") or "untrusted_unknown")
    signature_status = str(signature.get("status") or "unknown")

    features: dict[str, Any] = {
        "artifact_type": artifact_type,
        "trust_state": trust_state,
        "signature_status": signature_status,
        "has_strong_yara": _has_strong_yara(yara_matches),
        "has_crypto_yara": _has_crypto_yara(yara_matches),
        "has_packer_yara": _has_packer_yara(yara_matches),
        "has_anti_debug_yara": _has_anti_debug_yara(yara_matches),
        "has_anti_vm_yara": _has_anti_vm_yara(yara_matches),
        "yara_match_count": len(yara_matches),
        "hash_is_trusted": trust_state in {"trusted_known_hash", "trusted_signed"},
        "hash_is_known_malicious": trust_state == "known_malicious",
    }

    pe_structural = pe_analysis.get("structural_evidence", {})
    rich = pe_structural.get("rich_header_anomaly", {})
    iat = pe_structural.get("iat_red_flags", {})
    sec = pe_structural.get("section_name_and_entropy", {})
    die_keywords = pe_structural.get("die_packer_keywords", []) or []
    capa_blob = pe_analysis.get("capa", {})

    features.update(
        {
            "pe_has_rich_header_anomaly": _bool(rich.get("anomaly")),
            "pe_has_sparse_iat": _bool(iat.get("red_flag")),
            "pe_has_section_name_entropy_correlation": _bool(sec.get("correlated_red_flag")),
            "pe_has_suspicious_section_names": bool(sec.get("suspicious_section_names", [])),
            "pe_has_high_entropy_sections": bool(sec.get("high_entropy_sections", [])),
            "pe_die_packer_keyword_count": len(die_keywords),
            "pe_has_injection_capability": _contains_any_text(capa_blob, INJECTION_KEYWORDS),
            "pe_has_debugger_detection_capability": _contains_any_text(capa_blob, DEBUGGER_KEYWORDS)
            or features["has_anti_debug_yara"],
            "pe_has_vm_detection_capability": _contains_any_text(capa_blob, VM_KEYWORDS)
            or features["has_anti_vm_yara"],
            "pe_has_service_persistence_capability": _contains_any_text(capa_blob, SERVICE_PERSISTENCE_KEYWORDS),
        }
    )

    features["pe_is_packed_like"] = (
        features["pe_die_packer_keyword_count"] > 0
        or features["pe_has_sparse_iat"]
        or features["pe_has_section_name_entropy_correlation"]
        or features["has_packer_yara"]
    )

    apk_structural = apk_analysis.get("structural_evidence", {})
    mismatch = apk_structural.get("permission_to_code_mismatch", {})
    cert = apk_structural.get("certificate_triage", {})

    requested_permissions = set(mismatch.get("requested_permissions", []) or [])
    mismatches = set(mismatch.get("mismatches", []) or [])

    sms_permissions = {
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
    }

    features.update(
        {
            "apk_requested_sensitive_permission_count": len(requested_permissions),
            "apk_permission_mismatch_count": len(mismatches),
            "apk_has_permission_mismatch": len(mismatches) > 0,
            "apk_has_boot_persistence_permission": "android.permission.RECEIVE_BOOT_COMPLETED" in requested_permissions,
            "apk_has_boot_persistence_mismatch": "android.permission.RECEIVE_BOOT_COMPLETED" in mismatches,
            "apk_has_overlay_permission": "android.permission.SYSTEM_ALERT_WINDOW" in requested_permissions,
            "apk_has_install_packages_permission": "android.permission.REQUEST_INSTALL_PACKAGES" in requested_permissions,
            "apk_has_sms_permission": bool(requested_permissions & sms_permissions),
            "apk_has_debug_certificate": _bool(cert.get("debug_certificate")),
            "apk_has_randomized_issuer": _bool(cert.get("randomized_issuer")),
            "apk_has_no_certificate_data": str(cert.get("status") or "") == "no_certificate_data",
        }
    )

    return features


ALLOWED_AST_NODES = (
    ast.Expression,
    ast.BoolOp,
    ast.UnaryOp,
    ast.Compare,
    ast.Name,
    ast.Load,
    ast.Constant,
    ast.And,
    ast.Or,
    ast.Not,
    ast.Eq,
    ast.NotEq,
    ast.Gt,
    ast.GtE,
    ast.Lt,
    ast.LtE,
    ast.In,
    ast.NotIn,
)


def _validate_safe_expr(expr: str) -> ast.Expression:
    tree = ast.parse(expr, mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED_AST_NODES):
            raise ValueError(f"Unsupported rule expression node: {type(node).__name__}")
    return tree


@lru_cache(maxsize=256)
def _compile_rule_expr(expr: str):
    tree = _validate_safe_expr(expr)
    return compile(tree, "<correlation-rule>", "eval")


@lru_cache(maxsize=256)
def _expr_variable_names(expr: str) -> tuple[str, ...]:
    tree = _validate_safe_expr(expr)
    names = sorted({node.id for node in ast.walk(tree) if isinstance(node, ast.Name)})
    return tuple(names)


def _eval_rule_expr(expr: str, features: dict[str, Any]) -> bool:
    code = _compile_rule_expr(expr)
    return bool(eval(code, {"__builtins__": {}}, features))


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        if not item:
            continue
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _load_json_file(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def _load_current_rule_files() -> dict[str, list[dict[str, Any]]]:
    root = _correlation_rules_root()
    current_dir = root / "current"

    data: dict[str, list[dict[str, Any]]] = {
        "global": [],
        "pe": [],
        "apk": [],
    }

    files = {
        "global": current_dir / "global_rules.json",
        "pe": current_dir / "windows_pe_rules.json",
        "apk": current_dir / "android_apk_rules.json",
    }

    for key, path in files.items():
        if path.exists():
            payload = _load_json_file(path)
            if isinstance(payload, list):
                data[key] = payload

    return data


def _rules_for_artifact(artifact_type: str) -> list[dict[str, Any]]:
    loaded = _load_current_rule_files()
    rules = list(loaded.get("global", []))

    if artifact_type == "pe":
        rules.extend(loaded.get("pe", []))
    elif artifact_type == "apk":
        rules.extend(loaded.get("apk", []))

    return rules


def _build_rule_evidence(expr: str, features: dict[str, Any]) -> dict[str, Any]:
    names = _expr_variable_names(expr)
    return {name: features.get(name) for name in names if name in features}


def _apply_loaded_rules(
    *,
    artifact_type: str,
    features: dict[str, Any],
    fired_rules: list[dict[str, Any]],
    reasons: list[str],
    notes: list[str],
) -> int:
    total_delta = 0
    rules = _rules_for_artifact(artifact_type)

    if not rules:
        notes.append(
            f"No external correlation rules were loaded from {_correlation_rules_root() / 'current'}."
        )
        return 0

    for rule in rules:
        if not rule.get("enabled", True):
            continue

        rule_artifact_type = str(rule.get("artifact_type") or "any")
        if rule_artifact_type not in {"any", artifact_type}:
            continue

        expr = str(rule.get("expr") or "").strip()
        if not expr:
            continue

        try:
            matched = _eval_rule_expr(expr, features)
        except Exception as exc:
            notes.append(f"Skipped rule {rule.get('id', '<unknown>')}: {exc}")
            continue

        if not matched:
            continue

        score_delta = _safe_int(rule.get("score_delta", 0))
        reason = str(rule.get("reason") or rule.get("title") or rule.get("id") or "Correlation rule fired.")
        evidence = _build_rule_evidence(expr, features)

        fired_rules.append(
            {
                "rule_id": str(rule.get("id") or ""),
                "title": str(rule.get("title") or rule.get("id") or "Unnamed rule"),
                "score_delta": score_delta,
                "reason": reason,
                "evidence": {
                    "expr": expr,
                    "matched_values": evidence,
                    "standardized_behaviors": rule.get("standardized_behaviors", {}),
                    "source_basis": rule.get("source_basis", []),
                },
                "category": str(rule.get("category") or "correlation"),
                "severity": str(rule.get("severity") or "medium"),
            }
        )
        reasons.append(reason)
        total_delta += score_delta

    return total_delta


def apply_phase3_correlation(
    *,
    artifact_type: str,
    trust_analysis: dict[str, Any],
    common_analysis: dict[str, Any],
    pe_analysis: dict[str, Any] | None = None,
    apk_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    raw_yara_matches = common_analysis.get("yara_matches", [])
    filtered_yara_matches = filter_yara_matches(raw_yara_matches, artifact_type)

    filtered_common_analysis = dict(common_analysis)
    filtered_common_analysis["yara_matches"] = filtered_yara_matches

    reasons: list[str] = []
    notes: list[str] = []
    fired_rules: list[dict[str, Any]] = []

    pe_payload = pe_analysis or {}
    apk_payload = apk_analysis or {}
    trust_payload = trust_analysis or {}

    base_score, yara_reasons = _score_yara_matches(filtered_yara_matches)
    reasons.extend(yara_reasons)

    if artifact_type == "pe":
        base_score += _score_pe_phase2(pe_payload, reasons)
    elif artifact_type == "apk":
        base_score += _score_apk_phase2(apk_payload, reasons)
    else:
        reasons.append("Artifact type is unknown, so only limited analysis was performed.")

    features = _derive_features(
        artifact_type=artifact_type,
        trust_analysis=trust_payload,
        common_analysis=filtered_common_analysis,
        pe_analysis=pe_payload,
        apk_analysis=apk_payload,
    )

    score = base_score
    score += _apply_loaded_rules(
        artifact_type=artifact_type,
        features=features,
        fired_rules=fired_rules,
        reasons=reasons,
        notes=notes,
    )

    trust_reason = str((trust_payload.get("trust_decision", {}) or {}).get("reason") or "").strip()
    trust_state = str((trust_payload.get("trust_decision", {}) or {}).get("state") or "")

    if trust_state in {"known_neutral", "untrusted_unsigned", "lookup_error", "untrusted_unknown"} and trust_reason:
        reasons.insert(0, trust_reason)

    if trust_state == "trusted_known_hash":
        notes.append("Trusted hash matched, but the full pipeline still ran so all evidence remains visible.")
    elif trust_state == "trusted_signed":
        notes.append("Signature trust reduced the score, but suspicious findings remain visible for analyst review.")
    elif trust_state == "known_malicious":
        notes.append("A malicious reputation source increased the score before final classification.")

    score = max(score, 0)
    reasons = _dedupe_preserve_order(reasons)

    return {
        "filtered_common_analysis": filtered_common_analysis,
        "raw_yara_match_count": len(raw_yara_matches),
        "filtered_yara_match_count": len(filtered_yara_matches),
        "risk": {
            "score": score,
            "reasons": reasons,
        },
        "correlation": {
            "engine_version": "phase3-v2-rules-from-disk",
            "base_score": base_score,
            "final_score": score,
            "fired_rules": fired_rules,
            "notes": notes,
        },
    }