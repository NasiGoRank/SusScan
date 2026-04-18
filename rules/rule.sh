#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${ROOT:-/opt/SusScan/rules}"
SOURCES_DIR="$ROOT/sources"
FILTERED_DIR="$ROOT/filtered"
COMPILED_DIR="$ROOT/compiled"
CORRELATION_DIR="$ROOT/correlation"
CURRENT_CORR_DIR="$CORRELATION_DIR/current"
OPTIONAL_CORR_DIR="$CORRELATION_DIR/optional"
VENV_DIR="$ROOT/.rulesync-venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"

# Public demo key from Valhalla docs.
VALHALLA_API_KEY="${VALHALLA_API_KEY:-1111111111111111111111111111111111111111111111111111111111111111}"

YARARULES_REPO="https://github.com/Yara-Rules/rules.git"
SIGBASE_REPO="https://github.com/Neo23x0/signature-base.git"
CAPA_RULES_REPO="https://github.com/mandiant/capa-rules.git"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run this script as root or with sudo."
  exit 1
fi

mkdir -p \
  "$SOURCES_DIR" \
  "$FILTERED_DIR" \
  "$COMPILED_DIR" \
  "$CORRELATION_DIR" \
  "$CURRENT_CORR_DIR" \
  "$OPTIONAL_CORR_DIR"

clone_or_pull() {
  local url="$1"
  local dest="$2"

  if [[ -d "$dest/.git" ]]; then
    echo "[*] Updating $dest"
    git -C "$dest" pull --ff-only
  else
    echo "[*] Cloning $url -> $dest"
    git clone --depth 1 "$url" "$dest"
  fi
}

echo "[*] Installing prerequisites..."
apt-get update
apt-get install -y git python3 python3-venv curl

echo "[*] Preparing Python environment..."
if [[ ! -d "$VENV_DIR" ]]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel >/dev/null
"$VENV_DIR/bin/pip" install yara-python valhallaAPI >/dev/null

echo "[*] Syncing source repositories..."
clone_or_pull "$YARARULES_REPO" "$SOURCES_DIR/yara-rules"
clone_or_pull "$SIGBASE_REPO" "$SOURCES_DIR/signature-base"
clone_or_pull "$CAPA_RULES_REPO" "$SOURCES_DIR/capa-rules"

echo "[*] Building filtered YARA rule sets and compiled bundle..."
ROOT="$ROOT" \
SOURCES_DIR="$SOURCES_DIR" \
FILTERED_DIR="$FILTERED_DIR" \
COMPILED_DIR="$COMPILED_DIR" \
VALHALLA_API_KEY="$VALHALLA_API_KEY" \
"$VENV_DIR/bin/python" <<'PY'
import os
import re
import json
import shutil
import hashlib
from pathlib import Path

import yara
from valhallaAPI.valhalla import ValhallaAPI

ROOT = Path(os.environ["ROOT"])
SOURCES_DIR = Path(os.environ["SOURCES_DIR"])
FILTERED_DIR = Path(os.environ["FILTERED_DIR"])
COMPILED_DIR = Path(os.environ["COMPILED_DIR"])
VALHALLA_API_KEY = os.environ["VALHALLA_API_KEY"]

YARARULES_SRC = SOURCES_DIR / "yara-rules"
SIGBASE_SRC = SOURCES_DIR / "signature-base"

YARARULES_OUT = FILTERED_DIR / "yara-rules"
SIGBASE_OUT = FILTERED_DIR / "signature-base"
VALHALLA_OUT = FILTERED_DIR / "valhalla"

for d in [YARARULES_OUT, SIGBASE_OUT, VALHALLA_OUT, COMPILED_DIR]:
    d.mkdir(parents=True, exist_ok=True)

for d in [YARARULES_OUT, SIGBASE_OUT, VALHALLA_OUT]:
    for item in d.iterdir():
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()

seen_content_hashes = set()
seen_rule_names = set()

manifest = {
    "yara-rules": {"accepted": 0, "skipped_duplicate_content": 0, "skipped_index_or_excluded": 0},
    "signature-base": {"accepted": 0, "skipped_duplicate_content": 0, "skipped_known_bad": 0},
    "valhalla": {"accepted": 0, "skipped_duplicate_content": 0, "skipped_duplicate_name": 0},
    "validation": {"accepted": 0, "rejected": 0, "rejected_files": []},
}

RULE_NAME_RE = re.compile(
    r'(?mi)^\s*(?:(?:private|global)\s+)*(?:rule)\s+([A-Za-z_][A-Za-z0-9_]*)\b'
)

SIGBASE_EXCLUDE = {
    "generic_anomalies.yar",
    "general_cloaking.yar",
    "gen_webshells_ext_vars.yar",
    "thor_inverse_matches.yar",
    "yara_mixed_ext_vars.yar",
    "configured_vulns_ext_vars.yar",
    "gen_fake_amsi_dll.yar",
    "expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar",
    "yara-rules_vuln_drivers_strict_renamed.yar",
}

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def extract_rule_names(text: str):
    return set(RULE_NAME_RE.findall(text))

def safe_rel_namespace(repo_name: str, rel_path: Path) -> str:
    ns = f"{repo_name}__{str(rel_path)}"
    return re.sub(r"[^A-Za-z0-9_]+", "_", ns)

def copy_if_unique(src: Path, dst_root: Path, repo_name: str, rel_path: Path) -> None:
    data = src.read_bytes()
    content_hash = sha256_bytes(data)

    if content_hash in seen_content_hashes:
        manifest[repo_name]["skipped_duplicate_content"] += 1
        return

    dst = dst_root / rel_path
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)

    seen_content_hashes.add(content_hash)

    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        text = ""
    seen_rule_names.update(extract_rule_names(text))
    manifest[repo_name]["accepted"] += 1

# 1) Filter Yara-Rules
for src in sorted(YARARULES_SRC.rglob("*")):
    if not src.is_file():
        continue

    if src.suffix.lower() not in {".yar", ".yara"}:
        continue

    rel = src.relative_to(YARARULES_SRC)
    rel_str = str(rel).replace("\\", "/")

    if rel_str.startswith("deprecated/") or rel_str.startswith("mobile_malware/"):
        manifest["yara-rules"]["skipped_index_or_excluded"] += 1
        continue

    if src.name.endswith("_index.yar") or src.name == "index.yar":
        manifest["yara-rules"]["skipped_index_or_excluded"] += 1
        continue

    copy_if_unique(src, YARARULES_OUT, "yara-rules", rel)

# 2) Filter signature-base
sigbase_yara_dir = SIGBASE_SRC / "yara"
for src in sorted(sigbase_yara_dir.rglob("*")):
    if not src.is_file():
        continue

    if src.suffix.lower() not in {".yar", ".yara"}:
        continue

    if src.name in SIGBASE_EXCLUDE:
        manifest["signature-base"]["skipped_known_bad"] += 1
        continue

    rel = src.relative_to(sigbase_yara_dir)
    copy_if_unique(src, SIGBASE_OUT, "signature-base", rel)

# 3) Pull Valhalla rules as JSON and write one file per rule
v = ValhallaAPI(api_key=VALHALLA_API_KEY)
valhalla_json = v.get_rules_json()

(COMPILED_DIR / "valhalla_raw.json").write_text(
    json.dumps(valhalla_json, indent=2),
    encoding="utf-8"
)

rules = valhalla_json.get("rules", [])
for idx, rule in enumerate(rules, start=1):
    name = rule.get("name") or f"valhalla_rule_{idx}"
    content = rule.get("content", "")

    if not content.strip():
        continue

    content_hash = sha256_bytes(content.encode("utf-8", errors="ignore"))
    if content_hash in seen_content_hashes:
        manifest["valhalla"]["skipped_duplicate_content"] += 1
        continue

    if name in seen_rule_names:
        manifest["valhalla"]["skipped_duplicate_name"] += 1
        continue

    out_path = VALHALLA_OUT / f"{name}.yar"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content, encoding="utf-8")

    seen_content_hashes.add(content_hash)
    seen_rule_names.add(name)
    manifest["valhalla"]["accepted"] += 1

# 4) Validate each filtered file individually, then compile one combined bundle
valid_filepaths = {}

for repo_name, repo_dir in [
    ("yara-rules", YARARULES_OUT),
    ("signature-base", SIGBASE_OUT),
    ("valhalla", VALHALLA_OUT),
]:
    for path in sorted(repo_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".yar", ".yara"}:
            continue

        rel = path.relative_to(repo_dir)
        ns = safe_rel_namespace(repo_name, rel)

        try:
            yara.compile(filepaths={ns: str(path)}, includes=True)
            valid_filepaths[ns] = str(path)
            manifest["validation"]["accepted"] += 1
        except Exception as e:
            manifest["validation"]["rejected"] += 1
            manifest["validation"]["rejected_files"].append({
                "file": str(path),
                "error": str(e),
            })

if not valid_filepaths:
    raise SystemExit("No valid YARA files remained after filtering/validation.")

combined_rules = yara.compile(filepaths=valid_filepaths, includes=True)
combined_rules.save(str(COMPILED_DIR / "all_combined.yarc"))

(COMPILED_DIR / "compiled_sources.json").write_text(
    json.dumps(valid_filepaths, indent=2),
    encoding="utf-8"
)
(COMPILED_DIR / "build_manifest.json").write_text(
    json.dumps(manifest, indent=2),
    encoding="utf-8"
)

print("[*] YARA bundle build done.")
print(f"[*] Combined compiled file: {COMPILED_DIR / 'all_combined.yarc'}")
PY

echo "[*] Generating correlation rule pack..."
ROOT="$ROOT" \
SOURCES_DIR="$SOURCES_DIR" \
CORRELATION_DIR="$CORRELATION_DIR" \
CURRENT_CORR_DIR="$CURRENT_CORR_DIR" \
OPTIONAL_CORR_DIR="$OPTIONAL_CORR_DIR" \
"$VENV_DIR/bin/python" <<'PY'
import json
import os
from pathlib import Path

ROOT = Path(os.environ["ROOT"])
SOURCES_DIR = Path(os.environ["SOURCES_DIR"])
CORRELATION_DIR = Path(os.environ["CORRELATION_DIR"])
CURRENT_CORR_DIR = Path(os.environ["CURRENT_CORR_DIR"])
OPTIONAL_CORR_DIR = Path(os.environ["OPTIONAL_CORR_DIR"])

for d in [CORRELATION_DIR, CURRENT_CORR_DIR, OPTIONAL_CORR_DIR]:
    d.mkdir(parents=True, exist_ok=True)

def write_json(path: Path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

feature_catalog = {
    "version": "1.0",
    "description": "Normalized feature catalog used by SusScan/SusScan phase-3-lite correlation.",
    "features": [
        {"name": "artifact_type", "type": "string"},
        {"name": "trust_state", "type": "string"},
        {"name": "signature_status", "type": "string"},
        {"name": "has_strong_yara", "type": "boolean"},
        {"name": "has_crypto_yara", "type": "boolean"},
        {"name": "has_packer_yara", "type": "boolean"},
        {"name": "has_anti_debug_yara", "type": "boolean"},
        {"name": "has_anti_vm_yara", "type": "boolean"},
        {"name": "yara_match_count", "type": "integer"},
        {"name": "hash_is_trusted", "type": "boolean"},
        {"name": "hash_is_known_malicious", "type": "boolean"},
        {"name": "pe_has_rich_header_anomaly", "type": "boolean"},
        {"name": "pe_has_sparse_iat", "type": "boolean"},
        {"name": "pe_has_section_name_entropy_correlation", "type": "boolean"},
        {"name": "pe_has_suspicious_section_names", "type": "boolean"},
        {"name": "pe_has_high_entropy_sections", "type": "boolean"},
        {"name": "pe_die_packer_keyword_count", "type": "integer"},
        {"name": "pe_has_injection_capability", "type": "boolean"},
        {"name": "pe_has_debugger_detection_capability", "type": "boolean"},
        {"name": "pe_has_vm_detection_capability", "type": "boolean"},
        {"name": "pe_has_service_persistence_capability", "type": "boolean"},
        {"name": "pe_is_packed_like", "type": "boolean"},
        {"name": "apk_requested_sensitive_permission_count", "type": "integer"},
        {"name": "apk_permission_mismatch_count", "type": "integer"},
        {"name": "apk_has_permission_mismatch", "type": "boolean"},
        {"name": "apk_has_boot_persistence_permission", "type": "boolean"},
        {"name": "apk_has_boot_persistence_mismatch", "type": "boolean"},
        {"name": "apk_has_overlay_permission", "type": "boolean"},
        {"name": "apk_has_install_packages_permission", "type": "boolean"},
        {"name": "apk_has_sms_permission", "type": "boolean"},
        {"name": "apk_has_debug_certificate", "type": "boolean"},
        {"name": "apk_has_randomized_issuer", "type": "boolean"},
        {"name": "apk_has_no_certificate_data", "type": "boolean"}
    ]
}

references = {
    "version": "1.0",
    "sources_present_on_disk": {
        "capa_rules_repo": str(SOURCES_DIR / "capa-rules"),
        "yara_rules_repo": str(SOURCES_DIR / "yara-rules"),
        "signature_base_repo": str(SOURCES_DIR / "signature-base"),
    },
    "reference_families": {
        "capability_concepts": ["capa-rules"],
        "detection_side_signals": ["YARA-Rules", "Neo23x0/signature-base", "Malpedia", "YARA Forge"],
        "standardized_behavior_naming": ["MBC", "ATT&CK"],
        "apk_heuristics": ["OWASP MASTG"]
    }
}

global_rules = [
    {
        "id": "trusted_hash_discount",
        "title": "Trusted known hash reduces risk",
        "artifact_type": "any",
        "enabled": True,
        "expr": "trust_state == 'trusted_known_hash'",
        "score_delta": -35,
        "severity": "info",
        "category": "trust",
        "reason": "Hash matched a trusted known-good source.",
        "source_basis": ["phase_1_absolute_whitelisting", "cryptographic_whitelist"],
        "standardized_behaviors": {}
    },
    {
        "id": "valid_signature_discount",
        "title": "Valid signature reduces risk",
        "artifact_type": "any",
        "enabled": True,
        "expr": "trust_state == 'trusted_signed'",
        "score_delta": -25,
        "severity": "info",
        "category": "trust",
        "reason": "Valid trusted signature lowers the chance of false positive.",
        "source_basis": ["phase_1_absolute_whitelisting", "authenticode_verification"],
        "standardized_behaviors": {}
    },
    {
        "id": "known_malicious_reputation",
        "title": "Known malicious reputation strongly increases risk",
        "artifact_type": "any",
        "enabled": True,
        "expr": "trust_state == 'known_malicious'",
        "score_delta": 40,
        "severity": "high",
        "category": "trust",
        "reason": "Hash matched a malicious reputation provider.",
        "source_basis": ["phase_1_absolute_whitelisting", "provider_chain"],
        "standardized_behaviors": {}
    },
    {
        "id": "suspicious_reputation_signal",
        "title": "Suspicious reputation increases risk",
        "artifact_type": "any",
        "enabled": True,
        "expr": "trust_state == 'suspicious_reputation'",
        "score_delta": 18,
        "severity": "medium",
        "category": "trust",
        "reason": "A reputation source reported the sample as suspicious.",
        "source_basis": ["phase_1_absolute_whitelisting", "provider_chain"],
        "standardized_behaviors": {}
    },
    {
        "id": "conflicting_reputation_signal",
        "title": "Conflicting reputation increases uncertainty",
        "artifact_type": "any",
        "enabled": True,
        "expr": "trust_state == 'conflicting_reputation'",
        "score_delta": 12,
        "severity": "medium",
        "category": "trust",
        "reason": "Local trust signals conflict with external reputation.",
        "source_basis": ["phase_1_absolute_whitelisting", "provider_chain"],
        "standardized_behaviors": {}
    },
    {
        "id": "invalid_signature_penalty",
        "title": "Invalid signature increases risk",
        "artifact_type": "pe",
        "enabled": True,
        "expr": "trust_state == 'suspicious_invalid_signature'",
        "score_delta": 8,
        "severity": "medium",
        "category": "trust",
        "reason": "PE file contains an invalid Authenticode signature.",
        "source_basis": ["phase_1_absolute_whitelisting", "authenticode_verification"],
        "standardized_behaviors": {}
    }
]

windows_pe_rules = [
    {
        "id": "pe_stealth_injection_when_packed",
        "title": "Packed PE with injection-like capability",
        "artifact_type": "pe",
        "enabled": True,
        "expr": "pe_has_injection_capability and pe_is_packed_like",
        "score_delta": 35,
        "severity": "high",
        "category": "correlation",
        "reason": "PE shows injection-like capability together with packing or stealth indicators.",
        "source_basis": ["capa-rules", "YARA-Rules", "Neo23x0/signature-base"],
        "standardized_behaviors": {
            "mbc": ["E1055 Process Injection", "F0001 Software Packing"],
            "attack": ["T1055", "T1027"]
        }
    },
    {
        "id": "pe_injection_without_packing",
        "title": "Injection-like capability without packing context",
        "artifact_type": "pe",
        "enabled": True,
        "expr": "pe_has_injection_capability and not pe_is_packed_like",
        "score_delta": 15,
        "severity": "medium",
        "category": "correlation",
        "reason": "PE shows injection-like capability, but there is not enough stealth context to treat it as strongly malicious.",
        "source_basis": ["capa-rules"],
        "standardized_behaviors": {
            "mbc": ["E1055 Process Injection"],
            "attack": ["T1055"]
        }
    },
    {
        "id": "pe_multiple_structural_lies",
        "title": "Multiple structural lies align",
        "artifact_type": "pe",
        "enabled": True,
        "expr": "pe_has_rich_header_anomaly and pe_has_sparse_iat and pe_has_section_name_entropy_correlation",
        "score_delta": 28,
        "severity": "high",
        "category": "correlation",
        "reason": "PE shows a Rich Header anomaly, sparse imports, and suspicious section/entropy correlation at the same time.",
        "source_basis": ["phase_2_structural_static_analysis"],
        "standardized_behaviors": {
            "mbc": ["F0001 Software Packing"],
            "attack": ["T1027"]
        }
    },
    {
        "id": "pe_crypto_plus_untrusted_identity",
        "title": "Crypto indicator with untrusted PE identity",
        "artifact_type": "pe",
        "enabled": True,
        "expr": "has_crypto_yara and signature_status in ['unsigned', 'invalid']",
        "score_delta": 25,
        "severity": "high",
        "category": "correlation",
        "reason": "Crypto-related YARA logic matched and the PE lacks a valid trusted identity.",
        "source_basis": ["YARA-Rules", "Neo23x0/signature-base", "Malpedia", "YARA Forge"],
        "standardized_behaviors": {
            "mbc": ["C0012 Encrypt Data"],
            "attack": ["T1486"]
        }
    },
    {
        "id": "pe_trusted_but_generic_packing_discount",
        "title": "Trust dampens generic packing suspicion",
        "artifact_type": "pe",
        "enabled": True,
        "expr": "hash_is_trusted and pe_is_packed_like and not has_strong_yara and not pe_has_injection_capability",
        "score_delta": -12,
        "severity": "info",
        "category": "correlation",
        "reason": "The PE looks packed or compressed, but strong trust signals reduce the chance of a false positive.",
        "source_basis": ["phase_1_absolute_whitelisting", "phase_3_non_linear_contextual_scoring"],
        "standardized_behaviors": {}
    },
    {
        "id": "pe_anti_analysis_cluster",
        "title": "Anti-analysis signals align",
        "artifact_type": "pe",
        "enabled": True,
        "expr": "(pe_has_debugger_detection_capability or has_anti_debug_yara) and (pe_has_vm_detection_capability or has_anti_vm_yara)",
        "score_delta": 18,
        "severity": "medium",
        "category": "correlation",
        "reason": "PE combines debugger-detection and VM/sandbox-detection style signals.",
        "source_basis": ["capa-rules", "YARA-Rules"],
        "standardized_behaviors": {
            "mbc": ["B0001 Debugger Detection", "B0009 Virtual Machine Detection"],
            "attack": ["T1497", "T1622"]
        }
    },
    {
        "id": "pe_service_persistence_plus_packing",
        "title": "Persistence-like PE plus stealth indicators",
        "artifact_type": "pe",
        "enabled": True,
        "expr": "pe_has_service_persistence_capability and pe_is_packed_like",
        "score_delta": 20,
        "severity": "medium",
        "category": "correlation",
        "reason": "Service-persistence style behavior appears together with stealthy PE structure.",
        "source_basis": ["capa-rules", "phase_2_structural_static_analysis"],
        "standardized_behaviors": {
            "mbc": ["E1100 Service"],
            "attack": ["T1543.003"]
        }
    }
]

android_apk_rules = [
    {
        "id": "apk_persistence_plus_hidden_intent",
        "title": "Persistence-oriented APK permission pattern",
        "artifact_type": "apk",
        "enabled": True,
        "expr": "apk_has_boot_persistence_permission and apk_has_boot_persistence_mismatch and (apk_has_overlay_permission or apk_has_install_packages_permission or apk_has_sms_permission)",
        "score_delta": 35,
        "severity": "high",
        "category": "correlation",
        "reason": "APK requests boot persistence and also shows additional sensitive permission patterns without clear matching code usage.",
        "source_basis": ["OWASP MASTG", "phase_2_structural_static_analysis"],
        "standardized_behaviors": {
            "attack": ["T1402", "T1411"]
        }
    },
    {
        "id": "apk_debug_cert_plus_mismatch",
        "title": "Debug certificate plus multiple permission mismatches",
        "artifact_type": "apk",
        "enabled": True,
        "expr": "apk_has_debug_certificate and apk_permission_mismatch_count >= 2",
        "score_delta": 25,
        "severity": "high",
        "category": "correlation",
        "reason": "APK is signed with a debug certificate and also requests multiple sensitive permissions without clear code evidence.",
        "source_basis": ["OWASP MASTG", "phase_2_structural_static_analysis"],
        "standardized_behaviors": {}
    },
    {
        "id": "apk_randomized_issuer_sensitive_combo",
        "title": "Randomized issuer with sensitive APK permissions",
        "artifact_type": "apk",
        "enabled": True,
        "expr": "apk_has_randomized_issuer and (apk_has_overlay_permission or apk_has_install_packages_permission or apk_has_sms_permission)",
        "score_delta": 15,
        "severity": "medium",
        "category": "correlation",
        "reason": "APK certificate issuer looks machine-generated while the app also requests a high-risk permission combination.",
        "source_basis": ["OWASP MASTG", "phase_2_structural_static_analysis"],
        "standardized_behaviors": {}
    },
    {
        "id": "apk_trusted_hash_discount",
        "title": "Trusted APK hash reduces borderline suspicion",
        "artifact_type": "apk",
        "enabled": True,
        "expr": "hash_is_trusted and apk_permission_mismatch_count <= 1 and not has_strong_yara",
        "score_delta": -15,
        "severity": "info",
        "category": "correlation",
        "reason": "Trusted APK hash reduces the chance that light structural concerns are false positives.",
        "source_basis": ["phase_1_absolute_whitelisting"],
        "standardized_behaviors": {}
    },
    {
        "id": "apk_excessive_permission_pressure",
        "title": "Excessive sensitive permission pressure",
        "artifact_type": "apk",
        "enabled": True,
        "expr": "apk_requested_sensitive_permission_count >= 4 and apk_has_permission_mismatch",
        "score_delta": 14,
        "severity": "medium",
        "category": "correlation",
        "reason": "APK requests many sensitive permissions and at least some do not map cleanly to observed code usage.",
        "source_basis": ["OWASP MASTG", "phase_2_structural_static_analysis"],
        "standardized_behaviors": {}
    },
    {
        "id": "apk_sms_plus_overlay_combo",
        "title": "SMS plus overlay capability pattern",
        "artifact_type": "apk",
        "enabled": True,
        "expr": "apk_has_sms_permission and apk_has_overlay_permission",
        "score_delta": 18,
        "severity": "medium",
        "category": "correlation",
        "reason": "APK requests both SMS-related and overlay permissions, a combination often worth extra scrutiny.",
        "source_basis": ["OWASP MASTG"],
        "standardized_behaviors": {
            "attack": ["T1412"]
        }
    }
]

android_future_rules = [
    {
        "id": "apk_debuggable_release_build",
        "title": "Debuggable release-style APK",
        "artifact_type": "apk",
        "enabled": False,
        "expr": "apk_is_debuggable",
        "score_delta": 12,
        "severity": "medium",
        "category": "future",
        "reason": "APK appears debuggable in a release-like context.",
        "source_basis": ["OWASP MASTG"],
        "standardized_behaviors": {}
    },
    {
        "id": "apk_dynamic_code_runtime_fetch",
        "title": "Dynamic code loading signal",
        "artifact_type": "apk",
        "enabled": False,
        "expr": "apk_has_dynamic_code_loading",
        "score_delta": 20,
        "severity": "high",
        "category": "future",
        "reason": "APK shows signs of dynamic code loading at runtime.",
        "source_basis": ["OWASP MASTG", "ATT&CK Mobile"],
        "standardized_behaviors": {
            "attack": ["T1407"]
        }
    },
    {
        "id": "apk_hidden_launcher_plus_boot",
        "title": "Boot persistence with hidden launcher behavior",
        "artifact_type": "apk",
        "enabled": False,
        "expr": "apk_has_hidden_launcher_behavior and apk_has_boot_persistence_permission",
        "score_delta": 30,
        "severity": "high",
        "category": "future",
        "reason": "APK auto-starts on boot and appears to hide user-facing launcher behavior.",
        "source_basis": ["OWASP MASTG", "phase_3_non_linear_contextual_scoring"],
        "standardized_behaviors": {
            "attack": ["T1402"]
        }
    }
]

manifest = {
    "name": "SusScan-correlation-rule-pack",
    "version": "1.0",
    "root": str(CORRELATION_DIR),
    "files": {
        "feature_catalog": "feature_catalog.json",
        "references": "references.json",
        "current": [
            "current/global_rules.json",
            "current/windows_pe_rules.json",
            "current/android_apk_rules.json"
        ],
        "optional": [
            "optional/android_mastg_future_rules.json"
        ]
    }
}

write_json(CORRELATION_DIR / "feature_catalog.json", feature_catalog)
write_json(CORRELATION_DIR / "references.json", references)
write_json(CURRENT_CORR_DIR / "global_rules.json", global_rules)
write_json(CURRENT_CORR_DIR / "windows_pe_rules.json", windows_pe_rules)
write_json(CURRENT_CORR_DIR / "android_apk_rules.json", android_apk_rules)
write_json(OPTIONAL_CORR_DIR / "android_mastg_future_rules.json", android_future_rules)
write_json(CORRELATION_DIR / "manifest.json", manifest)

print("[*] Correlation rule pack generated.")
print(f"[*] Manifest: {CORRELATION_DIR / 'manifest.json'}")
PY

echo
echo "[*] Finished."
echo "[*] YARA filtered folders:"
echo "    $FILTERED_DIR/yara-rules"
echo "    $FILTERED_DIR/signature-base"
echo "    $FILTERED_DIR/valhalla"
echo
echo "[*] YARA compiled bundle:"
echo "    $COMPILED_DIR/all_combined.yarc"
echo
echo "[*] Correlation files:"
echo "    $CORRELATION_DIR/feature_catalog.json"
echo "    $CORRELATION_DIR/references.json"
echo "    $CURRENT_CORR_DIR/global_rules.json"
echo "    $CURRENT_CORR_DIR/windows_pe_rules.json"
echo "    $CURRENT_CORR_DIR/android_apk_rules.json"
echo "    $OPTIONAL_CORR_DIR/android_mastg_future_rules.json"
echo "    $CORRELATION_DIR/manifest.json"