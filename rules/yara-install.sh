#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${ROOT:-/opt/staticlab/rules}"
SOURCES_DIR="$ROOT/sources"
FILTERED_DIR="$ROOT/filtered"
COMPILED_DIR="$ROOT/compiled"
VENV_DIR="$ROOT/.rulesync-venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"

# Public demo key from Valhalla docs.
VALHALLA_API_KEY="${VALHALLA_API_KEY:-1111111111111111111111111111111111111111111111111111111111111111}"

YARARULES_REPO="https://github.com/Yara-Rules/rules.git"
SIGBASE_REPO="https://github.com/Neo23x0/signature-base.git"

mkdir -p "$SOURCES_DIR" "$FILTERED_DIR" "$COMPILED_DIR"

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
apt-get install -y git python3 python3-venv

echo "[*] Preparing Python environment..."
if [[ ! -d "$VENV_DIR" ]]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel >/dev/null
"$VENV_DIR/bin/pip" install yara-python valhallaAPI >/dev/null

echo "[*] Syncing source repositories..."
clone_or_pull "$YARARULES_REPO" "$SOURCES_DIR/yara-rules"
clone_or_pull "$SIGBASE_REPO" "$SOURCES_DIR/signature-base"

echo "[*] Building filtered rule sets and compiled bundle..."
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

# Clean filtered output so each run is deterministic.
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

    # Exclude deprecated mobile rules and deprecated folder.
    if rel_str.startswith("deprecated/") or rel_str.startswith("mobile_malware/"):
        manifest["yara-rules"]["skipped_index_or_excluded"] += 1
        continue

    # Exclude index bundles to avoid duplicate inclusion of leaf rules.
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

# Save raw JSON for reference/debugging
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

    # Valhalla demo overlaps processed signature-base heavily,
    # so dedupe by rule name too.
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

# Also write a source list and manifest
(COMPILED_DIR / "compiled_sources.json").write_text(
    json.dumps(valid_filepaths, indent=2),
    encoding="utf-8"
)
(COMPILED_DIR / "build_manifest.json").write_text(
    json.dumps(manifest, indent=2),
    encoding="utf-8"
)

print("[*] Done.")
print(f"[*] Combined compiled file: {COMPILED_DIR / 'all_combined.yarc'}")
print(f"[*] Manifest: {COMPILED_DIR / 'build_manifest.json'}")
print(f"[*] Rejected files logged: {manifest['validation']['rejected']}")
PY

echo
echo "[*] Finished."
echo "[*] Filtered folders:"
echo "    $FILTERED_DIR/yara-rules"
echo "    $FILTERED_DIR/signature-base"
echo "    $FILTERED_DIR/valhalla"
echo
echo "[*] Compiled file:"
echo "    $COMPILED_DIR/all_combined.yarc"
echo
echo "[*] Build manifest:"
echo "    $COMPILED_DIR/build_manifest.json"