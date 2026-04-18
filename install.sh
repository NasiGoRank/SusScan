#!/usr/bin/env bash
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run this script as root or with sudo."
  exit 1
fi

APP_ROOT="/opt/SusScan"
APP_DIR="${APP_ROOT}/app"
DATA_DIR="${APP_ROOT}/data"
TOOLS_DIR="${APP_ROOT}/tools"
RULES_DIR="${APP_ROOT}/rules"
VENV_DIR="${APP_ROOT}/venv"
BIN_DIR="${APP_ROOT}/bin"
ENV_FILE="${APP_ROOT}/.env"
ENV_EXAMPLE_FILE="${APP_ROOT}/.env.example"
SERVICE_NAME="susscan"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
detect_run_user() {
  if [[ -n "${APP_RUN_USER:-}" ]]; then
    printf '%s\n' "${APP_RUN_USER}"
    return
  fi

  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    printf '%s\n' "${SUDO_USER}"
    return
  fi

  if [[ -n "${PKEXEC_UID:-}" ]]; then
    local pk_user
    pk_user="$(getent passwd "${PKEXEC_UID}" | cut -d: -f1 || true)"
    if [[ -n "${pk_user}" && "${pk_user}" != "root" ]]; then
      printf '%s\n' "${pk_user}"
      return
    fi
  fi

  local console_user
  console_user="$(logname 2>/dev/null || true)"
  if [[ -n "${console_user}" && "${console_user}" != "root" ]]; then
    printf '%s\n' "${console_user}"
    return
  fi

  printf '%s\n' "main"
}

APP_RUN_USER="$(detect_run_user)"
TMP_DIR="$(mktemp -d)"
ARCH="$(uname -m)"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-${SCRIPT_DIR}}"

cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

log() {
  echo
  echo "[*] $*"
}

warn() {
  echo
  echo "[!] $*"
}

fail() {
  echo
  echo "[x] $*" >&2
  exit 1
}

download() {
  local url="$1"
  local out="$2"
  curl -fsSL --retry 3 --retry-delay 2 -H "User-Agent: SusScan-installer" "$url" -o "$out"
}

url_exists() {
  local url="$1"
  curl -fsI -H "User-Agent: SusScan-installer" "$url" >/dev/null 2>&1
}

gh_latest_asset_url() {
  local repo="$1"
  local pattern="$2"

  python3 - "$repo" "$pattern" <<'PY'
import json
import re
import sys
import urllib.request

repo = sys.argv[1]
pattern = re.compile(sys.argv[2])

url = f"https://api.github.com/repos/{repo}/releases/latest"
req = urllib.request.Request(
    url,
    headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "SusScan-installer",
    },
)

with urllib.request.urlopen(req) as resp:
    data = json.load(resp)

for asset in data.get("assets", []):
    name = asset.get("name", "")
    if pattern.search(name):
        print(asset["browser_download_url"])
        sys.exit(0)

raise SystemExit(f"No matching asset found for {repo} with pattern: {pattern.pattern}")
PY
}

gh_latest_tag() {
  local repo="$1"

  python3 - "$repo" <<'PY'
import json
import sys
import urllib.request

repo = sys.argv[1]
url = f"https://api.github.com/repos/{repo}/releases/latest"
req = urllib.request.Request(
    url,
    headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "SusScan-installer",
    },
)

with urllib.request.urlopen(req) as resp:
    data = json.load(resp)

print(data.get("tag_name", ""))
PY
}

find_one() {
  local root="$1"
  local name="$2"
  find "$root" -type f -name "$name" | head -n 1
}

set_env_value() {
  local file="$1"
  local key="$2"
  local value="$3"

  python3 - "$file" "$key" "$value" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
key = sys.argv[2]
value = sys.argv[3]
lines = path.read_text().splitlines() if path.exists() else []
needle = f"{key}="
replaced = False
new_lines = []
for line in lines:
    if line.startswith(needle):
        new_lines.append(f"{key}={value}")
        replaced = True
    else:
        new_lines.append(line)
if not replaced:
    new_lines.append(f"{key}={value}")
path.write_text("\n".join(new_lines).rstrip() + "\n")
PY
}

prompt_secret() {
  local label="$1"
  local current="$2"
  local value=""
  if [[ -n "$current" ]]; then
    read -r -s -p "${label} [press Enter to keep current]: " value
    echo
    if [[ -z "$value" ]]; then
      value="$current"
    fi
  else
    read -r -s -p "${label}: " value
    echo
  fi
  printf '%s' "$value"
}

sync_app_source_if_present() {
  if [[ -f "${SCRIPT_DIR}/main.py" && -d "${SCRIPT_DIR}/services" && -d "${SCRIPT_DIR}/templates" ]]; then
    log "Syncing application source into ${APP_DIR}..."
    rsync -a --delete \
      --exclude '.git/' \
      --exclude '__pycache__/' \
      --exclude '*.pyc' \
      --exclude 'venv/' \
      --exclude '.env' \
      --exclude '.env.*' \
      --exclude 'data/' \
      --exclude 'tools/' \
      --exclude 'rules/' \
      --exclude 'install*.sh' \
      "${SCRIPT_DIR}/" "${APP_DIR}/"
  else
    warn "Installer did not detect app source files next to install script."
    warn "Make sure your code is placed in ${APP_DIR} before starting the service."
  fi
}

sync_rule_assets_if_present() {
  local rule_script_source=""

  log "Syncing bundled rule assets from the repository if present..."
  if [[ -d "${REPO_ROOT}/rules" ]]; then
    mkdir -p "${RULES_DIR}"
    cp -a "${REPO_ROOT}/rules/." "${RULES_DIR}/"
    log "Bundled rules copied from ${REPO_ROOT}/rules -> ${RULES_DIR}"
  else
    warn "No bundled rules directory found at ${REPO_ROOT}/rules; skipping repo rule sync."
  fi

  if [[ -f "${REPO_ROOT}/rule.sh" ]]; then
    rule_script_source="${REPO_ROOT}/rule.sh"
  elif [[ -f "${APP_DIR}/rule.sh" ]]; then
    rule_script_source="${APP_DIR}/rule.sh"
  fi

  if [[ -n "${rule_script_source}" ]]; then
    log "Installing rule.sh helper..."
    install -m 0755 "${rule_script_source}" "${APP_ROOT}/rule.sh"
  else
    warn "No rule.sh found in the repository or app directory; skipping rule helper install."
  fi
}

run_rule_setup_if_present() {
  if [[ "${SKIP_RULE_SETUP:-0}" == "1" ]]; then
    warn "SKIP_RULE_SETUP=1 was set. Skipping rule.sh execution."
    return 0
  fi

  local rule_script=""
  if [[ -f "${APP_ROOT}/rule.sh" ]]; then
    rule_script="${APP_ROOT}/rule.sh"
  elif [[ -f "${APP_DIR}/rule.sh" ]]; then
    rule_script="${APP_DIR}/rule.sh"
  elif [[ -f "${SCRIPT_DIR}/rule.sh" ]]; then
    rule_script="${SCRIPT_DIR}/rule.sh"
  fi

  if [[ -z "${rule_script}" ]]; then
    warn "No rule.sh found. Skipping rule setup."
    return 0
  fi

  log "Running rule.sh to set up SusScan rules..."
  export SUSSCAN_HOME="${APP_ROOT}"
  export APP_ROOT APP_DIR DATA_DIR TOOLS_DIR RULES_DIR VENV_DIR BIN_DIR
  bash "${rule_script}" || fail "rule.sh failed. Fix it and rerun /opt/SusScan/rule.sh, or rerun installer with SKIP_RULE_SETUP=1 to skip this step."
}


write_env_templates() {
  log "Writing environment template files..."
  cat > "${ENV_EXAMPLE_FILE}" <<'EOF2'
# Copy to /opt/SusScan/.env and fill the values you need.
# Minimum required to start the systemd service:
#   - SUSSCAN_GROQ_API_KEY
#   - at least one of the hash/reputation API keys below

SUSSCAN_HOME=/opt/SusScan

# Runtime
SUSSCAN_MAX_UPLOAD_SIZE_MB=100
SUSSCAN_PROCESS_TIMEOUT_SECONDS=300
SUSSCAN_ENABLE_JADX_DECOMPILE=true

# Trust / reputation controls
SUSSCAN_ENABLE_PHASE1_TRUST=true
SUSSCAN_ENABLE_HASH_LOOKUP=true
SUSSCAN_ENABLE_PE_SIGNATURE_VERIFICATION=true
SUSSCAN_HASH_LOOKUP_PROVIDER=circl_hashlookup
SUSSCAN_HASH_LOOKUP_URL=https://hashlookup.circl.lu/lookup/sha256/
SUSSCAN_HASH_LOOKUP_TIMEOUT_SECONDS=8
SUSSCAN_TRUST_CACHE_TTL_HOURS=168
SUSSCAN_ENABLE_REPUTATION_ENRICHMENT=true
SUSSCAN_ENABLED_REPUTATION_PROVIDERS=malwarebazaar,hybrid_analysis,metadefender,virustotal
SUSSCAN_REPUTATION_TIMEOUT_SECONDS=10
SUSSCAN_MIN_MALICIOUS_PROVIDER_HITS_FOR_KNOWN_MALICIOUS=2
SUSSCAN_MIN_POSITIVE_PROVIDER_HITS_FOR_SUSPICIOUS=1

# Optional provider keys. At least one is required before the service may start.
SUSSCAN_MALWAREBAZAAR_API_KEY=
SUSSCAN_MALWAREBAZAAR_URL=https://mb-api.abuse.ch/api/v1/

SUSSCAN_HYBRID_ANALYSIS_API_KEY=
SUSSCAN_HYBRID_ANALYSIS_SEARCH_URL=https://hybrid-analysis.com/api/v2/search/hash

SUSSCAN_METADEFENDER_API_KEY=
SUSSCAN_METADEFENDER_HASH_URL=https://api.metadefender.com/v4/hash

SUSSCAN_VIRUSTOTAL_API_KEY=
SUSSCAN_VIRUSTOTAL_FILE_URL=https://www.virustotal.com/api/v3/files

# Report chat. Groq key is required before the service may start.
SUSSCAN_GROQ_API_KEY=
SUSSCAN_GROQ_MODEL=llama-3.3-70b-versatile
SUSSCAN_GROQ_CHAT_COMPLETIONS_URL=https://api.groq.com/openai/v1/chat/completions
SUSSCAN_GROQ_TIMEOUT_SECONDS=45
SUSSCAN_GROQ_MAX_COMPLETION_TOKENS=700
SUSSCAN_GROQ_TEMPERATURE=0.2
SUSSCAN_REPORT_CHAT_HISTORY_TURN_LIMIT=8
EOF2

  if [[ ! -f "${ENV_FILE}" ]]; then
    cp "${ENV_EXAMPLE_FILE}" "${ENV_FILE}"
    chmod 600 "${ENV_FILE}"
  fi
}

configure_env_interactively() {
  if [[ ! -t 0 ]]; then
    warn "Non-interactive shell detected. Skipping API key prompts."
    return 0
  fi

  echo
  read -r -p "Do you want to configure required API keys now? [Y/n]: " configure_now
  configure_now="${configure_now:-Y}"
  if [[ ! "$configure_now" =~ ^[Yy]$ ]]; then
    return 0
  fi

  set -a
  source "${ENV_FILE}"
  set +a

  local groq_key="${SUSSCAN_GROQ_API_KEY:-}"
  local mb_key="${SUSSCAN_MALWAREBAZAAR_API_KEY:-}"
  local ha_key="${SUSSCAN_HYBRID_ANALYSIS_API_KEY:-}"
  local md_key="${SUSSCAN_METADEFENDER_API_KEY:-}"
  local vt_key="${SUSSCAN_VIRUSTOTAL_API_KEY:-}"

  echo
  echo "Enter your API keys. Leave any optional provider blank if you do not want to use it yet."
  groq_key="$(prompt_secret "Groq API key (required)" "$groq_key")"
  mb_key="$(prompt_secret "MalwareBazaar API key (optional)" "$mb_key")"
  ha_key="$(prompt_secret "Hybrid Analysis API key (optional)" "$ha_key")"
  md_key="$(prompt_secret "MetaDefender API key (optional)" "$md_key")"
  vt_key="$(prompt_secret "VirusTotal API key (optional)" "$vt_key")"

  set_env_value "${ENV_FILE}" "SUSSCAN_GROQ_API_KEY" "$groq_key"
  set_env_value "${ENV_FILE}" "SUSSCAN_MALWAREBAZAAR_API_KEY" "$mb_key"
  set_env_value "${ENV_FILE}" "SUSSCAN_HYBRID_ANALYSIS_API_KEY" "$ha_key"
  set_env_value "${ENV_FILE}" "SUSSCAN_METADEFENDER_API_KEY" "$md_key"
  set_env_value "${ENV_FILE}" "SUSSCAN_VIRUSTOTAL_API_KEY" "$vt_key"
  chmod 600 "${ENV_FILE}"
}

write_helper_scripts() {
  log "Writing helper scripts..."

  cat > "${APP_ROOT}/activate.sh" <<EOF2
#!/usr/bin/env bash
source "${VENV_DIR}/bin/activate"
export SUSSCAN_HOME="${APP_ROOT}"
export STATICLAB_HOME="${APP_ROOT}"
export PATH="${VENV_DIR}/bin:\$PATH"
if [[ -f "${ENV_FILE}" ]]; then
  set -a
  source "${ENV_FILE}"
  set +a
elif [[ -f "${APP_DIR}/.env" ]]; then
  set -a
  source "${APP_DIR}/.env"
  set +a
fi
EOF2
  chmod +x "${APP_ROOT}/activate.sh"

  cat > "${BIN_DIR}/validate_env.sh" <<'EOF2'
#!/usr/bin/env bash
set -Eeuo pipefail
ENV_FILE="/opt/SusScan/.env"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Missing /opt/SusScan/.env. Copy .env.example first." >&2
  exit 1
fi

set -a
source "${ENV_FILE}"
set +a

if [[ -z "${SUSSCAN_GROQ_API_KEY:-}" ]]; then
  echo "SUSSCAN_GROQ_API_KEY is required before SusScan may start." >&2
  exit 1
fi

hash_provider_count=0
for key_name in \
  SUSSCAN_MALWAREBAZAAR_API_KEY \
  SUSSCAN_HYBRID_ANALYSIS_API_KEY \
  SUSSCAN_METADEFENDER_API_KEY \
  SUSSCAN_VIRUSTOTAL_API_KEY
  do
    if [[ -n "${!key_name:-}" ]]; then
      hash_provider_count=$((hash_provider_count + 1))
    fi
  done

if (( hash_provider_count < 1 )); then
  echo "At least one hash/reputation API key is required before SusScan may start." >&2
  exit 1
fi
EOF2
  chmod +x "${BIN_DIR}/validate_env.sh"

  cat > "${BIN_DIR}/configure_env.sh" <<'EOF2'
#!/usr/bin/env bash
set -Eeuo pipefail
ENV_FILE="/opt/SusScan/.env"
if [[ ! -f "${ENV_FILE}" ]]; then
  cp /opt/SusScan/.env.example "${ENV_FILE}"
  chmod 600 "${ENV_FILE}"
fi
editor="${EDITOR:-nano}"
exec "$editor" "${ENV_FILE}"
EOF2
  chmod +x "${BIN_DIR}/configure_env.sh"
}

write_systemd_service() {
  log "Writing systemd service..."
  cat > "${SERVICE_FILE}" <<EOF2
[Unit]
Description=SusScan FastAPI app
After=network.target

[Service]
Type=simple
User=${APP_RUN_USER}
Group=${APP_RUN_USER}
WorkingDirectory=${APP_DIR}
ExecStartPre=${BIN_DIR}/validate_env.sh
ExecStart=${VENV_DIR}/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8080
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF2

  systemctl daemon-reload
}

maybe_enable_and_start_service() {
  if "${BIN_DIR}/validate_env.sh"; then
    log "Required API keys detected. Enabling and starting ${SERVICE_NAME}.service..."
    systemctl enable --now "${SERVICE_NAME}"
  else
    warn "SusScan service was installed but not started."
    warn "Reason: required API keys are still missing."
    warn "Edit ${ENV_FILE}, then start it with: sudo systemctl enable --now ${SERVICE_NAME}"
  fi
}

log "Updating apt metadata and installing system packages..."
apt-get update
apt-get install -y \
  ca-certificates \
  curl \
  wget \
  unzip \
  zip \
  git \
  jq \
  file \
  sqlite3 \
  rsync \
  python3 \
  python3-dev \
  python3-venv \
  python3-pip \
  build-essential \
  pkg-config \
  libssl-dev \
  libffi-dev \
  libmagic1 \
  libmagic-dev \
  default-jre-headless \
  yara \
  osslsigncode

log "Creating project directories..."
install -d -m 0755 \
  "${APP_ROOT}" \
  "${APP_DIR}" \
  "${DATA_DIR}/uploads" \
  "${DATA_DIR}/jobs" \
  "${DATA_DIR}/reports" \
  "${DATA_DIR}/decompiled" \
  "${TOOLS_DIR}" \
  "${RULES_DIR}" \
  "${RULES_DIR}/compiled" \
  "${RULES_DIR}/filtered" \
  "${RULES_DIR}/sources" \
  "${RULES_DIR}/correlation" \
  "${RULES_DIR}/correlation/current" \
  "${BIN_DIR}"

if ! id -u "${APP_RUN_USER}" >/dev/null 2>&1; then
  fail "Service user '${APP_RUN_USER}' does not exist. Set APP_RUN_USER before running installer."
fi

log "Detected service user: ${APP_RUN_USER}"

log "Creating Python virtual environment..."
if [[ ! -d "${VENV_DIR}" ]]; then
  python3 -m venv "${VENV_DIR}"
fi
"${VENV_DIR}/bin/pip" install --upgrade pip setuptools wheel

log "Installing Python dependencies..."
"${VENV_DIR}/bin/pip" install \
  fastapi \
  "uvicorn[standard]" \
  python-multipart \
  jinja2 \
  pydantic \
  python-magic \
  yara-python \
  androguard \
  pefile \
  flare-capa \
  openai \
  python-dotenv \
  requests

sync_app_source_if_present
sync_rule_assets_if_present
write_env_templates
configure_env_interactively
write_helper_scripts

log "Installing JADX (latest cross-platform Linux zip release)..."
JADX_URL="$(gh_latest_asset_url "skylot/jadx" '^jadx-[0-9].*\.zip$')"
mkdir -p "${TOOLS_DIR}/jadx"
download "${JADX_URL}" "${TMP_DIR}/jadx.zip"
rm -rf "${TOOLS_DIR}/jadx"/*
unzip -q "${TMP_DIR}/jadx.zip" -d "${TOOLS_DIR}/jadx"
JADX_BIN="$(find_one "${TOOLS_DIR}/jadx" 'jadx')"
JADX_GUI="$(find_one "${TOOLS_DIR}/jadx" 'jadx-gui')"
[[ -n "${JADX_BIN}" && -n "${JADX_GUI}" ]] || fail "Failed to locate JADX binaries after extraction."
chmod +x "${JADX_BIN}" "${JADX_GUI}"
ln -sfn "${JADX_BIN}" /usr/local/bin/jadx
ln -sfn "${JADX_GUI}" /usr/local/bin/jadx-gui

log "Installing capa through the Python virtual environment and downloading matching rules..."
CAPA_VERSION="$(${VENV_DIR}/bin/python - <<'PY'
import importlib.metadata
print(importlib.metadata.version("flare-capa"))
PY
)"
CAPA_RULES_CANDIDATE_URL="https://github.com/mandiant/capa-rules/archive/refs/tags/v${CAPA_VERSION}.zip"
if url_exists "${CAPA_RULES_CANDIDATE_URL}"; then
  CAPA_RULES_URL="${CAPA_RULES_CANDIDATE_URL}"
else
  warn "No exact capa-rules tag for flare-capa ${CAPA_VERSION}; falling back to the latest capa-rules release."
  CAPA_RULES_TAG="$(gh_latest_tag "mandiant/capa-rules")"
  [[ -n "${CAPA_RULES_TAG}" ]] || fail "Failed to resolve latest capa-rules tag."
  CAPA_RULES_URL="https://github.com/mandiant/capa-rules/archive/refs/tags/${CAPA_RULES_TAG}.zip"
fi

download "${CAPA_RULES_URL}" "${TMP_DIR}/capa-rules.zip"
rm -rf "${TOOLS_DIR}/capa-rules" "${TOOLS_DIR}"/capa-rules-* "${TOOLS_DIR}/capa"
unzip -q "${TMP_DIR}/capa-rules.zip" -d "${TOOLS_DIR}"
CAPA_RULES_EXTRACTED_DIR="$(find "${TOOLS_DIR}" -maxdepth 1 -mindepth 1 -type d -name 'capa-rules*' | head -n 1)"
[[ -n "${CAPA_RULES_EXTRACTED_DIR}" ]] || fail "Failed to locate extracted capa-rules directory."
ln -sfn "${CAPA_RULES_EXTRACTED_DIR}" "${TOOLS_DIR}/capa-rules"
cat > /usr/local/bin/capa <<EOF2
#!/usr/bin/env bash
exec "${VENV_DIR}/bin/capa" -r "${TOOLS_DIR}/capa-rules" "\$@"
EOF2
chmod +x /usr/local/bin/capa

log "Installing FLOSS (latest Linux zip release)..."
FLOSS_URL="$(gh_latest_asset_url "mandiant/flare-floss" 'linux.*\.zip$')"
mkdir -p "${TOOLS_DIR}/floss"
download "${FLOSS_URL}" "${TMP_DIR}/floss.zip"
rm -rf "${TOOLS_DIR}/floss"/*
unzip -q "${TMP_DIR}/floss.zip" -d "${TOOLS_DIR}/floss"
FLOSS_BIN="$(find_one "${TOOLS_DIR}/floss" 'floss')"
[[ -n "${FLOSS_BIN}" ]] || fail "Failed to locate FLOSS binary after extraction."
chmod +x "${FLOSS_BIN}"
ln -sfn "${FLOSS_BIN}" /usr/local/bin/floss

if [[ "${ARCH}" =~ ^(x86_64|amd64)$ ]]; then
  log "Installing Detect It Easy (latest x86_64 AppImage)..."
  DIE_URL="$(gh_latest_asset_url "horsicq/DIE-engine" 'Detect_It_Easy-.*-x86_64\.AppImage$')"
  mkdir -p "${TOOLS_DIR}/die"
  download "${DIE_URL}" "${TOOLS_DIR}/die/Detect_It_Easy.AppImage"
  chmod +x "${TOOLS_DIR}/die/Detect_It_Easy.AppImage"
  cat > /usr/local/bin/die <<'EOF2'
#!/usr/bin/env bash
set -Eeuo pipefail
APPIMAGE_EXTRACT_AND_RUN=1 exec /opt/SusScan/tools/die/Detect_It_Easy.AppImage "$@"
EOF2
  chmod +x /usr/local/bin/die
  ln -sfn /usr/local/bin/die /usr/local/bin/diec
  ln -sfn /usr/local/bin/die /usr/local/bin/diel
else
  warn "Skipping Detect It Easy: upstream Linux assets are x86_64/amd64 only. Current architecture: ${ARCH}"
fi

log "Writing a tiny sample YARA rule..."
cat > "${RULES_DIR}/sample.yar" <<'EOF2'
rule always_true_sample
{
  condition:
    true
}
EOF2

run_rule_setup_if_present

write_systemd_service

log "Running smoke tests..."
echo "Python: $(python3 --version)"
echo "Java:"
java -version || true
echo "YARA: $(yara --version || true)"
echo "SQLite: $(sqlite3 --version || true)"
echo "osslsigncode: $(osslsigncode --version 2>/dev/null || true)"
echo "Architecture: ${ARCH}"

"${VENV_DIR}/bin/python" - <<'PY'
import fastapi
import magic
import yara
import androguard
import pefile
import requests
import importlib.metadata
import openai
import dotenv
print("Python packages: OK")
print("flare-capa version:", importlib.metadata.version("flare-capa"))
print("openai version:", importlib.metadata.version("openai"))
print("python-dotenv version:", importlib.metadata.version("python-dotenv"))
print("requests version:", importlib.metadata.version("requests"))
PY

echo "JADX version:"
jadx --version || true

echo "capa version:"
capa --version || true

echo "FLOSS version:"
floss --version || true

if command -v diec >/dev/null 2>&1; then
  echo "DiE wrapper installed at: $(command -v diec)"
else
  echo "DiE wrapper: skipped"
fi

chown -R "${APP_RUN_USER}:${APP_RUN_USER}" "${APP_ROOT}"
maybe_enable_and_start_service

echo
echo "Install complete."
echo "Project root : ${APP_ROOT}"
echo "App dir      : ${APP_DIR}"
echo "Python venv  : ${VENV_DIR}"
echo "Rules dir    : ${RULES_DIR}"
echo "Service name : ${SERVICE_NAME}.service"
echo
echo "Useful commands:"
echo "  sudo systemctl status ${SERVICE_NAME}"
echo "  sudo journalctl -u ${SERVICE_NAME} -f"
echo "  ${BIN_DIR}/configure_env.sh"
if [[ -f "${APP_ROOT}/rule.sh" ]]; then
  echo "  sudo ${APP_ROOT}/rule.sh"
fi
echo
