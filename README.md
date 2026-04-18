# SusScan

SusScan is a Linux-based static analysis platform for suspicious **Windows PE** and **Android APK** files.

It performs:

- file hashing and reputation lookup
- PE/APK static analysis
- YARA-based detection
- deterministic correlation scoring
- HTML report generation
- report-grounded chatbot explanation

The project is designed to run on a single Linux server and install itself into:

```text
/opt/SusScan
```

---

## Features

- Upload and analyze suspicious **PE** and **APK** files
- SHA-256 based trust / reputation enrichment
- PE analysis using:
  - `pefile`
  - `Detect It Easy (DiE)`
  - `FLOSS`
  - `capa`
  - `osslsigncode`
- APK analysis using:
  - `Androguard`
  - `JADX`
- YARA scanning
- Deterministic contextual correlation engine
- HTML report page
- Report-grounded Groq chatbot
- Systemd service support
- Installer can:
  - install dependencies
  - copy app source into `/opt/SusScan/app`
  - sync bundled `rules/`
  - copy and run `rule.sh`
  - create and validate `.env`
  - install and start `susscan.service`

---

## Supported Artifact Types

- Windows PE (`.exe`, `.dll`, etc.)
- Android APK (`.apk`)

---

## Requirements

Tested for:

- Ubuntu Server 24.04 or similar Debian/Ubuntu-based Linux

You need:

- sudo/root access
- internet connection during installation
- a GitHub clone of this repository

---

## Repository Layout

Expected repository layout:

```text
SusScan/
├── README.md
├── .gitignore
├── .env.example
├── install.sh
├── main.py
├── config.py
├── db.py
├── schemas.py
├── services/
├── templates/
├── utils/
├── rules/
└── rule.sh
```

Important notes:

- Put the installer in the **repo root**
- Keep `rules/` in the **repo root** if you want the installer to sync them automatically
- Keep `rule.sh` in the **repo root** if you want the installer to copy and run it automatically

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/NasiGoRank/SusScan.git
cd SusScan
```

### 2. Run the installer

```bash
sudo bash install.sh.sh
```

What the installer does:

- installs required system packages
- creates `/opt/SusScan`
- creates Python virtual environment
- installs Python dependencies
- copies app source into `/opt/SusScan/app`
- copies bundled `rules/` into `/opt/SusScan/rules`
- copies and runs `rule.sh` if present
- creates `/opt/SusScan/.env.example`
- creates `/opt/SusScan/.env` if missing
- installs `susscan.service`
- starts the service only if required API keys are configured

### 3. Configure the environment

Edit:

```bash
sudo nano /opt/SusScan/.env
```

At minimum, the service requires:

- [`SUSSCAN_GROQ_API_KEY`](https://console.groq.com/keys)
- at least **one** of:
  - [`SUSSCAN_MALWAREBAZAAR_API_KEY`](https://bazaar.abuse.ch/api/)
  - [`SUSSCAN_HYBRID_ANALYSIS_API_KEY`](https://hybrid-analysis.com/docs/api/v2)
  - [`SUSSCAN_METADEFENDER_API_KEY`](https://www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4)
  - [`SUSSCAN_VIRUSTOTAL_API_KEY`](https://docs.virustotal.com/reference/overview)

Example:

```env
SUSSCAN_GROQ_API_KEY=your_groq_key_here
SUSSCAN_GROQ_MODEL=llama-3.3-70b-versatile
SUSSCAN_GROQ_CHAT_COMPLETIONS_URL=https://api.groq.com/openai/v1/chat/completions
SUSSCAN_GROQ_TIMEOUT_SECONDS=45
SUSSCAN_GROQ_MAX_COMPLETION_TOKENS=700
SUSSCAN_GROQ_TEMPERATURE=0.2
SUSSCAN_REPORT_CHAT_HISTORY_TURN_LIMIT=8

SUSSCAN_MALWAREBAZAAR_API_KEY=your_key_here
SUSSCAN_METADEFENDER_API_KEY=
SUSSCAN_HYBRID_ANALYSIS_API_KEY=
SUSSCAN_VIRUSTOTAL_API_KEY=
```

If you do not set the required keys during installation, the app will **not start** until they are added.

---

## Start the Service

After configuring `/opt/SusScan/.env`, start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now susscan
```

Check status:

```bash
sudo systemctl status susscan
```

View logs:

```bash
sudo journalctl -u susscan -f
```

---

## Access the App

By default, Uvicorn runs on:

```text
http://SERVER_IP:8080
```

If you place it behind Nginx later, you can expose it on port 80/443 like a respectable server instead of raw-porting everything into the void.

---

## Manual Development Run

If you want to run it manually without systemd:

```bash
cd /opt/SusScan/app
source /opt/SusScan/activate.sh
python -m uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```

For production, do **not** use `--reload`.

---

## Rules Setup

The installer supports two rule setup mechanisms:

### Bundled rules
If the repo contains:

```text
rules/
```

the installer copies them into:

```text
/opt/SusScan/rules
```

### `rule.sh`
If the repo contains:

```text
rule.sh
```

the installer copies it to:

```text
/opt/SusScan/rule.sh
```

and runs it automatically.

If needed, you can run it manually later:

```bash
sudo /opt/SusScan/rule.sh
```

To skip automatic execution during install:

```bash
sudo SKIP_RULE_SETUP=1 bash install.sh.sh
```

---

## Useful Paths

```text
/opt/SusScan/app                 # application source
/opt/SusScan/data/uploads        # uploaded files
/opt/SusScan/data/jobs           # job metadata
/opt/SusScan/data/reports        # generated reports
/opt/SusScan/data/decompiled     # JADX / decompiled output
/opt/SusScan/rules               # rule storage
/opt/SusScan/tools               # installed external tools
/opt/SusScan/venv                # Python virtual environment
/opt/SusScan/.env                # runtime configuration
/opt/SusScan/.env.example        # example environment file
```

---

## Update / Redeploy

If you update the repo and want to redeploy:

```bash
cd SusScan
git pull
sudo bash install.sh.sh
```

Then restart the service:

```bash
sudo systemctl restart susscan
```

---

## Troubleshooting

### Service will not start
Check logs:

```bash
sudo systemctl status susscan
sudo journalctl -u susscan -f
```

Most common causes:

- missing `SUSSCAN_GROQ_API_KEY`
- no hash/reputation provider key configured
- `rule.sh` failed
- invalid `.env` formatting

### API key errors
Make sure your keys are in:

```text
/opt/SusScan/.env
```

Then restart:

```bash
sudo systemctl restart susscan
```

### Old reports still show old provider results
Completed reports are saved as generated results. If config changes later, upload and analyze the file again to create a fresh report.

### Trust cache confusion
Recent versions avoid caching `disabled` and `error` provider results. If you are migrating from an older test setup, clear stale cache data if necessary.

### Port already in use
Change the configured port in the systemd service if another process is already using `8080`.

---

## Security Notes

- Do **not** commit your real `.env`
- Keep only `.env.example` in Git
- Rotate any API keys that were ever pasted into chat, screenshots, terminal history, or public files
- Do not expose this app directly to the public internet without proper hardening and reverse proxying

---

## Git Ignore Reminder

Recommended entries include:

```gitignore
__pycache__/
*.py[cod]
*.pyd

.venv/
venv/
env/

.env
.env.*
!.env.example

*.log
*.db
*.sqlite
*.sqlite3

data/uploads/
data/jobs/
data/reports/
data/decompiled/

tools/

.DS_Store
Thumbs.db
.vscode/
.idea/
.pytest_cache/
.mypy_cache/
build/
dist/
*.egg-info/
*.zip
*.tar
*.gz
*.tmp
*.bak
```

---

## License

Add your preferred license here.
