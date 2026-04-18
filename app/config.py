from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class Settings:
    susscan_home: Path = Path("/opt/SusScan")
    app_dir: Path = Path("/opt/SusScan/app")
    data_dir: Path = Path("/opt/SusScan/data")
    uploads_dir: Path = Path("/opt/SusScan/data/uploads")
    jobs_dir: Path = Path("/opt/SusScan/data/jobs")
    reports_dir: Path = Path("/opt/SusScan/data/reports")
    decompiled_dir: Path = Path("/opt/SusScan/data/decompiled")
    rules_dir: Path = Path("/opt/SusScan/rules")
    db_path: Path = Path("/opt/SusScan/data/SusScan.db")
    compiled_yara_path: Path = Path("/opt/SusScan/rules/compiled/all_combined.yarc")
    max_upload_size_mb: int = 100
    process_timeout_seconds: int = 300
    enable_jadx_decompile: bool = True

    # Phase 1 trust analysis
    enable_phase1_trust: bool = _env_bool("SUSSCAN_ENABLE_PHASE1_TRUST", True)
    enable_hash_lookup: bool = _env_bool("SUSSCAN_ENABLE_HASH_LOOKUP", True)
    enable_pe_signature_verification: bool = _env_bool("SUSSCAN_ENABLE_PE_SIGNATURE_VERIFICATION", True)
    hash_lookup_provider: str = os.getenv("SUSSCAN_HASH_LOOKUP_PROVIDER", "circl_hashlookup")
    hash_lookup_url: str = os.getenv("SUSSCAN_HASH_LOOKUP_URL", "https://hashlookup.circl.lu/lookup/sha256/")
    hash_lookup_timeout_seconds: int = int(os.getenv("SUSSCAN_HASH_LOOKUP_TIMEOUT_SECONDS", "8"))
    trust_cache_ttl_hours: int = int(os.getenv("SUSSCAN_TRUST_CACHE_TTL_HOURS", "168"))

    # External reputation providers
    enable_reputation_enrichment: bool = _env_bool("SUSSCAN_ENABLE_REPUTATION_ENRICHMENT", True)
    enabled_reputation_providers: str = os.getenv(
        "SUSSCAN_ENABLED_REPUTATION_PROVIDERS",
        "malwarebazaar,metadefender,hybrid_analysis,virustotal",
    )
    reputation_timeout_seconds: int = int(os.getenv("SUSSCAN_REPUTATION_TIMEOUT_SECONDS", "10"))
    min_malicious_provider_hits_for_known_malicious: int = int(
        os.getenv("SUSSCAN_MIN_MALICIOUS_PROVIDER_HITS_FOR_KNOWN_MALICIOUS", "2")
    )
    min_positive_provider_hits_for_suspicious: int = int(
        os.getenv("SUSSCAN_MIN_POSITIVE_PROVIDER_HITS_FOR_SUSPICIOUS", "1")
    )

    malwarebazaar_api_key: str = os.getenv("SUSSCAN_MALWAREBAZAAR_API_KEY", "")
    malwarebazaar_url: str = os.getenv("SUSSCAN_MALWAREBAZAAR_URL", "https://mb-api.abuse.ch/api/v1/")

    metadefender_api_key: str = os.getenv("SUSSCAN_METADEFENDER_API_KEY", "")
    metadefender_hash_url: str = os.getenv(
        "SUSSCAN_METADEFENDER_HASH_URL",
        "https://api.metadefender.com/v4/hash",
    )

    hybrid_analysis_api_key: str = os.getenv("SUSSCAN_HYBRID_ANALYSIS_API_KEY", "")
    hybrid_analysis_search_url: str = os.getenv(
        "SUSSCAN_HYBRID_ANALYSIS_SEARCH_URL",
        "https://hybrid-analysis.com/api/v2/search/hash",
    )

    virustotal_api_key: str = os.getenv("SUSSCAN_VIRUSTOTAL_API_KEY", "")
    virustotal_file_url: str = os.getenv(
        "SUSSCAN_VIRUSTOTAL_FILE_URL",
        "https://www.virustotal.com/api/v3/files",
    )

    # Report chatbot
    groq_api_key: str = os.getenv("SUSSCAN_GROQ_API_KEY", "")
    groq_chat_completions_url: str = os.getenv(
        "SUSSCAN_GROQ_CHAT_COMPLETIONS_URL",
        "https://api.groq.com/openai/v1/chat/completions",
    )
    groq_model: str = os.getenv("SUSSCAN_GROQ_MODEL", "llama-3.3-70b-versatile")
    groq_timeout_seconds: int = int(os.getenv("SUSSCAN_GROQ_TIMEOUT_SECONDS", "45"))
    groq_max_completion_tokens: int = int(os.getenv("SUSSCAN_GROQ_MAX_COMPLETION_TOKENS", "700"))
    groq_temperature: float = float(os.getenv("SUSSCAN_GROQ_TEMPERATURE", "0.2"))
    report_chat_history_turn_limit: int = int(os.getenv("SUSSCAN_REPORT_CHAT_HISTORY_TURN_LIMIT", "8"))

    def ensure_directories(self) -> None:
        for path in [
            self.app_dir,
            self.data_dir,
            self.uploads_dir,
            self.jobs_dir,
            self.reports_dir,
            self.decompiled_dir,
            self.rules_dir,
        ]:
            path.mkdir(parents=True, exist_ok=True)


settings = Settings()