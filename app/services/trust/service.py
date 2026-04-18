from __future__ import annotations

from pathlib import Path
from typing import Any

from config import settings
from .providers import resolve_hash_lookup_chain
from .signature import verify_pe_signature


def _build_decision(
    *,
    hash_lookup: dict[str, Any],
    signature_verification: dict[str, Any],
    artifact_type: str,
) -> dict[str, Any]:
    state = "not_applicable"
    trust_weight = 0
    reason = "Phase 1 trust analysis did not apply."

    hash_status = hash_lookup.get("status")
    signature_status = signature_verification.get("status")

    if hash_status == "known_malicious":
        state = "known_malicious"
        trust_weight = -60
        reason = hash_lookup.get("reason") or "Hash matched a malicious reputation provider."
    elif hash_status == "known_suspicious":
        state = "suspicious_reputation"
        trust_weight = -25
        reason = hash_lookup.get("reason") or "Hash matched a suspicious reputation provider."
    elif hash_status == "trusted":
        state = "trusted_known_hash"
        trust_weight = 100
        reason = hash_lookup.get("reason") or "Hash is present in the trusted lookup source."
    elif artifact_type == "pe" and signature_status == "valid":
        state = "trusted_signed"
        trust_weight = 35
        reason = signature_verification.get("reason") or "PE file has a valid Authenticode signature."
    elif hash_status == "known_neutral":
        state = "known_neutral"
        trust_weight = 0
        reason = hash_lookup.get("reason") or "Hash was found, but trust is neutral."
    elif hash_status == "known_low_trust":
        state = "known_low_trust"
        trust_weight = -5
        reason = hash_lookup.get("reason") or "Hash was found, but trust is below neutral."
    elif artifact_type == "pe" and signature_status == "invalid":
        state = "suspicious_invalid_signature"
        trust_weight = -10
        reason = signature_verification.get("reason") or "PE file contains an invalid Authenticode signature."
    elif artifact_type == "pe" and signature_status == "unsigned":
        state = "untrusted_unsigned"
        trust_weight = 0
        reason = signature_verification.get("reason") or "PE file is unsigned."
    elif hash_status == "unknown":
        state = "untrusted_unknown"
        trust_weight = 0
        reason = hash_lookup.get("reason") or "Hash was not found in any configured provider."
    elif hash_status == "error":
        state = "lookup_error"
        trust_weight = 0
        reason = hash_lookup.get("reason") or "Hash lookup failed, so no trust conclusion was made."
    elif hash_status == "disabled":
        state = "lookup_error"
        trust_weight = 0
        reason = hash_lookup.get("reason") or "Hash lookup is disabled."

    return {
        "state": state,
        "early_exit": False,
        "trust_weight": trust_weight,
        "reason": reason,
    }


def analyze_trust(file_path: Path, *, sha256: str, artifact_type: str) -> dict[str, Any]:
    chain = resolve_hash_lookup_chain(sha256, artifact_type=artifact_type)
    effective_hash_lookup = chain.get("selected_hash_lookup", {})
    provider_attempts = chain.get("provider_attempts", [])
    summary = chain.get("summary", {})

    if artifact_type == "pe" and settings.enable_pe_signature_verification:
        signature_verification = verify_pe_signature(file_path)
    elif artifact_type == "pe":
        signature_verification = {
            "applicable": True,
            "status": "disabled",
            "verified": False,
            "signer": None,
            "issuer": None,
            "timestamp": None,
            "reason": "PE signature verification is disabled for this deployment.",
        }
    else:
        signature_verification = {
            "applicable": False,
            "status": "not_applicable",
            "verified": False,
            "signer": None,
            "issuer": None,
            "timestamp": None,
            "reason": "Signature verification only applies to PE files in this build.",
        }

    return {
        "hash_lookup": effective_hash_lookup,
        "reputation_summary": summary,
        "reputation_providers": provider_attempts,
        "signature_verification": signature_verification,
        "trust_decision": _build_decision(
            hash_lookup=effective_hash_lookup,
            signature_verification=signature_verification,
            artifact_type=artifact_type,
        ),
    }