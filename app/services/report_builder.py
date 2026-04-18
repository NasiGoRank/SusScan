from __future__ import annotations

from pathlib import Path
from typing import Any

from schemas import CommonAnalysis, CorrelationSummary, FileInfo, ReportModel, RiskInfo, TrustAnalysis
from services.correlation import apply_phase3_correlation


def _risk_level(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def build_report(
    *,
    job_id: str,
    original_name: str,
    file_path: Path,
    sha256: str,
    artifact_type: str,
    mime_type: str | None,
    trust_analysis: dict[str, Any] | None,
    common_analysis: dict[str, Any],
    pe_analysis: dict[str, Any] | None = None,
    apk_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    trust_payload = trust_analysis or {}
    pe_payload = pe_analysis or {}
    apk_payload = apk_analysis or {}

    correlation_result = apply_phase3_correlation(
        artifact_type=artifact_type,
        trust_analysis=trust_payload,
        common_analysis=common_analysis,
        pe_analysis=pe_payload,
        apk_analysis=apk_payload,
    )

    filtered_common_analysis = correlation_result["filtered_common_analysis"]
    risk_result = correlation_result["risk"]
    correlation_summary = correlation_result["correlation"]
    final_score = int(risk_result.get("score", 0))

    report = ReportModel(
        job_id=job_id,
        sha256=sha256,
        artifact_type=artifact_type,
        file_info=FileInfo(
            original_name=original_name,
            stored_path=str(file_path),
            size=file_path.stat().st_size,
            mime_type=mime_type,
            extension=file_path.suffix.lower() or None,
        ),
        trust_analysis=TrustAnalysis(**trust_payload),
        common_analysis=CommonAnalysis(**filtered_common_analysis),
        pe_analysis=pe_payload,
        apk_analysis=apk_payload,
        risk=RiskInfo(
            score=final_score,
            level=_risk_level(final_score),
            reasons=list(risk_result.get("reasons", [])),
        ),
        correlation=CorrelationSummary(**correlation_summary),
        raw_outputs={
            "note": "Trust checks, general detection, and file-specific analysis were all completed.",
            "raw_yara_match_count": correlation_result.get("raw_yara_match_count", 0),
            "filtered_yara_match_count": correlation_result.get("filtered_yara_match_count", 0),
            "analysis_early_exit": False,
        },
        timestamps={},
    )
    return report.model_dump()