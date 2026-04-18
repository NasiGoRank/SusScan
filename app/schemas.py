from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field


ArtifactType = Literal["pe", "apk", "unknown"]
RiskLevel = Literal["low", "medium", "high"]
JobStatus = Literal["queued", "processing", "completed", "failed"]


class FileInfo(BaseModel):
    original_name: str
    stored_path: str
    size: int
    mime_type: str | None = None
    extension: str | None = None


class CorrelationRuleTrace(BaseModel):
    rule_id: str
    title: str
    score_delta: int = 0
    reason: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    category: str | None = None
    severity: str | None = None


class CorrelationSummary(BaseModel):
    engine_version: str = "phase3-v1"
    base_score: int = 0
    final_score: int = 0
    fired_rules: list[CorrelationRuleTrace] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class RiskInfo(BaseModel):
    score: int = 0
    level: RiskLevel = "low"
    reasons: list[str] = Field(default_factory=list)


class CommonAnalysis(BaseModel):
    magic: dict[str, Any] = Field(default_factory=dict)
    yara_matches: list[dict[str, Any]] = Field(default_factory=list)


class TrustAnalysis(BaseModel):
    hash_lookup: dict[str, Any] = Field(default_factory=dict)
    reputation_summary: dict[str, Any] = Field(default_factory=dict)
    reputation_providers: list[dict[str, Any]] = Field(default_factory=list)
    signature_verification: dict[str, Any] = Field(default_factory=dict)
    trust_decision: dict[str, Any] = Field(default_factory=dict)


class ReportModel(BaseModel):
    job_id: str
    sha256: str
    artifact_type: ArtifactType
    file_info: FileInfo
    trust_analysis: TrustAnalysis = Field(default_factory=TrustAnalysis)
    common_analysis: CommonAnalysis = Field(default_factory=CommonAnalysis)
    pe_analysis: dict[str, Any] = Field(default_factory=dict)
    apk_analysis: dict[str, Any] = Field(default_factory=dict)
    risk: RiskInfo = Field(default_factory=RiskInfo)
    correlation: CorrelationSummary = Field(default_factory=CorrelationSummary)
    raw_outputs: dict[str, Any] = Field(default_factory=dict)
    timestamps: dict[str, Any] = Field(default_factory=dict)

class ReportChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class StoredReportChatMessage(BaseModel):
    id: int
    job_id: str
    role: Literal["user", "assistant"]
    content: str
    created_at: str


class ReportChatRequest(BaseModel):
    message: str


class ReportChatResponse(BaseModel):
    answer: str
    model: str
    usage: dict[str, Any] = Field(default_factory=dict)


class ReportChatHistoryResponse(BaseModel):
    items: list[StoredReportChatMessage] = Field(default_factory=list)


class ReportChatClearResponse(BaseModel):
    deleted: int
