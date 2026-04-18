from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import HTTPException
from openai import OpenAI

from config import settings
from db import get_job


def load_report_for_chat(job_id: str) -> dict[str, Any]:
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    if job.get("status") != "completed":
        raise HTTPException(status_code=409, detail="Report is not ready yet.")

    report_path = job.get("report_path")
    if not report_path:
        raise HTTPException(status_code=404, detail="Report path missing.")

    path = Path(report_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report file not found.")

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail="Stored report JSON is invalid.") from exc


def build_safe_report_context(report: dict[str, Any]) -> dict[str, Any]:
    file_info = report.get("file_info", {})
    trust = report.get("trust_analysis", {})
    common = report.get("common_analysis", {})
    correlation = report.get("correlation", {})
    pe = report.get("pe_analysis", {})
    apk = report.get("apk_analysis", {})

    safe_context: dict[str, Any] = {
        "job_id": report.get("job_id"),
        "artifact_type": report.get("artifact_type"),
        "sha256": report.get("sha256"),
        "file_info": {
            "original_name": file_info.get("original_name"),
            "size": file_info.get("size"),
            "mime_type": file_info.get("mime_type"),
            "extension": file_info.get("extension"),
        },
        "risk": report.get("risk", {}),
        "trust_analysis": {
            "trust_decision": trust.get("trust_decision", {}),
            "hash_lookup": trust.get("hash_lookup", {}),
            "reputation_summary": trust.get("reputation_summary", {}),
            "signature_verification": trust.get("signature_verification", {}),
            "reputation_providers": [
                {
                    "provider": item.get("provider"),
                    "status": item.get("status"),
                    "found": item.get("found"),
                    "reason": item.get("reason"),
                }
                for item in trust.get("reputation_providers", [])[:8]
            ],
        },
        "common_analysis": {
            "magic": common.get("magic", {}),
            "yara_matches": [
                {
                    "rule": item.get("rule"),
                    "namespace": item.get("namespace"),
                    "tags": item.get("tags", []),
                }
                for item in common.get("yara_matches", [])[:30]
            ],
        },
        "correlation": {
            "engine_version": correlation.get("engine_version"),
            "base_score": correlation.get("base_score"),
            "final_score": correlation.get("final_score"),
            "notes": correlation.get("notes", []),
            "fired_rules": [
                {
                    "rule_id": item.get("rule_id"),
                    "title": item.get("title"),
                    "category": item.get("category"),
                    "severity": item.get("severity"),
                    "score_delta": item.get("score_delta"),
                    "reason": item.get("reason"),
                    "evidence": item.get("evidence", {}),
                }
                for item in correlation.get("fired_rules", [])[:20]
            ],
        },
        "analysis_scope_limitations": {
            "static_only": True,
            "dynamic_analysis_performed": False,
            "sandbox_detonation_performed": False,
            "ai_changes_verdict": False,
        },
    }

    artifact_type = report.get("artifact_type")

    if artifact_type == "pe":
        safe_context["pe_analysis"] = {
            "metadata": {
                "machine_type": pe.get("metadata", {}).get("machine_type"),
                "imphash": pe.get("metadata", {}).get("imphash"),
                "compile_time": pe.get("metadata", {}).get("compile_time"),
                "sections": [
                    {
                        "name": item.get("name"),
                        "entropy": item.get("entropy"),
                        "raw_size": item.get("raw_size"),
                        "virtual_size": item.get("virtual_size"),
                    }
                    for item in pe.get("metadata", {}).get("sections", [])[:20]
                ],
            },
            "structural_evidence": pe.get("structural_evidence", {}),
        }

    elif artifact_type == "apk":
        safe_context["apk_analysis"] = {
            "metadata": {
                "package_name": apk.get("metadata", {}).get("package_name"),
                "main_activity": apk.get("metadata", {}).get("main_activity"),
                "permissions": apk.get("metadata", {}).get("permissions", [])[:50],
            },
            "structural_evidence": apk.get("structural_evidence", {}),
        }

    return safe_context


SYSTEM_PROMPT = (
    "You are the SusScan report assistant. "
    "Answer only from the provided SusScan report context. "
    "Do not invent facts, do not claim dynamic analysis happened, and do not change the verdict, score, or routing. "
    "If the answer is not supported by the report context, clearly say that the report does not contain enough evidence. "
    "Keep answers concise, helpful, and analyst-friendly."
)


def _build_messages(
    *,
    safe_context: dict[str, Any],
    history: list[dict[str, str]],
    user_message: str,
) -> list[dict[str, str]]:
    history_tail = history[-settings.report_chat_history_turn_limit :]

    messages: list[dict[str, str]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "system",
            "content": "SusScan report context:\n" + json.dumps(safe_context, indent=2, ensure_ascii=False),
        },
    ]

    for item in history_tail:
        role = item.get("role", "user")
        if role not in {"user", "assistant"}:
            continue

        content = (item.get("content") or "").strip()
        if content:
            messages.append({"role": role, "content": content})

    messages.append({"role": "user", "content": user_message.strip()})
    return messages


def ask_report_chatbot(
    *,
    job_id: str,
    user_message: str,
    history: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    if not settings.groq_api_key:
        raise HTTPException(
            status_code=503,
            detail="Report chat is not configured yet. Set SUSSCAN_GROQ_API_KEY on the server first.",
        )

    report = load_report_for_chat(job_id)
    safe_context = build_safe_report_context(report)
    messages = _build_messages(
        safe_context=safe_context,
        history=history or [],
        user_message=user_message,
    )

    try:
        client = OpenAI(
            api_key=settings.groq_api_key,
            base_url="https://api.groq.com/openai/v1",
        )

        response = client.chat.completions.create(
            model=settings.groq_model,
            messages=messages,
            temperature=settings.groq_temperature,
            max_completion_tokens=settings.groq_max_completion_tokens,
        )

    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Groq/OpenAI-compatible request failed: {str(exc)}") from exc

    if not response.choices:
        raise HTTPException(status_code=502, detail="Groq API returned no choices.")

    answer = (response.choices[0].message.content or "").strip()
    if not answer:
        raise HTTPException(status_code=502, detail="Groq API returned an empty response.")

    usage: dict[str, Any] = {}
    if getattr(response, "usage", None):
        usage = {
            "prompt_tokens": getattr(response.usage, "prompt_tokens", None),
            "completion_tokens": getattr(response.usage, "completion_tokens", None),
            "total_tokens": getattr(response.usage, "total_tokens", None),
        }

    return {
        "answer": answer,
        "model": getattr(response, "model", settings.groq_model),
        "usage": usage,
    }