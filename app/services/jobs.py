from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path

from fastapi import UploadFile

from config import settings
from db import delete_job, get_job, insert_job, update_job
from services.analyzer_apk import analyze_apk
from services.analyzer_common import detect_magic, run_common_analysis
from services.analyzer_pe import analyze_pe
from services.report_builder import build_report
from services.trust import analyze_trust
from utils.filetype import classify_artifact_type
from utils.hashing import sha256_file
from utils.storage import save_upload_file


async def create_job_and_store_upload(file: UploadFile) -> str:
    settings.ensure_directories()

    job_id = str(uuid.uuid4())
    stored_path = await save_upload_file(file, job_id=job_id)

    insert_job(
        job_id=job_id,
        original_filename=file.filename or "uploaded_file",
        stored_filename=stored_path.name,
        stored_path=str(stored_path),
        status="queued",
    )
    return job_id


def process_job(job_id: str) -> None:
    job = get_job(job_id)
    if not job:
        return

    file_path = Path(job["stored_path"])

    try:
        update_job(job_id, status="processing", error_message=None)

        sha256 = sha256_file(file_path)
        magic_info = detect_magic(file_path)
        mime_type = magic_info.get("mime_type")
        artifact_type = classify_artifact_type(file_path, mime_type=mime_type)

        trust_analysis = analyze_trust(file_path, sha256=sha256, artifact_type=artifact_type)
        common_analysis = run_common_analysis(file_path, magic_info=magic_info, skip_yara=False)

        pe_analysis: dict = {}
        apk_analysis: dict = {}

        if artifact_type == "pe":
            pe_analysis = analyze_pe(file_path)
        elif artifact_type == "apk":
            apk_analysis = analyze_apk(file_path, job_id)

        report = build_report(
            job_id=job_id,
            original_name=job["original_filename"],
            file_path=file_path,
            sha256=sha256,
            artifact_type=artifact_type,
            mime_type=mime_type,
            trust_analysis=trust_analysis,
            common_analysis=common_analysis,
            pe_analysis=pe_analysis,
            apk_analysis=apk_analysis,
        )

        report_path = settings.reports_dir / f"{job_id}.json"
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        risk = report.get("risk", {})
        update_job(
            job_id,
            status="completed",
            sha256=sha256,
            artifact_type=artifact_type,
            mime_type=mime_type,
            report_path=str(report_path),
            risk_score=risk.get("score"),
            risk_level=risk.get("level"),
            error_message=None,
        )
    except Exception as exc:
        update_job(job_id, status="failed", error_message=str(exc))


def delete_job_and_assets(job_id: str) -> bool:
    job = get_job(job_id)
    if not job:
        return False

    stored_path = job.get("stored_path")
    if stored_path:
        try:
            Path(stored_path).unlink(missing_ok=True)
        except Exception:
            pass

    report_path = job.get("report_path")
    if report_path:
        try:
            Path(report_path).unlink(missing_ok=True)
        except Exception:
            pass

    decompiled_dir = settings.decompiled_dir / job_id
    if decompiled_dir.exists():
        shutil.rmtree(decompiled_dir, ignore_errors=True)

    return delete_job(job_id)