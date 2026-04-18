from __future__ import annotations

import json
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from config import settings
from db import (
    add_report_chat_message,
    clear_report_chat_messages,
    get_job,
    init_db,
    list_recent_jobs,
    list_report_chat_messages,
    list_report_chat_messages_for_context,
)
from schemas import (
    ReportChatClearResponse,
    ReportChatHistoryResponse,
    ReportChatRequest,
    ReportChatResponse,
)
from services.jobs import create_job_and_store_upload, delete_job_and_assets, process_job
from services.report_chat import ask_report_chatbot

app = FastAPI(title="SusScan", version="0.4.0")
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))


@app.on_event("startup")
def startup() -> None:
    init_db()
    settings.ensure_directories()


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "title": "SusScan",
            "max_upload_mb": settings.max_upload_size_mb,
            "recent_jobs": list_recent_jobs(limit=10),
        },
    )


@app.post("/upload")
async def upload_sample(background_tasks: BackgroundTasks, sample: UploadFile = File(...)):
    if not sample.filename:
        raise HTTPException(status_code=400, detail="Uploaded file must have a name.")

    job_id = await create_job_and_store_upload(sample)
    background_tasks.add_task(process_job, job_id)
    return RedirectResponse(url=f"/jobs/{job_id}", status_code=303)


@app.get("/jobs/{job_id}")
def job_status(
    job_id: str,
    request: Request,
    format: str = Query(default="html", pattern="^(html|json)$"),
):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    if format == "json":
        return JSONResponse(job)

    return templates.TemplateResponse(
        request=request,
        name="job.html",
        context={"job": job},
    )


@app.post("/jobs/{job_id}/delete")
def delete_job_route(job_id: str):
    deleted = delete_job_and_assets(job_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Job not found.")
    return RedirectResponse(url="/", status_code=303)


@app.get("/report/{job_id}")
def get_report(
    job_id: str,
    request: Request,
    format: str = Query(default="html", pattern="^(html|json)$"),
):
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

    report = json.loads(path.read_text(encoding="utf-8"))
    report.setdefault("trust_analysis", {})
    report["trust_analysis"].setdefault("trust_decision", {})
    report["trust_analysis"].setdefault("hash_lookup", {})
    report["trust_analysis"].setdefault("signature_verification", {})

    if format == "json":
        return JSONResponse(content=report)

    return templates.TemplateResponse(
        request=request,
        name="report.html",
        context={
            "job": job,
            "report": report,
        },
    )


@app.get("/report/{job_id}/chat/history", response_model=ReportChatHistoryResponse)
def report_chat_history(job_id: str) -> ReportChatHistoryResponse:
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    items = list_report_chat_messages(job_id, limit=100)
    return ReportChatHistoryResponse(items=items)


@app.delete("/report/{job_id}/chat/history", response_model=ReportChatClearResponse)
def clear_report_chat_history(job_id: str) -> ReportChatClearResponse:
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    deleted = clear_report_chat_messages(job_id)
    return ReportChatClearResponse(deleted=deleted)


@app.post("/report/{job_id}/chat", response_model=ReportChatResponse)
def report_chat(job_id: str, payload: ReportChatRequest) -> ReportChatResponse:
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    user_message = payload.message.strip()
    if not user_message:
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    prior_history_rows = list_report_chat_messages_for_context(job_id, limit=16)
    prior_history = [
        {
            "role": item["role"],
            "content": item["content"],
        }
        for item in prior_history_rows
    ]

    add_report_chat_message(job_id=job_id, role="user", content=user_message)

    result = ask_report_chatbot(
        job_id=job_id,
        user_message=user_message,
        history=prior_history,
    )

    answer = (result.get("answer") or "").strip()
    if answer:
        add_report_chat_message(job_id=job_id, role="assistant", content=answer)

    return ReportChatResponse(**result)