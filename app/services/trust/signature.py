from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from utils.process import run_command


_SIGNER_RE = re.compile(r"Subject:\s*(.+)", re.IGNORECASE)
_ISSUER_RE = re.compile(r"Issuer:\s*(.+)", re.IGNORECASE)
_TIMESTAMP_RE = re.compile(r"Timestamp:\s*(.+)", re.IGNORECASE)


def verify_pe_signature(path: Path) -> dict[str, Any]:
    result = run_command(["osslsigncode", "verify", "-in", str(path)])

    if result.get("error") == "Command not found: osslsigncode":
        return {
            "applicable": True,
            "status": "error",
            "verified": False,
            "signer": None,
            "issuer": None,
            "timestamp": None,
            "reason": "osslsigncode is not installed on this system.",
            "raw_command_ok": False,
        }

    text = ((result.get("stdout") or "") + "\n" + (result.get("stderr") or "")).strip()
    lowered = text.lower()

    signer = None
    issuer = None
    timestamp = None
    for line in text.splitlines():
        line = line.strip()
        if signer is None:
            m = _SIGNER_RE.search(line)
            if m:
                signer = m.group(1).strip()
        if issuer is None:
            m = _ISSUER_RE.search(line)
            if m:
                issuer = m.group(1).strip()
        if timestamp is None:
            m = _TIMESTAMP_RE.search(line)
            if m:
                timestamp = m.group(1).strip()

    status = "error"
    verified = False
    reason = "Signature verification could not determine the file state."

    if "no signature found" in lowered or "signature not found" in lowered:
        status = "unsigned"
        reason = "PE file does not contain an Authenticode signature."
    elif result.get("ok") and ("signature verification: ok" in lowered or "succeeded" in lowered):
        status = "valid"
        verified = True
        reason = "PE file has a valid Authenticode signature."
    elif (not result.get("ok")) and ("signature verification: failed" in lowered or "invalid" in lowered):
        status = "invalid"
        reason = "PE file contains a signature, but verification failed."
    elif not text:
        status = "error"
        reason = "Signature verification returned no output."

    return {
        "applicable": True,
        "status": status,
        "verified": verified,
        "signer": signer,
        "issuer": issuer,
        "timestamp": timestamp,
        "reason": reason,
        "raw_command_ok": result.get("ok", False),
        "returncode": result.get("returncode"),
    }
