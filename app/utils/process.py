from __future__ import annotations

import shutil
import subprocess
from typing import Any

from config import settings



def run_command(command: list[str], *, timeout: int | None = None) -> dict[str, Any]:
    binary = shutil.which(command[0])
    if not binary:
        return {
            "ok": False,
            "error": f"Command not found: {command[0]}",
            "stdout": "",
            "stderr": "",
            "returncode": None,
            "command": command,
        }

    try:
        completed = subprocess.run(
            [binary, *command[1:]],
            capture_output=True,
            text=True,
            timeout=timeout or settings.process_timeout_seconds,
            check=False,
        )
        return {
            "ok": completed.returncode == 0,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "returncode": completed.returncode,
            "command": [binary, *command[1:]],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "error": f"Timeout after {exc.timeout} seconds",
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "returncode": None,
            "command": [binary, *command[1:]],
        }
