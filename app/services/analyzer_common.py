from __future__ import annotations

from pathlib import Path
from typing import Any

import magic
import yara

from config import settings


def detect_magic(file_path: Path) -> dict[str, Any]:
    mime = magic.Magic(mime=True)
    desc = magic.Magic(mime=False)

    return {
        "mime_type": mime.from_file(str(file_path)),
        "description": desc.from_file(str(file_path)),
    }


def _get_yara_source() -> Path | None:
    compiled_bundle = settings.rules_dir / "compiled" / "all_combined.yarc"
    if compiled_bundle.exists():
        return compiled_bundle

    if not settings.rules_dir.exists():
        return None

    return settings.rules_dir


def _build_yara_file_map(rules_root: Path) -> dict[str, str]:
    file_map: dict[str, str] = {}

    for rule_file in sorted(rules_root.rglob("*")):
        if not rule_file.is_file():
            continue

        if rule_file.name == "sample.yar":
            continue

        if rule_file.suffix.lower() not in {".yar", ".yara"}:
            continue

        namespace = rule_file.stem.replace("-", "_").replace(".", "_")
        if namespace in file_map:
            namespace = f"{namespace}_{len(file_map)}"

        file_map[namespace] = str(rule_file)

    return file_map


def run_yara_scan(file_path: Path) -> list[dict[str, Any]]:
    yara_source = _get_yara_source()
    if not yara_source:
        return []

    try:
        if yara_source.is_file():
            rules = yara.load(str(yara_source))
        else:
            file_map = _build_yara_file_map(yara_source)
            if not file_map:
                return []
            rules = yara.compile(filepaths=file_map)

        matches = rules.match(str(file_path))
        results: list[dict[str, Any]] = []

        for match in matches:
            results.append(
                {
                    "rule": match.rule,
                    "namespace": getattr(match, "namespace", None),
                    "tags": list(getattr(match, "tags", []) or []),
                    "meta": dict(getattr(match, "meta", {}) or {}),
                }
            )

        return results

    except Exception as exc:
        return [{"error": f"YARA scan failed: {exc}"}]


def run_common_analysis(
    file_path: Path,
    *,
    magic_info: dict[str, Any] | None = None,
    skip_yara: bool = False,
) -> dict[str, Any]:
    magic_payload = magic_info or detect_magic(file_path)
    yara_matches = [] if skip_yara else run_yara_scan(file_path)

    return {
        "magic": magic_payload,
        "yara_matches": yara_matches,
    }


# compatibility alias for older imports
def analyze_common(file_path: Path) -> dict[str, Any]:
    return run_common_analysis(file_path)
