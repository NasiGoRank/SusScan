from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pefile

from utils.process import run_command


SUSPICIOUS_SECTION_NAMES = {".upx", ".vmp", ".aspack", ".packed", ".petite", ".boom", ".asdfg"}
HIGH_ENTROPY_THRESHOLD = 7.2
LOW_IMPORT_THRESHOLD = 5


def _safe_year_from_timestamp(ts: int | None) -> int | None:
    if not ts:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).year
    except Exception:
        return None


def _parse_rich_header_info(pe: pefile.PE) -> dict[str, Any]:
    try:
        if not hasattr(pe, "parse_rich_header"):
            return {
                "present": False,
                "entry_count": 0,
                "checksum": None,
                "parse_status": "parse_rich_header_unavailable",
            }

        rich = pe.parse_rich_header()
        if not rich:
            return {
                "present": False,
                "entry_count": 0,
                "checksum": None,
                "parse_status": "not_present",
            }

        values = rich.get("values", []) if isinstance(rich, dict) else []
        checksum = rich.get("checksum") if isinstance(rich, dict) else None

        return {
            "present": True,
            "entry_count": len(values) // 2 if isinstance(values, list) else 0,
            "checksum": checksum,
            "parse_status": "ok",
        }
    except Exception as exc:
        return {
            "present": False,
            "entry_count": 0,
            "checksum": None,
            "parse_status": f"error: {exc}",
        }


def _parse_pe_metadata(path: Path) -> dict[str, Any]:
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories()

        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT[:50]:
                dll_name = entry.dll.decode(errors="ignore") if entry.dll else None
                funcs = []
                for imp in entry.imports[:100]:
                    funcs.append(
                        {
                            "name": imp.name.decode(errors="ignore") if imp.name else None,
                            "address": imp.address,
                        }
                    )
                imports.append({"dll": dll_name, "functions": funcs})

        sections = []
        for section in pe.sections[:30]:
            sections.append(
                {
                    "name": section.Name.decode(errors="ignore").rstrip("\x00"),
                    "virtual_size": int(section.Misc_VirtualSize),
                    "raw_size": int(section.SizeOfRawData),
                    "entropy": round(section.get_entropy(), 3),
                }
            )

        timestamp = pe.FILE_HEADER.TimeDateStamp
        rich_header = _parse_rich_header_info(pe)

        return {
            "machine": hex(pe.FILE_HEADER.Machine),
            "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            "timestamp": timestamp,
            "timestamp_year": _safe_year_from_timestamp(timestamp),
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "linker_major": getattr(pe.OPTIONAL_HEADER, "MajorLinkerVersion", None),
            "linker_minor": getattr(pe.OPTIONAL_HEADER, "MinorLinkerVersion", None),
            "rich_header": rich_header,
            "sections": sections,
            "imports": imports,
        }
    except Exception as exc:
        return {"error": f"pefile failed: {exc}"}


def _build_structural_evidence(metadata: dict[str, Any], die_result: dict[str, Any]) -> dict[str, Any]:
    imports = metadata.get("imports", [])
    total_import_functions = sum(len(entry.get("functions", [])) for entry in imports)
    total_import_dlls = len(imports)

    high_entropy_sections = [
        sec.get("name")
        for sec in metadata.get("sections", [])
        if isinstance(sec.get("entropy"), (int, float)) and sec.get("entropy", 0) >= HIGH_ENTROPY_THRESHOLD
    ]

    suspicious_section_names = [
        sec.get("name")
        for sec in metadata.get("sections", [])
        if str(sec.get("name", "")).lower() in SUSPICIOUS_SECTION_NAMES
    ]

    section_name_and_entropy = {
        "suspicious_section_names": suspicious_section_names,
        "high_entropy_sections": high_entropy_sections,
        "correlated_red_flag": bool(
            set(name.lower() for name in suspicious_section_names)
            & set(name.lower() for name in high_entropy_sections)
        ),
        "reason": None,
    }

    if section_name_and_entropy["correlated_red_flag"]:
        section_name_and_entropy["reason"] = (
            "Suspicious section names are also high-entropy, indicating compression or encryption."
        )
    elif suspicious_section_names or high_entropy_sections:
        section_name_and_entropy["reason"] = (
            "Only one side of the section-name/entropy correlation is present."
        )

    rich = metadata.get("rich_header", {})
    build_year = metadata.get("timestamp_year")
    linker_major = metadata.get("linker_major")

    rich_header_anomaly = {
        "present": bool(rich.get("present")),
        "timestamp_year": build_year,
        "linker_major": linker_major,
        "entry_count": rich.get("entry_count"),
        "anomaly": None,
        "reason": None,
    }

    if rich_header_anomaly["present"] and build_year is not None and linker_major is not None:
        if build_year >= 2022 and linker_major <= 9:
            rich_header_anomaly["anomaly"] = True
            rich_header_anomaly["reason"] = "Modern PE timestamp with very old linker/compiler-era signal."
        elif build_year <= 2012 and linker_major >= 14:
            rich_header_anomaly["anomaly"] = True
            rich_header_anomaly["reason"] = "Old PE timestamp with unusually modern linker/compiler-era signal."
        else:
            rich_header_anomaly["anomaly"] = False

    die_text = ((die_result.get("stdout") or "") + " " + (die_result.get("stderr") or "")).lower()
    die_keywords = [kw for kw in ["packer", "protector", "obfusc", "vmprotect", "themida", "upx"] if kw in die_text]

    iat_red_flags = {
        "import_function_count": total_import_functions,
        "import_dll_count": total_import_dlls,
        "red_flag": total_import_functions < LOW_IMPORT_THRESHOLD,
        "reason": (
            "IAT contains fewer than 5 imported functions, which strongly suggests packing or heavy dynamic resolution."
            if total_import_functions < LOW_IMPORT_THRESHOLD
            else None
        ),
    }

    return {
        "rich_header_anomaly": rich_header_anomaly,
        "iat_red_flags": iat_red_flags,
        "section_name_and_entropy": section_name_and_entropy,
        "die_packer_keywords": die_keywords,
    }


def analyze_pe(path: Path) -> dict[str, Any]:
    metadata = _parse_pe_metadata(path)
    die_result = run_command(["diec", str(path)])
    floss_result = run_command(["floss", "--no-static-strings", str(path)])
    capa_result = run_command(["capa", "-j", str(path)])

    return {
        "metadata": metadata,
        "structural_evidence": _build_structural_evidence(metadata, die_result),
        "die": die_result,
        "floss": floss_result,
        "capa": capa_result,
    }