"""
Local forensic analysis helpers.

Provides sandboxed file-system operations (metadata, hashing, syslog scanning)
adapted from axdithyaxo/mcp-forensic-toolkit with stronger path validation
and cross-platform log support.
"""

from __future__ import annotations

import datetime
import hashlib
import logging
import os
import platform
import subprocess
from typing import Any, Dict, List, Optional

from .exceptions import SafePathError

logger = logging.getLogger(__name__)


def validate_safe_path(path: str, safe_base: str) -> str:
    """Resolve *path* and ensure it lives under *safe_base*."""
    resolved = os.path.abspath(path)
    base = os.path.abspath(safe_base)
    if not resolved.startswith(base + os.sep) and resolved != base:
        raise SafePathError(
            f"Access denied — '{path}' is outside the allowed directory '{safe_base}'."
        )
    return resolved


def get_file_metadata(path: str, safe_base: str) -> Dict[str, Any]:
    """Return size, timestamps, and SHA-256 for a single file."""
    resolved = validate_safe_path(path, safe_base)
    stat = os.stat(resolved)
    sha = hashlib.sha256()
    with open(resolved, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha.update(chunk)
    return {
        "path": resolved,
        "size_bytes": stat.st_size,
        "created_at": datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "modified_at": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "sha256": sha.hexdigest(),
    }


def hash_directory(path: str, safe_base: str) -> Dict[str, str]:
    """Recursively SHA-256 every file under *path*."""
    resolved = validate_safe_path(path, safe_base)
    if not os.path.isdir(resolved):
        raise SafePathError(f"Not a directory: {resolved}")

    results: Dict[str, str] = {}
    for root, _, files in os.walk(resolved):
        for fname in files:
            full = os.path.join(root, fname)
            try:
                sha = hashlib.sha256()
                with open(full, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        sha.update(chunk)
                results[full] = sha.hexdigest()
            except Exception as exc:
                results[full] = f"error: {exc}"
    return results


def scan_syslog(keyword: str, max_lines: int = 100) -> List[str]:
    """Search system logs for *keyword* (case-insensitive)."""
    system = platform.system()

    try:
        if system == "Linux":
            log_path = "/var/log/syslog"
            if not os.path.exists(log_path):
                return [f"Log file '{log_path}' not found."]
            with open(log_path, "r") as fh:
                hits = [ln for ln in fh if keyword.lower() in ln.lower()]
            return hits[-max_lines:] if hits else ["No matching entries found."]

        if system == "Darwin":
            result = subprocess.run(
                [
                    "log", "show",
                    "--predicate", f'eventMessage contains[c] "{keyword}"',
                    "--last", "10m",
                ],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                return [f"log show error: {result.stderr.strip()}"]
            lines = [
                ln for ln in result.stdout.splitlines()
                if ln.strip() and not ln.strip().startswith("Timestamp")
            ]
            return lines[-max_lines:] if lines else ["No matching entries found."]

        return [f"Unsupported OS for syslog scanning: {system}"]
    except Exception as exc:
        return [f"Error reading logs: {exc}"]


def correlate_file_and_logs(
    filename: str,
    keyword: str,
    safe_base: str,
) -> Dict[str, Any]:
    """Combine log scanning with file metadata to find correlations."""
    log_hits = scan_syslog(keyword)
    try:
        meta = get_file_metadata(filename, safe_base)
    except (SafePathError, OSError) as exc:
        return {"error": str(exc)}

    basename = os.path.basename(filename).lower()
    found = any(basename in line.lower() for line in log_hits)

    return {
        "filename": meta["path"],
        "keyword": keyword,
        "file_modified_time": meta["modified_at"],
        "sha256": meta["sha256"],
        "log_hits": log_hits[:10],
        "correlation_found": found,
    }


def generate_forensic_report(
    filename: str,
    keyword: str,
    safe_base: str,
) -> Dict[str, Any]:
    """High-level report wrapping ``correlate_file_and_logs``."""
    result = correlate_file_and_logs(filename, keyword, safe_base)
    if "error" in result:
        return {"status": "error", "message": result["error"], "filename": filename, "keyword": keyword}

    return {
        "status": "ok",
        "filename": result["filename"],
        "keyword": result["keyword"],
        "file_modified_time": result["file_modified_time"],
        "sha256": result["sha256"],
        "log_hits": result["log_hits"],
        "correlation_found": result["correlation_found"],
    }
