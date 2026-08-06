"""Shared curl helper for networked witnesses.

Centralizing curl keeps every witness honest about the same rules inherited
from Forebode's NVD fetcher (forebode/sources/nvd.py): header-only auth, the
`__HTTP__%{http_code}` status-split, no credentials in the URL. Kept in its
own module so it has no import dependency on the witness layer (avoids the
base <-> nvd_cve import cycle).
"""

from __future__ import annotations
import json
import subprocess
from typing import Any


def curl_get(url: str, headers: list[str] | None = None, max_time: int = 60,
             extra: list[str] | None = None) -> tuple[Any, int, str]:
    """GET via curl. Returns (parsed_json_or_None, http_status, body_or_empty).

    The `-w '\\n__HTTP__%{http_code}'` sentinel splits the HTTP status from the
    body reliably (Forebode's pattern). Auth is HEADER-ONLY — never in the URL
    (putting the NVD key in the query string is the run-#10 fleet-wipe root cause).
    """
    cmd = ["curl", "-sS", "--max-time", str(max_time),
           "-w", "\n__HTTP__%{http_code}"]
    for h in headers or []:
        cmd += ["-H", h]
    if extra:
        cmd += list(extra)
    cmd += [url]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=max_time + 10)
    except subprocess.TimeoutExpired:
        return None, 0, ""
    raw = r.stdout.decode("utf-8", "replace")
    body, _, status = raw.rpartition("__HTTP__")
    status = status.strip()
    code = int(status) if status.isdigit() else 0
    if not body:
        return None, code, ""
    try:
        return json.loads(body), code, body
    except json.JSONDecodeError:
        return None, code, body


def curl_get_bytes(url: str, headers: list[str] | None = None,
                   max_time: int = 60,
                   extra: list[str] | None = None) -> tuple[bytes | None, int]:
    """GET via curl, returning the RAW bytes (no utf-8 decode). Returns
    ``(bytes_or_None, http_status)``. Use this for binary payloads (zips, etc.)
    where :func:`curl_get`'s lossy ``utf-8`` ``errors="replace"`` decode would
    corrupt the body — encoding that str back to bytes cannot recover the
    original. Auth stays HEADER-ONLY (same rule as ``curl_get``)."""
    cmd = ["curl", "-sS", "--max-time", str(max_time),
           "-w", "\n__HTTP__%{http_code}"]
    for h in headers or []:
        cmd += ["-H", h]
    if extra:
        cmd += list(extra)
    cmd += [url]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=max_time + 10)
    except subprocess.TimeoutExpired:
        return None, 0
    raw = r.stdout  # bytes, NOT decoded
    body, _, status = raw.rpartition(b"__HTTP__")
    status = status.strip()
    code = int(status) if status.isdigit() else 0
    if not body:
        return None, code
    return body, code