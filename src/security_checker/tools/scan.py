"""Stateless one-shot scan.

Consolidates ingest + classification + secret detection into a single
pass over the file contents the agent forwards in one request. No
server-side state is retained between calls.

Enforces two limits (see limits.py):
  - per-file: oversize files are skipped and reported, not reviewed
  - per-call (batch): an oversize call is rejected with a self-correcting
    payload_too_large error telling the caller to split into batches
"""

from pathlib import Path

from security_checker.limits import PER_FILE_MAX_BYTES, BATCH_MAX_BYTES, mb
from security_checker.tools.file_scanner import classify_path
from security_checker.tools.secret_scanner import scan_content, SKIP_EXTENSIONS
from security_checker.tools.file_reader import number_content


def _nbytes(s: str) -> int:
    return len(s.encode("utf-8", "ignore"))


def run_scan(files: list[dict], include_numbered: bool = False) -> dict:
    """Classify and secret-scan a batch of in-memory files.

    Args:
        files: list of {"path": str, "content": str}.
        include_numbered: if True, also return line-numbered content per
            file (larger response; off by default to save tokens).

    Returns:
        A result dict. On batch overflow, returns a payload_too_large
        error dict with recovery instructions instead of scanning.
    """
    if not isinstance(files, list):
        return {"error": "invalid_input", "message": "files must be a list of {path, content} objects."}

    # ── Batch ceiling: reject early with a self-correcting error ──
    incoming = sum(_nbytes(f.get("content", "")) for f in files if isinstance(f, dict))
    if incoming > BATCH_MAX_BYTES:
        return {
            "error": "payload_too_large",
            "limit_bytes": BATCH_MAX_BYTES,
            "limit": mb(BATCH_MAX_BYTES),
            "received_bytes": incoming,
            "received": mb(incoming),
            "action_required": (
                f"This scan call carries {mb(incoming)} of file content, over the "
                f"{mb(BATCH_MAX_BYTES)} per-call limit. Split the files into multiple "
                "scan calls, each under the limit, and combine the results. "
                "Findings are independent across calls, so batching does not change the outcome."
            ),
        }

    manifest: list[dict] = []
    findings: list[dict] = []
    numbered: dict[str, str] = {}
    skipped: list[dict] = []

    for f in files:
        if not isinstance(f, dict):
            continue
        path = f.get("path", "")
        content = f.get("content", "")
        if not path:
            skipped.append({"path": path, "reason": "missing path"})
            continue

        size = _nbytes(content)
        if size > PER_FILE_MAX_BYTES:
            skipped.append({"path": path, "reason": f"file is {mb(size)}, over the {mb(PER_FILE_MAX_BYTES)} per-file limit; not reviewed"})
            continue

        # Pass 1 — classification (name-based)
        info = classify_path(path)
        if info:
            manifest.append(info)

        # Pass 2 — secret detection (skip binary/minified by extension)
        if Path(path).suffix.lower() not in SKIP_EXTENSIONS:
            findings.extend(scan_content(path, content))

        if include_numbered:
            numbered[path] = number_content(path, content)

    result = {
        "files": manifest,
        "total": len(manifest),
        "secret_findings": findings,
        "total_secret_findings": len(findings),
        "files_with_secrets": len({x["file_path"] for x in findings}),
        "skipped": skipped,
    }
    if include_numbered:
        result["numbered_files"] = numbered
    return result
