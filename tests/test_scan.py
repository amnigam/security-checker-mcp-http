"""Regression tests: pure functions match the legacy disk path, and the
stateless scan enforces its limits."""

import json
from pathlib import Path

from security_checker.tools.file_scanner import scan_directory, classify_path
from security_checker.tools.secret_scanner import scan_for_secrets, scan_content, SKIP_EXTENSIONS
from security_checker.tools.scan import run_scan
from security_checker.limits import PER_FILE_MAX_BYTES, BATCH_MAX_BYTES

FIX = Path(__file__).resolve().parent / "fixtures"


def _mem_files():
    return {p.name: p.read_text(errors="ignore") for p in sorted(FIX.iterdir()) if p.is_file()}


def test_classification_matches_disk():
    disk = sorted(json.loads(scan_directory(str(FIX)))["files"], key=lambda x: x["path"])
    mem = sorted([classify_path(n) for n in _mem_files() if classify_path(n)], key=lambda x: x["path"])
    assert disk == mem


def test_secret_findings_match_disk():
    disk = json.loads(scan_for_secrets(str(FIX)))
    mem = []
    for name, content in _mem_files().items():
        if Path(name).suffix.lower() not in SKIP_EXTENSIONS:
            mem.extend(scan_content(name, content))
    key = lambda f: (f["file_path"], f["line"], f["secret_type"])
    assert sorted(map(key, disk["findings"])) == sorted(map(key, mem))
    assert disk["total_findings"] == len(mem)


def test_scan_consolidation():
    files = [{"path": n, "content": c} for n, c in _mem_files().items()]
    r = run_scan(files)
    assert r["total"] == 4
    assert r["total_secret_findings"] == 10
    assert r["files_with_secrets"] == 2
    assert r["skipped"] == []


def test_per_file_skip():
    files = [{"path": "huge.py", "content": "x = 1\n" * 300_000}]  # ~1.7 MB
    r = run_scan(files)
    assert any(s["path"] == "huge.py" for s in r["skipped"])
    assert not any(m["path"] == "huge.py" for m in r["files"])


def test_batch_overflow_self_corrects():
    files = [{"path": f"f{i}.py", "content": "a" * 70_000} for i in range(100)]  # ~7 MB
    r = run_scan(files)
    assert r["error"] == "payload_too_large"
    assert r["received_bytes"] > BATCH_MAX_BYTES
    assert "action_required" in r


def test_redaction_present():
    files = [{"path": ".env.test", "content": (FIX / ".env.test").read_text()}]
    r = run_scan(files)
    assert r["total_secret_findings"] > 0
    assert all("REDACTED" in f["evidence"] or "***" in f["evidence"] for f in r["secret_findings"])
