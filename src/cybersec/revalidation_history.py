"""Offline tamper-evident history for evidence revalidation reports."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64

def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def _entry_core(entry: dict) -> dict:
    return {k: v for k, v in entry.items() if k != "entry_sha256"}

def verify_history_file(path: str | Path) -> dict:
    """Verify every report digest, entry digest, sequence number and predecessor link."""
    source = Path(path)
    try:
        raw = source.read_bytes()
        entries = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {"report_type": "revalidation-history-verification", "valid": False,
                "entries_checked": 0, "errors": [f"history_read_error: {exc}"]}
    errors: list[str] = []
    previous = GENESIS
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            errors.append(f"entry_{index}:not_object")
            break
        if entry.get("sequence") != index:
            errors.append(f"entry_{index}:sequence_mismatch")
        if entry.get("previous_entry_sha256") != previous:
            errors.append(f"entry_{index}:predecessor_mismatch")
        report = entry.get("report")
        expected_report_hash = sha256_bytes(canonical(report))
        if entry.get("report_sha256") != expected_report_hash:
            errors.append(f"entry_{index}:report_hash_mismatch")
        expected_entry_hash = sha256_bytes(canonical(_entry_core(entry)))
        if entry.get("entry_sha256") != expected_entry_hash:
            errors.append(f"entry_{index}:entry_hash_mismatch")
        previous = entry.get("entry_sha256", "")
    return {"report_type": "revalidation-history-verification", "valid": not errors,
            "history_path": str(source), "entries_checked": len(entries),
            "head_sha256": previous if entries else GENESIS, "errors": errors,
            "limitations": ["A hash chain detects edits only relative to a trusted copy of its head hash.",
                            "This format does not provide author authentication; protect/export the head hash separately."]}

def append_report(history_path: str | Path, report_path: str | Path) -> dict:
    """Append one JSON report only after validating the existing chain."""
    history, report_file = Path(history_path), Path(report_path)
    report = json.loads(report_file.read_text(encoding="utf-8"))
    if not isinstance(report, dict) or report.get("report_type") != "continuous-evidence-revalidation":
        raise ValueError("report must be a continuous-evidence-revalidation JSON object")
    if not report.get("generated_at"):
        raise ValueError("report must contain generated_at")
    if history.exists() and history.stat().st_size:
        verification = verify_history_file(history)
        if not verification.get("valid"):
            raise ValueError("existing history failed verification; refusing to append")
        existing = [json.loads(line) for line in history.read_text(encoding="utf-8").splitlines() if line.strip()]
    else:
        existing = []
    previous = existing[-1]["entry_sha256"] if existing else GENESIS
    entry = {"sequence": len(existing) + 1,
             "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
             "previous_entry_sha256": previous,
             "report_sha256": sha256_bytes(canonical(report)),
             "report": report}
    entry["entry_sha256"] = sha256_bytes(canonical(entry))
    history.parent.mkdir(parents=True, exist_ok=True)
    # Atomic replacement prevents a process interruption from leaving a half-written JSONL line.
    content = history.read_bytes() if history.exists() else b""
    if content and not content.endswith(b"\n"):
        content += b"\n"
    content += canonical(entry) + b"\n"
    fd, tmp_name = tempfile.mkstemp(prefix=f".{history.name}.", suffix=".tmp", dir=str(history.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content); stream.flush(); os.fsync(stream.fileno())
        os.replace(tmp_name, history)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
    return {"appended": True, "sequence": entry["sequence"], "entry_sha256": entry["entry_sha256"],
            "report_sha256": entry["report_sha256"], "history_path": str(history)}

def export_audit_package(history_path: str | Path, output_path: str | Path) -> dict:
    """Create a portable package containing the exact chain and its verification result."""
    history = Path(history_path)
    verification = verify_history_file(history)
    package = {"format": "cybersec-revalidation-audit-package", "schema_version": 1,
               "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
               "history_sha256": sha256_bytes(history.read_bytes()) if history.exists() else None,
               "history_jsonl": history.read_text(encoding="utf-8") if history.exists() else "",
               "verification": verification,
               "limitations": ["Package integrity is not an external signature.",
                               "For strong tamper evidence, preserve the exported history/head hash independently."]}
    destination = Path(output_path); destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(package, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return {"exported": True, "output": str(destination), "history_valid": verification.get("valid", False),
            "entries_checked": verification.get("entries_checked", 0), "history_sha256": package["history_sha256"]}

def verify_audit_package(package_path: str | Path) -> dict:
    """Verify embedded JSONL chain and its package-level history digest offline."""
    try:
        package = json.loads(Path(package_path).read_text(encoding="utf-8"))
        if package.get("format") != "cybersec-revalidation-audit-package":
            raise ValueError("unsupported package format")
        history_text = package.get("history_jsonl")
        if not isinstance(history_text, str):
            raise ValueError("history_jsonl must be a string")
        digest_ok = sha256_bytes(history_text.encode("utf-8")) == package.get("history_sha256")
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".jsonl", delete=False) as temp:
            temp.write(history_text); temp_path = temp.name
        try:
            chain = verify_history_file(temp_path)
        finally:
            os.unlink(temp_path)
        return {"report_type": "revalidation-audit-package-verification", "valid": digest_ok and chain.get("valid", False),
                "package_history_hash_valid": digest_ok, "chain_verification": chain}
    except (OSError, json.JSONDecodeError, ValueError, AttributeError) as exc:
        return {"report_type": "revalidation-audit-package-verification", "valid": False, "errors": [str(exc)]}
