import json
from pathlib import Path

from cybersec.revalidation_history import (
    append_report, export_audit_package, verify_audit_package, verify_history_file,
)


def make_report(path: Path, name: str) -> Path:
    report = {"report_type": "continuous-evidence-revalidation", "generated_at": "2026-10-28T12:00:00Z",
              "valid": True, "bundle_count": 1, "results": [{"file": name, "valid": True, "transition": "new"}]}
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def test_append_and_verify_chain(tmp_path):
    history = tmp_path / "history.jsonl"
    first = make_report(tmp_path / "first.json", "a.json")
    second = make_report(tmp_path / "second.json", "b.json")
    assert append_report(history, first)["sequence"] == 1
    assert append_report(history, second)["sequence"] == 2
    result = verify_history_file(history)
    assert result["valid"] is True
    assert result["entries_checked"] == 2


def test_tampered_entry_is_detected_and_append_refused(tmp_path):
    history = tmp_path / "history.jsonl"
    report = make_report(tmp_path / "report.json", "a.json")
    append_report(history, report)
    entry = json.loads(history.read_text().splitlines()[0])
    entry["report"]["valid"] = False
    history.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    assert verify_history_file(history)["valid"] is False
    try:
        append_report(history, report)
    except ValueError as exc:
        assert "failed verification" in str(exc)
    else:
        raise AssertionError("tampered history must not accept new entries")


def test_reordering_or_deletion_in_middle_is_detected(tmp_path):
    history = tmp_path / "history.jsonl"
    for n in range(3):
        report = make_report(tmp_path / f"r{n}.json", f"{n}.json")
        append_report(history, report)
    lines = history.read_text().splitlines()
    history.write_text(lines[0] + "\n" + lines[2] + "\n", encoding="utf-8")
    result = verify_history_file(history)
    assert result["valid"] is False
    assert any("predecessor_mismatch" in error or "sequence_mismatch" in error for error in result["errors"])


def test_export_and_verify_package(tmp_path):
    history = tmp_path / "history.jsonl"
    report = make_report(tmp_path / "report.json", "a.json")
    append_report(history, report)
    package = tmp_path / "package.json"
    assert export_audit_package(history, package)["history_valid"] is True
    assert verify_audit_package(package)["valid"] is True
    payload = json.loads(package.read_text())
    payload["history_jsonl"] += "{}\n"
    package.write_text(json.dumps(payload), encoding="utf-8")
    assert verify_audit_package(package)["valid"] is False


def test_empty_history_is_valid(tmp_path):
    history = tmp_path / "empty.jsonl"
    history.write_text("", encoding="utf-8")
    result = verify_history_file(history)
    assert result["valid"] is True
    assert result["entries_checked"] == 0
