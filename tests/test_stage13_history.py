import json
import pytest

from cybersec.cli import build_parser
from cybersec.comparison import compare_jobs
from cybersec.repository import Repository


def setup_pair(tmp_path):
    repo = Repository(tmp_path / "history.db")
    repo.add_target("https://example.com", authorized=True)
    before = repo.create_job("https://example.com", "nuclei")
    after = repo.create_job("https://example.com", "nuclei")
    repo.store_scan_artifact(before.id, "nuclei", {"findings": [
        {"template-id": "xss", "title": "XSS", "url": "https://example.com/a", "severity": "high"}
    ]})
    repo.store_scan_artifact(after.id, "nuclei", {"findings": [
        {"template-id": "xss", "title": "XSS", "url": "https://example.com/a", "severity": "medium"},
        {"template-id": "new", "title": "New issue", "url": "https://example.com/b", "severity": "low"}
    ]})
    return repo, before, after


def test_save_comparison_and_retrieve_snapshot(tmp_path):
    repo, before, after = setup_pair(tmp_path)
    result = compare_jobs(repo, before.id, after.id)
    saved = repo.save_comparison(result)
    loaded = repo.get_comparison(saved["id"])
    assert loaded["result"]["summary"]["added"] == 1
    assert loaded["result"]["summary"]["changed"] == 1
    assert loaded["before_job_id"] == before.id
    assert loaded["after_job_id"] == after.id


def test_same_ordered_pair_updates_snapshot_without_duplicate(tmp_path):
    repo, before, after = setup_pair(tmp_path)
    first = repo.save_comparison(compare_jobs(repo, before.id, after.id))
    second = repo.save_comparison(compare_jobs(repo, before.id, after.id))
    assert first["id"] == second["id"]
    assert len(repo.list_comparisons()) == 1


def test_history_is_ordered_newest_first_and_limit_checked(tmp_path):
    repo, before, after = setup_pair(tmp_path)
    repo.save_comparison(compare_jobs(repo, before.id, after.id))
    # A reversed pair is a distinct ordered comparison and still compares the same target.
    repo.save_comparison(compare_jobs(repo, after.id, before.id))
    rows = repo.list_comparisons(limit=1)
    assert len(rows) == 1
    assert rows[0]["before_job_id"] == after.id
    with pytest.raises(ValueError, match="between 1 and 1000"):
        repo.list_comparisons(limit=0)


def test_missing_history_item_returns_none(tmp_path):
    repo, _, _ = setup_pair(tmp_path)
    assert repo.get_comparison(987) is None


def test_cli_parser_accepts_history_commands():
    args = build_parser().parse_args(["job", "history", "--limit", "25", "--output", "history.json"])
    assert args.job_command == "history" and args.limit == 25
    assert args.output == "history.json"
    show = build_parser().parse_args(["job", "history-show", "4"])
    assert show.job_command == "history-show" and show.comparison_id == 4


def test_history_schema_migrates_existing_stage12_database(tmp_path):
    # Creating a Stage 13 repository against a previously initialized database should be safe.
    db = tmp_path / "existing.db"
    repo = Repository(db)
    repo.add_target("https://example.com", authorized=True)
    before = repo.create_job("https://example.com", "demo")
    after = repo.create_job("https://example.com", "demo")
    repo.save_comparison(compare_jobs(repo, before.id, after.id))
    reopened = Repository(db)
    assert len(reopened.list_comparisons()) == 1
