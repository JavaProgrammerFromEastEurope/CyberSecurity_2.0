import json

import pytest

from cybersec.comparison import compare_jobs
from cybersec.repository import Repository
from cybersec.cli import build_parser


def _setup(tmp_path):
    repo = Repository(tmp_path / "compare.db")
    repo.add_target("https://example.com", authorized=True)
    before = repo.create_job("https://example.com", "nuclei")
    after = repo.create_job("https://example.com", "nuclei")
    return repo, before, after


def test_comparison_classifies_added_resolved_unchanged_and_changed(tmp_path):
    repo, before, after = _setup(tmp_path)
    repo.store_scan_artifact(before.id, "nuclei", {"findings": [
        {"template-id": "keep", "title": "Keep", "severity": "medium", "url": "https://example.com/keep"},
        {"template-id": "gone", "title": "Gone", "severity": "low", "url": "https://example.com/gone"},
        {"template-id": "change", "title": "Change", "severity": "low", "url": "https://example.com/change"},
    ]})
    repo.store_scan_artifact(after.id, "nuclei", {"findings": [
        {"template-id": "keep", "title": "Keep", "severity": "medium", "url": "https://example.com/keep"},
        {"template-id": "change", "title": "Change", "severity": "critical", "url": "https://example.com/change"},
        {"template-id": "new", "title": "New", "severity": "high", "url": "https://example.com/new"},
    ]})
    result = compare_jobs(repo, before.id, after.id)
    assert result["summary"] == {"added": 1, "resolved": 1, "unchanged": 1, "changed": 1,
                                 "before_findings": 3, "after_findings": 3}
    assert result["added"][0]["title"] == "New"
    assert result["resolved"][0]["title"] == "Gone"
    assert result["changed"][0]["after"]["severity"] == "Critical"
    assert result["comparison"]["network_requests"] == 0


def test_comparison_is_repeatable_and_does_not_mutate_database(tmp_path):
    repo, before, after = _setup(tmp_path)
    repo.store_scan_artifact(before.id, "nuclei", {"findings": [{"template-id": "a", "title": "A", "url": "https://example.com/a", "severity": "low"}]})
    repo.store_scan_artifact(after.id, "nuclei", {"findings": []})
    first = compare_jobs(repo, before.id, after.id)
    second = compare_jobs(repo, before.id, after.id)
    assert first == second
    assert repo.search_scan_artifacts(job_id=before.id)[0]["payload"]


def test_comparison_rejects_different_targets(tmp_path):
    repo, before, after = _setup(tmp_path)
    repo.add_target("https://other.example", authorized=True)
    other = repo.create_job("https://other.example", "nuclei")
    with pytest.raises(ValueError, match="same registered target"):
        compare_jobs(repo, before.id, other.id)


def test_comparison_rejects_unknown_job(tmp_path):
    repo, before, _ = _setup(tmp_path)
    with pytest.raises(ValueError, match="does not exist"):
        compare_jobs(repo, before.id, 999)


def test_cli_parser_accepts_job_compare():
    args = build_parser().parse_args(["job", "compare", "--before", "2", "--after", "3", "--output", "out.json"])
    assert args.job_command == "compare"
    assert args.before == 2 and args.after == 3 and args.output == "out.json"
