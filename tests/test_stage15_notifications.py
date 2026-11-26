import pytest

from cybersec.cli import build_parser
from cybersec.comparison import compare_jobs
from cybersec.notifications import add_policy, evaluate_comparison, list_events, list_policies, update_event_status
from cybersec.repository import Repository


def setup_comparison(tmp_path):
    repo = Repository(tmp_path / "alerts.db")
    repo.add_target("https://example.com", authorized=True)
    before = repo.create_job("https://example.com", "nuclei")
    after = repo.create_job("https://example.com", "nuclei")
    repo.store_scan_artifact(before.id, "nuclei", {"findings": []})
    repo.store_scan_artifact(after.id, "nuclei", {"findings": [
        {"template-id": "critical-1", "title": "Critical issue", "url": "https://example.com/a", "severity": "critical"},
        {"template-id": "low-1", "title": "Low issue", "url": "https://example.com/b", "severity": "low"},
    ]})
    saved = repo.save_comparison(compare_jobs(repo, before.id, after.id))
    return repo, saved


def test_policy_defaults_and_update_by_name(tmp_path):
    repo, _ = setup_comparison(tmp_path)
    first = add_policy(repo, "critical-high")
    second = add_policy(repo, "critical-high", severities=["Critical"], event_types=["added"])
    assert first["id"] == second["id"]
    assert second["severities"] == ["Critical"]
    assert len(list_policies(repo)) == 1


def test_evaluation_queues_only_matching_events_and_is_idempotent(tmp_path):
    repo, saved = setup_comparison(tmp_path)
    add_policy(repo, "critical only", ["Critical"], ["added"])
    first = evaluate_comparison(repo, saved["id"])
    second = evaluate_comparison(repo, saved["id"])
    assert first["newly_queued"] == 1
    assert second["newly_queued"] == 0
    events = list_events(repo, status="pending")
    assert len(events) == 1
    assert events[0]["severity"] == "Critical"
    assert events[0]["event_type"] == "added"
    assert first["delivery"].startswith("disabled")


def test_acknowledge_and_suppress_are_auditable_status_changes(tmp_path):
    repo, saved = setup_comparison(tmp_path)
    add_policy(repo, "all", ["Critical", "Low"], ["added"])
    evaluate_comparison(repo, saved["id"])
    events = list_events(repo)
    assert len(events) == 2
    updated = update_event_status(repo, events[0]["id"], "acknowledged")
    assert updated["status"] == "acknowledged"
    with pytest.raises(ValueError, match="does not exist"):
        update_event_status(repo, 9999, "suppressed")


def test_invalid_policy_and_event_filters_rejected(tmp_path):
    repo, _ = setup_comparison(tmp_path)
    with pytest.raises(ValueError, match="valid severities"):
        add_policy(repo, "bad", ["Severe"], ["added"])
    with pytest.raises(ValueError, match="valid event types"):
        add_policy(repo, "bad-event", ["High"], ["deleted"])
    with pytest.raises(ValueError, match="Event limit"):
        list_events(repo, limit=0)


def test_alert_cli_parser():
    args = build_parser().parse_args(["alert", "policy-add", "highs", "--severity", "High", "--event", "added"])
    assert args.alert_command == "policy-add"
    assert args.name == "highs"
    assert args.severity == ["High"]
    assert args.event == ["added"]
