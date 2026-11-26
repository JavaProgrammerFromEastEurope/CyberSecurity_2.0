import json

import pytest

from cybersec.cli import build_parser
from cybersec.comparison import compare_jobs
from cybersec.db import connect
from cybersec.delivery_queue import claim_next, finish_claim, queue_stats, release_claim
from cybersec.notifications import add_policy, evaluate_comparison
from cybersec.repository import Repository


def pending_event(tmp_path):
    repo = Repository(tmp_path / "stage18.db")
    repo.add_target("https://example.com", authorized=True)
    before = repo.create_job("https://example.com", "demo")
    after = repo.create_job("https://example.com", "demo")
    repo.store_scan_artifact(before.id, "demo", {"findings": []})
    repo.store_scan_artifact(after.id, "demo", {"findings": [{"title": "Issue", "severity": "critical", "url": "https://example.com/x", "template-id": "T1"}]})
    comparison = repo.save_comparison(compare_jobs(repo, before.id, after.id))
    add_policy(repo, "urgent", ["Critical"], ["added"])
    evaluate_comparison(repo, comparison["id"])
    return repo


def test_claim_is_exclusive_and_released(tmp_path):
    repo = pending_event(tmp_path)
    first = claim_next(repo, "worker-a", 30)
    assert first and first["lease_owner"] == "worker-a"
    assert claim_next(repo, "worker-b", 30) is None
    assert queue_stats(repo)["leased"] == 1
    assert release_claim(repo, first["id"], "worker-a") is True
    assert claim_next(repo, "worker-b", 30)["id"] == first["id"]


def test_claim_validates_lease_and_worker(tmp_path):
    repo = pending_event(tmp_path)
    with pytest.raises(ValueError, match="between 5 and 3600"):
        claim_next(repo, "worker-a", 2)
    with pytest.raises(ValueError, match="1-128"):
        claim_next(repo, "", 30)


def test_finish_requires_lease_owner_and_schedules_backoff(tmp_path):
    repo = pending_event(tmp_path)
    event = claim_next(repo, "worker-a", 30)
    with pytest.raises(PermissionError, match="does not own"):
        finish_claim(repo, event["id"], "worker-b", outcome="failed", error="Timeout")
    result = finish_claim(repo, event["id"], "worker-a", outcome="failed", error="Timeout", base_delay_seconds=10)
    assert result["delivery_attempts"] == 1
    assert result["next_attempt_at"] is not None
    assert queue_stats(repo)["delayed"] == 1
    with connect(repo.db_path) as db:
        row = db.execute("SELECT last_delivery_error, lease_owner FROM notification_events WHERE id=?", (event["id"],)).fetchone()
    assert row["last_delivery_error"] == "Timeout"
    assert row["lease_owner"] is None


def test_finish_sent_acknowledges_event(tmp_path):
    repo = pending_event(tmp_path)
    event = claim_next(repo, "worker-a", 30)
    result = finish_claim(repo, event["id"], "worker-a", outcome="sent")
    assert result["outcome"] == "sent"
    assert queue_stats(repo)["by_status"]["acknowledged"] == 1
    assert queue_stats(repo)["due_pending"] == 0


def test_cli_stage18_queue_commands_parse():
    args = build_parser().parse_args(["alert", "worker-once", "--worker-id", "worker-1", "--confirm"])
    assert args.alert_command == "worker-once" and args.confirm
    args = build_parser().parse_args(["alert", "queue-stats"])
    assert args.alert_command == "queue-stats"
