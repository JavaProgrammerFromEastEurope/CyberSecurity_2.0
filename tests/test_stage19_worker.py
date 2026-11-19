import pytest

from cybersec.cli import build_parser
from cybersec.comparison import compare_jobs
from cybersec.db import connect
from cybersec.delivery_queue import claim_next, finish_claim, list_dead_letters, queue_stats, resolve_dead_letter
from cybersec.notifications import add_policy, evaluate_comparison
from cybersec.repository import Repository
from cybersec.worker import run_worker


def make_pending_event(tmp_path):
    repo = Repository(tmp_path / "stage19.db")
    repo.add_target("https://example.com", authorized=True)
    before = repo.create_job("https://example.com", "demo")
    after = repo.create_job("https://example.com", "demo")
    repo.store_scan_artifact(before.id, "demo", {"findings": []})
    repo.store_scan_artifact(after.id, "demo", {"findings": [{"title": "Issue", "severity": "critical", "url": "https://example.com/x", "template-id": "T1"}]})
    comparison = repo.save_comparison(compare_jobs(repo, before.id, after.id))
    add_policy(repo, "urgent", ["Critical"], ["added"])
    evaluate_comparison(repo, comparison["id"])
    return repo


def test_failure_quarantines_after_max_attempts_and_requires_resolution(tmp_path):
    repo = make_pending_event(tmp_path)
    event = claim_next(repo, "worker-a", 30)
    result = finish_claim(repo, event["id"], "worker-a", outcome="failed", error="configuration failure", max_attempts=1)
    assert result["quarantined"] is True
    assert queue_stats(repo)["quarantined"] == 1
    assert claim_next(repo, "worker-b", 30) is None
    dead = list_dead_letters(repo)
    assert len(dead) == 1 and dead[0]["event_id"] == event["id"]
    assert resolve_dead_letter(repo, event["id"]) is True
    assert queue_stats(repo)["quarantined"] == 0
    assert claim_next(repo, "worker-b", 30)["id"] == event["id"]


def test_worker_requires_confirmation_and_validates_limits(tmp_path):
    repo = make_pending_event(tmp_path)
    with pytest.raises(PermissionError, match="explicit confirmation"):
        run_worker(repo, worker_id="worker", confirmed=False, sleeper=lambda _: None)
    with pytest.raises(ValueError, match="Idle interval"):
        run_worker(repo, worker_id="worker", confirmed=True, idle_seconds=0, sleeper=lambda _: None)


def test_worker_processes_event_and_stops_at_max_events(tmp_path, monkeypatch):
    repo = make_pending_event(tmp_path)
    def fake_delivery(_repo, event_id, *, confirmed=False):
        assert confirmed is True
        return {"event_id": event_id, "outcome": "failed", "error": "simulated test failure"}
    monkeypatch.setattr("cybersec.worker.deliver_event", fake_delivery)
    result = run_worker(repo, worker_id="worker-test", max_events=1, idle_seconds=0.1,
                        max_attempts=1, confirmed=True, sleeper=lambda _: None)
    assert result["processed"] == 1
    assert result["failed"] == 1
    assert result["stopped"] is False
    assert queue_stats(repo)["quarantined"] == 1


def test_cli_stage19_worker_and_quarantine_commands_parse():
    args = build_parser().parse_args(["alert", "worker", "--worker-id", "worker-a", "--max-events", "3", "--confirm"])
    assert args.alert_command == "worker" and args.max_events == 3 and args.confirm
    args = build_parser().parse_args(["alert", "dead-letters", "--all"])
    assert args.alert_command == "dead-letters" and args.all
    args = build_parser().parse_args(["alert", "resolve-dead-letter", "42"])
    assert args.event_id == 42
