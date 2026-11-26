from concurrent.futures import ThreadPoolExecutor
import json
import logging

from cybersec.cli import build_parser
from cybersec.comparison import compare_jobs
from cybersec.db import connect
from cybersec.delivery_queue import claim_next
from cybersec.notifications import add_policy, evaluate_comparison
from cybersec.observability import queue_diagnostics, queue_metrics
from cybersec.repository import Repository
from cybersec.worker import run_worker


def make_pending_event(tmp_path):
    repo = Repository(tmp_path / "stage20.db")
    repo.add_target("https://example.com", authorized=True)
    before = repo.create_job("https://example.com", "demo")
    after = repo.create_job("https://example.com", "demo")
    repo.store_scan_artifact(before.id, "demo", {"findings": []})
    repo.store_scan_artifact(after.id, "demo", {"findings": [{"title": "Issue", "severity": "critical", "url": "https://example.com/x", "template-id": "T1"}]})
    comparison = repo.save_comparison(compare_jobs(repo, before.id, after.id))
    add_policy(repo, "urgent", ["Critical"], ["added"])
    evaluate_comparison(repo, comparison["id"])
    return repo


def test_two_concurrent_workers_cannot_claim_same_event(tmp_path):
    repo = make_pending_event(tmp_path)
    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(lambda worker: claim_next(repo, worker, 30), ["worker-a", "worker-b"]))
    claimed = [item for item in claims if item is not None]
    assert len(claimed) == 1
    assert claimed[0]["id"] > 0


def test_metrics_and_diagnostics_are_local_and_healthy(tmp_path):
    repo = make_pending_event(tmp_path)
    metrics = queue_metrics(repo)
    diag = queue_diagnostics(repo)
    assert metrics["queue"]["due_pending"] == 1
    assert metrics["delivery_attempts"]["total_attempts"] == 0
    assert diag["healthy"] is True
    assert diag["sqlite_integrity"] == "ok"
    assert "pending_events_due" in diag["warnings"]


def test_expired_lease_appears_in_diagnostics(tmp_path):
    repo = make_pending_event(tmp_path)
    event = claim_next(repo, "worker-a", 5)
    with connect(repo.db_path) as db:
        db.execute("UPDATE notification_events SET lease_until='2000-01-01T00:00:00Z' WHERE id=?", (event["id"],))
    diag = queue_diagnostics(repo)
    assert diag["expired_leases"] == 1
    assert "expired_leases_present" in diag["warnings"]


def test_worker_emits_structured_logs_and_duration(tmp_path, monkeypatch, caplog):
    repo = make_pending_event(tmp_path)
    monkeypatch.setattr("cybersec.worker.deliver_event", lambda _repo, event_id, confirmed=False: {"event_id": event_id, "outcome": "failed", "error": "test-only"})
    caplog.set_level(logging.INFO, logger="cybersec.worker")
    result = run_worker(repo, worker_id="worker-test", max_events=1, idle_seconds=0.1,
                        max_attempts=1, confirmed=True, sleeper=lambda _: None)
    assert result["duration_seconds"] >= 0
    parsed = [json.loads(record.message) for record in caplog.records if record.name == "cybersec.worker"]
    assert {item["event"] for item in parsed} >= {"event_claimed", "event_finished", "worker_stopped"}
    assert all("payload" not in item for item in parsed)


def test_cli_stage20_observability_commands_parse():
    assert build_parser().parse_args(["alert", "metrics"]).alert_command == "metrics"
    assert build_parser().parse_args(["alert", "diagnostics"]).alert_command == "diagnostics"
