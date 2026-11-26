import json
from urllib.error import URLError

import pytest

from cybersec.cli import build_parser
from cybersec.notifications import (
    add_policy, check_delivery_config, deliver_event, evaluate_comparison,
    list_deliveries, mask_sensitive, preview_event, retry_failed_delivery,
)
from cybersec.comparison import compare_jobs
from cybersec.repository import Repository


class Response:
    status = 200
    def getcode(self): return self.status
    def read(self, size=-1): return b"ok"


class FakeOpener:
    def __init__(self, values): self.values = list(values); self.requests = []
    def open(self, request, timeout=0):
        self.requests.append(request)
        value = self.values.pop(0)
        if isinstance(value, Exception): raise value
        return value


def make_pending_event(tmp_path):
    repo = Repository(tmp_path / "stage17.db")
    repo.add_target("https://example.com", authorized=True)
    before = repo.create_job("https://example.com", "nuclei")
    after = repo.create_job("https://example.com", "nuclei")
    repo.store_scan_artifact(before.id, "nuclei", {"findings": []})
    repo.store_scan_artifact(after.id, "nuclei", {"findings": [{
        "template-id": "critical-1", "title": "Critical issue", "url": "https://example.com/a",
        "severity": "critical", "api_token": "never-send-this", "notes": "Bearer abc.def.ghi"
    }]})
    comparison = repo.save_comparison(compare_jobs(repo, before.id, after.id))
    add_policy(repo, "critical", ["Critical"], ["added"])
    evaluate_comparison(repo, comparison["id"])
    return repo


def test_mask_sensitive_recurses_without_mutating_source():
    original = {"api_token": "secret", "nested": [{"Authorization": "Bearer value", "ok": "fine"}], "notes": "Bearer abc.def"}
    safe = mask_sensitive(original)
    assert safe["api_token"] == "[REDACTED]"
    assert safe["nested"][0]["Authorization"] == "[REDACTED]"
    assert safe["notes"] == "Bearer [REDACTED]"
    assert original["api_token"] == "secret"


def test_preview_redacts_sensitive_values(tmp_path):
    repo = make_pending_event(tmp_path)
    from cybersec.db import connect
    with connect(repo.db_path) as db:
        db.execute("UPDATE notification_events SET payload_json=? WHERE id=1", (json.dumps({"api_token": "never-send-this", "notes": "Bearer abc.def.ghi"}),))
    payload = preview_event(repo, 1)["payload"]
    assert payload["api_token"] == "[REDACTED]"
    assert payload["notes"] == "Bearer [REDACTED]"


def test_config_check_requires_https_and_optional_allowlist(monkeypatch):
    monkeypatch.setenv("CYBERSEC_WEBHOOK_URL", "http://hooks.example.org/path")
    assert check_delivery_config()["valid"] is False
    monkeypatch.setenv("CYBERSEC_WEBHOOK_URL", "https://hooks.example.org/path")
    monkeypatch.setenv("CYBERSEC_WEBHOOK_ALLOWED_HOSTS", "hooks.example.org, other.example.org")
    assert check_delivery_config()["valid"] is True
    monkeypatch.setenv("CYBERSEC_WEBHOOK_ALLOWED_HOSTS", "trusted.example.org")
    result = check_delivery_config()
    assert result["valid"] is False and "allowlist" in result["reason"]


def test_delivery_masks_and_sends_stable_idempotency_key(monkeypatch, tmp_path):
    repo = make_pending_event(tmp_path)
    monkeypatch.setenv("CYBERSEC_WEBHOOK_URL", "https://hooks.example.org/path")
    from cybersec.db import connect
    with connect(repo.db_path) as db:
        db.execute("UPDATE notification_events SET payload_json=? WHERE id=1", (json.dumps({"api_token": "never-send-this", "notes": "Bearer abc.def.ghi"}),))
    fake = FakeOpener([Response()])
    result = deliver_event(repo, 1, confirmed=True, opener=fake)
    sent = json.loads(fake.requests[0].data)
    assert sent["event"]["payload"]["api_token"] == "[REDACTED]"
    assert fake.requests[0].get_header("Idempotency-key")
    assert result["outcome"] == "sent"
    assert list_deliveries(repo)[0]["idempotency_key"] == fake.requests[0].get_header("Idempotency-key")


def test_allowlist_blocks_delivery_before_http(monkeypatch, tmp_path):
    repo = make_pending_event(tmp_path)
    monkeypatch.setenv("CYBERSEC_WEBHOOK_URL", "https://hooks.example.org/path")
    monkeypatch.setenv("CYBERSEC_WEBHOOK_ALLOWED_HOSTS", "trusted.example.org")
    fake = FakeOpener([Response()])
    with pytest.raises(ValueError, match="allowlist"):
        deliver_event(repo, 1, confirmed=True, opener=fake)
    assert fake.requests == []


def test_retry_requires_failed_latest_attempt_and_confirmation(monkeypatch, tmp_path):
    repo = make_pending_event(tmp_path)
    monkeypatch.setenv("CYBERSEC_WEBHOOK_URL", "https://hooks.example.org/path")
    with pytest.raises(ValueError, match="latest delivery attempt failed"):
        retry_failed_delivery(repo, 1, confirmed=True, opener=FakeOpener([Response()]))
    failed = FakeOpener([TimeoutError("timeout")])
    first = deliver_event(repo, 1, confirmed=True, retries=0, opener=failed)
    assert first["outcome"] == "failed"
    with pytest.raises(PermissionError, match="explicit --confirm"):
        retry_failed_delivery(repo, 1, confirmed=False, opener=FakeOpener([Response()]))
    second = retry_failed_delivery(repo, 1, confirmed=True, opener=FakeOpener([Response()]))
    assert second["outcome"] == "sent"
    assert len(list_deliveries(repo)) == 2


def test_cli_stage17_commands_parse():
    args = build_parser().parse_args(["alert", "retry", "8", "--confirm"])
    assert args.alert_command == "retry" and args.event_id == 8 and args.confirm
    args = build_parser().parse_args(["alert", "delivery-config"])
    assert args.alert_command == "delivery-config"
