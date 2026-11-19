import json
from urllib.error import HTTPError
from io import BytesIO

import pytest

from cybersec.cli import build_parser
from cybersec.comparison import compare_jobs
from cybersec.notifications import (
    add_policy, deliver_event, evaluate_comparison, list_deliveries, preview_event,
)
from cybersec.repository import Repository


class FakeResponse:
    status = 204
    def getcode(self): return self.status
    def read(self, size=-1): return b""


class FakeOpener:
    def __init__(self, responses): self.responses = list(responses); self.requests = []
    def open(self, request, timeout=0):
        self.requests.append((request, timeout))
        item = self.responses.pop(0)
        if isinstance(item, Exception): raise item
        return item


def setup_event(tmp_path):
    repo = Repository(tmp_path / "delivery.db")
    repo.add_target("https://example.com", authorized=True)
    before = repo.create_job("https://example.com", "nuclei")
    after = repo.create_job("https://example.com", "nuclei")
    repo.store_scan_artifact(before.id, "nuclei", {"findings": []})
    repo.store_scan_artifact(after.id, "nuclei", {"findings": [
        {"template-id": "critical-1", "title": "Critical issue", "url": "https://example.com/a", "severity": "critical"}
    ]})
    comparison = repo.save_comparison(compare_jobs(repo, before.id, after.id))
    add_policy(repo, "critical", ["Critical"], ["added"])
    evaluate_comparison(repo, comparison["id"])
    return repo


def test_preview_does_not_send_or_change_status(tmp_path):
    repo = setup_event(tmp_path)
    event = preview_event(repo, 1)
    assert event["status"] == "pending"
    assert event["severity"] == "Critical"
    assert event["delivery_requires"]
    assert list_deliveries(repo) == []


def test_delivery_requires_confirmation_and_https(monkeypatch, tmp_path):
    repo = setup_event(tmp_path)
    monkeypatch.setenv("CYBERSEC_WEBHOOK_URL", "http://example.org/hook")
    with pytest.raises(PermissionError, match="explicit --confirm"):
        deliver_event(repo, 1)
    with pytest.raises(ValueError, match="HTTPS"):
        deliver_event(repo, 1, confirmed=True)
    assert list_deliveries(repo) == []


def test_successful_delivery_is_audited_and_acknowledged(monkeypatch, tmp_path):
    repo = setup_event(tmp_path)
    monkeypatch.setenv("CYBERSEC_WEBHOOK_URL", "https://hooks.example.org/security")
    fake = FakeOpener([FakeResponse()])
    result = deliver_event(repo, 1, confirmed=True, opener=fake)
    assert result["outcome"] == "sent"
    assert result["attempt_count"] == 1
    assert len(fake.requests) == 1
    req, timeout = fake.requests[0]
    assert req.full_url == "https://hooks.example.org/security"
    assert json.loads(req.data)["event"]["severity"] == "Critical"
    assert timeout == 5.0
    assert list_deliveries(repo)[0]["outcome"] == "sent"
    assert preview_event(repo, 1)["status"] == "acknowledged"


def test_failed_delivery_retries_and_logs_without_body(monkeypatch, tmp_path):
    repo = setup_event(tmp_path)
    monkeypatch.setenv("CYBERSEC_WEBHOOK_URL", "https://hooks.example.org/security")
    fake = FakeOpener([TimeoutError(), FakeResponse()])
    result = deliver_event(repo, 1, confirmed=True, retries=1, opener=fake)
    assert result["outcome"] == "sent"
    assert result["attempt_count"] == 2
    assert len(list_deliveries(repo)) == 1


def test_redirect_is_not_followed(monkeypatch, tmp_path):
    repo = setup_event(tmp_path)
    monkeypatch.setenv("CYBERSEC_WEBHOOK_URL", "https://hooks.example.org/security")
    redirect = HTTPError("https://hooks.example.org/security", 302, "redirect", {}, BytesIO(b""))
    fake = FakeOpener([redirect, FakeResponse()])
    result = deliver_event(repo, 1, confirmed=True, retries=2, opener=fake)
    assert result["outcome"] == "failed"
    assert result["attempt_count"] == 1
    assert "Redirect refused" in result["error"]
    assert len(fake.requests) == 1


def test_delivery_cli_requires_explicit_confirmation():
    args = build_parser().parse_args(["alert", "deliver", "7", "--confirm"])
    assert args.event_id == 7 and args.confirm is True
    args = build_parser().parse_args(["alert", "preview", "7"])
    assert args.alert_command == "preview"
