from datetime import datetime, timedelta, timezone
import pytest

from cybersec.repository import Repository


def make_rule(repo):
    return repo.save_risk_intelligence_rule({"name": "Exception test", "description": "", "config": {"minimum_findings": 1}, "actor": "author"})


def expiry(days=3):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def test_exception_requires_independent_assigned_reviewer_and_audits(tmp_path):
    repo = Repository(tmp_path / "exceptions.db")
    rule = make_rule(repo)
    item = repo.create_risk_policy_exception(rule["id"], "requester", "reviewer", "Temporary documented exception", expiry())
    assert item["status"] == "pending"
    with pytest.raises(ValueError, match="assigned reviewer"):
        repo.review_risk_policy_exception(item["id"], "other", "approved")
    reviewed = repo.review_risk_policy_exception(item["id"], "reviewer", "approved", "Reviewed")
    assert reviewed["status"] == "approved"
    audit = repo.list_risk_policy_exception_audit(item["id"])
    assert [event["action"] for event in reversed(audit["items"])] == ["requested", "approved"]


def test_exception_rejects_self_review_and_expired_deadline(tmp_path):
    repo = Repository(tmp_path / "validation.db")
    rule = make_rule(repo)
    with pytest.raises(ValueError, match="different from requester"):
        repo.create_risk_policy_exception(rule["id"], "same", "same", "reason", expiry())
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    with pytest.raises(ValueError, match="future"):
        repo.create_risk_policy_exception(rule["id"], "requester", "reviewer", "reason", past)


def test_exception_revoke_and_no_policy_bypass(tmp_path):
    repo = Repository(tmp_path / "no-bypass.db")
    rule = make_rule(repo)
    exception = repo.create_risk_policy_exception(rule["id"], "requester", "reviewer", "Temporary exception", expiry())
    repo.review_risk_policy_exception(exception["id"], "reviewer", "approved")
    # An approved exception is governance metadata, not a policy approval.
    assert repo.get_risk_intelligence_policy_status()["eligible"] == 0
    revoked = repo.revoke_risk_policy_exception(exception["id"], "admin", "No longer needed")
    assert revoked["status"] == "revoked"


def test_retention_dry_run_and_delete_only_old_policy_evaluations(tmp_path):
    repo = Repository(tmp_path / "retention.db")
    repo.set_risk_policy_retention(30, "admin")
    with pytest.raises(ValueError, match="between 1 and 3650"):
        repo.set_risk_policy_retention(0)
    with __import__("cybersec.db", fromlist=["connect"]).connect(repo.db_path) as db:
        db.execute("INSERT INTO risk_intelligence_policy_evaluations(evaluated_by,summary_json,result_json,created_at) VALUES(?,?,?,?)", ("old", "{}", "{}", "2000-01-01T00:00:00Z"))
        db.execute("INSERT INTO risk_intelligence_policy_evaluations(evaluated_by,summary_json,result_json) VALUES(?,?,?)", ("new", "{}", "{}"))
    preview = repo.prune_risk_policy_evaluations(dry_run=True)
    assert preview["matched"] == 1 and preview["deleted"] == 0
    deleted = repo.prune_risk_policy_evaluations("retention-admin", dry_run=False)
    assert deleted["deleted"] == 1
    assert repo.list_risk_intelligence_policy_evaluations()["total"] == 1


def test_exception_api_and_retention_routes_protected(tmp_path):
    import json, threading, urllib.error, urllib.request
    from http.server import ThreadingHTTPServer
    from cybersec.api import API_VERSION, make_handler
    token = "stage43-test-token"
    repo = Repository(tmp_path / "api.db")
    rule = make_rule(repo)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(repo, token))
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    def call(path, method="GET", body=None, auth=True):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if auth: headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=3) as res: return res.status, json.loads(res.read())
        except urllib.error.HTTPError as exc: return exc.code, json.loads(exc.read())
    try:
        assert API_VERSION == "2.33.0"
        assert call("/api/v1/risk/policy/exceptions", auth=False)[0] == 401
        status, created = call("/api/v1/risk/policy/exceptions", "POST", {"rule_id": rule["id"], "requested_by": "alice", "reviewer": "bob", "reason": "temporary", "expires_at": expiry()})
        assert status == 201 and created["status"] == "pending"
        assert call(f"/api/v1/risk/policy/exceptions/{created['id']}/review", "POST", {"reviewer": "bob", "decision": "approved"})[1]["status"] == "approved"
        assert call("/api/v1/risk/policy/retention", "POST", {"retention_days": 90})[1]["retention_days"] == 90
        spec = call("/openapi.json")[1]
        assert "/api/v1/risk/policy/exceptions/{exception_id}/review" in spec["paths"]
        assert "/api/v1/risk/policy/retention/prune" in spec["paths"]
    finally:
        server.shutdown(); thread.join(timeout=3); server.server_close()
