import copy
import hashlib
import json

import pytest

from cybersec.repository import Repository


def _rule(repo, name="Governed rule", config=None):
    return repo.save_risk_intelligence_rule({"name": name, "description": "test", "config": config or {"minimum_findings": 3}, "actor": "author"})


def test_active_version_approval_lock_and_audit(tmp_path):
    repo = Repository(tmp_path / "governance.db")
    rule = _rule(repo)
    repo.save_risk_intelligence_rule({"id": rule["id"], "name": rule["name"], "description": rule["description"], "config": {"minimum_findings": 5}, "actor": "editor"})
    state = repo.set_risk_intelligence_active_version(rule["id"], 1, "analyst")
    assert state["active_version_number"] == 1
    state = repo.approve_risk_intelligence_rule(rule["id"], "reviewer")
    assert state["approved_version_number"] == 1 and state["locked"] == 1
    with pytest.raises(PermissionError):
        repo.save_risk_intelligence_rule({"id": rule["id"], "name": rule["name"], "description": "changed", "config": {}, "actor": "oops"})
    repo.unlock_risk_intelligence_rule(rule["id"], "reviewer", "approved change request")
    updated = repo.save_risk_intelligence_rule({"id": rule["id"], "name": rule["name"], "description": "changed", "config": {}, "actor": "editor"})
    assert updated["description"] == "changed"
    audit = repo.list_risk_intelligence_governance_audit(rule["id"])
    assert [x["action"] for x in audit["items"]][:2] == ["unlocked", "approved"]


def test_compare_version_outcomes_uses_preview_only(tmp_path):
    repo = Repository(tmp_path / "compare.db")
    rule = _rule(repo, config={"minimum_findings": 1})
    repo.save_risk_intelligence_rule({"id": rule["id"], "name": rule["name"], "description": rule["description"], "config": {"minimum_findings": 20}, "actor": "editor"})
    result = repo.compare_risk_intelligence_rule_versions(rule["id"], 1, 2)
    assert result["before"]["version_number"] == 1
    assert result["after"]["version_number"] == 2
    assert "no alerts" in result["note"]


def test_export_import_integrity_and_validation(tmp_path):
    repo = Repository(tmp_path / "export.db")
    _rule(repo, "Exported rule", {"growth_ratio": 2.25})
    bundle = repo.export_risk_intelligence_rules()
    assert bundle["sha256"] == hashlib.sha256(json.dumps({k: bundle[k] for k in ("format", "schema_version", "rules")}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    target = Repository(tmp_path / "import.db")
    result = target.import_risk_intelligence_rules(bundle, "operator")
    assert result["integrity"] == "verified" and result["imported"] == 1
    changed = copy.deepcopy(bundle)
    changed["rules"][0]["name"] = "tampered"
    with pytest.raises(ValueError, match="integrity"):
        target.import_risk_intelligence_rules(changed)
    # Even a valid digest cannot bypass schema validation.
    bad = {"format": "cybersec-risk-rules", "schema_version": 1, "rules": [{"name": "bad", "config": {"unknown": 1}}]}
    bad["sha256"] = hashlib.sha256(json.dumps(bad, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    with pytest.raises(ValueError, match="Unknown configuration fields"):
        target.import_risk_intelligence_rules(bad)


def test_export_selected_ids_and_locked_active_version(tmp_path):
    repo = Repository(tmp_path / "selected.db")
    a = _rule(repo, "A")
    b = _rule(repo, "B")
    assert [x["name"] for x in repo.export_risk_intelligence_rules([b["id"]])["rules"]] == ["B"]
    repo.approve_risk_intelligence_rule(a["id"], "reviewer")
    with pytest.raises(PermissionError):
        repo.set_risk_intelligence_active_version(a["id"], 1)
