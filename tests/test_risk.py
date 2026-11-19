from cybersec.risk import assess_risk, normalize_vuln_type


def test_sql_injection_aliases_share_taxonomy():
    assert normalize_vuln_type("SQL Injection") == "sql_injection"
    assert normalize_vuln_type("sqli") == "sql_injection"
    assert normalize_vuln_type("SQL-injection") == "sql_injection"


def test_common_cross_tool_labels_normalize():
    assert normalize_vuln_type("Cross-Site Scripting (Reflected)") == "cross_site_scripting"
    assert normalize_vuln_type("Remote Code Execution") == "command_injection"
    assert normalize_vuln_type("Broken Access Control / IDOR") == "authorization_bypass"


def test_unknown_type_is_preserved_conservatively():
    assert normalize_vuln_type("Vendor Widget Oddity") == "vendor widget oddity"
    assert normalize_vuln_type("") == "unknown"


def test_risk_score_uses_severity_and_confidence_separately():
    certain = assess_risk("High", "Certain", "SQL Injection")
    tentative = assess_risk("High", "Tentative", "sqli")
    assert certain.risk_score == 8.0
    assert certain.priority == "P1"
    assert tentative.risk_score == 4.4
    assert tentative.priority == "P3"
    assert certain.severity_score == tentative.severity_score == 8.0
    assert "not CVSS" in certain.rationale


def test_risk_input_validation():
    import pytest
    with pytest.raises(ValueError):
        assess_risk("Urgent", "Certain", "SQL Injection")
    with pytest.raises(ValueError):
        assess_risk("High", "Verified", "SQL Injection")
