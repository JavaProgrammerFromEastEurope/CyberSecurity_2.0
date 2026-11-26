"""Conservative vulnerability taxonomy and explainable risk prioritization."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

# Ordered rules intentionally favor specific categories over broad keywords.
_TAXONOMY: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sql_injection", ("sql injection", "sqli", "sql-injection", "database injection")),
    ("command_injection", ("command injection", "os command injection", "rce", "remote code execution", "shell injection")),
    ("cross_site_scripting", ("cross site scripting", "cross-site scripting", " xss", "stored xss", "reflected xss", "dom xss")),
    ("server_side_request_forgery", ("server-side request forgery", "server side request forgery", " ssrf")),
    ("path_traversal", ("path traversal", "directory traversal", "local file inclusion", " lfi")),
    ("authentication_bypass", ("authentication bypass", "auth bypass", "broken authentication", "improper authentication")),
    ("authorization_bypass", ("authorization bypass", "privilege escalation", "broken access control", "idor", "insecure direct object reference")),
    ("xxe", ("xml external entity", "xxe")),
    ("deserialization", ("insecure deserialization", "unsafe deserialization", "deserialization")),
    ("sensitive_data_exposure", ("sensitive data exposure", "cleartext password", "plaintext password", "information disclosure", "data exposure")),
    ("security_misconfiguration", ("misconfiguration", "security header", "directory listing", "default credentials", "debug enabled")),
    ("tls_configuration", ("tls", "ssl", "certificate expired", "weak cipher", "certificate hostname")),
    ("outdated_component", ("outdated component", "vulnerable component", "known vulnerability", "cve-")),
)

def _text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (value or "").casefold()).strip()

def normalize_vuln_type(value: str) -> str:
    """Map common scanner labels to a stable category; unknown labels stay distinct."""
    text = _text(value)
    padded = f" {text} "
    for canonical, aliases in _TAXONOMY:
        for alias in aliases:
            if _text(alias) in padded or _text(alias) == text:
                return canonical
    return text or "unknown"

_SEVERITY_BASE = {"Info": 0.5, "Low": 2.0, "Medium": 5.0, "High": 8.0, "Critical": 9.5}
_CONFIDENCE_FACTOR = {"Certain": 1.0, "Firm": 0.8, "Tentative": 0.55, "Unknown": 0.4}

@dataclass(frozen=True)
class RiskAssessment:
    severity_score: float
    confidence_factor: float
    risk_score: float
    priority: str
    rationale: str
    taxonomy: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

def assess_risk(severity: str, confidence: str, vuln_type: str) -> RiskAssessment:
    """Calculate an explainable triage score, not a CVSS score or proof of exploitability."""
    if severity not in _SEVERITY_BASE:
        raise ValueError(f"Unsupported severity: {severity}")
    if confidence not in _CONFIDENCE_FACTOR:
        raise ValueError(f"Unsupported confidence: {confidence}")
    taxonomy = normalize_vuln_type(vuln_type)
    base = _SEVERITY_BASE[severity]
    factor = _CONFIDENCE_FACTOR[confidence]
    score = round(min(10.0, max(0.0, base * factor)), 2)
    if score >= 8.0:
        priority = "P1"
    elif score >= 5.0:
        priority = "P2"
    elif score >= 2.0:
        priority = "P3"
    else:
        priority = "P4"
    rationale = (f"{severity} severity baseline {base:.1f}/10 × {confidence.lower()} confidence factor "
                 f"{factor:.2f} = {score:.2f}/10. Taxonomy: {taxonomy}. "
                 "This is a triage heuristic, not CVSS and not a confirmation of exploitability.")
    return RiskAssessment(base, factor, score, priority, rationale, taxonomy)
