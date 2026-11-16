"""Shared domain models."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Target:
    id: int
    url: str
    hostname: str
    authorized: bool
    created_at: str
    criticality: str = "medium"


@dataclass(frozen=True)
class ScanJob:
    id: int
    target_id: int
    tool: str
    status: str
    created_at: str
    started_at: str | None
    finished_at: str | None
    error: str | None


@dataclass(frozen=True)
class Finding:
    id: int
    target_id: int
    job_id: int | None
    title: str
    severity: str
    confidence: str
    url: str
    vuln_type: str
    parameter: str | None
    evidence: str | None
    recommendation: str | None
    source_tool: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "job_id": self.job_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "url": self.url,
            "vuln_type": self.vuln_type,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "source_tool": self.source_tool,
            "created_at": self.created_at,
        }
