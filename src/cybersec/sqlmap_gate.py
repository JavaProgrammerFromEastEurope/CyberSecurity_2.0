"""Repository-backed, single-use approval gate for bounded sqlmap confirmations."""
from __future__ import annotations

from urllib.parse import parse_qs, urlsplit
import re
from cybersec.scanners import ScanContext, SqlmapConfirmationAdapter


def validate_candidate(target_url: str, candidate_url: str, parameter: str | None) -> None:
    if not isinstance(parameter, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", parameter):
        raise ValueError("Invalid query parameter")
    base, candidate = urlsplit(target_url), urlsplit(candidate_url)
    if (base.scheme not in ("http", "https") or candidate.scheme != base.scheme
            or not base.hostname or candidate.hostname != base.hostname
            or base.port != candidate.port or candidate.username or candidate.password
            or candidate.fragment or not (candidate.path == base.path or
                candidate.path.startswith(base.path.rstrip("/") + "/"))):
        raise ValueError("Candidate outside exact registered scope")
    if parameter not in parse_qs(candidate.query, keep_blank_values=True):
        raise ValueError("Candidate parameter absent")


def execute_approved_confirmation(repository, confirmation_id: int, *, adapter=None):
    """One-shot consumption, then bounded adapter execution. No worker auto-dispatch."""
    candidate = repository.claim_sqlmap_confirmation(confirmation_id)
    adapter = adapter if adapter is not None else SqlmapConfirmationAdapter()
    try:
        result = adapter.run(ScanContext(
            job_id=0, target_url=candidate["target_url"], tool="sqlmap",
            options={"authorized": True, "candidate_recorded": True,
                     "candidate_url": candidate["candidate_url"], "parameter": candidate["parameter"]}))
    except Exception as exc:
        repository.finish_sqlmap_confirmation(confirmation_id, status="failed",
                                             summary=f"{type(exc).__name__}: {exc}")
        raise
    repository.finish_sqlmap_confirmation(confirmation_id, status="completed", summary=result.summary)
    return result
