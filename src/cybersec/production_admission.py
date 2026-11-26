"""Stage 64 mandatory production scanner gate: fail closed.

This guard is defense-in-depth, not OS MAC. Untrusted same-UID code can remove
an environment variable or import a legacy API. A production deployment MUST
enforce denial at the kernel and independent service-manager boundary.
"""
from __future__ import annotations

import os


class ProductionAdmissionDenied(PermissionError):
    pass


def production_requested() -> bool:
    """Read both historical and Stage 64 deployment modes for compatibility."""
    return any(os.environ.get(name, '').strip().lower() == 'production' for name in
               ('CYBERSEC_EXECUTION_MODE', 'CYBERSEC_RUNTIME_MODE'))


def require_production_admission(*, action: str) -> None:
    """Never grant production scanner execution from local process observations.

    Always refuse active production paths pending separately provisioned
    MAC, cgroup and signed, one-shot authorization integration in Stage 65.
    """
    if production_requested():
        raise ProductionAdmissionDenied(
            f'BLOCKED/NO-GO: {action} cannot be production-admitted by Stage 64; '
            'independent systemd/cgroup/LSM proof and signed per-attempt authority absent'
        )
