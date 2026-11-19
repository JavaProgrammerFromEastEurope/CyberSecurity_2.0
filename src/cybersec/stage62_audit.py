"""Read-only Stage 62 OS admission report. Never issues a production permit."""
from __future__ import annotations
import json
import pwd
import sys
from pathlib import Path
from cybersec.cgroup_containment import readonly_host_preflight

ROLES = ('cybersec-worker','cybersec-attester','cybersec-witness','cybersec-publisher')


def audit_host() -> dict:
    preflight = readonly_host_preflight()
    role_uids={}
    for role in ROLES:
        try:
            entry=pwd.getpwnam(role)
            role_uids[role]=entry.pw_uid
        except KeyError:
            role_uids[role]=None
    uid_separation=(all(uid is not None and uid != 0 for uid in role_uids.values())
                    and len(set(role_uids.values()))==len(ROLES))
    controls={
        'four_distinct_nonroot_uids':uid_separation,
        'current_uid_is_scanner_worker':role_uids['cybersec-worker']==__import__('os').geteuid(),
        'root_pinned_scope_key_present':Path('/etc/cybersec/trust/lab_ed25519.pub').is_file(),
        'root_owned_lab_ticket_present':Path('/etc/cybersec/lab-ticket.json').is_file(),
        'independent_mac_profile_installed':Path('/etc/apparmor.d/cybersec-worker').is_file(),
        'service_manager_unit_installed':Path('/etc/systemd/system/cybersec-scanner-worker.service').is_file(),
    }
    checks={**preflight.checks,**controls}
    # Not enough to prove enforcement / trust / restart. No status other than NO-GO.
    return {'schema':'cybersec.stage62.host-audit.v1','status':'BLOCKED/NO-GO',
            'production_permit':False,'checks':checks,
            'role_uids':role_uids,
            'blockers':[name for name,ok in checks.items() if not ok],
            'unproven':['MAC same-UID legacy confinement','cgroup PID migration prohibition',
                        'systemd service kill/restart and four-UID end-to-end',
                        'external trust-root origin and signed per-attempt authorization',
                        'ZAP remote-daemon termination','actual authorized Nuclei lab E2E']}


def main() -> int:
    print(json.dumps(audit_host(),sort_keys=True,ensure_ascii=False,indent=2))
    return 3  # always NO-GO until independent external attestation integration


if __name__=='__main__':
    sys.exit(main())
