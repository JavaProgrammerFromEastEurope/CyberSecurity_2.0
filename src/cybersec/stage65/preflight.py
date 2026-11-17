"""Read-only Stage 65 release gate: never returns production GO."""
from __future__ import annotations
import json
import sys

from cybersec.stage64_runtime import audit_host
from .host import actual_role_map
from .ledger import LedgerBlocked


def preflight():
    prior=audit_host()
    checks=dict(prior.checks)
    try:
        roles=actual_role_map()
        checks['five_separate_service_uids']=True
        role_uids={key:getattr(roles,key) for key in ('broker','worker','attester','witness','publisher')}
    except LedgerBlocked:
        checks['five_separate_service_uids']=False
        role_uids={}
    # These are independent facts that cannot be claimed from a self-report.
    checks.update({
        'kernel_app_armor_negative_tests':False,
        'authenticated_production_broker_wired_to_every_legacy_entry':False,
        'independent_durable_nonrollbackable_witness_root':False,
        'systemd_sigkill_restart_accepted_on_ubuntu_2610':False,
        'four_uid_live_cross_principal_evidence':False,
        'signed_operator_production_approval':False,
    })
    return {'schema':'cybersec.stage65.host-inventory.v1','version':'2.45.0',
            'status':'BLOCKED/NO-GO','production_admitted':False,
            'host':prior.os_release,'uids':role_uids,'checks':checks,
            'blockers':[k for k,v in checks.items() if not v]}


def main(argv=None):
    import argparse
    a=argparse.ArgumentParser()
    a.add_argument('--require-admission',action='store_true')
    a.parse_args(argv)
    print(json.dumps(preflight(),ensure_ascii=False,indent=2,sort_keys=True))
    return 3

if __name__=='__main__': sys.exit(main())
