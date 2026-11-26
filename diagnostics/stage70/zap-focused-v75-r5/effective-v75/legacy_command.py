#!/usr/bin/env python3
"""V74 compatibility shim for historical commands in verified immutable V73."""
import sys
sys.dont_write_bytecode=True
from restore_v73 import inherited
ALLOWED={'restore_v72.py','restore_v71.py','restore_v70.py','restore_v69.py',
 'restore_v68.py','restore_v67.py','restore_v66.py','restore_v65.py',
 'audit_lineage.py','audit_evidence.py','audit_evidence_v68.py','audit_evidence_v69.py',
 'audit_evidence_v70.py','audit_evidence_v71.py','audit_evidence_v72.py',
 'integrity_selftest.py'}
def run(script,args):
 if script not in ALLOWED:raise SystemExit('LEGACY_SCRIPT_NOT_ALLOWED')
 inherited(script,args)
 return 0
