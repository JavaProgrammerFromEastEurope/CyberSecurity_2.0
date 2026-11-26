#!/usr/bin/env python3
"""Offline ZAP-mock contract smoke. Never claim a real network scan."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from cybersec.day03_zap import TARGET, run_lab

class MockLab:
    def __init__(self):
        self.calls = []
    def call(self, component, category, name, params=None):
        self.calls.append((component, category, name, params or {}))
        responses = {
            ('core', 'view', 'version'): {'version': 'SYNTHETIC_NOT_ZAP'},
            ('spider', 'action', 'scan'): {'scan': '10'},
            ('spider', 'view', 'status'): {'status': '100'},
            ('pscan', 'view', 'recordsToScan'): {'recordsToScan': '0'},
            ('core', 'view', 'alerts'): {'alerts': [
                {'url': TARGET+'about.html', 'alert': 'Synthetic demo finding', 'riskcode': '0'},
                {'url': 'https://outside.invalid/', 'alert': 'Must discard'}]},
        }
        return responses.get((component, category, name), {'Result': 'OK'})

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise RuntimeError('REFUSE_OVERWRITE_EVIDENCE')
    mock = MockLab()
    report = run_lab(mock, authorization=True, runtime=True)
    assert report['active_scan'] is False
    assert len(report['alerts']) == 1 and report['discarded_out_of_scope'] == 1
    assert all(c != 'ascan' for c,_,_,_ in mock.calls)
    evidence = {
        'kind': 'MOCK_ZAP_ONLY_NOT_REAL_NETWORK_SCAN',
        'actual_zap_docker_executed': False,
        'ajax_real_browser_executed': False,
        'real_lab_status': 'SKIP_DOCKER_UNAVAILABLE_OR_NOT_AUTHORIZED',
        'production': 'BLOCKED/NO-GO', 'stage71': 'NOT_OPENED',
        'calls': [[a,b,c] for a,b,c,_ in mock.calls],
        'in_scope_findings': len(report['alerts']),
        'out_of_scope_dropped': report['discarded_out_of_scope'],
        'result': 'PASS'
    }
    args.out.mkdir(parents=True, mode=0o700)
    path = args.out/'mock_e2e.json'
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True)+'\n')
    (args.out/'SHA256SUMS.txt').write_text(hashlib.sha256(path.read_bytes()).hexdigest()+'  mock_e2e.json\n')
    print('DAY03_MOCK_E2E_PASS: real ZAP and Ajax are SKIP/NOT_EXECUTED')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
