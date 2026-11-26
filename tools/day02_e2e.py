#!/usr/bin/env python3
"""Local non-scanning acceptance of Stage70 WP04-WP06; never production admission."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from cybersec.repository import Repository
from cybersec.runner import JobRunner
from cybersec.day02 import DemoController, add_report_asset, get_enriched_finding, ingest_raw_finding, require_scope
from cybersec.db import connect
from cybersec.scope import ScopeError

TARGET = 'http://127.0.0.1:8765/day02/'


def run(out: Path) -> dict:
    if any(os.getenv(key, '').casefold().strip() == 'production' for key in ('CYBERSEC_EXECUTION_MODE', 'CYBERSEC_RUNTIME_MODE')):
        raise RuntimeError('PRODUCTION_MODE_FORBIDDEN')
    if out.exists():
        raise ValueError('EVIDENCE_DIR_MUST_NOT_EXIST')
    out.mkdir(parents=True, mode=0o700)
    repo = Repository(out/'day02.db')
    repo.add_target(TARGET, True)
    ctl=DemoController(repo)
    pid=ctl.create_plan(TARGET, request_key='stage70-day02-real-e2e-0001', tools=('demo','demo'))
    steps=[]
    for n in (1,2):
        step=ctl.advance(pid)
        assert step['queued_now'] and step['tool']=='demo'
        job=JobRunner(repo).run(step['job_id'])
        assert job.status=='completed' and job.raw_output.get('network_requests')==0
        finding=ingest_raw_finding(repo, job_id=step['job_id'],
            raw={'mode':'synthetic','step':n,'network_requests':0},
            finding_url=TARGET+'endpoint?id='+str(n),title='Synthetic evidence '+str(n),
            vuln_type='demo-only',severity='Info',method='GET',
            reproduction_steps='Offline demonstration: no vulnerability verified')
        if n==1:
            add_report_asset(repo,finding_id=finding.finding_id,
                filename='synthetic.txt',media_type='text/plain',content=b'Synthetic only; no scan performed')
        enriched=get_enriched_finding(repo,finding.finding_id)
        assert enriched['raw_sha256']==finding.sha256
        steps.append({'ordinal':n,'job_id':step['job_id'],'raw_ref':finding.raw_id,'finding_id':finding.finding_id})
    assert ctl.advance(pid)['status']=='succeeded'
    denied=False
    try:
        require_scope(TARGET,'http://not-local.test/foreign')
    except ScopeError:
        denied=True
    assert denied
    with connect(repo.db_path) as db:
        counts={k:db.execute('SELECT COUNT(*) FROM '+k).fetchone()[0] for k in
                ('targets','scan_jobs','raw_findings','normalized_findings','report_assets','controller_plans','controller_steps')}
        integrity=db.execute('PRAGMA integrity_check').fetchone()[0]
        migration=db.execute('SELECT COUNT(*) FROM day02_schema_migrations').fetchone()[0]
    assert integrity=='ok'
    assert counts=={'targets':1,'scan_jobs':2,'raw_findings':2,'normalized_findings':2,'report_assets':1,'controller_plans':1,'controller_steps':2}
    report={'mode':'OFFLINE_DEMO_ONLY','production':'BLOCKED/NO-GO', 'stage71':'NOT_OPENED',
            'scope_denial':'PASS', 'network_scanner_requests':0,'migration_count':migration,
            'sqlite_integrity':integrity, 'counts':counts, 'steps':steps, 'result':'PASS'}
    (out/'DAY02_E2E_RESULT.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    (out/'SHA256SUMS.txt').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n'
        for p in (out/'DAY02_E2E_RESULT.json',out/'day02.db')))
    return report


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--evidence-dir',required=True,type=Path)
    args=p.parse_args()
    try:
        report=run(args.evidence_dir)
    except Exception as exc:
        print('DAY02_E2E_FAIL:',type(exc).__name__,str(exc),file=sys.stderr)
        return 1
    print('DAY02_E2E_PASS:',json.dumps(report,sort_keys=True))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
