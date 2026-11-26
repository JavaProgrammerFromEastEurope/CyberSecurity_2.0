"""Stage70 Day02: schema, evidence, scope, serial controller, rollback and compatibility."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import hashlib
import pytest

from cybersec.repository import Repository
from cybersec.day02 import (DemoController, MIGRATION_ID, add_report_asset,
                             get_enriched_finding, ingest_raw_finding, require_scope)
from cybersec.db import connect, initialize
from cybersec.runner import JobRunner
from cybersec.scope import ScopeError

BASE='http://127.0.0.1:8765/lab/'


@pytest.fixture
def repo(tmp_path):
    r=Repository(tmp_path/'test.db')
    r.add_target(BASE,True)
    return r


def test_migration_applied_once_and_legacy_data_retained(repo):
    job=repo.create_job(BASE,'demo')
    finding=repo.add_finding(BASE,'legacy','Low','Unknown','unknown')
    for _ in range(3):
        initialize(repo.db_path)
    with connect(repo.db_path) as db:
        assert db.execute('SELECT count(*) FROM day02_schema_migrations WHERE migration_id=?',(MIGRATION_ID,)).fetchone()[0] == 1
        assert db.execute('SELECT title FROM normalized_findings WHERE id=?',(finding.id,)).fetchone()[0] == 'legacy'
        assert all(name in {r['name'] for r in db.execute('PRAGMA table_info(normalized_findings)')}
                   for name in ('http_method','reproduction_steps','raw_ref','confidence_basis'))
        assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'


def test_forward_only_migration_refuses_version_drift(repo):
    with connect(repo.db_path) as db:
        db.execute('UPDATE day02_schema_migrations SET version=99 WHERE migration_id=?',(MIGRATION_ID,))
    with pytest.raises(RuntimeError,match='MIGRATION_VERSION_DRIFT'):
        initialize(repo.db_path)
    with connect(repo.db_path) as db:
        assert db.execute('SELECT version FROM day02_schema_migrations WHERE migration_id=?',(MIGRATION_ID,)).fetchone()[0] == 99


@pytest.mark.parametrize('bad',["http://evil.local/lab/", "https://127.0.0.1:8765/lab/",
    "http://127.0.0.1:8766/lab/", "http://127.0.0.1:8765/laboratory/",
    "http://127.0.0.1:8765/lab/../admin", "http://127.0.0.1:8765/lab/%2e%2e/x",
    "http://127.0.0.1:8765/lab/%252e%252e/x", "http://a@127.0.0.1:8765/lab/x",
    "http://127.0.0.1:8765//lab/x", "http://127.0.0.1:8765/lab/x#fragment"])
def test_scope_denies_outside_or_ambiguous(bad):
    with pytest.raises((ScopeError,ValueError)):
        require_scope(BASE,bad)


def test_scope_accepts_exact_or_subpath():
    assert require_scope(BASE,BASE).startswith('http://127.0.0.1:8765/lab')
    assert require_scope(BASE,BASE+'a?b=1').endswith('a?b=1')


def test_ingest_raw_atomic_idempotent_and_linked(repo):
    job=repo.create_job(BASE,'demo')
    args=dict(job_id=job.id,raw={'name':'synthetic', 'note':'not an exploit'},
              finding_url=BASE+'q?id=1',title='Synthetic only',vuln_type='other',
              severity='Low',method='POST',reproduction_steps='No network requests')
    a=ingest_raw_finding(repo,**args)
    b=ingest_raw_finding(repo,**args)
    assert a==b
    enriched=get_enriched_finding(repo,a.finding_id)
    assert enriched['raw_ref']==a.raw_id
    assert enriched['raw_sha256']==hashlib.sha256(b'{"name":"synthetic","note":"not an exploit"}').hexdigest()
    assert enriched['http_method']=='POST'
    assert enriched['reproduction_steps']=='No network requests'
    with connect(repo.db_path) as db:
        assert db.execute('SELECT count(*) FROM raw_findings').fetchone()[0]==1


def test_ingest_rejects_authorization_revocation_and_rolls_back(repo):
    job=repo.create_job(BASE,'demo')
    with connect(repo.db_path) as db:
        db.execute('UPDATE targets SET authorized=0')
    with pytest.raises(PermissionError,match='NOT_AUTHORIZED'):
        ingest_raw_finding(repo,job_id=job.id,raw={},finding_url=BASE,title='x',vuln_type='other')
    with connect(repo.db_path) as db:
        assert db.execute('SELECT count(*) FROM raw_findings').fetchone()[0]==0


def test_ingest_scope_failure_no_partial_raw(repo):
    job=repo.create_job(BASE,'demo')
    with pytest.raises(ScopeError):
        ingest_raw_finding(repo,job_id=job.id,raw={'x':1},finding_url='http://outside.local/',title='x',vuln_type='other')
    with connect(repo.db_path) as db:
        assert db.execute('SELECT count(*) FROM raw_findings').fetchone()[0]==0


@pytest.mark.parametrize('method,confidence,basis',[
    ('TRACE','Low',None),('GET','Certain',None)])
def test_ingest_invalid_method_or_unjustified_certain(repo,method,confidence,basis):
    job=repo.create_job(BASE,'demo')
    with pytest.raises(ValueError):
        ingest_raw_finding(repo,job_id=job.id,raw={'x':1},finding_url=BASE,title='x',vuln_type='other',
                           method=method,confidence=confidence,confidence_basis=basis)


def test_report_asset_bounded_dedup_and_rejects_traversal(repo):
    job=repo.create_job(BASE,'demo')
    fid=ingest_raw_finding(repo,job_id=job.id,raw={'x':1},finding_url=BASE,title='x',vuln_type='other').finding_id
    a=add_report_asset(repo,finding_id=fid,filename='proof.txt',media_type='text/plain',content=b'synthetic')
    assert a==add_report_asset(repo,finding_id=fid,filename='proof.txt',media_type='text/plain',content=b'synthetic')
    with pytest.raises(ValueError,match='FILENAME'):
        add_report_asset(repo,finding_id=fid,filename='../secret',media_type='text/plain',content=b'a')
    with pytest.raises(ValueError,match='SIZE'):
        add_report_asset(repo,finding_id=fid,filename='big.txt',media_type='text/plain',content=b'a'*1048577)
    with pytest.raises(ValueError,match='MEDIA'):
        add_report_asset(repo,finding_id=fid,filename='bad.sh',media_type='application/x-sh',content=b'a')
    with connect(repo.db_path) as db:
        assert db.execute('SELECT count(*) FROM report_assets').fetchone()[0]==1


def test_controller_serial_workflow_with_real_offline_runner(repo):
    controller=DemoController(repo)
    plan=controller.create_plan(BASE,request_key='request-stage70-day2-e2e',tools=('demo','demo'))
    assert plan==controller.create_plan(BASE,request_key='request-stage70-day2-e2e',tools=('demo','demo'))
    first=controller.advance(plan)
    assert first['queued_now']
    assert controller.advance(plan)['job_id']==first['job_id']
    assert controller.advance(plan)['queued_now'] is False
    with connect(repo.db_path) as db:
        assert db.execute('SELECT count(*) FROM scan_jobs').fetchone()[0]==1
    assert JobRunner(repo).run(first['job_id']).status=='completed'
    second=controller.advance(plan)
    assert second['job_id']!=first['job_id']
    assert JobRunner(repo).run(second['job_id']).status=='completed'
    assert controller.advance(plan)['status']=='succeeded'
    assert controller.advance(plan)['status']=='succeeded'


def test_controller_concurrent_advance_only_one_job(repo):
    controller=DemoController(repo)
    plan=controller.create_plan(BASE,request_key='concurrent-stage70-day02',tools=('demo','demo'))
    with ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(controller.advance,[plan]*12))
    ids={r['job_id'] for r in results}
    assert len(ids)==1
    with connect(repo.db_path) as db:
        assert db.execute('SELECT count(*) FROM scan_jobs').fetchone()[0]==1


def test_controller_failure_is_blocked_not_retried(repo):
    ctl=DemoController(repo)
    plan=ctl.create_plan(BASE,request_key='fail-stage70-day02',tools=('demo','demo'))
    job_id=ctl.advance(plan)['job_id']
    repo.start_job(job_id)
    repo.finish_job(job_id,error='lab simulated failure')
    state=ctl.advance(plan)
    assert state['status']=='blocked'
    assert state['reason']=='NON_COMPLETED_STEP_NO_RETRY'
    with connect(repo.db_path) as db:
        assert db.execute('SELECT count(*) FROM scan_jobs').fetchone()[0]==1


def test_controller_deny_external_scanners_and_key_replay(repo):
    ctl=DemoController(repo)
    with pytest.raises(PermissionError,match='EXTERNAL_SCANNER'):
        ctl.create_plan(BASE,request_key='external-stage70-day2',tools=('nuclei',))
    ctl.create_plan(BASE,request_key='replay-stage70-day02',tools=('demo',))
    with pytest.raises(ValueError,match='IDEMPOTENCY_KEY_CONFLICT'):
        ctl.create_plan(BASE,request_key='replay-stage70-day02',tools=('demo','demo'))


def test_controller_deny_unapproved_target(repo):
    repo.add_target('http://127.0.0.1:8766/private',False)
    with pytest.raises(PermissionError):
        DemoController(repo).create_plan('http://127.0.0.1:8766/private',request_key='missing-consent-day02')


def test_day01_legacy_finding_to_dict_compat(repo):
    finding=repo.add_finding(BASE,'old','Low','Unknown','Other')
    as_dict=finding.to_dict()
    assert 'raw_ref' not in as_dict
    assert as_dict['title']=='old'
