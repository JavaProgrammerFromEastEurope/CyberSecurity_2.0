import pytest
from cybersec.repository import Repository
from cybersec.sqlmap_gate import execute_approved_confirmation
from cybersec.scanners import ScanResult


def candidate(repo, authorized=True):
    t = repo.add_target('https://example.test/app', authorized=authorized)
    f = repo.add_finding(t.url, 'SQLi candidate', 'High', 'Tentative', 'SQL Injection',
                         url='https://example.test/app/page?id=1', parameter='id')
    return f


def test_approval_one_shot_and_provenance(tmp_path):
    repo = Repository(tmp_path/'test.db')
    f = candidate(repo)
    cid = repo.request_sqlmap_confirmation(f.id, requested_by='analyst')
    with pytest.raises(PermissionError):
        repo.approve_sqlmap_confirmation(cid, approved_by='analyst')
    repo.approve_sqlmap_confirmation(cid, approved_by='reviewer')
    class Fake:
        def run(self, context):
            assert context.options['candidate_url'].endswith('id=1')
            return ScanResult('sqlmap', 'completed', 'inconclusive')
    assert execute_approved_confirmation(repo, cid, adapter=Fake()).summary == 'inconclusive'
    with pytest.raises(PermissionError):
        execute_approved_confirmation(repo, cid, adapter=Fake())


def test_revoked_authorization_blocks_claim(tmp_path):
    repo = Repository(tmp_path/'test.db')
    f = candidate(repo)
    cid = repo.request_sqlmap_confirmation(f.id, requested_by='a')
    repo.approve_sqlmap_confirmation(cid, approved_by='b')
    from cybersec.db import connect
    with connect(repo.db_path) as db:
        db.execute('UPDATE targets SET authorized=0 WHERE id=?', (f.target_id,))
    with pytest.raises(PermissionError):
        repo.claim_sqlmap_confirmation(cid)


def test_changed_finding_blocks_claim(tmp_path):
    repo = Repository(tmp_path/'test.db')
    f = candidate(repo)
    cid = repo.request_sqlmap_confirmation(f.id, requested_by='a')
    repo.approve_sqlmap_confirmation(cid, approved_by='b')
    from cybersec.db import connect
    with connect(repo.db_path) as db:
        db.execute('UPDATE normalized_findings SET parameter=? WHERE id=?', ('other', f.id))
    with pytest.raises(PermissionError):
        repo.claim_sqlmap_confirmation(cid)


def test_out_of_scope_rejected_before_approval(tmp_path):
    repo = Repository(tmp_path/'test.db')
    t = repo.add_target('https://example.test/app', authorized=True)
    f = repo.add_finding(t.url, 'SQLi', 'High', 'Tentative', 'SQL Injection',
                         url='https://example.test/other?id=1', parameter='id')
    with pytest.raises(ValueError):
        repo.request_sqlmap_confirmation(f.id, requested_by='a')


def test_non_sqli_rejected(tmp_path):
    repo = Repository(tmp_path/'test.db')
    t = repo.add_target('https://example.test/app', authorized=True)
    f = repo.add_finding(t.url, 'XSS', 'High', 'Tentative', 'XSS',
                         url='https://example.test/app?a=1', parameter='a')
    with pytest.raises(ValueError):
        repo.request_sqlmap_confirmation(f.id, requested_by='a')
