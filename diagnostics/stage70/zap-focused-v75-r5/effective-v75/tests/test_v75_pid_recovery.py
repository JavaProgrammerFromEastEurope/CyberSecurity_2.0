import sys
sys.dont_write_bytecode=True
from pathlib import Path
import unittest,tempfile,json,zipfile,io,os,copy,hashlib,lzma
from unittest.mock import patch
import pid_recovery as p
import mac_pid_ab_runner as runner
from restore_v74 import checked
ROOT=Path(__file__).resolve().parents[1]

def base_compose():
 return {'name':'cybersec-day03','services':{'zap':{'image':'pinned','security_opt':['no-new-privileges:true'],
              'networks':['lab']},'day03-target':{'image':'pinned','networks':['lab']}}}

def changed(a=128):
 c=base_compose();c['services']['zap']['shm_size']=268435456;c['services']['zap']['pids_limit']=a
 return c

def cell(rep,arm,role):
 return dict(replicate=rep,arm=arm,role=role,pid_denial='NO',outcome='FAIL',quiescence='DRAINED',
             sandbox_verified=True,budget_verified=True)

class TestV75PID(unittest.TestCase):
 def test_v74_exact_bytes(self):
  b=checked();self.assertEqual(len(b),9188012)
  self.assertEqual(hashlib.sha256(b).hexdigest(),'8c4108e3af996e053188c5da55d04454c1891f876e333f8d9910a52d49ecf9a0')
 def test_v74_no_corruption(self):
  with zipfile.ZipFile(io.BytesIO(checked())) as z:self.assertIsNone(z.testzip())
 def test_evidence_v74_preserved(self):
  from audit_latest_v75_candidate import read_pair,OLD,DIGESTS
  raw=read_pair()[OLD]
  with zipfile.ZipFile(io.BytesIO(raw)) as z:self.assertIsNone(z.testzip())
  self.assertEqual(hashlib.sha256(raw).hexdigest(),DIGESTS[OLD])
 def test_new_evidence_pair_complete(self):
  from audit_latest_v75_candidate import audit
  report=audit()
  self.assertEqual(report['historical_runs_unchanged'],19)
  self.assertEqual(report['total_runs'],20)
  self.assertEqual(report['all_nested_crc_sha256_manifests'],'PASS')
 def test_evidence1_gap(self):
  self.assertEqual(json.loads((ROOT/'EVIDENCE/SOURCE_GAP.json').read_text())['EVIDENCE(1).zip'],
                   'UNAVAILABLE_NOT_SUBSTITUTED')
 def test_no_production(self):
  s=(ROOT/'README_RU.md').read_text();self.assertIn('BLOCKED/NO-GO',s)
 def test_budget_plan(self):
  a=p.admissible_budgets(128,256,[{'current':20,'max':400}]);self.assertEqual(a['cells'],24)
 def test_budget_default_not_set(self):
  self.assertNotIn('pids.max=',(ROOT/'README_RU.md').read_text())
 def test_no_cgroup_mutating_ops(self):
  s=(ROOT/'pid_recovery.py').read_text();self.assertNotIn("os.O_WRONLY",s)
  self.assertNotIn("os.O_RDWR",s)
  self.assertNotIn('mount -o',s)
 def test_compose_delta(self):
  self.assertEqual(p.compose_pid_delta(base_compose(),changed(),128)['pids_limit'],128)
 def test_preexisting_compose_finite_pids_limit_accepted(self):
  b=base_compose();b['services']['zap']['pids_limit']=80
  self.assertEqual(p.compose_pid_delta(b,changed(128),128)['pids_limit'],128)
 def test_preexisting_negative_pids_limit_rejected(self):
  b=base_compose();b['services']['zap']['pids_limit']=-1
  with self.assertRaises(p.BudgetBlocked):p.compose_pid_delta(b,changed(128),128)
 def test_preexisting_boolean_pids_limit_rejected(self):
  b=base_compose();b['services']['zap']['pids_limit']=True
  with self.assertRaises(p.BudgetBlocked):p.compose_pid_delta(b,changed(128),128)
 def test_preexisting_noncanonical_pids_limit_rejected(self):
  b=base_compose();b['services']['zap']['pids_limit']='00080'
  with self.assertRaises(p.BudgetBlocked):p.compose_pid_delta(b,changed(128),128)
 def test_newest_evidence_genuine(self):
  from audit_latest_v75_candidate import read_pair,NEW,DIGESTS
  b=read_pair()[NEW]
  self.assertEqual(hashlib.sha256(b).hexdigest(),DIGESTS[NEW])
 def test_malformed_evidence_pair_refused(self):
  import audit_latest_v75_candidate as audit
  with tempfile.TemporaryDirectory() as td:
   pth=Path(td)/'corrupt.tar.xz';pth.write_bytes(b'wrong')
   with patch.object(audit,'BUNDLE',pth):
    with self.assertRaises((ValueError,EOFError,IOError,lzma.LZMAError)):
     audit.read_pair()
 def test_no_seccomp_change(self):
  c=changed();c['services']['zap']['security_opt']=[]
  with self.assertRaises(p.BudgetBlocked):p.compose_pid_delta(base_compose(),c,128)
 def test_no_image_change(self):
  c=changed();c['services']['zap']['image']='changed'
  with self.assertRaises(p.BudgetBlocked):p.compose_pid_delta(base_compose(),c,128)
 def test_no_network_change(self):
  c=changed();c['services']['zap']['networks']=['public']
  with self.assertRaises(p.BudgetBlocked):p.compose_pid_delta(base_compose(),c,128)
 def test_no_target_change(self):
  c=changed();c['services']['day03-target']['image']='other'
  with self.assertRaises(p.BudgetBlocked):p.compose_pid_delta(base_compose(),c,128)
 def test_actual_security(self):
  self.assertTrue(p.verify_runtime_budget(128,128,{'seccomp':2,'no_new_privs':1}))
 def test_quiescence(self):
  self.assertTrue(p.verify_runtime_budget(128,128,{'seccomp':2,'no_new_privs':1},True))
 def test_no_mutating_cgroup_in_vm(self):
  s=(ROOT/'zap_focus_vm.py').read_text();self.assertNotIn('pids.max.write_text(',s)
 def test_operator_script(self):
  self.assertTrue((ROOT/'Run_V75_AB.command').is_file())
 def test_operator_denial(self):
  s=(ROOT/'mac_pid_ab_runner.py').read_text();self.assertIn('INTERACTIVE_YES_REQUIRED',s)
 def test_hostkey_policy(self):
  s=(ROOT/'mac_run.py').read_text();self.assertIn('StrictHostKeyChecking=yes',s)
 def test_lab_target(self):
  s=(ROOT/'zap_focus_vm.py').read_text();self.assertIn("TARGET = 'http://day03-target:8080/'",s)
 def test_original_gate(self):
  s=(ROOT/'zap_focus_vm.py').read_text();self.assertIn("gate(evidence['fixture_navigation_confirmed']",s)
  self.assertIn("'AJAX_NOT_COMPLETED_WITH_ACTUAL_RESULTS'",s)
 def test_quiescence_fail_closed(self):
  s=(ROOT/'zap_focus_vm.py').read_text();self.assertIn("state['checks']['v75_compose_quiescence']",s)
 def test_source_pinned(self):
  self.assertIn("BASE = '9de9fe0c2fc4e31d695aa9f3bd4594a0a5ecf5dd'",(ROOT/'zap_focus_vm.py').read_text())
 def test_compare_missing(self):self.assertEqual(p.compare_trials([]),'INCOMPLETE_NO_CAUSALITY')
 def test_compare_complete(self):
  cells=[cell(i,a,r) for i in (1,2,3) for a in ('A','B') for r in ('NO_CLIENT','ONE_CLIENT','THREE_CLIENTS','WEBDRIVER')]
  self.assertEqual(p.compare_trials(cells),'COMPLETE_AB_OBSERVATIONAL_ONLY_NO_CAUSALITY')
 def test_compare_unknown(self):
  cells=[cell(i,a,r) for i in (1,2,3) for a in ('A','B') for r in ('NO_CLIENT','ONE_CLIENT','THREE_CLIENTS','WEBDRIVER')]
  cells[0]['outcome']='UNKNOWN'
  self.assertEqual(p.compare_trials(cells),'UNVERIFIED_NO_CAUSALITY')
 def test_numeric(self):
  self.assertEqual(p.number('0042\n'),42)
 def test_ceiling(self):self.assertIsNone(p.ceiling('max'))
 def test_counter(self):self.assertEqual(p.counter('max 3\nother 4\n','max'),3)
 def test_container_code_no_network(self):
  self.assertNotIn('http://',p.CONTAINER_TELEMETRY_CODE)
  self.assertNotIn('subprocess',p.CONTAINER_TELEMETRY_CODE)
 def test_container_telemetry_source_parses(self):
  import ast;ast.parse(p.CONTAINER_TELEMETRY_CODE)
 def test_file_bound(self):
  with tempfile.TemporaryDirectory() as td:
   f=Path(td)/'test';f.write_text('a'*9000)
   self.assertIsNone(p.read_regular(f))
 def test_symlink_refused(self):
  with tempfile.TemporaryDirectory() as td:
   f=Path(td)/'test';f.write_text('42');l=Path(td)/'link';l.symlink_to(f)
   self.assertIsNone(p.read_regular(l))
 def test_cgroup_snapshot(self):
  with tempfile.TemporaryDirectory() as td:
   d=Path(td);(d/'pids.current').write_text('12\n');(d/'pids.max').write_text('128\n')
   (d/'pids.events').write_text('max 2\n');(d/'pids.events.local').write_text('max 1\n')
   c=p.cgroup_node(d);self.assertEqual(c['current'],12);self.assertEqual(c['max'],128)
   self.assertEqual(c['denied_local'],1)
 def test_unavailable_not_zero(self):
  with tempfile.TemporaryDirectory() as td:
   c=p.cgroup_node(td);self.assertIsNone(c['denied_local']);self.assertIsNone(c['max'])
 def test_provenance_v75_collision(self):
  self.assertEqual(json.loads((ROOT/'V75_PROVENANCE.json').read_text())['prior_v75_webdriver_boundary'],
                   'EXISTS_SEPARATE_UNMODIFIED')
 def test_ab_report_never_production(self):
  s=(ROOT/'mac_pid_ab_runner.py').read_text();self.assertIn("'production':'BLOCKED/NO-GO'",s)
 def test_ab_sequential(self):
  s=(ROOT/'mac_pid_ab_runner.py').read_text();self.assertIn("for rep in (1,2,3)",s)
  self.assertIn("('A',args.budget_a),('B',args.budget_b)",s)
 def test_qa_warnings_as_errors(self):
  s=(ROOT/'run_strict_regressions.py').read_text();self.assertIn('error::ResourceWarning',s);self.assertIn('error::DeprecationWarning',s)
 def test_no_active_scan(self):
  s=(ROOT/'zap_focus_vm.py').read_text();self.assertIn("'active_scan':False",s)
 def test_vm_requires_non_root(self):
  s=(ROOT/'zap_focus_vm.py').read_text();self.assertIn('os.geteuid()!=0',s)
 def test_vm_pid_limit_exact(self):
  s=(ROOT/'zap_focus_vm.py').read_text();self.assertIn('V75_DOCKER_RUNTIME_PID_BUDGET_MISMATCH',s)
 def test_sandbox_invariant(self):
  s=(ROOT/'zap_focus_vm.py').read_text();self.assertIn('V75_PID_BUDGET_OR_SANDBOX_UNVERIFIED',s)
 def test_ssh_no_password(self):
  s=(ROOT/'mac_run.py').read_text();self.assertIn('BatchMode=yes',s)
 def test_no_stage71(self):
  s=(ROOT/'zap_focus_vm.py').read_text();self.assertIn("'stage71':'NOT_OPENED'",s)
 def test_no_day04(self):
  s=(ROOT/'zap_focus_vm.py').read_text();self.assertIn("'day04':'NOT_RUN'",s)
 def test_footer_gate(self):
  s=(ROOT/'README_RU.md').read_text();self.assertIn('EVIDENCE(1).zip',s)
 def test_no_raw_pid_telemetry(self):
  x=p.numeric_telemetry(include_ancestors=False)
  self.assertNotIn('pid',x)
 def test_tasks_summary(self):
  with tempfile.TemporaryDirectory() as td:
   d=Path(td);(d/'123').mkdir();(d/'123/status').write_text('Threads:\t3\nSeccomp:\t2\nNoNewPrivs:\t1\n')
   self.assertEqual(p.tasks_summary(d)['thread_count'],3)

if __name__=='__main__':unittest.main()
