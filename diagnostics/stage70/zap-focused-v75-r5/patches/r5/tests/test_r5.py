import sys, copy, importlib.util, io, json, os, stat, tempfile, unittest, zipfile
from pathlib import Path
from unittest.mock import patch
THIS=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(THIS))
import r5_compose_fix as r, r5_launcher as launcher
BASE=None
R3=None
V75_FOLDER='Stage70_ZAP_API_AJAX_SPIDER_PASSIVE_FOCUSED_V75_PID_BUDGET_CAUSALITY_RECOVERY_CANDIDATE_LT10MB'

def base(pid=768):
 return {'name':'cybersec-day03','services':{
 'zap':{'image':'pinned','security_opt':['no-new-privileges:true'],
        'cap_drop':['ALL'],'read_only':True,'user':'1000:1000',
        'pids_limit':pid,'networks':['lab']},
 'day03-target':{'image':'pinned','networks':['lab']}}}

def changed(a=256, b=None):
 c=copy.deepcopy(b or base());c['services']['zap']['pids_limit']=a
 c['services']['zap']['shm_size']='268435456';return c

class FixTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  # Every test runs from the real immutable nested ZIPs, on macOS too.
  global BASE,R3
  cls._temp=tempfile.TemporaryDirectory(prefix='r5_regression_verified_')
  work=Path(cls._temp.name)
  r4=launcher.safe_extract(THIS/'originals'/launcher.PARENT,work,launcher.R4_FOLDER)
  R3=launcher.safe_extract(r4/'originals'/launcher.R3_ZIP,work,launcher.R3_FOLDER)
  BASE=launcher.safe_extract(R3/(V75_FOLDER+'.zip'),work,V75_FOLDER)
  # This is the actual ORIGINAL SOURCE transformed by the deterministic R3/R5 patches.
  sys.path.insert(0,str(R3))
  import root_fix_r3
  old=(BASE/'pid_recovery.py').read_bytes()
  r3src=root_fix_r3.patched_code(old)
  assert r.sha(r3src)==r.PINNED_R3_PID_SOURCE
  r5src=r.replace_once(r3src,r.PID_OLD,r.PID_NEW,'PID_DELTA')
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'p.py';p.write_bytes(r5src)
   spec=importlib.util.spec_from_file_location('r5_pid_test',p)
   m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
   cls.p=m
 @classmethod
 def tearDownClass(cls):
  sys.path.remove(str(R3))
  cls._temp.cleanup()
 def assert_block(self,b,a=256):
  with self.assertRaises(self.p.BudgetBlocked):self.p.compose_pid_delta(b,changed(a,b),a)
 def test_valid_existing_baseline_256(self):self.assertEqual(self.p.compose_pid_delta(base(),changed(),256)['pids_limit'],256)
 def test_valid_existing_baseline_384(self):self.assertEqual(self.p.compose_pid_delta(base(),changed(384),384)['pids_limit'],384)
 def test_valid_base_same_as_arm(self):self.assertEqual(self.p.compose_pid_delta(base(256),changed(256,base(256)),256)['pids_limit'],256)
 def test_valid_missing_base_pid(self):
  b=base();del b['services']['zap']['pids_limit']
  self.assertEqual(self.p.compose_pid_delta(b,changed(256,b),256)['pids_limit'],256)
 def test_valid_canonical_string_base_pid(self):self.assertEqual(self.p.compose_pid_delta(base('768'),changed(),256)['pids_limit'],256)
 def test_noncanonical_baseline(self):self.assert_block(base('0768'))
 def test_negative_baseline(self):self.assert_block(base(-1))
 def test_bool_baseline(self):self.assert_block(base(True))
 def test_unlimited_baseline(self):self.assert_block(base('max'))
 def test_zero_baseline(self):self.assert_block(base(0))
 def test_oversized_baseline(self):self.assert_block(base(10000001))
 def test_wrong_budget(self):
  with self.assertRaises(self.p.BudgetBlocked):self.p.compose_pid_delta(base(),changed(384),256)
 def test_invalid_budget_range(self):
  with self.assertRaises(self.p.BudgetBlocked):self.p.compose_pid_delta(base(),changed(512),513)
 def test_wrong_shm(self):
  b=base();a=changed();a['services']['zap']['shm_size']='256m'
  with self.assertRaises(self.p.BudgetBlocked):self.p.compose_pid_delta(b,a,256)
 def test_unexpected_base_shm(self):
  b=base();b['services']['zap']['shm_size']='268435456';self.assert_block(b)
 def test_changed_network(self):
  b=base();a=changed();a['services']['zap']['networks']=['public']
  with self.assertRaises(self.p.BudgetBlocked):self.p.compose_pid_delta(b,a,256)
 def test_changed_image(self):
  b=base();a=changed();a['services']['zap']['image']='other'
  with self.assertRaises(self.p.BudgetBlocked):self.p.compose_pid_delta(b,a,256)
 def test_changed_capabilities(self):
  b=base();a=changed();a['services']['zap']['cap_add']=['SYS_ADMIN']
  with self.assertRaises(self.p.BudgetBlocked):self.p.compose_pid_delta(b,a,256)
 def test_seccomp_removal(self):
  b=base();a=changed();a['services']['zap']['security_opt']=[]
  with self.assertRaises(self.p.BudgetBlocked):self.p.compose_pid_delta(b,a,256)
 def test_changed_uid(self):
  b=base();a=changed();a['services']['zap']['user']='root'
  with self.assertRaises(self.p.BudgetBlocked):self.p.compose_pid_delta(b,a,256)
 def test_changed_target(self):
  b=base();a=changed();a['services']['day03-target']['image']='evil'
  with self.assertRaises(self.p.BudgetBlocked):self.p.compose_pid_delta(b,a,256)
 def test_changed_mount(self):
  b=base();a=changed();a['services']['zap']['volumes']=['/:/host']
  with self.assertRaises(self.p.BudgetBlocked):self.p.compose_pid_delta(b,a,256)
 def test_r3_pinned_wrapper(self):
  raw=(R3/'auto_runner.py').read_bytes()
  self.assertEqual(r.sha(raw),r.PINNED_R3_AUTORUNNER)
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'auto_runner.py';p.write_bytes(raw)
   proof=r.patch_r3_autorunner(p)
   self.assertEqual(proof['original_sha256'],r.PINNED_R3_AUTORUNNER)
   self.assertIn(b'R5_COMPOSE_POLICY',p.read_bytes())
   with self.assertRaises(ValueError):r.patch_r3_autorunner(p)
 def test_original_pid_patch_pinned(self):
  with self.assertRaises(ValueError):r.replace_once(b'not python',r.PID_OLD,r.PID_NEW,'test')
 def test_sources_integrity(self):
  result=launcher.verify_sources();self.assertEqual(result['sources'],'PASS')
 def test_lineage_r4_r3(self):
  self.assertEqual(launcher.verify_sources()['r4_sha256'],launcher.PIN_R4)
 def test_integrity_review_flags_rejected(self):
  with self.assertRaises(ValueError):launcher.main(['--mode','review','--budget-a','256'])
 def test_review_no_remote(self):
  src=(THIS/'r5_launcher.py').read_text()
  self.assertIn("if mode=='integrity'",src)
  self.assertIn("if mode!='interactive':args+=['--mode',mode]",src)
 def test_zip_traversal_refused(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'z.zip'
   with zipfile.ZipFile(p,'w') as z:
    for i in range(10):z.writestr('safe/../traversal%d'%i,'payload')
   with self.assertRaises(ValueError):launcher.validate_zip(p,'safe')
 def test_zip_symlink_refused(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'z.zip'
   with zipfile.ZipFile(p,'w') as z:
    for i in range(9):z.writestr('safe/p%d'%i,'payload')
    info=zipfile.ZipInfo('safe/link');info.create_system=3;info.external_attr=(0o120777<<16)
    z.writestr(info,'/etc/passwd')
   with self.assertRaises(ValueError):launcher.validate_zip(p,'safe')
 def test_no_active_scan(self):
  self.assertIn('Never weakens Docker, seccomp, NoNewPrivs',(THIS/'r5_launcher.py').read_text())
 def test_source_has_warning_flags(self):
  self.assertIn('V75', (THIS/'README_RU.md').read_text())
 def test_no_day04(self):self.assertEqual(launcher.verify_sources()['day04'],'NOT_RUN')
 def test_no_stage71(self):self.assertEqual(launcher.verify_sources()['stage71'],'NOT_OPENED')

if __name__=='__main__':unittest.main()
