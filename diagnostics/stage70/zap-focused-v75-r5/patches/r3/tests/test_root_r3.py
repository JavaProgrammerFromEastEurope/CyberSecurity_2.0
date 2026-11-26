import sys, tempfile, subprocess, json, os, hashlib, unittest, zipfile
from pathlib import Path
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import root_fix_r3 as r3

BASE_NAME='Stage70_ZAP_API_AJAX_SPIDER_PASSIVE_FOCUSED_V75_PID_BUDGET_CAUSALITY_RECOVERY_CANDIDATE_LT10MB'
BASE_ZIP=Path(__file__).resolve().parents[1]/(BASE_NAME+'.zip')
# independent test against the byte-exact original inside the R3 package.
with zipfile.ZipFile(BASE_ZIP) as archive:
 ORIG=archive.read(BASE_NAME+'/pid_recovery.py')

class RootTest(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory()
  self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name)/'cg'
  self.proc=Path(self.tmp.name)/'proc'
  (self.proc/'self').mkdir(parents=True)
  self.leaf=self.root/'user.slice'/'user-1000.slice'/'session.scope'
  self.leaf.mkdir(parents=True)
  (self.proc/'self'/'cgroup').write_text('0::/user.slice/user-1000.slice/session.scope\n')
  (self.proc/'self'/'mountinfo').write_text(f'31 30 0:27 / {self.root} rw - cgroup2 cgroup rw\n')
  for path,curr,limit in [(self.leaf,3,'max'),(self.leaf.parent,7,'8998'),(self.root/'user.slice',7,'max')]:
   (path/'pids.current').write_text(f'{curr}\n')
   (path/'pids.max').write_text(f'{limit}\n')
  (self.root/'cgroup.controllers').write_text('cpu memory pids\n')
  (self.root/'cgroup.subtree_control').write_text('cpu pids\n')
  self.namespace={}
  exec(compile(r3.patched_code(ORIG),'patched.pid_recovery.py','exec'),self.namespace)
  self.v=self.namespace
 def nodes(self):return self.v['ancestors_visible'](self.root,self.proc)
 def test_valid_structural_root(self):
  self.assertTrue(self.v['verified_structural_pids_root'](self.root,self.proc))
  self.assertEqual(len(self.nodes()),3)
  p=self.v['admissible_budgets'](256,384,self.nodes()[1:]);self.assertEqual(p['parent_min_headroom'],8991)
 def test_missing_nonroot_current_fails(self):
  (self.leaf.parent/'pids.current').unlink()
  with self.assertRaises(self.v['BudgetBlocked']) as x:self.v['admissible_budgets'](256,384,self.nodes()[1:])
  self.assertEqual(str(x.exception),'PARENT_CURRENT_UNKNOWN')
 def test_missing_nonroot_max_fails(self):
  (self.leaf.parent/'pids.max').unlink()
  with self.assertRaises(self.v['BudgetBlocked']) as x:self.v['admissible_budgets'](256,384,self.nodes()[1:])
  self.assertEqual(str(x.exception),'PARENT_LIMIT_UNKNOWN')
 def test_root_symlink_blocked(self):
  (self.root/'pids.current').symlink_to('/proc/self/status')
  self.assertFalse(self.v['verified_structural_pids_root'](self.root,self.proc))
  with self.assertRaises(self.v['BudgetBlocked']):self.v['admissible_budgets'](256,384,self.nodes()[1:])
 def test_root_partial_file_blocked(self):
  (self.root/'pids.max').write_text('max\n')
  self.assertFalse(self.v['verified_structural_pids_root'](self.root,self.proc))
  with self.assertRaises(self.v['BudgetBlocked']):self.v['admissible_budgets'](256,384,self.nodes()[1:])
 def test_root_disabled_pids_blocked(self):
  (self.root/'cgroup.subtree_control').write_text('cpu memory\n')
  self.assertFalse(self.v['verified_structural_pids_root'](self.root,self.proc))
  with self.assertRaises(self.v['BudgetBlocked']):self.v['admissible_budgets'](256,384,self.nodes()[1:])
 def test_root_no_controller_blocked(self):
  (self.root/'cgroup.controllers').write_text('cpu memory\n')
  self.assertFalse(self.v['verified_structural_pids_root'](self.root,self.proc))
 def test_mount_is_not_true_root_blocked(self):
  p=self.proc/'self'/'mountinfo'
  p.write_text(p.read_text().replace('0:27 / ','0:27 /virtual '))
  self.assertFalse(self.v['verified_structural_pids_root'](self.root,self.proc))
 def test_mount_wrong_fs_blocked(self):
  p=self.proc/'self'/'mountinfo';p.write_text(p.read_text().replace(' - cgroup2 ',' - tmpfs '))
  self.assertFalse(self.v['verified_structural_pids_root'](self.root,self.proc))
 def test_duplicate_mount_blocked(self):
  p=self.proc/'self'/'mountinfo';p.write_text(p.read_text()*2)
  self.assertFalse(self.v['verified_structural_pids_root'](self.root,self.proc))
 def test_mount_unreadable_or_missing_blocked(self):
  (self.proc/'self'/'mountinfo').unlink()
  self.assertFalse(self.v['verified_structural_pids_root'](self.root,self.proc))
 def test_no_finite_parent_blocked(self):
  (self.leaf.parent/'pids.max').write_text('max\n')
  with self.assertRaises(self.v['BudgetBlocked']) as x:self.v['admissible_budgets'](256,384,self.nodes()[1:])
  self.assertEqual(str(x.exception),'PARENT_FINITE_LIMIT_UNVERIFIED')
 def test_insufficient_headroom_blocked(self):
  (self.leaf.parent/'pids.max').write_text('400\n')
  with self.assertRaises(self.v['BudgetBlocked']) as x:self.v['admissible_budgets'](256,384,self.nodes()[1:])
  self.assertEqual(str(x.exception),'PARENT_HEADROOM_INSUFFICIENT')
 def test_base_checksum_mismatch(self):
  with self.assertRaises(ValueError):r3.patched_code(ORIG+b'bad')
 def test_current_cgroup_unknown_blocks(self):
  (self.leaf/'pids.current').unlink()
  self.assertIsNone(self.nodes())
 def test_file_missing_symlink_does_not_override(self):
  (self.leaf.parent/'pids.max').unlink();(self.leaf.parent/'pids.max').symlink_to('/dev/null')
  with self.assertRaises(self.v['BudgetBlocked']):self.v['admissible_budgets'](256,384,self.nodes()[1:])
 def test_only_readonly_source(self):
  patched=r3.patched_code(ORIG).decode()
  self.assertNotIn('O_WRONLY',patched);self.assertNotIn('O_RDWR',patched)
  self.assertNotIn('subprocess.',patched)
 def test_boundary_state_does_not_claim_production(self):
  self.assertIn('BLOCKED/NO-GO',str(r3.apply.__code__.co_consts))
 def test_original_unchanged(self):
  self.assertEqual(hashlib.sha256(ORIG).hexdigest(),r3.PINNED_PID)
 def test_incomplete_cgroup_metadata_blocks(self):
  (self.root/'cgroup.controllers').unlink()
  self.assertFalse(self.v['verified_structural_pids_root'](self.root,self.proc))

if __name__=='__main__':unittest.main()
