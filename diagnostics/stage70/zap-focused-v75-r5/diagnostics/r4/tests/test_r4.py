import sys,unittest,io,tempfile,json,os,zipfile,hashlib,copy
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import compose_delta_probe as probe
import diagnose_mac as mac
import audit_uploaded_evidence as audit

def base():
 return {'name':'cybersec-day03','services':{'zap':{'image':'pinned','security_opt':['no-new-privileges:true']},'day03-target':{'image':'pinned'}}}
def after(b=256):
 c=copy.deepcopy(base());c['services']['zap']['pids_limit']=b;c['services']['zap']['shm_size']='268435456';return c

class TestComposeRedaction(unittest.TestCase):
 def test_valid_diff_scope(self):
  x=probe.scope_report(base(),after(),256);self.assertEqual(x['scope'],'EXPECTED')
 def test_only_two_fields(self):self.assertTrue(probe.scope_report(base(),after(),256)['changed_only_two_approved_fields'])
 def test_pid_int(self):self.assertTrue(probe.scope_report(base(),after(),256)['pid_matches_exact'])
 def test_pid_str(self):
  b=after();b['services']['zap']['pids_limit']='256';self.assertTrue(probe.scope_report(base(),b,256)['pid_matches_exact'])
 def test_pid_bool_denied(self):
  b=after();b['services']['zap']['pids_limit']=True;self.assertFalse(probe.scope_report(base(),b,256)['pid_matches_exact'])
 def test_pid_float_denied(self):
  b=after();b['services']['zap']['pids_limit']=256.0;self.assertFalse(probe.scope_report(base(),b,256)['pid_matches_exact'])
 def test_pid_numeric_wrong(self):self.assertFalse(probe.scope_report(base(),after(384),256)['pid_matches_exact'])
 def test_shm_int_accepted(self):
  b=after();b['services']['zap']['shm_size']=268435456;self.assertTrue(probe.scope_report(base(),b,256)['shm_matches_exact'])
 def test_shm_unit_string_rejected(self):
  b=after();b['services']['zap']['shm_size']='256m';self.assertFalse(probe.scope_report(base(),b,256)['shm_matches_exact'])
 def test_shm_float_denied(self):
  b=after();b['services']['zap']['shm_size']=268435456.0;self.assertFalse(probe.scope_report(base(),b,256)['shm_matches_exact'])
 def test_missing_shm_denied(self):
  b=after();b['services']['zap'].pop('shm_size');self.assertFalse(probe.scope_report(base(),b,256)['shm_matches_exact'])
 def test_preexisting_shm(self):
  x=base();x['services']['zap']['shm_size']=16;self.assertFalse(probe.scope_report(x,after(),256)['base_shm_absent'])
 def test_preexisting_pid(self):
  x=base();x['services']['zap']['pids_limit']=55;self.assertFalse(probe.scope_report(x,after(),256)['base_pid_absent'])
 def test_no_env_leak(self):
  a=base();b=after();a['services']['zap']['environment']={'API_SECRET':'TOPSECRET123'}
  b['services']['zap']['environment']={'API_SECRET':'ULTRASECRET345'}
  text=json.dumps(probe.scope_report(a,b,256))
  self.assertNotIn('TOPSECRET',text);self.assertNotIn('ULTRASECRET',text);self.assertNotIn('API_SECRET',text)
 def test_no_label_leak(self):
  a=base();b=after();a['services']['zap']['labels']={'sensitive':'PEPPERSECRET'}
  b['services']['zap']['labels']={'sensitive':'CHANGEDSECRET'}
  text=json.dumps(probe.redact_delta(a,b))
  self.assertNotIn('PEPPERSECRET',text);self.assertNotIn('CHANGEDSECRET',text)
 def test_unknown_key_redacted(self):
  x=base();y=after();y['services']['zap']['private-secret-identifier']='SECRET'
  text=json.dumps(probe.redact_delta(x,y))
  self.assertNotIn('private-secret',text);self.assertNotIn('SECRET',text)
 def test_network_change_reported(self):
  x=after();x['services']['zap']['networks']=['public']
  o=probe.scope_report(base(),x,256);self.assertFalse(o['changed_only_two_approved_fields'])
 def test_service_added(self):
  x=after();x['services']['untrusted']={};self.assertEqual(probe.scope_report(base(),x,256)['scope'],'MISMATCH')
 def test_project_name_change(self):
  x=after();x['name']='bad';self.assertEqual(probe.scope_report(base(),x,256)['scope'],'MISMATCH')
 def test_dict_malformed(self):self.assertEqual(probe.scope_report([],after(),256)['scope'],'INVALID_CONFIG_TYPE')
 def test_missing_services(self):self.assertEqual(probe.scope_report({'name':'test'},after(),256)['scope'],'INVALID_SERVICES_TYPE')
 def test_no_diffs(self):self.assertEqual(probe.redact_delta(base(),base())['changed_paths'],[])
 def test_type_name_bool(self):self.assertEqual(probe.typename(True),'bool')
 def test_type_name_none(self):self.assertEqual(probe.typename(None),'absent')
 def test_type_name_float(self):self.assertEqual(probe.typename(0.1),'float')
 def test_type_name_tuple(self):self.assertEqual(probe.typename((1,2)),'unknown')
 def test_diff_cap(self):
  a=base();b=base();b['services']['zap'].update({str(i):i for i in range(50)})
  o=probe.redact_delta(a,b);self.assertTrue(o['truncated']);self.assertLessEqual(len(o['changed_paths']),24)
 def test_invalid_images_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'images.env';p.write_text('ZAP_IMAGE=latest\nTARGET_IMAGE=latest\n')
   with self.assertRaises(RuntimeError):probe.load_images(p)
 def test_duplicate_image_var(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'images.env';p.write_text('ZAP_IMAGE=latest\nZAP_IMAGE=another\n')
   with self.assertRaises(RuntimeError):probe.load_images(p)
 def test_images_file_symlink(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'images.env';p.write_text('x');q=Path(d)/'link';q.symlink_to(p)
   with self.assertRaises(RuntimeError):probe.load_images(q)
 def test_digest_pinning(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'images.env';p.write_text('CYBERSEC_DAY03_ZAP_IMAGE=registry.example/zap@sha256:'+probe.IMAGE_DIGESTS['ZAP']+'\nCYBERSEC_DAY03_TARGET_IMAGE=registry.example/target@sha256:'+probe.IMAGE_DIGESTS['TARGET']+'\n')
   a,b=probe.load_images(p);self.assertIn('@sha256:',a);self.assertIn('@sha256:',b)
 def test_unsuccessful_remote_on_non_arm64(self):
  with patch.object(probe.sys,'platform','linux'):
   with patch.object(probe.os,'geteuid',return_value=1000):
    with patch.object(probe.os,'uname',return_value=type('U',(),{'machine':'x86_64'})()):
     buf=io.StringIO()
     with patch('sys.stdout',buf):r=probe.main()
     self.assertEqual(r,4)
     self.assertIn('NONROOT_UBUNTU_ARM64_REQUIRED',buf.getvalue())
 def test_remote_report_no_keys(self):self.assertTrue(probe.scrub_field('api_secret')=='<other>')
 def test_remote_diagnostic_never_production(self):
  s=(ROOT/'compose_delta_probe.py').read_text();self.assertIn("'BLOCKED/NO-GO'",s)
 def test_remote_no_docker_mutating_subprocess(self):
  s=(ROOT/'compose_delta_probe.py').read_text();self.assertIn("['config','--format','json']",s)
  self.assertNotIn("['up'",s);self.assertNotIn("['down'",s)
 def test_mac_ssh_host_fixed(self):self.assertEqual(mac.SSH_HOST,'cyberadmin@192.168.64.2')
 def test_mac_ssh_strict(self):
  s=(ROOT/'diagnose_mac.py').read_text();self.assertIn('StrictHostKeyChecking=yes',s);self.assertIn('BatchMode=yes',s)
 def test_mac_refuses_non_mac(self):
  with patch.object(mac.sys,'platform','linux'):
   with self.assertRaises(mac.Blocked):mac.workflow('probe')
 def test_sources_exact(self):self.assertEqual(mac.validate_sources()['status'],'PASS')
 def test_user_evidence_audit(self):
  o=audit.audit();self.assertEqual(o['integrity'],'PASS');self.assertEqual(o['blocker'],'Blocked: V75_COMPOSE_DELTA_INVALID')
 def test_embedded_ubuntu_crc(self):self.assertEqual(audit.audit()['vm_sha256_manifest_entries'],5)
 def test_stage71_closed(self):self.assertIn('NOT_OPENED',(ROOT/'compose_delta_probe.py').read_text())
 def test_no_day04(self):self.assertIn('NOT_RUN',(ROOT/'diagnose_mac.py').read_text())
 def test_py39_safe(self):
  import ast;ast.parse((ROOT/'compose_delta_probe.py').read_text());ast.parse((ROOT/'diagnose_mac.py').read_text())
 def test_negative_corrupt_zip(self):
  with tempfile.TemporaryDirectory() as td:
   f=Path(td)/'bad';f.write_bytes(b'wrong')
   with patch.object(mac,'USER',f):
    with self.assertRaises(mac.Blocked):mac.validate_sources()
 def test_sha(self):self.assertEqual(mac.sha(mac.USER),mac.PIN_EVD)

if __name__=='__main__':unittest.main()
