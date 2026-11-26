#!/usr/bin/env python3
"""Independent immutable V74 evidence audit with strict nested ZIP checks."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import hashlib,io,json,re,zipfile
from restore_v74 import checked,NAME
from zap_focus_vm import make_v74_attribution,validate_v74_attribution,validate_v73_local_dwell,validated_driver_session_probe
ROOT=Path(__file__).resolve().parent
from audit_latest_v75_candidate import read_pair,OLD
E=ROOT/'EVIDENCE/USER_EVIDENCE_PAIR.tar.xz'
EXPECTED='625e101eb8146afc1372e6cb916f452acdf9fe7b3d8075819805ca0647d00dcb'
h=lambda b:hashlib.sha256(b).hexdigest()

def opened(data,size_limit=10000000,max_members=600,max_item=3000000):
 if len(data)>size_limit:raise ValueError('ARCHIVE_TOO_LARGE')
 z=zipfile.ZipFile(io.BytesIO(data));ns=z.namelist()
 if z.testzip() is not None or len(ns)!=len(set(ns)) or len(ns)>max_members:raise ValueError('CRC_OR_DUPLICATE')
 if any(n.startswith('/') or '..' in Path(n).parts for n in ns):raise ValueError('TRAVERSAL')
 if any(i.file_size>max_item for i in z.infolist()):raise ValueError('MEMBER_LIMIT')
 return z

def manifest(z):
 ns=z.namelist();fields=[x for x in ns if x.endswith('/SHA256SUMS.txt')]
 if len(fields)!=1:raise ValueError('MANIFEST_COUNT')
 base=fields[0].split('/')[0]+'/';seen=set()
 for line in z.read(fields[0]).decode().splitlines():
  val,sep,name=line.partition('  ')
  if sep!='  ' or not re.fullmatch('[a-f0-9]{64}',val) or name in seen or name=='SHA256SUMS.txt':raise ValueError('MANIFEST_BAD_LINE')
  seen.add(name)
  if base+name not in ns or h(z.read(base+name))!=val:raise ValueError('MANIFEST_HASH_MISMATCH')
 if seen!={n[len(base):] for n in ns if n!=fields[0]}:raise ValueError('MANIFEST_FILESET')

def audit(raw=None):
 b=read_pair()[OLD] if raw is None else raw
 if h(b)!=EXPECTED:raise ValueError('ORIGINAL_USER_EVIDENCE_CHANGED')
 with opened(b,max_item=7000000) as outer:
  ns=outer.namelist()
  new=sorted(n for n in ns if re.fullmatch(r'EVIDENCE/ZAP_FOCUSED_MAC_V74_\d{8}T\d{6}Z\.zip',n))
  old=sorted(n for n in ns if re.fullmatch(r'EVIDENCE/ZAP_FOCUSED_MAC_V(?:68|69|70|71|72|73)_\d{8}T\d{6}Z\.zip',n))
  if len(new)!=4 or len(old)!=15:raise ValueError('RUN_COUNT_MISMATCH')
  with opened(checked(),max_item=10000000) as archive:
   previous=archive.read(NAME+'/EVIDENCE/ORIGINAL_USER_EVIDENCE_V73_UNCHANGED.zip')
  with opened(previous,max_item=7000000) as prior:
   for n in old:
    if (n not in prior.namelist() or outer.read(n)!=prior.read(n) or
       n+'.sha256' not in ns or outer.read(n+'.sha256')!=prior.read(n+'.sha256')):
     raise ValueError('HISTORICAL_EVIDENCE_CHANGED')
  reports=[]
  for n in new:
   mraw=outer.read(n)
   if h(mraw)!=outer.read(n+'.sha256').decode().split()[0]:raise ValueError('MAC_SIDECAR')
   with opened(mraw) as mac:
    manifest(mac)
    prefix=mac.namelist()[0].split('/')[0]+'/'
    for item in mac.namelist():
     if 'EVIDENCE/'+item not in ns or outer.read('EVIDENCE/'+item)!=mac.read(item):
      raise ValueError('UNPACKED_COPY_CHANGED')
    ms=json.loads(mac.read(prefix+'MAC_FOCUSED_STATUS.json'))
    if (ms.get('schema')!='stage70-zap-mac-v74-cross-phase-observed-association' or
        ms.get('vm_exit_code')!=4 or ms.get('result')!='BLOCKED' or
        ms.get('vm_evidence_sha256')!='PASS' or ms.get('vm_evidence_crc')!='PASS' or
        ms.get('production')!='BLOCKED/NO-GO' or ms.get('day04')!='NOT_RUN' or
        ms.get('stage71')!='NOT_OPENED'):raise ValueError('MAC_GATE')
    if mac.read(prefix+'ubuntu_zap_focused.exitcode').strip()!=b'4':raise ValueError('VM_EXITCODE')
    vmraw=mac.read(prefix+'VM_ZAP_FOCUSED_EVIDENCE.zip')
    if h(vmraw)!=mac.read(prefix+'VM_ZAP_FOCUSED_EVIDENCE.zip.sha256').decode().split()[0]:raise ValueError('VM_SIDECAR')
    with opened(vmraw) as vm:
     manifest(vm)
     base=vm.namelist()[0].split('/')[0]+'/'
     s=json.loads(vm.read(base+'ZAP_FOCUSED_STATUS.json'))
     proof=json.loads(vm.read(base+'spider_passive_proof.json'))
     if (s.get('schema')!='stage70-zap-focused-v74-v1' or
         s.get('overall')!='BLOCKED/NO-GO' or s.get('production')!='BLOCKED/NO-GO' or
         s.get('day04')!='NOT_RUN' or s.get('stage71')!='NOT_OPENED' or
         s.get('active_scan') is not False or s.get('ajax_spider')!='NOT_RUN' or
         s.get('spider')!='PASS_100_PERCENT' or
         s.get('passive')!='PASS_DRAINED_AFTER_SPIDER' or
         s['checks'].get('api_version')!='2.17.0' or s['checks'].get('cleanup')!='PASS'):
      raise ValueError('VM_FAIL_CLOSED_GATE')
     if len(proof.get('alerts',[]))!=14 or any(x.get('verification')!='UNCONFIRMED_PASSIVE'
               for x in proof['alerts']):raise ValueError('PASSIVE_ALERT_INVALID')
     if b'35 passed' not in vm.read(base+'zap_targeted_pytest.stdout.txt'):raise ValueError('TARGETED_QA_MISSING')
     a=s['checks']['ajax_diagnostic'];r=a['real_webdriver_session_probe']
     validated_driver_session_probe(r)
     if r['fixture_navigation_confirmed'] is not False or a.get('browser_selected')!='PENDING':raise ValueError('WEBDRIVER_FALSE_PASS')
     native=a['firefox_v73_local_dwell_control'];validate_v73_local_dwell(native)
     cross=a['firefox_v74_cross_phase_control'];validate_v74_attribution(cross,native)
     if (cross!=make_v74_attribution(native) or any(t['security']!={'seccomp':'2','no_new_privs':'1'}
             for t in native['trials'])):raise ValueError('COHORT_SECURITY_OR_PROJECTION')
     repeat=a.get('independent_repeat_probe')
     if repeat is not None:validated_driver_session_probe(repeat)
     reports.append({'run_id':s['run_id'],'mac_sha256':h(mraw),'vm_sha256':h(vmraw),
      'v75_primary_webdriver_navigation':r['fixture_navigation_confirmed'],'v74_native_phase':cross['classification'],
      'ajax':'NOT_RUN','second_passive':'NOT_RUN','exit_code':4})
  return {'schema':'stage70-v75pid-new-v74-evidence-audit-v1','source_sha256':EXPECTED,
   'new_v74_runs':reports,'historical_v68_v73_runs':len(old),
   'nested_crc_sha256_manifests':'PASS','production':'BLOCKED/NO-GO',
   'day04':'NOT_RUN','stage71':'NOT_OPENED'}
if __name__=='__main__':print(json.dumps(audit(),ensure_ascii=False,indent=2,sort_keys=True))
