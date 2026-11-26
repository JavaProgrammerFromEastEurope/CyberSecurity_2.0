#!/usr/bin/env python3
"""Independent exact two-source evidence audit, byte preservation via solid tar.xz."""
from __future__ import annotations
import hashlib,io,json,lzma,re,tarfile,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
BUNDLE=ROOT/'EVIDENCE/USER_EVIDENCE_PAIR.tar.xz'
OLD='EVIDENCE(20261126-172555).zip'
NEW='EVIDENCE(20261126-180821).zip'
DIGESTS={OLD:'625e101eb8146afc1372e6cb916f452acdf9fe7b3d8075819805ca0647d00dcb',
NEW:'98adaa5c42e796a88fe5716cdcb64d0d60e48986fbd9f02e3e5a3de615f52ed9'}
def h(b):return hashlib.sha256(b).hexdigest()
def read_pair():
 if not BUNDLE.is_file() or BUNDLE.stat().st_size>1000000:raise ValueError('BUNDLE_MISSING_OR_OVERSIZED')
 with lzma.open(BUNDLE) as f:
  raw=f.read(1300000)
 if len(raw)>1250000:raise ValueError('UNCOMPRESSED_BUNDLE_OVERSIZED')
 with tarfile.open(fileobj=io.BytesIO(raw)) as t:
  members=t.getmembers()
  if len(members)!=2 or set(m.name for m in members)!={OLD,NEW}:raise ValueError('BUNDLE_MEMBER_MISMATCH')
  if any(not m.isfile() or m.size>600000 for m in members):raise ValueError('BUNDLE_UNSAFE')
  out={m.name:t.extractfile(m).read() for m in members}
 for n,sha in DIGESTS.items():
  if h(out[n])!=sha:raise ValueError('EVIDENCE_ORIGINAL_HASH_MISMATCH '+n)
 return out

def checked(raw,*,maxfiles=700,maxsize=10000000):
 if len(raw)>maxsize:raise ValueError('ZIP_TOO_LARGE')
 z=zipfile.ZipFile(io.BytesIO(raw));ns=z.namelist()
 if len(ns)>maxfiles or len(ns)!=len(set(ns)) or z.testzip() is not None:raise ValueError('ZIP_CRC_DUPLICATES_OR_SIZE')
 for m in z.infolist():
  n=m.filename
  if n.startswith('/') or '..' in Path(n).parts or '\\' in n or m.file_size>maxsize:
   raise ValueError('ZIP_UNSAFE_MEMBER')
 return z

def manifest(z):
 names=z.namelist()
 sums=[n for n in names if n.endswith('/SHA256SUMS.txt')]
 if len(sums)!=1:raise ValueError('MANIFEST_AMBIGUOUS')
 d=sums[0].split('/')[0]+'/'
 out={}
 for line in z.read(sums[0]).decode('ascii').splitlines():
  m=re.fullmatch(r'([a-f0-9]{64})  ([^\r\n]+)',line)
  if not m or m.group(2) in out:raise ValueError('MANIFEST_PARSE')
  out[m.group(2)]=m.group(1)
 actual={n[len(d):] for n in names if n.startswith(d) and n!=sums[0] and not n.endswith('/')}
 if set(out)!=actual:raise ValueError('MANIFEST_FILESET')
 for n,digest in out.items():
  if h(z.read(d+n))!=digest:raise ValueError('MANIFEST_HASH_MISMATCH')
 return d

def verify_mac(outer, n):
 raw=outer.read(n);side=outer.read(n+'.sha256').decode().split()
 if len(side)!=2 or side[0]!=h(raw) or side[1]!=n.split('/')[-1]:raise ValueError('MAC_SIDECAR')
 with checked(raw) as m:
  pref=manifest(m)
  # check redundant unpacked copy for each MAC archive member
  for entry in m.namelist():
   if entry.endswith('/'):continue
   if outer.read('EVIDENCE/'+entry)!=m.read(entry):raise ValueError('UNPACKED_COPY_MISMATCH')
  mac=json.loads(m.read(pref+'MAC_FOCUSED_STATUS.json'))
  if (mac.get('vm_exit_code')!=4 or mac.get('production')!='BLOCKED/NO-GO' or
      mac.get('result')!='BLOCKED' or mac.get('vm_evidence_sha256')!='PASS' or
      mac.get('vm_evidence_crc')!='PASS' or mac.get('day04')!='NOT_RUN' or
      mac.get('stage71')!='NOT_OPENED'):raise ValueError('MAC_GATE_UNEXPECTED')
  vmdata=m.read(pref+'VM_ZAP_FOCUSED_EVIDENCE.zip')
  vmsha=m.read(pref+'VM_ZAP_FOCUSED_EVIDENCE.zip.sha256').decode().split()
  if len(vmsha)!=2 or vmsha[0]!=h(vmdata):raise ValueError('VM_SIDECAR')
  with checked(vmdata) as v:
   vp=manifest(v)
   s=json.loads(v.read(vp+'ZAP_FOCUSED_STATUS.json'))
   if not (s.get('overall')=='BLOCKED/NO-GO' and s.get('production')=='BLOCKED/NO-GO' and
      s.get('day04')=='NOT_RUN' and s.get('stage71')=='NOT_OPENED' and
      s.get('active_scan') is False and s.get('ajax_spider')=='NOT_RUN' and
      s.get('spider')=='PASS_100_PERCENT' and s.get('passive')=='PASS_DRAINED_AFTER_SPIDER' and
      s.get('checks',{}).get('cleanup')=='PASS'):
    raise ValueError('VM_GATE_UNEXPECTED')
   return {'run':n.rsplit('/',1)[-1],'mac_sha256':h(raw),'vm_sha256':h(vmdata),
           'primary_webdriver':s['checks']['ajax_diagnostic']['real_webdriver_session_probe']['failure_category'],
           'window_handles':s['checks']['ajax_diagnostic']['real_webdriver_session_probe']['window_handles_before_navigation'],
           'ajax':'NOT_RUN','second_passive':'NOT_RUN'}

def audit():
 blobs=read_pair()
 with checked(blobs[OLD]) as old,checked(blobs[NEW]) as new:
  nr=lambda z:sorted(n for n in z.namelist() if re.fullmatch(r'EVIDENCE/ZAP_FOCUSED_MAC_V\d+_\d{8}T\d{6}Z\.zip',n))
  os,ns=nr(old),nr(new)
  if len(os)!=19 or len(ns)!=20 or not set(os).issubset(ns):raise ValueError('HISTORICAL_RUN_COUNT')
  for n in os:
   if old.read(n)!=new.read(n) or old.read(n+'.sha256')!=new.read(n+'.sha256'):
    raise ValueError('OLDER_SOURCE_NOT_IDENTICAL')
  only=sorted(set(ns)-set(os))
  if len(only)!=1 or not only[0].startswith('EVIDENCE/ZAP_FOCUSED_MAC_V74_20261126T173624Z'):
   raise ValueError('UNEXPECTED_NEW_RUN')
  checked_runs=[verify_mac(new,n) for n in ns]
  return {'schema':'stage70-v75-ubuntu-new-evidence-pair-audit-v1',
          'old_exact_sha256':DIGESTS[OLD],'new_exact_sha256':DIGESTS[NEW],
          'historical_runs_unchanged':len(os),'total_runs':len(ns),
          'new_v74':checked_runs[-1],
          'all_nested_crc_sha256_manifests':'PASS',
          'production':'BLOCKED/NO-GO','day04':'NOT_RUN','stage71':'NOT_OPENED'}
if __name__=='__main__':print(json.dumps(audit(),ensure_ascii=False,indent=2,sort_keys=True))
