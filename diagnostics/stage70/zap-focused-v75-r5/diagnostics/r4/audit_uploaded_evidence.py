#!/usr/bin/env python3
"""Offline audit; never modifies user ZIP, never calls Docker or network."""
from __future__ import annotations
import hashlib,io,json,re,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
EVD=ROOT/'originals/EVIDENCE(20261126-193829).zip'

def sha(data):return hashlib.sha256(data).hexdigest()

def audit():
    report={'schema':'stage70-v75-compose-delta-evidence-audit-r4',
      'production':'BLOCKED/NO-GO','day04':'NOT_RUN','stage71':'NOT_OPENED',
      'source_sha256':'1fbf59d9b9f65e2c87b28ea73aa0adbd5f95d8007ebc6bae8c4eae38739376c7',
      'ab_attempts':0,'r1_a_attempts':0,'docker_compose_up':'NOT_STARTED','findings':[]}
    data=EVD.read_bytes()
    if sha(data)!=report['source_sha256']:raise ValueError('USER_EVIDENCE_SHA256_MISMATCH')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        if archive.testzip() is not None:raise ValueError('USER_EVIDENCE_ZIP_CRC')
        members=archive.namelist()
        report['outer_members']=len(members)
        prefixes=[('ZAP_FOCUSED_MAC_V75_PID_AB_20261126T193735Z',
                   'EVIDENCE/ZAP_FOCUSED_MAC_V75_PID_AB_20261126T193735Z/'),
                  ('STAGE70_V75_PID_AUTORUN_20261126T193700_625568Z',
                   'EVIDENCE/STAGE70_V75_PID_AUTORUN_20261126T193700_625568Z/')]
        for name,prefix in prefixes:
            if prefix+'SHA256SUMS.txt' not in members:raise ValueError('MANIFEST_MISSING_'+name)
            lines=archive.read(prefix+'SHA256SUMS.txt').decode('utf-8').splitlines()
            for line in lines:
                m=re.fullmatch(r'([a-f0-9]{64})  ([^\r\n]+)',line)
                if not m:raise ValueError('MANIFEST_SYNTAX')
                digest,rel=m.groups()
                if '..' in Path(rel).parts or prefix+rel not in members or sha(archive.read(prefix+rel))!=digest:
                    raise ValueError('MANIFEST_MISMATCH_'+rel)
            report[name+'_sha256_manifest_entries']=len(lines)
        macpref=prefixes[0][1]
        status=json.loads(archive.read(macpref+'V75_AB_SUMMARY.json'))
        pre=json.loads(archive.read(macpref+'AB_PRECHECK.json'))
        if pre.get('preflight')!='PASS':raise ValueError('PARENT_PREFLIGHT_NOT_PASS')
        if status.get('reason')!='TRIAL_CLEANUP_UNVERIFIED_STOP':raise ValueError('UNEXPECTED_ABORT')
        if len(status.get('trials',[]))!=1 or status['trials'][0].get('vm_exit_code')!=4:raise ValueError('TRIAL_COUNT_MISMATCH')
        report['ab_attempts']=len(status['trials'])
        report['r1_a_attempts']=1
        report['parent_min_headroom']=pre['plan']['parent_min_headroom']
        inner=[name for name in members if name.endswith('stage70_zap_focused_v75pid_20261126T193741Z_d792058b.zip')]
        if len(inner)!=1:raise ValueError('VM_EVIDENCE_ZIP_NOT_UNIQUE')
        innerdata=archive.read(inner[0])
        remote_side=archive.read(inner[0]+'.sha256').decode('ascii').split()
        if len(remote_side)!=2 or sha(innerdata)!=remote_side[0]:raise ValueError('INNER_SHA256_MISMATCH')
        with zipfile.ZipFile(io.BytesIO(innerdata)) as innerzip:
            if innerzip.testzip() is not None:raise ValueError('INNER_ZIP_CRC')
            statusfiles=[n for n in innerzip.namelist() if n.endswith('/ZAP_FOCUSED_STATUS.json')]
            if len(statusfiles)!=1:raise ValueError('VM_STATUS_NOT_UNIQUE')
            state=json.loads(innerzip.read(statusfiles[0]))
            report['blocker']=state.get('error')
            report['targeted_pytest']=state.get('checks',{}).get('targeted_tests')
            report['compose_quiescence']=state.get('checks',{}).get('v75_compose_quiescence')
            report['docker_compose_up']='NOT_STARTED' if state.get('checks',{}).get('docker_before_cleanup')=='NOT_STARTED' else 'UNVERIFIED'
            report['ajax']=state.get('ajax_spider')
            report['passive']=state.get('passive')
            report['spider']=state.get('spider')
            if report['blocker']!='Blocked: V75_COMPOSE_DELTA_INVALID':raise ValueError('UNEXPECTED_BLOCKER')
            if not (report['targeted_pytest']=='PASS_NO_SKIPS_OR_WARNINGS' and report['docker_compose_up']=='NOT_STARTED'):
                raise ValueError('UNEXPECTED_RUN_PHASE')
            prefix=statusfiles[0].rsplit('/',1)[0]+'/'
            ilines=innerzip.read(prefix+'SHA256SUMS.txt').decode().splitlines()
            for line in ilines:
                m=re.fullmatch(r'([a-f0-9]{64})  ([^\r\n]+)',line)
                if not m or sha(innerzip.read(prefix+m.group(2)))!=m.group(1):
                    raise ValueError('VM_MANIFEST_MISMATCH')
            report['vm_sha256_manifest_entries']=len(ilines)
    report['integrity']='PASS'
    return report

if __name__=='__main__':print(json.dumps(audit(),sort_keys=True,indent=2))
