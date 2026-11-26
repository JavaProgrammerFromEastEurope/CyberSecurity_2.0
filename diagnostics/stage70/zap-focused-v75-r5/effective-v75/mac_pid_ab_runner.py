#!/usr/bin/env python3
"""Explicitly consented macOS -> pinned UTM Ubuntu ARM64 finite PID A/B.
Six sequential full Stage70 lab attempts, no production or Active Scan.
"""
from __future__ import annotations
import argparse,io,json,os,re,subprocess,sys,zipfile
from datetime import datetime,timezone
from pathlib import Path
from mac_run import ROOT,VM,REMOTE_DIR,EVIDENCE,SSH,SCP,sha,verify,runstep,zip_evidence,read_operator_consent
from pid_recovery import compare_trials, BudgetBlocked

def gate(b,reason):
    if not b:raise BudgetBlocked(reason)

def check_zip(path:Path,side:Path):
    gate(path.is_file() and side.is_file(),'EVIDENCE_MISSING')
    line=side.read_text().strip().split()
    gate(len(line)==2 and re.fullmatch('[a-f0-9]{64}',line[0]) is not None and
         line[1]==path.name and sha(path)==line[0],'EVIDENCE_HASH_INVALID')
    with zipfile.ZipFile(path) as z:
        gate(z.testzip() is None,'EVIDENCE_CRC_INVALID')
        names=z.namelist();gate(len(names)==len(set(names)),'DUPLICATE_ZIP_MEMBER')
        status_files=[x for x in names if x.endswith('/ZAP_FOCUSED_STATUS.json')]
        gate(len(status_files)==1,'STATUS_MISSING_OR_AMBIGUOUS')
        return json.loads(z.read(status_files[0]))

def cells_for_result(replicate,arm,status):
    d=status.get('checks',{}).get('ajax_diagnostic',{})
    t=d.get('firefox_v73_local_dwell_control',{}).get('trials',[])
    roles={'NO_CLIENT','ONE_CLIENT','THREE_CLIENTS'}
    cells=[]
    for role in sorted(roles):
        trial=next((x for x in t if x.get('role')==role),None)
        drain=(d.get('firefox_v70_group_quiescence_control',{}).get('cleanup_classification'))
        cells.append({'replicate':replicate,'arm':arm,'role':role,
            'pid_denial':'YES' if trial and trial.get('cgroup',{}).get('pids_max_delta')=='POSITIVE'
                 else 'NO' if trial and trial.get('cgroup',{}).get('pids_max_delta')=='ZERO' else 'UNKNOWN',
            'outcome':'PASS' if trial and trial.get('state_after_dwell')=='LIVE' else
                    'FAIL' if trial else 'UNKNOWN',
            'quiescence':'DRAINED' if drain=='ALL_DRAINED' else 'UNKNOWN',
            'sandbox_verified':bool(trial and trial.get('security')=={'seccomp':'2','no_new_privs':'1'}),
            'budget_verified':status.get('checks',{}).get('v75_ab',{}).get('status')=='BUDGET_ENFORCED'})
    primary=d.get('real_webdriver_session_probe',{})
    cells.append({'replicate':replicate,'arm':arm,'role':'WEBDRIVER',
      'pid_denial':'UNKNOWN',
      'outcome':'PASS' if primary.get('fixture_navigation_confirmed') is True else
          'FAIL' if type(primary.get('fixture_navigation_confirmed')) is bool else 'UNKNOWN',
      'quiescence':'DRAINED' if status.get('checks',{}).get('v75_compose_quiescence')=='PASS' else 'UNKNOWN',
      'sandbox_verified':status.get('checks',{}).get('v75_ab',{}).get('status')=='BUDGET_ENFORCED',
      'budget_verified':status.get('checks',{}).get('v75_ab',{}).get('status')=='BUDGET_ENFORCED'})
    return cells

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--budget-a',type=int,required=True)
    ap.add_argument('--budget-b',type=int,required=True)
    ap.add_argument('--lab-consent',action='store_true')
    ap.add_argument('--vm-snapshot-confirmed',action='store_true')
    ap.add_argument('--review',action='store_true')
    args=ap.parse_args()
    verify()
    gate(type(args.budget_a) is int and type(args.budget_b) is int and
         64<=args.budget_a<args.budget_b<=512,'BUDGET_BOUNDS')
    if args.review:
        print('REVIEW: two explicit finite budgets; three independent repetitions; four roles per arm; PID root and ancestor preflight; no Active Scan')
        return 0
    gate(args.lab_consent and args.vm_snapshot_confirmed,'LAB_CONSENT_OR_SNAPSHOT_ABSENT')
    gate(read_operator_consent()=='YES','INTERACTIVE_YES_REQUIRED')
    EVIDENCE.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(EVIDENCE,0o700)
    work=EVIDENCE/('ZAP_FOCUSED_MAC_V75_PID_AB_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    work.mkdir(mode=0o700)
    summary={'schema':'stage70-v75-finite-ab-v1','production':'BLOCKED/NO-GO',
       'day04':'NOT_RUN','stage71':'NOT_OPENED','status':'BLOCKED',
       'budget_a':args.budget_a,'budget_b':args.budget_b,'cells':[],
       'trials':[],'reason':'NOT_RUN'}
    try:
        rc,_=runstep(SSH+[VM,'mkdir -p -m 700 '+REMOTE_DIR],work,'ssh_create_dir',35)
        gate(rc==0,'SSH_CREATE_DIR_FAILED')
        for name in ('zap_focus_vm.py','pid_recovery.py'):
            rc,_=runstep(SCP+[str(ROOT/name),VM+':'+REMOTE_DIR+'/'+name],work,
                         'scp_upload_'+name,90)
            gate(rc==0,'SCP_DEPLOY_FAILED')
        cmd=f'python3 -B {REMOTE_DIR}/pid_recovery.py --preflight --budget-a {args.budget_a} --budget-b {args.budget_b}'
        rc,out=runstep(SSH+[VM,cmd],work,'cgroup_parent_preflight',50)
        gate(rc==0,'PARENT_PID_PREFLIGHT_BLOCKED')
        proof=json.loads(out)
        gate(proof.get('preflight')=='PASS' and proof.get('plan',{}).get('cells')==24,
             'PARENT_PID_PREFLIGHT_INVALID')
        (work/'AB_PRECHECK.json').write_text(json.dumps(proof,indent=2,sort_keys=True)+'\n')
        for rep in (1,2,3):
            for arm,budget in ((('B',args.budget_b),('A',args.budget_a)) if rep==2 else (('A',args.budget_a),('B',args.budget_b))):
                label=f'R{rep}_{arm}'
                cmd=f'python3 -B {REMOTE_DIR}/zap_focus_vm.py --apply --pid-budget {budget} --ab-label {arm} --ab-replicate {rep}'
                # Code 4 is normal for failed WebDriver; results still collected.
                code,out=runstep(SSH+[VM,cmd],work,label+'_ubuntu_full',1500)
                summary['trials'].append({'replicate':rep,'arm':arm,'pid_budget':budget,
                                         'vm_exit_code':code})
                m=re.search(r'^FOCUSED_EVIDENCE_ZIP=(/home/cyberadmin/cybersec-zap-focused-evidence/stage70_zap_focused_v75pid_\d{8}T\d{6}Z_[a-f0-9]{8}\.zip)$',out,re.M)
                gate(m is not None,'VM_EVIDENCE_LOCATOR_NOT_FOUND')
                remote=m.group(1)
                z=work/(label+'_VM_EVIDENCE.zip');side=work/(label+'_VM_EVIDENCE.zip.sha256')
                # Remote sidecar refers to the original filename; keep it exact
                # by using a temporary subfolder with original basename.
                original=Path(remote).name; dest=work/label;dest.mkdir(mode=0o700)
                local=dest/original
                r1,_=runstep(SCP+[VM+':'+remote,str(local)],work,label+'_download_zip',150)
                r2,_=runstep(SCP+[VM+':'+remote+'.sha256',str(dest/(original+'.sha256'))],
                              work,label+'_download_sha256',70)
                gate(r1==0 and r2==0,'VM_EVIDENCE_DOWNLOAD_FAILED')
                status=check_zip(local,dest/(original+'.sha256'))
                summary['cells']+=cells_for_result(rep,arm,status)
                # Proof of cleanup is mandatory even if the primary WebDriver
                # failed. Without it, refuse to launch any further iteration.
                gate(status.get('checks',{}).get('v75_compose_quiescence')=='PASS' and
                     status.get('checks',{}).get('cleanup')=='PASS',
                     'TRIAL_CLEANUP_UNVERIFIED_STOP')
        summary['classification']=compare_trials(summary['cells'])
        summary['reason']='AB_COMPLETED_DIAGNOSTIC_ONLY'
        # Never change production or Stage70 admission in A/B results.
        summary['status']='AB_COMPLETE_PRODUCTION_NO_GO'
    except (BudgetBlocked,ValueError,OSError,subprocess.TimeoutExpired,zipfile.BadZipFile) as e:
        summary['reason']=str(e) if isinstance(e,BudgetBlocked) else type(e).__name__
    finally:
        (work/'V75_AB_SUMMARY.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
        zip_evidence(work)
    return 0 if summary['status']=='AB_COMPLETE_PRODUCTION_NO_GO' else 4

if __name__=='__main__':
    try:raise SystemExit(main())
    except BudgetBlocked as e:
        print('BLOCKED: '+str(e),file=sys.stderr)
        raise SystemExit(4)
