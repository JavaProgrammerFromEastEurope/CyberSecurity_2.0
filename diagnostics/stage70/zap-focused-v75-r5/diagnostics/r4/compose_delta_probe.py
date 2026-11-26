#!/usr/bin/env python3
"""Read-only Compose-config differential diagnosis for the pinned Stage70 V75 lab.

This code never runs `docker compose up`, `down`, `create`, `start` or `run`.
The only remote filesystem change is a self-deleting unprivileged 0600 overlay.
Docker config JSON and all environment secrets remain in memory on the VM.
Only allowlisted field names, value TYPES and boolean matches are returned.
"""
from __future__ import annotations
import json, os, re, secrets, subprocess, sys, tempfile
from pathlib import Path

SCHEMA='stage70-v75-compose-delta-readonly-r4'
PINNED_GIT='9de9fe0c2fc4e31d695aa9f3bd4594a0a5ecf5dd'
IMAGE_DIGESTS={'ZAP':'0b8847b2c722b16f0964431aabcbb499560a1f17e8698d52326d82db29efac1d',
               'TARGET':'2ea78c019e6896e39afdb39bc494738ca517d7b58b0f38d6c05018ff76c01f1f'}
FIELD_NAMES={'name','services','zap','day03-target','shm_size','pids_limit','image',
             'networks','network_mode','ports','expose','volumes','cap_add','cap_drop',
             'security_opt','privileged','user','userns_mode','environment','labels',
             'depends_on','healthcheck','restart','init','pid','ipc','ulimits',
             'read_only','tmpfs','sysctls','extra_hosts','devices','hostname',
             'entrypoint','command','dns','working_dir','stop_grace_period',
             'logging','deploy','configs','secrets','volumes_from','platform',
             'profiles','container_name','pull_policy','stdin_open','tty',
             'annotations','build','shm_size','cgroup','cgroup_parent',
             'mem_limit','memswap_limit','mem_reservation','cpus','cpuset',
             'links','scale','extends','networks','volumes'}

def typename(v):
    if v is None: return 'absent'
    if type(v) is bool: return 'bool'
    if type(v) is int:return 'int'
    if type(v) is float:return 'float'
    if type(v) is str:return 'str'
    if type(v) is dict:return 'object'
    if type(v) is list:return 'array'
    return 'unknown'

def scrub_field(part):
    return part if type(part) is str and part in FIELD_NAMES else '<other>'

def redact_delta(before, after, *, limit=24):
    """Return *paths and types only*. Never return an environment value."""
    diffs=[]
    def walk(a,b,path):
        if a==b:return
        if len(diffs)>=limit:return
        if type(a) is dict and type(b) is dict:
            for k in sorted(set(a)|set(b),key=str):
                if len(diffs)>=limit:return
                if k not in a or k not in b:
                    diffs.append({'field':'.'.join(path+[scrub_field(k)]),
                                  'before':'absent' if k not in a else typename(a[k]),
                                  'after':'absent' if k not in b else typename(b[k])})
                elif a[k]!=b[k]:
                    # No recursion through environment, labels, secrets or lists.
                    if k in ('environment','labels','secrets','configs') or type(a[k]) is list or type(b[k]) is list:
                        diffs.append({'field':'.'.join(path+[scrub_field(k)]),
                                      'before':typename(a[k]),'after':typename(b[k])})
                    else: walk(a[k],b[k],path+[scrub_field(k)])
        else:
            diffs.append({'field':'.'.join(path), 'before':typename(a),'after':typename(b)})
    walk(before,after,[])
    return {'changed_paths':diffs,'truncated':len(diffs)>=limit}

def scope_report(before, after, budget):
    allowed=redact_delta(before,after)
    if type(before) is not dict or type(after) is not dict:
        return {'scope':'INVALID_CONFIG_TYPE',**allowed}
    bs=before.get('services');a_s=after.get('services')
    if type(bs) is not dict or type(a_s) is not dict:
        return {'scope':'INVALID_SERVICES_TYPE',**allowed}
    a=a_s.get('zap',{});b=bs.get('zap',{})
    if type(a) is not dict or type(b) is not dict:a={};b={}
    pid=a.get('pids_limit');shm=a.get('shm_size')
    expected_paths={'services.zap.pids_limit','services.zap.shm_size'}
    got_paths={x['field'] for x in allowed['changed_paths']}
    fields_only=(not allowed['truncated'] and got_paths==expected_paths)
    return {'scope':'EXPECTED' if (before.get('name')=='cybersec-day03' and
       after.get('name')=='cybersec-day03' and set(bs)==set(a_s)=={'zap','day03-target'}) else 'MISMATCH',
       'base_pid_absent':'pids_limit' not in b,
       'base_shm_absent':'shm_size' not in b,
       'pid_type':typename(pid),'pid_matches_exact':(type(pid) is int and pid==budget) or
           (type(pid) is str and pid==str(budget)),
       'shm_type':typename(shm),'shm_matches_exact':(type(shm) is int and shm==268435456) or
           (type(shm) is str and shm=='268435456'),
       'changed_only_two_approved_fields':fields_only,
       **allowed}

def run(cmd,*,cwd,env,timeout=22):
    out=subprocess.run(cmd,cwd=cwd,env=env,capture_output=True,timeout=timeout,check=False)
    # Never include raw stdout/stderr in a returned report.
    if out.returncode!=0 or len(out.stdout)>200000:
        raise RuntimeError('COMPOSE_CONFIG_NONZERO_OR_OVERSIZED')
    try:return json.loads(out.stdout)
    except (TypeError,ValueError):raise RuntimeError('COMPOSE_CONFIG_JSON_INVALID')

def load_images(path):
    if not path.is_file() or path.is_symlink() or path.stat().st_size>8192:raise RuntimeError('PINNED_IMAGES_ENV_UNAVAILABLE')
    values={}
    for line in path.read_text('utf-8').splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        m=re.fullmatch(r'(?:export\s+)?([A-Z_][A-Z_0-9]*)\s*=\s*(.*?)\s*',line)
        if not m:raise RuntimeError('IMAGES_ENV_INVALID')
        k,v=m.groups()
        if v[:1] in ("'",'"'):
            if not v.endswith(v[0]):raise RuntimeError('IMAGES_ENV_QUOTES_INVALID')
            v=v[1:-1]
        if k in values:raise RuntimeError('IMAGES_ENV_DUPLICATED')
        values[k]=v
    def grab(a,b,digest):
        val=values.get(a) or values.get(b,'')
        if not re.fullmatch(r'[a-z0-9./_-]+@sha256:[a-f0-9]{64}',val) or val.split('sha256:')[-1]!=digest:
            raise RuntimeError('IMAGE_DIGEST_NOT_PINNED')
        return val
    return grab('CYBERSEC_DAY03_ZAP_IMAGE','ZAP_IMAGE',IMAGE_DIGESTS['ZAP']),grab('CYBERSEC_DAY03_TARGET_IMAGE','TARGET_IMAGE',IMAGE_DIGESTS['TARGET'])

def main():
    report={'schema':SCHEMA,'status':'BLOCKED_DIAGNOSTIC_ONLY','production':'BLOCKED/NO-GO',
            'stage71':'NOT_OPENED','day04':'NOT_RUN','docker_mutations':'NONE',
            'outputs_sanitized':True,'arms':{}}
    try:
        if sys.platform!='linux' or os.geteuid()==0 or os.uname().machine not in ('aarch64','arm64'):
            raise RuntimeError('NONROOT_UBUNTU_ARM64_REQUIRED')
        repo=Path.home()/'CyberSecurity_2.0_Day03_R6'
        if not (repo/'deployment/day03/compose.lab.yml').is_file():raise RuntimeError('PINNED_COMPOSE_SOURCE_MISSING')
        head=subprocess.run(['git','-C',str(repo),'rev-parse','HEAD'],capture_output=True,timeout=15,check=False)
        if head.returncode or head.stdout.decode('ascii','replace').strip()!=PINNED_GIT:
            raise RuntimeError('GIT_HEAD_NOT_PINNED')
        zap,target=load_images(Path.home()/'cybersec-day03-lab/images.env')
        env=os.environ.copy();env.update(CYBERSEC_DAY03_ZAP_IMAGE=zap,
              CYBERSEC_DAY03_TARGET_IMAGE=target,CYBERSEC_DAY03_ZAP_API_KEY=secrets.token_urlsafe(40))
        base=['docker','compose','-f','deployment/day03/compose.lab.yml']
        before=run(base+['config','--format','json'],cwd=repo,env=env)
        report['base_rendered']='PASS'
        with tempfile.TemporaryDirectory(prefix='stage70_compose_readonly_') as td:
            overlay=Path(td)/'lab_shm_override.yml'
            for arm,budget in (('A',256),('B',384)):
                overlay.write_text('services:\n  zap:\n    shm_size: 256m\n    pids_limit: '+str(budget)+'\n','utf-8')
                overlay.chmod(0o600)
                after=run(base+['-f',str(overlay),'config','--format','json'],cwd=repo,env=env)
                report['arms'][arm]={'budget':budget,**scope_report(before,after,budget)}
        report['status']='DIAGNOSTIC_RECORDED_PRODUCTION_NO_GO'
    except (RuntimeError,OSError,ValueError,TypeError,subprocess.TimeoutExpired) as e:
        report['status']='BLOCKED_DIAGNOSTIC_ONLY'
        report['blocker']=str(e) if isinstance(e,RuntimeError) else type(e).__name__
    print(json.dumps(report,ensure_ascii=True,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if report['status']=='DIAGNOSTIC_RECORDED_PRODUCTION_NO_GO' else 4

if __name__=='__main__':raise SystemExit(main())
