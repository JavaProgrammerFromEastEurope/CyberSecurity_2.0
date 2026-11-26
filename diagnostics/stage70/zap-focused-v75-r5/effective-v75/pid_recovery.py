"""Stage70 V75 finite PID budget and numeric telemetry; no mutating cgroups."""
from __future__ import annotations
import json, os, re, resource, stat, time
from pathlib import Path

class BudgetBlocked(ValueError):
    pass

def require(ok, code):
    if not ok: raise BudgetBlocked(code)

def read_regular(path: Path, limit=8192):
    """No symlink following; cgroup pseudo-files often report st_size=0."""
    try:
        f=os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os,'O_NOFOLLOW',0))
        try:
            info=os.fstat(f)
            if not stat.S_ISREG(info.st_mode) or info.st_size>limit: return None
            b=os.read(f,limit+1)
            return b.decode('ascii','strict') if len(b)<=limit else None
        finally: os.close(f)
    except (OSError,ValueError,UnicodeError): return None

def number(raw):
    if raw is None:return None
    value=raw.strip()
    return int(value) if re.fullmatch(r'[0-9]{1,20}',value) else None

def ceiling(raw):
    if raw is None: return None
    value=raw.strip()
    return None if value=='max' else number(raw)

def counter(raw,key):
    if raw is None:return None
    found=[]
    for line in raw.splitlines():
        p=line.split()
        if len(p)==2 and p[0]==key:found.append(number(p[1]))
    return found[0] if len(found)==1 else None

def proc_status(pid='self',proc_root=Path('/proc')):
    raw=read_regular(proc_root/str(pid)/'status',16384)
    if raw is None:return None
    ans={}
    for field in ('Threads','Seccomp','NoNewPrivs'):
        m=re.search(r'(?m)^'+field+r':\s*([0-9]+)\s*$',raw)
        ans[field]=int(m.group(1)) if m else None
    return ans

def proc_starttime(pid,proc_root=Path('/proc')):
    require(isinstance(pid,int) and 1<=pid<2**31,'PID_INVALID')
    raw=read_regular(proc_root/str(pid)/'stat',4096)
    if raw is None:return None
    i=raw.rfind(') ')
    if i<0:return None
    fields=raw[i+2:].split()
    return number(fields[19]) if len(fields)>19 else None

def tasks_summary(proc_root=Path('/proc'),limit=16384):
    try: names=list(proc_root.iterdir())
    except OSError:return {'process_count':None,'thread_count':None}
    if len(names)>limit:return {'process_count':None,'thread_count':None}
    procs=0;threads=0
    for p in names:
        if not p.name.isdigit():continue
        status=proc_status(p.name,proc_root)
        if status is None or status['Threads'] is None:continue
        procs+=1;threads+=status['Threads']
    return {'process_count':procs,'thread_count':threads}

def cgroup_node(root):
    p=Path(root)
    raw={x:read_regular(p/x,8192) for x in ('pids.current','pids.max','pids.peak',
           'pids.events','pids.events.local','memory.events')}
    return {'current':number(raw['pids.current']), 'max':ceiling(raw['pids.max']),
            'max_unlimited':raw['pids.max'] is not None and raw['pids.max'].strip()=='max',
            'peak':number(raw['pids.peak']),
            'denied_total':counter(raw['pids.events'],'max'),
            'denied_local':counter(raw['pids.events.local'],'max'),
            'oom':counter(raw['memory.events'],'oom'),
            'oom_kill':counter(raw['memory.events'],'oom_kill')}

def verified_structural_pids_root(root, proc_root):
    """Strict root-only exception, never an exception for any nonroot parent.

    Return False if mount/proc provenance, path, pids activation or the *exact*
    ENOENT state of both pids files cannot be proven. A missing read due to
    permissions or a symlink is NOT an allowable exception.
    """
    try:
        root=Path(root)
        if root.is_symlink() or not root.is_dir():return False
        raw=read_regular(Path(proc_root)/'self'/'mountinfo',262144)
        if raw is None:return False
        lines=[]
        for line in raw.splitlines():
            if ' - ' not in line:continue
            left,right=line.split(' - ',1)
            head=left.split(); tail=right.split()
            if (len(head)>=5 and len(tail)>=1 and tail[0]=='cgroup2' and
                head[4]==str(root)):
                lines.append((head,tail))
        # Root of cgroup2 mount must be an unambiguous / mount, not a bind
        # of a nested cgroup namespace hierarchy or an alias of another mount.
        if len(lines)!=1 or lines[0][0][3]!='/':return False
        controllers=read_regular(root/'cgroup.controllers')
        subtree=read_regular(root/'cgroup.subtree_control')
        if controllers is None or subtree is None:return False
        if 'pids' not in controllers.split() or 'pids' not in subtree.split():
            return False
        # Distinguish ENOENT from EACCES, ELOOP or an unreadable pseudo-file.
        for name in ('pids.current','pids.max'):
            try:
                os.lstat(root/name)
            except FileNotFoundError:
                continue
            except OSError:
                return False
            else:
                return False
        return True
    except (OSError,ValueError,TypeError):
        return False

def ancestors_visible(cgroup_root=Path('/sys/fs/cgroup'), proc_root=Path('/proc')):
    """Conservative host cgroup-v2 ancestors; do not infer hidden namespace parents."""
    raw=read_regular(proc_root/'self'/'cgroup',4096)
    if raw is None:return None
    paths=[line[3:] for line in raw.splitlines() if line.startswith('0::/')]
    if len(paths)!=1:return None
    parts=Path(paths[0]).parts
    if '..' in parts or len(parts)>24:return None
    root=Path(cgroup_root)
    # The host path is only valid if it exists below the host mount. In a cgroup
    # namespace its parent can be hidden: treat this as unverifiable, not safe.
    candidates=[]
    p=root.joinpath(*parts[1:])
    while True:
        if not p.is_relative_to(root):return None
        if p.is_symlink():return None
        candidates.append(p)
        if p==root:break
        p=p.parent
        if len(candidates)>24:return None
    readings=[cgroup_node(p) for p in candidates]
    # The cgroup-v2 structural root may intentionally lack both pids files.
    # Only omit this exact *last* root node after explicit provenance proof.
    # Never infer unlimited headroom for missing files in a nonroot parent.
    if (len(readings)>1 and readings[-1]['current'] is None and
        readings[-1]['max'] is None and not readings[-1]['max_unlimited'] and
        verified_structural_pids_root(root,proc_root)):
        readings=readings[:-1]
    if not readings or readings[0]['current'] is None:return None
    return readings

def numeric_telemetry(cgroup_root=Path('/sys/fs/cgroup'),proc_root=Path('/proc'),
                      *, include_ancestors=True):
    node=cgroup_node(cgroup_root)
    tasks=tasks_summary(proc_root)
    status=proc_status('self',proc_root)
    try:
        soft,hard=resource.getrlimit(resource.RLIMIT_NPROC)
        nproc_soft=None if soft==resource.RLIM_INFINITY else soft
        nproc_hard=None if hard==resource.RLIM_INFINITY else hard
    except (OSError,ValueError):nproc_soft=nproc_hard=None
    ancestors=ancestors_visible(cgroup_root,proc_root) if include_ancestors else None
    return {'schema':'stage70-v75-numeric-telemetry-v1','monotonic_ns':time.monotonic_ns(),
      'cgroup':node,'tasks':tasks,'self_threads':status['Threads'] if status else None,
      'security':{'seccomp':status['Seccomp'] if status else None,
                  'no_new_privs':status['NoNewPrivs'] if status else None},
      'rlimit_nproc':{'soft':nproc_soft,'hard':nproc_hard},
      'ancestors_visible':ancestors is not None and len(ancestors)>1,
      'ancestor_budgets':[{'current':x['current'],'max':x['max']} for x in ancestors[1:]]
                          if ancestors is not None else None}

def admissible_budgets(a,b,parent_nodes,*,margin=24):
    require(type(a) is int and type(b) is int and 64<=a<b<=512,'BUDGET_BOUNDS')
    require(type(margin) is int and 8<=margin<=128,'MARGIN_INVALID')
    require(isinstance(parent_nodes,list) and len(parent_nodes)>0,'PARENT_CGROUP_UNVERIFIED')
    remain=[]
    for v in parent_nodes:
        require(type(v) is dict and type(v.get('current')) is int and v['current']>=0,
                'PARENT_CURRENT_UNKNOWN')
        maximum=v.get('max')
        # Unlimited parent is a valid explicit reading; None alone is not.
        if maximum is None:
            require(v.get('max_unlimited') is True,'PARENT_LIMIT_UNKNOWN')
            continue
        require(type(maximum) is int and maximum>=v['current'],'PARENT_LIMIT_EXCEEDED')
        remain.append(maximum-v['current'])
    require(len(remain)>0,'PARENT_FINITE_LIMIT_UNVERIFIED')
    require(min(remain)>=b+margin,'PARENT_HEADROOM_INSUFFICIENT')
    return {'schema':'stage70-v75-budget-plan-v1','A':a,'B':b,
            'parent_min_headroom':min(remain),'safety_margin':margin,
            'repetitions':3,'cells':24,'causality':'NOT_ESTABLISHED',
            'production':'BLOCKED/NO-GO'}

def compose_pid_delta(before,after,budget):
    """Rendered Compose JSON: only ZAP shm_size and pids_limit can change."""
    require(type(budget) is int and 64<=budget<=512,'BUDGET_BOUNDS')
    require(type(before) is dict and type(after) is dict and
            type(before.get('services')) is dict and type(after.get('services')) is dict and
            set(before['services'])=={'zap','day03-target'} and
            set(after['services'])=={'zap','day03-target'} and
            before.get('name')==after.get('name')=='cybersec-day03',
            'COMPOSE_SCOPE_INVALID')
    got=after['services']['zap'].get('pids_limit')
    require(type(got) is int and got==budget or type(got) is str and got==str(budget),
            'COMPOSE_PID_BUDGET_MISMATCH')
    got_shm=after['services']['zap'].get('shm_size')
    require((type(got_shm) is int and got_shm==268435456) or
            (type(got_shm) is str and got_shm=='268435456'),'COMPOSE_SHM_MISMATCH')
    # The pinned base lab Compose already has an integer pids_limit on ZAP.
    # Reject malformed, unlimited, bool, or unreasonably large base limits.
    # A *verified* pre-existing finite ZAP budget is not an unapproved change.
    base_zap=before['services']['zap']
    require(type(base_zap) is dict, 'COMPOSE_BASE_ZAP_INVALID')
    require('shm_size' not in base_zap, 'BASE_SHM_UNEXPECTED')
    if 'pids_limit' in base_zap:
        baseline=base_zap['pids_limit']
        if type(baseline) is str:
            require(re.fullmatch(r'[1-9][0-9]{0,6}',baseline) is not None,
                    'BASE_PID_LIMIT_NOT_CANONICAL')
            baseline=int(baseline)
        require(type(baseline) is int and 1<=baseline<=10000000,
                'BASE_PID_LIMIT_NOT_FINITE')
    # Complete structural equality enforces images, networks, UID, caps,
    # privileged, seccomp, no-new-privileges, mounts and all other fields.
    normalized=json.loads(json.dumps(after))
    normalized['services']['zap'].pop('pids_limit',None)
    normalized['services']['zap'].pop('shm_size',None)
    original=json.loads(json.dumps(before))
    original['services']['zap'].pop('pids_limit',None)
    original['services']['zap'].pop('shm_size',None)
    require(normalized==original,'COMPOSE_UNAPPROVED_CHANGE')
    return {'schema':'stage70-v75-compose-delta-v1','only_changes':['zap.pids_limit','zap.shm_size'],
            'pids_limit':budget,'shm_bytes':268435456}

def verify_runtime_budget(runtime_limit,budget,security,cleanup=None):
    require(type(runtime_limit) is int and runtime_limit==budget,'DOCKER_RUNTIME_PID_LIMIT_INVALID')
    require(type(security) is dict and security.get('seccomp')==2 and
            security.get('no_new_privs')==1,'SECURITY_FLAGS_UNVERIFIED')
    if cleanup is not None:require(cleanup is True,'QUIESCENCE_UNVERIFIED')
    return True

def compare_trials(cells):
    """Classifies, does not assert causal attribution without complete balanced A/B."""
    require(type(cells) is list,'CELLS_INVALID')
    roles={'NO_CLIENT','ONE_CLIENT','THREE_CLIENTS','WEBDRIVER'}
    expected={(rep,arm,role) for rep in (1,2,3) for arm in ('A','B') for role in roles}
    seen=set()
    for c in cells:
        require(type(c) is dict and set(c)=={'replicate','arm','role','pid_denial','outcome','quiescence',
                'sandbox_verified','budget_verified'},'CELL_SCHEMA')
        key=(c['replicate'],c['arm'],c['role'])
        require(key in expected and key not in seen,'CELL_DUPLICATE_OR_OUT_OF_SCOPE');seen.add(key)
        require(c['pid_denial'] in ('YES','NO','UNKNOWN') and c['outcome'] in
                ('PASS','FAIL','UNKNOWN') and type(c['sandbox_verified']) is bool and
                type(c['budget_verified']) is bool and c['quiescence'] in
                ('DRAINED','RESIDUAL','UNKNOWN'),'CELL_INVALID')
    if seen!=expected:return 'INCOMPLETE_NO_CAUSALITY'
    if any(c['quiescence']!='DRAINED' or not c['sandbox_verified'] or
           not c['budget_verified'] or c['pid_denial']=='UNKNOWN' or
           c['outcome']=='UNKNOWN' for c in cells):return 'UNVERIFIED_NO_CAUSALITY'
    return 'COMPLETE_AB_OBSERVATIONAL_ONLY_NO_CAUSALITY'

# Self-contained code for read-only telemetry inside pinned ZAP container.
CONTAINER_TELEMETRY_CODE='''import json,os,re,resource\ndef rd(x):\n try:\n  fd=os.open('/sys/fs/cgroup/'+x,os.O_RDONLY|os.O_NOFOLLOW)\n  try:return os.read(fd,4096).decode('ascii','strict')\n  finally:os.close(fd)\n except (OSError,UnicodeError):return None\ndef val(x):\n return int(x.strip()) if x is not None and re.fullmatch('[0-9]{1,20}',x.strip()) else None\ndef cnt(x,key):\n x=rd(x)\n if x is None:return None\n a=[val(p[1]) for line in x.splitlines() if len(p:=line.split())==2 and p[0]==key]\n return a[0] if len(a)==1 else None\ns=open('/proc/self/status').read(16384)\ndef field(x):\n m=re.search('(?m)^'+x+':\\s*([0-9]+)\\s*$',s)\n return int(m.group(1)) if m else None\np=rd('pids.max')\nsoft,_=resource.getrlimit(resource.RLIMIT_NPROC)\nprint(json.dumps({'schema':'stage70-v75-container-pid-numeric-v1','pids_current':val(rd('pids.current')),'pids_max':val(p),'pids_max_unlimited':p is not None and p.strip()=='max','pids_peak':val(rd('pids.peak')),'pids_denied':cnt('pids.events','max'),'pids_denied_local':cnt('pids.events.local','max'),'oom':cnt('memory.events','oom'),'oom_kill':cnt('memory.events','oom_kill'),'threads':field('Threads'),'seccomp':field('Seccomp'),'no_new_privs':field('NoNewPrivs'),'rlimit_nproc_soft':None if soft==resource.RLIM_INFINITY else soft},separators=(',',':')))'''

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description='Read-only cgroup ancestry and finite budget preflight')
    p.add_argument('--preflight',action='store_true')
    p.add_argument('--budget-a',type=int,required=True)
    p.add_argument('--budget-b',type=int,required=True)
    args=p.parse_args()
    if not args.preflight:raise SystemExit(4)
    try:
        t=numeric_telemetry()
        parents=ancestors_visible()
        if parents is None or len(parents)<2:raise BudgetBlocked('PARENT_CGROUP_NOT_VISIBLE')
        plan=admissible_budgets(args.budget_a,args.budget_b,parents[1:])
        # No raw PID, mount path, environment variables or cgroup path.
        print(json.dumps({'preflight':'PASS','plan':plan,'telemetry':t},sort_keys=True))
    except (BudgetBlocked,OSError,ValueError) as e:
        print(json.dumps({'preflight':'BLOCKED','error':str(e)},sort_keys=True))
        raise SystemExit(4)
