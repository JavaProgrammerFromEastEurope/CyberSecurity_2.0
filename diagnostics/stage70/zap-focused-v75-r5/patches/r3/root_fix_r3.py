#!/usr/bin/env python3
"""Deterministically apply reviewed cgroup-v2 root exception to an extracted COPY.

The original cumulative Stage70 V75 ZIP is pinned and remains byte-identical.
The exception only excludes a proven cgroup-v2 *structural root* whose pids
controller is active in its subtree but its own pids.current/max files are
provably absent. All unknown intermediate parents still block.
"""
from __future__ import annotations
import hashlib, json, os, re
from pathlib import Path

PINNED_BASE = '11d3add1a47a86a14ba9cb652e8f3a4261a499d1139d27a968d8063b23059d18'
PINNED_PID = '27eaffbff0ab931c84b9139798bf2502b3e64e711ace64cc42c6c603687490e3'

def sha(b:bytes)->str:
    return hashlib.sha256(b).hexdigest()

INSERT_AT = 'def ancestors_visible(cgroup_root=Path(\'/sys/fs/cgroup\'), proc_root=Path(\'/proc\')):'
INSERT = '''def verified_structural_pids_root(root, proc_root):
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

'''
OLD = """    readings=[cgroup_node(p) for p in candidates]
    if not readings or readings[0]['current'] is None:return None
    return readings
"""
NEW = """    readings=[cgroup_node(p) for p in candidates]
    # The cgroup-v2 structural root may intentionally lack both pids files.
    # Only omit this exact *last* root node after explicit provenance proof.
    # Never infer unlimited headroom for missing files in a nonroot parent.
    if (len(readings)>1 and readings[-1]['current'] is None and
        readings[-1]['max'] is None and not readings[-1]['max_unlimited'] and
        verified_structural_pids_root(root,proc_root)):
        readings=readings[:-1]
    if not readings or readings[0]['current'] is None:return None
    return readings
"""

def patched_code(base:bytes)->bytes:
    if sha(base)!=PINNED_PID:raise ValueError('ORIGINAL_PID_SOURCE_MISMATCH')
    code=base.decode('utf-8','strict')
    if code.count(INSERT_AT)!=1 or code.count(OLD)!=1:
        raise ValueError('PATCH_ANCHOR_MISMATCH')
    code=code.replace(INSERT_AT, INSERT+INSERT_AT).replace(OLD,NEW)
    compile(code,'pid_recovery.py','exec')
    return code.encode('utf-8')

def apply(project:Path, record:Path|None=None):
    project=Path(project)
    manifest_path=project/'SOURCE_SHA256.json'
    manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
    before=project/'pid_recovery.py'
    old=before.read_bytes()
    if manifest['files'].get('pid_recovery.py')!=PINNED_PID:
        raise ValueError('ORIGINAL_MANIFEST_SOURCE_MISMATCH')
    revised=patched_code(old)
    before.write_bytes(revised)
    # The existing SHA256SUMS excludes itself and SOURCE_SHA256.json. Rebuild
    # its exact lines deterministically and update only two manifest entries.
    sums=project/'SHA256SUMS.txt'
    previous=sums.read_text(encoding='ascii').splitlines()
    updated=[]
    for line in previous:
        if '  ' not in line:raise ValueError('BASE_SHA256SUMS_INVALID')
        digest, rel=line.split('  ',1)
        if len(digest)!=64 or not re.fullmatch('[a-f0-9]{64}',digest):
            raise ValueError('BASE_SHA256SUMS_INVALID')
        checked=(project/rel)
        if not checked.is_file() or checked.is_symlink() or '..' in Path(rel).parts:
            raise ValueError('BASE_SOURCE_FILESET_INVALID')
        updated.append(sha(checked.read_bytes())+'  '+rel)
    sums.write_text('\n'.join(updated)+'\n',encoding='ascii')
    files=manifest['files']
    files['pid_recovery.py']=sha(revised)
    files['SHA256SUMS.txt']=sha(sums.read_bytes())
    # Verify the original listing was complete, not only the two altered files.
    listing={p.relative_to(project).as_posix() for p in project.rglob('*')
             if p.is_file() and p.name!='SOURCE_SHA256.json'}
    if listing!=set(files):raise ValueError('PATCHED_FILESET_MISMATCH')
    for rel,digest in files.items():
        if sha((project/rel).read_bytes())!=digest:
            raise ValueError('PATCHED_FILE_SHA256_MISMATCH:'+rel)
    manifest_path.write_text(json.dumps(manifest,ensure_ascii=True,sort_keys=True,indent=2)+'\n',encoding='utf-8')
    proof={'schema':'stage70-v75-cgroup-root-fix-r3','base_v75_sha256':PINNED_BASE,
           'original_pid_sha256':PINNED_PID,'patched_pid_sha256':sha(revised),
           'updated_source_manifest_sha256':sha(manifest_path.read_bytes()),
           'exception':'EXACT_CGROUP_V2_ROOT_ENOENT_ONLY',
           'nonroot_unknown':'BLOCKED','production':'BLOCKED/NO-GO',
           'day04':'NOT_RUN','stage71':'NOT_OPENED'}
    if record:
        (Path(record)/'R3_ROOT_POLICY.json').write_text(json.dumps(proof,indent=2,sort_keys=True)+'\n')
    return proof
