#!/usr/bin/env python3
"""Verify and optionally restore unchanged predecessor V61, never overwrite."""
import hashlib,io,lzma,sys,zipfile
from pathlib import Path
root=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
def run(mode):
    assert mode in ('verify','restore')
    payload=(root/'HISTORY/ORIGINAL_V61_UNCHANGED.zip.xz').read_bytes()
    assert sha(payload)==(root/'HISTORY/ORIGINAL_V61_COMPRESSED_SHA256.txt').read_text().split()[0]
    raw=lzma.decompress(payload)
    assert sha(raw)==(root/'HISTORY/ORIGINAL_V61_SHA256.txt').read_text().split()[0]
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        assert z.testzip() is None
        assert all(not Path(n).is_absolute() and '..' not in Path(n).parts for n in z.namelist())
        count=len(z.infolist())
    if mode=='restore':
        dest=root.parent/'Stage70_V61_ORIGINAL_RESTORED_EXACT.zip'
        with dest.open('xb') as f:f.write(raw)
        assert sha(dest.read_bytes())==sha(raw)
        print('V61_RESTORED_EXACT',dest)
    else:print('V61_ORIGINAL_EXACT_RECOVERY_PASS',len(raw),count)
if __name__=='__main__':
    if len(sys.argv)!=2 or sys.argv[1] not in ('verify','restore'):
        raise SystemExit('usage: python3 restore_v61.py verify|restore')
    run(sys.argv[1])
