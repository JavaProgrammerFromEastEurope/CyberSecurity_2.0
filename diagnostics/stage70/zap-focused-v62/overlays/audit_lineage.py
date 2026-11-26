#!/usr/bin/env python3
"""Read-only cryptographic ancestry V61 -> V60 -> V59 -> V58 -> V57."""
from pathlib import Path
from zipfile import ZipFile
import io,lzma,hashlib,json
r=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
versions=[61,60,59,58,57]
rows=[]
base={f.relative_to(r).as_posix():f.read_bytes() for f in (r/'HISTORY').iterdir() if f.is_file()}
for n in versions:
    key=f'HISTORY/ORIGINAL_V{n}_UNCHANGED.zip.xz'
    digest=f'HISTORY/ORIGINAL_V{n}_SHA256.txt'
    compressed=f'HISTORY/ORIGINAL_V{n}_COMPRESSED_SHA256.txt'
    assert key in base and compressed in base and digest in base,(n,list(base))
    pack=base[key]
    assert sha(pack)==base[compressed].decode().split()[0]
    raw=lzma.decompress(pack)
    assert sha(raw)==base[digest].decode().split()[0]
    with ZipFile(io.BytesIO(raw)) as z:
        assert z.testzip() is None
        members=z.namelist()
        assert all(not Path(x).is_absolute() and '..' not in Path(x).parts for x in members)
        path=f'Stage70_ZAP_API_AJAX_SPIDER_PASSIVE_FOCUSED_V{n}_'
        assert all(x.startswith(path) for x in members)
        base={x[len(path):].split('/',1)[1]:z.read(x) for x in members if x.startswith(path) and '/' in x[len(path):] and not x.endswith('/')}
    rows.append({'version':n,'sha256':sha(raw),'zip_crc':'PASS','bytes':len(raw)})
print(json.dumps({'schema':'stage70-v62-lineage-audit-v1','versions':rows,'originals_untouched':True},indent=2,sort_keys=True))
