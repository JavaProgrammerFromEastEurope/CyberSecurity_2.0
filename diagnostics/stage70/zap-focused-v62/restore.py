#!/usr/bin/env python3
"""Fail-closed reconstruction of V62 diagnostic sources, without editing V61."""
from __future__ import annotations
import argparse
import hashlib
import lzma
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--v61-zip', required=True, type=Path)
    parser.add_argument('--out-dir', required=True, type=Path)
    args = parser.parse_args()
    manifest = json.loads((HERE / 'GIT_SYNC_MANIFEST.json').read_text())
    src = args.v61_zip.resolve(strict=True)
    out = args.out_dir.resolve()
    if out.exists():
        raise RuntimeError('Destination must not exist (no overwrite)')
    if sha256(src) != manifest['source_v61_zip_sha256']:
        raise RuntimeError('Input V61 ZIP SHA-256 mismatch')
    if not shutil.which('patch'):
        raise RuntimeError('Required patch executable unavailable')
    out.mkdir(parents=True)
    try:
        with zipfile.ZipFile(src) as z:
            if z.testzip() is not None:
                raise RuntimeError('Input ZIP CRC failure')
            files = [x for x in z.infolist() if not x.is_dir()]
            roots = {PurePosixPath(x.filename).parts[0] for x in files}
            if len(roots) != 1:
                raise RuntimeError('Unexpected V61 ZIP layout')
            for item in files:
                pp = PurePosixPath(item.filename)
                if len(pp.parts) < 2 or pp.is_absolute() or '..' in pp.parts or '\\' in item.filename:
                    raise RuntimeError('Unsafe archive member')
                if (item.external_attr >> 16) & 0o170000 == 0o120000:
                    raise RuntimeError('Symlink member denied')
                dest = out.joinpath(*pp.parts[1:])
                dest.parent.mkdir(parents=True, exist_ok=True)
                with z.open(item) as source, dest.open('xb') as target:
                    shutil.copyfileobj(source, target)
        # Recreate only the predecessor-history dependency required by local V62 tests.
        # The original V61 ZIP remains untouched, and compressed bytes need not
        # equal V62's canonical XZ encoding (only recovered V61 SHA must match).
        raw = src.read_bytes()
        compressed = lzma.compress(raw, preset=9)
        history = out / 'HISTORY'
        history.mkdir(exist_ok=True)
        (history/'ORIGINAL_V61_UNCHANGED.zip.xz').write_bytes(compressed)
        (history/'ORIGINAL_V61_SHA256.txt').write_text(hashlib.sha256(raw).hexdigest()+'  V61.zip\n')
        (history/'ORIGINAL_V61_COMPRESSED_SHA256.txt').write_text(hashlib.sha256(compressed).hexdigest()+'  V61.zip.xz\n')
        subprocess.run(['patch', '--batch', '--forward', '-p1', '-i', str(HERE/'v61_to_v62.patch')],
                       cwd=out, check=True, capture_output=True, text=True)
        for name in manifest['added_files']:
            if name.startswith('/') or '..' in PurePosixPath(name).parts:
                raise RuntimeError('Unsafe overlay member')
            dest = out/name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(HERE/'overlays'/name, dest)
        for group in ('modified_sha256', 'added_sha256'):
            for name, expected in manifest[group].items():
                if sha256(out/name) != expected:
                    raise RuntimeError(f'Output SHA-256 mismatch: {name}')
        print('PASS: 10 V62 source files match canonical ZIP SHA-256; not a production admission')
        return 0
    except BaseException:
        shutil.rmtree(out, ignore_errors=True)
        raise

if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print(f'BLOCKED: {type(exc).__name__}: {exc}', file=sys.stderr)
        sys.exit(4)
