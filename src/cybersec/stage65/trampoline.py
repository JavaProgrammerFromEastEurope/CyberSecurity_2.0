"""Non-privileged pre-exec gate. Child NEVER execs before broker releases gate."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import sys


def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument('--gate-fd', type=int, required=True)
    p.add_argument('--expected-cgroup',required=True)
    p.add_argument('args',nargs=argparse.REMAINDER)
    a=p.parse_args(argv)
    args=a.args[1:] if a.args and a.args[0]=='--' else a.args
    if not args or not a.expected_cgroup.startswith('/') or '..' in a.expected_cgroup.split('/'):
        return 125
    with os.fdopen(a.gate_fd, 'rb', closefd=True) as gate:
        authorized=gate.read(1)
        # Require EOF after exactly one byte to reject injected multiline permits.
        closed=gate.read(1)
    if authorized!=b'1' or closed!=b'': return 125
    try:
        if Path('/proc/self/cgroup').read_text(encoding='ascii').splitlines()!=['0::'+a.expected_cgroup]:
            return 125
    except OSError: return 125
    os.execv(args[0],args)
    return 125

if __name__=='__main__':
    sys.exit(main())
