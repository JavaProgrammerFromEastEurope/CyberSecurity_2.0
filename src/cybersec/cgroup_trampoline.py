"""Stage 62: single-shot pre-exec barrier; never grants a production permit."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument('--gate-fd',type=int,required=True)
    p.add_argument('--expected-cgroup',required=True)
    p.add_argument('command',nargs=argparse.REMAINDER)
    a = p.parse_args(argv)
    cmd = a.command[1:] if a.command and a.command[0]=='--' else a.command
    if not cmd or a.gate_fd < 3 or not a.expected_cgroup.startswith('/') or '\x00' in a.expected_cgroup:
        return 125
    try:
        token = os.read(a.gate_fd,2)
        os.close(a.gate_fd)
        # Parent death, EOF, extra bytes or no attach => refuse exec.
        if token != b'1':
            return 125
        lines = Path('/proc/self/cgroup').read_text(encoding='ascii').splitlines()
        if [line[3:].strip() for line in lines if line.startswith('0::')] != [a.expected_cgroup]:
            return 125
        os.execvp(cmd[0],cmd)
    except (OSError, ValueError):
        return 125
    return 125


if __name__=='__main__':
    sys.exit(main())
