#!/bin/bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd -P)"
exec /usr/bin/env python3 -B "$HERE/mac_pid_ab_runner.py" "$@"
