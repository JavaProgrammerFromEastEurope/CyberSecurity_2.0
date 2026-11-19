#!/usr/bin/env bash
# Review-only: never elevates, installs, changes service state, or scans.
set -euo pipefail
umask 077
python3 -m cybersec.stage63_host
