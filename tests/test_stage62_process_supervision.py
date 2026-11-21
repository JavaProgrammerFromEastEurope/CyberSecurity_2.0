import os
import subprocess
import sys
import time

import pytest

from cybersec.process_supervisor import ProcessCancelled, ProcessSupervisor

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")


def test_bounded_success():
    result = ProcessSupervisor().run([sys.executable, "-c", "print('safe')"], timeout=3)
    assert result.returncode == 0
    assert result.stdout.strip() == "safe"


def test_timeout_kills_process():
    with pytest.raises(subprocess.TimeoutExpired):
        ProcessSupervisor(grace_seconds=.1).run([sys.executable, "-c", "import time;time.sleep(20)"], timeout=.2)


def test_cancellation_before_start():
    with pytest.raises(ProcessCancelled):
        ProcessSupervisor().run([sys.executable, "-c", "print(1)"], timeout=3, cancelled=lambda: True)


def test_cancellation_during_run():
    start = time.monotonic()
    with pytest.raises(ProcessCancelled):
        ProcessSupervisor(grace_seconds=.1).run([sys.executable, "-c", "import time;time.sleep(20)"], timeout=5, cancelled=lambda: time.monotonic()-start > .2)


def test_reject_bad_args():
    with pytest.raises(ValueError):
        ProcessSupervisor().run([], timeout=1)
