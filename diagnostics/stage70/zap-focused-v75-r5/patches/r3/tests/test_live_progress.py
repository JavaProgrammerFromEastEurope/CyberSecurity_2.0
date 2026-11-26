"""Offline negative/interactive checks: no Docker/SSH, no real A/B."""
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import select
import signal
import sys
import tempfile
import time
import unittest
import warnings
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('v75_live', ROOT/'auto_runner.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class LiveProgressTests(unittest.TestCase):
    def run_mock(self, code, timeout=4,heartbeat=.12):
        with tempfile.TemporaryDirectory() as d:
            record=pathlib.Path(d)
            screen=io.StringIO();errors=io.StringIO()
            with contextlib.redirect_stdout(screen),contextlib.redirect_stderr(errors):
                rc=m.run_command([sys.executable,'-u','-c',code],
                                 'test',record,timeout,heartbeat)
            result=(rc,screen.getvalue(),errors.getvalue(),
                    (record/'test.stdout.txt').read_text(),
                    (record/'test.stderr.txt').read_text(),
                    (record/'test.exitcode').read_text(),
                    [json.loads(x) for x in (record/'PROGRESS.jsonl').read_text().splitlines()])
            return result
    def test_partial_stdout_no_newline(self):
        rc,console,errors,out,err,exitcode,events=self.run_mock(
            "import sys,time;sys.stdout.write('NO_NEWLINE');sys.stdout.flush();time.sleep(.2)")
        self.assertEqual(rc,0);self.assertEqual(out,'NO_NEWLINE')
        self.assertIn('NO_NEWLINE',console);self.assertEqual(exitcode,'0\n')
    def test_partial_stderr_no_newline(self):
        rc,console,errors,out,err,exitcode,events=self.run_mock(
            "import sys;sys.stderr.write('Введите YES: ');sys.stderr.flush()")
        self.assertEqual(rc,0);self.assertIn('Введите YES:',errors)
        self.assertIn('Введите YES:',err)
    def test_heartbeat_without_child_output(self):
        rc,console,errors,out,err,exitcode,events=self.run_mock(
            'import time;time.sleep(.55)',heartbeat=.1)
        self.assertEqual(rc,0);self.assertGreaterEqual(sum(x['event']=='RUNNING' for x in events),2)
        self.assertIn('awaiting child/SSH progress',console)
    def test_timeout_marks_blocked(self):
        rc,console,errors,out,err,exitcode,events=self.run_mock(
            'import time;time.sleep(6)',timeout=.4,heartbeat=.1)
        self.assertEqual(rc,124);self.assertEqual(exitcode,'124\n')
        self.assertIn('TIMEOUT',[x['event'] for x in events]);self.assertIn('BLOCKED',console)
    def test_nonzero_marks_blocked(self):
        rc,console,errors,out,err,exitcode,events=self.run_mock('import sys;sys.exit(7)')
        self.assertEqual(rc,7);self.assertEqual(exitcode,'7\n');self.assertIn('BLOCKED',console)
    def test_output_is_preserved_binary_exactly(self):
        rc,console,errors,out,err,exitcode,events=self.run_mock(
            "import os;os.write(1,b'123\\x00xyz');os.write(2,b'ERR')")
        self.assertEqual(rc,0)
        self.assertEqual(out.encode(),b'123\x00xyz');self.assertEqual(err,'ERR')
    def test_progress_schema_does_not_log_command(self):
        rc,console,errors,out,err,exitcode,events=self.run_mock('print(1)')
        self.assertEqual(rc,0)
        self.assertEqual(events[0]['event'],'START');self.assertEqual(events[-1]['event'],'EXIT')
        for entry in events:
            self.assertEqual(set(entry),{'time_utc','step','event','details'})
            self.assertNotIn('secret',str(entry))
    def test_command_is_executable_after_unix_unzip(self):
        self.assertTrue(os.stat(ROOT/'Run_Stage70_V75_PID_Recovery.command').st_mode & 0o100)

    def test_timeout_validation_failclosed(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(m.Blocked):
                m.run_command(['true'],'test',pathlib.Path(d),0)
    def test_heartbeat_validation_failclosed(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(m.Blocked):
                m.run_command(['true'],'test',pathlib.Path(d),2,0)
    @unittest.skipUnless(hasattr(os,'fork') and hasattr(os,'openpty'),'requires UNIX PTY')
    def test_real_pty_second_yes_prompt_visible_and_accepted(self):
        import pty
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore',message='This process.*multi-threaded',category=DeprecationWarning)
            child_pid,master=pty.fork()
        if child_pid==0:
            with tempfile.TemporaryDirectory() as d:
                code=("import sys;sys.stderr.write('Введите YES: ');sys.stderr.flush();"
                      "x=sys.stdin.readline().strip();print('CONSENT='+x,flush=True)")
                try:
                    rc=m.run_command([sys.executable,'-u','-c',code],
                                      'pty',pathlib.Path(d),timeout=7,heartbeat_seconds=.3)
                except Exception as e:
                    print('PTY_EXCEPTION='+repr(e),flush=True);rc=4
                os._exit(rc)
        total=b''; sent=False;start=time.monotonic();status=None
        try:
            while time.monotonic()-start<9:
                ready,_,_=select.select([master],[],[],.2)
                if ready:
                    try:chunk=os.read(master,65536)
                    except OSError:
                        chunk=b''
                    if not chunk:
                        pid,st=os.waitpid(child_pid,0)
                        status=st
                        break
                    total+=chunk
                    if b'YES:' in total and not sent:
                        os.write(master,b'YES\n');sent=True
                pid,st=os.waitpid(child_pid,os.WNOHANG)
                if pid==child_pid:status=st;break
            if status is None:
                try:os.kill(child_pid,signal.SIGKILL)
                except ProcessLookupError:pass
                os.waitpid(child_pid,0)
                self.fail('PTY child timed out: '+repr(total[-300:]))
            self.assertTrue(sent,'never displayed prompt: '+repr(total[-300:]))
            self.assertIn(b'CONSENT=YES',total)
            self.assertEqual(os.waitstatus_to_exitcode(status),0,repr(total[-300:]))
        finally:os.close(master)

if __name__=='__main__':unittest.main(verbosity=2)
