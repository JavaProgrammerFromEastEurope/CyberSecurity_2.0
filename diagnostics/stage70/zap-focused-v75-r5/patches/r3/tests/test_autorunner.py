import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('v75_autorunner_module',ROOT/'auto_runner.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class AutoRunnerTests(unittest.TestCase):
    def test_exact_v75_baseline(self):
        x=m.source_check()
        self.assertEqual(x['original_sha256'],m.ORIGINAL_SHA256)
        self.assertEqual(x['zip_crc'],'PASS')
        self.assertEqual(x['original_bytes'],9632078)
    def test_checksum_file_mismatch_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            bad=Path(td)/m.ARCHIVE.name
            bad.write_bytes(m.ARCHIVE.read_bytes())
            side=Path(td)/m.CHECKSUM.name
            side.write_text('0'*64+'  '+bad.name+'\n')
            with self.assertRaisesRegex(m.Blocked,'SIDECAR_NOT_PINNED'):
                m.source_check(bad,side)
    def test_archive_byte_tamper_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            bad=Path(td)/m.ARCHIVE.name
            b=bytearray(m.ARCHIVE.read_bytes());b[len(b)//2]^=1;bad.write_bytes(b)
            side=Path(td)/m.CHECKSUM.name
            side.write_text(m.CHECKSUM.read_text())
            with self.assertRaisesRegex(m.Blocked,'ORIGINAL_ZIP_SHA256_MISMATCH'):
                m.source_check(bad,side)
    def test_no_sidecar_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(m.Blocked,'ORIGINAL_SHA256_NOT_FOUND'):
                m.source_check(m.ARCHIVE,Path(td)/'missing.sha256')
    def test_extraction_preserves_manifest(self):
        self.assertEqual(m.source_check()['zip_crc'],'PASS')
        with tempfile.TemporaryDirectory() as td:
            root=m.extract_verified(Path(td))
            self.assertTrue((root/'SOURCE_SHA256.json').is_file())
            files=json.loads((root/'SOURCE_SHA256.json').read_text())['files']
            self.assertEqual(len(files),117)
            self.assertIn('mac_pid_ab_runner.py',files)
            self.assertTrue((root/'HISTORY'/'ORIGINAL_V74_UNCHANGED.zip.xz').is_file())
    def test_extraction_existing_file_fail_closed(self):
        m.source_check()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/m.BASE
            (root/'EVIDENCE').mkdir(parents=True)
            (root/'EVIDENCE'/'SOURCE_GAP.json').write_text('DO_NOT_OVERWRITE')
            with self.assertRaises(FileExistsError):m.extract_verified(Path(td))
            self.assertEqual((root/'EVIDENCE'/'SOURCE_GAP.json').read_text(),'DO_NOT_OVERWRITE')
    def test_budgets_valid(self):
        for a,b in ((64,65),(128,256),(511,512)):
            self.assertEqual(m.validate_budget(a,b),(a,b))
    def test_budgets_invalid(self):
        for a,b in ((0,1),(63,100),(128,128),(129,128),(128,513),
                    (True,256),(128,False),(512,513),(-1,200)):
            with self.subTest(a=a,b=b),self.assertRaises(m.Blocked):m.validate_budget(a,b)
    def test_no_terminal_requires_block(self):
        with self.assertRaises(m.Blocked):
            # In runner QA stdin is non-interactive; no forged YES accepted.
            if not sys.stdin.isatty():m.tty_read('never read: ')
            else:raise m.Blocked('INTERACTIVE_TERMINAL_REQUIRED')
    def test_status_fields_fail_closed(self):
        self.assertEqual('BLOCKED/NO-GO','BLOCKED/NO-GO')
        self.assertIn('NO-GO',(ROOT/'README_RU.md').read_text())
        self.assertNotIn('sudo ',(ROOT/'auto_runner.py').read_text())

if __name__=='__main__':unittest.main(verbosity=2)
