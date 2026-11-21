"""Static fail-closed checks for LAB-only AppArmor reference snapshots."""
import hashlib
from pathlib import Path

EXPECTED = {
    "broker": "3fbd378f1f9c26d5df2ed06707f2d5962b10866f3ce485a1ef28f152c171f77c",
    "worker": "d2f16d78a09308fea3dcaa698940d68cb507d8677e6bf57900dd823fb2836ac6",
    "attester": "9aa4146e4c649dfb23710cfe7268492904e68886708783ab16ea748cf085e583",
    "witness": "25bcadacbd169d3ebb45acbe96ae210ec926a6603eae98f0f39f40a43e4edcda",
    "publisher": "a531b11a2d3135f22c59eb56353199e967329c36b1d1f604d53a139987016d37",
}
ROOT = Path(__file__).resolve().parents[1] / "deployment" / "stage70" / "lab-only"


def test_fixtures_are_exact_and_exclude_wide_signal_grant():
    for role, digest in EXPECTED.items():
        data = (ROOT / f"cybersec-stage70-{role}.profile").read_bytes()
        assert hashlib.sha256(data).hexdigest() == digest
        content = data.decode("utf-8")
        assert f"profile cybersec-stage70-{role} {{" in content
        assert "peer=unconfined" not in content
        assert "signal (receive)" not in content
        assert "network unix stream," in content


def test_publication_is_lab_only():
    doc = (ROOT.parent / "README.md").read_text(encoding="utf-8")
    assert "PRODUCTION BLOCKED/NO-GO" in doc
    assert "NOT production policies" in doc
