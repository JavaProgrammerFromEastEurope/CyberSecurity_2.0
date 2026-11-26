#!/usr/bin/env python3
"""Reproducible source distributions of Git-tracked Day01 application files.

FULL means the complete PUBLIC GITHUB APP source tree at HEAD, not the private
Stage70 G09 VM evidence archive. LIGHT is the runnable product subset.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
LIGHT_FILES = {
    "pyproject.toml", "README.md", "LICENSE", "Stage70_DAY01_DEMO.command",
    "tools/day01_smoke.py", "tools/day01_package.py",
    "tools/day02_e2e.py", "tools/day02_package.py",
    "Stage70_DAY02_DEMO.command", "docs/STAGE70_DAY02_WP04_WP06.md",
    "tests/test_stage70_day02.py",
    "docs/STAGE70_DAY01_FUNCTIONAL_ACCEPTANCE.md",
    "Stage70_DAY03_ZAP.command",
    "tools/day03_mock_e2e.py", "tools/day03_package.py",
    "tests/test_stage70_day03_zap.py",
    "docs/STAGE70_DAY03_WP07_WP09.md",
    "deployment/day03/compose.lab.yml",
    "deployment/day03/fixture/index.html",
    "deployment/day03/fixture/about.html",
}


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tracked() -> list[str]:
    output = subprocess.check_output(["git", "-C", str(ROOT), "ls-files", "-z"])
    names = [name.decode("utf-8") for name in output.split(b"\0") if name]
    for name in names:
        path = ROOT / name
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(ROOT):
            raise RuntimeError("UNTRUSTED_GIT_ENTRY_" + name)
    return sorted(names)


def select(files: list[str], mode: str) -> list[str]:
    if mode == "FULL":
        return files
    return [name for name in files if name in LIGHT_FILES or name.startswith("src/")]


def make_archive(mode: str, dest: Path, files: list[str], commit: str) -> dict:
    root = "CyberSecurity_Stage70_DAY03_PRODUCT_" + mode
    index = {}
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name in files:
            data = (ROOT / name).read_bytes()
            index[name] = {"sha256": _hash(data), "bytes": len(data)}
            entry = zipfile.ZipInfo(root + "/" + name, (2026, 11, 22, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = (0o755 if name.endswith(".command") or name.startswith("tools/") and name.endswith(".py") else 0o644) << 16
            z.writestr(entry, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        manifest = {
            "schema": "stage70-day03-source-manifest-v1",
            "mode": mode, "git_commit": commit,
            "scope": "GITHUB_PRODUCT_SOURCE_NOT_PRIVATE_STAGE70_G09_VM_EVIDENCE",
            "production": "BLOCKED/NO-GO", "stage71": "NOT_OPENED",
            "files": index,
        }
        entry = zipfile.ZipInfo(root + "/SOURCE_MANIFEST.json", (2026, 11, 22, 0, 0, 0))
        entry.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(entry, json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    return manifest


def verify(archive: Path, mode: str) -> dict:
    with zipfile.ZipFile(archive) as z:
        crc_bad = z.testzip()
        if crc_bad:
            raise RuntimeError("ZIP_CRC_FAILURE_" + crc_bad)
        prefix = "CyberSecurity_Stage70_DAY03_PRODUCT_" + mode + "/"
        manifest = json.loads(z.read(prefix + "SOURCE_MANIFEST.json"))
        expected = {prefix + name for name in manifest["files"]} | {prefix + "SOURCE_MANIFEST.json"}
        if set(z.namelist()) != expected:
            raise RuntimeError("ZIP_FILESET_MISMATCH")
        for name, record in manifest["files"].items():
            data = z.read(prefix + name)
            if len(data) != record["bytes"] or _hash(data) != record["sha256"]:
                raise RuntimeError("ZIP_SHA256_OR_SIZE_MISMATCH_" + name)
        with tempfile.TemporaryDirectory(prefix="day01-verify-") as temp:
            z.extractall(temp)
            root = Path(temp) / prefix
            for name, record in manifest["files"].items():
                p = root / name
                if _hash(p.read_bytes()) != record["sha256"]:
                    raise RuntimeError("REEXTRACTION_SHA256_FAILURE_" + name)
    return {"mode": mode, "crc": "PASS", "source_sha256": "PASS",
            "reextraction": "PASS", "entries": len(expected),
            "sha256": _hash(archive.read_bytes()), "size_bytes": archive.stat().st_size}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    target = args.out_dir.resolve()
    target.mkdir(parents=True, exist_ok=True)
    commit = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    names = tracked()
    summary = {"source_commit": commit, "formats": [], "stage70_private_evidence": "NOT_INCLUDED"}
    for mode in ("FULL", "LIGHT"):
        selected = select(names, mode)
        if not selected or "src/cybersec/cli.py" not in selected:
            raise RuntimeError("APP_SOURCE_MISSING_" + mode)
        dest = target / ("CyberSecurity_Stage70_DAY03_PRODUCT_" + mode + ".zip")
        make_archive(mode, dest, selected, commit)
        report = verify(dest, mode)
        if mode == "LIGHT" and report["size_bytes"] >= 10_000_000:
            raise RuntimeError("LIGHT_SIZE_LIMIT_EXCEEDED")
        (target / (dest.name + ".sha256")).write_text(report["sha256"] + "  " + dest.name + "\n")
        summary["formats"].append(report)
        print(mode + "_ZIP_VERIFIED=" + str(report["size_bytes"]) + " sha256=" + report["sha256"])
    (target / "VERIFICATION.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
