"""Offline, bounded, customer-facing PDF reports; no scanner execution."""
from __future__ import annotations
import hashlib
import json
import os
import re
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from cybersec.reports import _SEVERITIES

MAX_FIELD = 12000


def _safe(value: Any, limit: int = MAX_FIELD) -> str:
    """Treat all assessment content as untrusted text, never markup or URLs."""
    raw = str(value) if value is not None else "—"
    raw = "".join(c if c in "\n\t" or ord(c) >= 32 else " " for c in raw)
    raw = raw[:limit] + ("… [truncated]" if len(raw) > limit else "")
    return escape(raw).replace("\n", "<br/>")


def _font_path(font_path: str | Path | None) -> Path:
    paths = [Path(font_path)] if font_path else [Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'), Path('/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf')]
    for path in paths:
        if path.is_file():
            return path
    raise RuntimeError('Unicode TrueType font unavailable; supply --font-path to a local TTF')


def write_pdf_report(data: dict[str, Any], output: str | Path, *, profile: str = 'technical', project_name: str = 'Cyber Security Assessment', assessment_start: str | None = None, assessment_end: str | None = None, font_path: str | Path | None = None, generated_at: str | None = None) -> tuple[Path, Path]:
    """Write A4 PDF and SHA-256 manifest, atomically, without network or scanner calls."""
    if profile not in ('technical', 'executive'):
        raise ValueError('invalid report profile')
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
    font_file = _font_path(font_path)
    # A unique font name prevents reportlab global font registration collisions.
    font_name = 'CyberSecUnicode_' + hashlib.sha256(font_file.read_bytes()).hexdigest()[:12]
    if font_name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(font_name, str(font_file)))
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='CS_Title', fontName=font_name, fontSize=17, leading=23, spaceAfter=14))
    styles.add(ParagraphStyle(name='CS_Heading', fontName=font_name, fontSize=12, leading=17, spaceBefore=12, spaceAfter=7))
    styles.add(ParagraphStyle(name='CS_Body', fontName=font_name, fontSize=8.5, leading=13, spaceAfter=6, splitLongWords=True))
    styles.add(ParagraphStyle(name='CS_Small', parent=styles['CS_Body'], fontSize=7, leading=10))
    body = styles['CS_Body']
    story = []
    def paragraph(value: Any, *, style=body, limit=MAX_FIELD):
        story.append(Paragraph(_safe(value, limit), style))
    def heading(value: str):
        story.append(Paragraph(_safe(value, 250), styles['CS_Heading']))
    targets = data.get('targets', [])
    jobs = data.get('jobs', [])
    findings = data.get('findings', [])
    if not all(isinstance(x, list) for x in (targets, jobs, findings)):
        raise ValueError('targets/jobs/findings must be lists')
    story.append(Paragraph(_safe(project_name, 200), styles['CS_Title']))
    paragraph(('Technical assessment report' if profile == 'technical' else 'Executive summary') + ' | ' + (generated_at or datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')))
    paragraph(f'Assessment window: {assessment_start or "not specified"} — {assessment_end or "not specified"}')
    heading('Executive summary')
    paragraph(f'{len(targets)} target(s), {len(jobs)} job(s), {len(findings)} recorded finding(s).')
    counts = Counter(str(x.get('severity', 'Info')) for x in findings)
    paragraph('Severity: ' + ', '.join(f'{s}: {counts[s]}' for s in _SEVERITIES))
    paragraph('Findings are recorded observations, not independently verified vulnerabilities. Internal risk priorities are not CVSS scores.')
    heading('Assessment targets')
    for t in targets:
        paragraph(f'#{t.get("id", "—")} | {t.get("url", "—")} | authorization acknowledged: {bool(t.get("authorized"))}', limit=1500)
    if not targets:
        paragraph('No targets registered.')
    if profile == 'technical':
        heading('Scan jobs')
        for j in jobs:
            paragraph(f'#{j.get("id", "—")} | {j.get("tool", "—")} | {j.get("status", "—")}', limit=1500)
    heading('Findings and recommended actions')
    for index, f in enumerate(findings, 1):
        if not isinstance(f, dict):
            raise ValueError('finding must be a mapping')
        heading(f'{index}. {f.get("title") or "Untitled finding"} [{f.get("severity", "Info")}]')
        paragraph(f'Finding ID: {f.get("id", "—")} | Confidence: {f.get("confidence", "—")} | Type: {f.get("vuln_type", "—")}')
        if profile == 'technical':
            for label, key in [('URL', 'url'), ('Parameter', 'parameter'), ('Source tool', 'source_tool'), ('Evidence', 'evidence'), ('Reproduction', 'reproduction'), ('Recommendation', 'recommendation')]:
                paragraph(label + ':')
                paragraph(f.get(key) or ('Not recorded' if key == 'reproduction' else '—'))
            paragraph('Source artifact IDs: ' + ', '.join(map(str, f.get('source_artifact_ids') or [])))
        else:
            paragraph('Recommended action:')
            paragraph(f.get('recommendation') or 'Review and validate this finding.')
    if not findings:
        paragraph('No findings recorded.')
    heading('Appendix — evidence and limitations')
    paragraph('Evidence and URLs are reproduced as untrusted plain text. No active verification, network retrieval, or scanner execution occurred during report generation.')
    paragraph('This report may contain sensitive security information. Share only with authorized recipients. Missing reproduction steps are explicitly marked as not recorded.')
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.cybersec-pdf-', suffix='.pdf', dir=output.parent)
    os.close(fd)
    try:
        def footer(canvas, doc):
            canvas.saveState()
            canvas.setFont(font_name, 7)
            canvas.drawString(18*mm, 12*mm, 'Cyber Security 2.0 — confidential assessment')
            canvas.drawRightString(A4[0]-18*mm, 12*mm, f'Page {doc.page}')
            canvas.restoreState()
        document = SimpleDocTemplate(tmp, pagesize=A4, leftMargin=18*mm, rightMargin=18*mm, topMargin=20*mm, bottomMargin=20*mm, title=project_name[:200], author='Cyber Security 2.0')
        document.build(story, onFirstPage=footer, onLaterPages=footer)
        digest = hashlib.sha256(Path(tmp).read_bytes()).hexdigest()
        manifest = {'schema': 'cybersec-pdf-report-manifest-v1', 'filename': output.name, 'sha256': digest, 'size_bytes': Path(tmp).stat().st_size, 'profile': profile, 'targets': len(targets), 'jobs': len(jobs), 'findings': len(findings), 'generated_at': generated_at or datetime.now(timezone.utc).isoformat(), 'integrity_note': 'SHA-256 detects modification only when manifest digest is independently trusted; not a signature.'}
        manifest_path = Path(str(output) + '.manifest.json')
        fd2, manifest_tmp = tempfile.mkstemp(prefix='.cybersec-manifest-', dir=output.parent)
        try:
            with os.fdopen(fd2, 'w', encoding='utf-8') as fp:
                json.dump(manifest, fp, ensure_ascii=False, indent=2)
                fp.write('\n')
            os.replace(tmp, output)
            os.replace(manifest_tmp, manifest_path)
        finally:
            if os.path.exists(manifest_tmp): os.unlink(manifest_tmp)
        return output, manifest_path
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def verify_pdf_manifest(pdf_path: str | Path, manifest_path: str | Path) -> bool:
    pdf_path = Path(pdf_path)
    manifest = json.loads(Path(manifest_path).read_text(encoding='utf-8'))
    return manifest.get('schema') == 'cybersec-pdf-report-manifest-v1' and manifest.get('filename') == pdf_path.name and manifest.get('size_bytes') == pdf_path.stat().st_size and manifest.get('sha256') == hashlib.sha256(pdf_path.read_bytes()).hexdigest()
