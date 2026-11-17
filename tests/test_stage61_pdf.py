import json
from pathlib import Path
import pytest
from cybersec.pdf_reports import write_pdf_report, verify_pdf_manifest
from cybersec.reports import filter_report_data, render_html_report

DATA = {'targets':[{'id':1,'url':'https://example.test','authorized':True}], 'jobs':[{'id':7,'target_id':1,'tool':'demo','status':'completed'}], 'findings':[{'id':8,'target_id':1,'job_id':7,'title':'Проверка SQL <script>alert(1)</script>','severity':'High','confidence':'Medium','vuln_type':'sqli','url':'https://example.test/?a=1','parameter':'a','source_tool':'demo','evidence':'Доказательство <b>тест</b>','recommendation':'Использовать параметризованные запросы'}]}

def test_pdf_unicode_and_manifest(tmp_path):
    p,m=write_pdf_report(DATA,tmp_path/'client.pdf',generated_at='2026-11-17')
    assert p.read_bytes().startswith(b'%PDF-1.')
    assert verify_pdf_manifest(p,m)
    assert json.loads(m.read_text())['findings']==1
    p.write_bytes(p.read_bytes()+b'x')
    assert not verify_pdf_manifest(p,m)

def test_pdf_both_profiles(tmp_path):
    for profile in ('executive','technical'):
        p,_=write_pdf_report(DATA,tmp_path/f'{profile}.pdf',profile=profile)
        assert p.stat().st_size>1000

def test_pdf_html_same_filtered_findings(tmp_path):
    filtered=filter_report_data(DATA,target_id=1,job_id=7,severities=['High'])
    html=render_html_report(filtered)
    assert 'Проверка SQL' in html
    p,m=write_pdf_report(filtered,tmp_path/'filtered.pdf')
    assert json.loads(m.read_text())['findings']==len(filtered['findings'])==1
    from pypdf import PdfReader
    text='\n'.join(page.extract_text() for page in PdfReader(str(p)).pages)
    assert 'Проверка SQL' in text
    assert 'Доказательство' in text
    assert 'Использовать параметризованные запросы' in text
    assert 'Not recorded' in text

def test_pdf_escapes_markup_and_rejects_profile(tmp_path):
    with pytest.raises(ValueError): write_pdf_report(DATA,tmp_path/'x.pdf',profile='unknown')
    from cybersec.pdf_reports import _safe
    assert '&lt;script&gt;' in _safe('<script>')

def test_pdf_rejects_missing_font(tmp_path):
    with pytest.raises(RuntimeError): write_pdf_report(DATA,tmp_path/'x.pdf',font_path=tmp_path/'missing.ttf')
