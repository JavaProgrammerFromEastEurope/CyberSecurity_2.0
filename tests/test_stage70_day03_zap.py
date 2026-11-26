"""Stage70 Day03 security and functional tests: mock only; loopback transport is real."""
from __future__ import annotations
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from pathlib import Path
from unittest.mock import patch
import pytest
from cybersec import day03_zap as d

class FakeAPI:
    def __init__(self, status='100', pending='0', browser=True, ajax='stopped'):
        self.calls=[]; self.status=status; self.pending=pending; self.browser=browser; self.ajax=ajax
    def call(self,c,cat,n,p=None):
        self.calls.append((c,cat,n,p or {}))
        look={
            ('core','view','version'):{'version':'MOCK'},
            ('spider','action','scan'):{'scan':'9'},
            ('spider','view','status'):{'status':self.status},
            ('pscan','view','recordsToScan'):{'recordsToScan':self.pending},
            ('core','view','alerts'):{'alerts':[{'url':d.TARGET+'about.html','alert':'SYNTHETIC'},
                                        {'url':'https://invalid.example/','alert':'OUTSIDE'}]},
            ('selenium','view','getBrowserIds'):{'browserIds':['firefox-headless'] if self.browser else []},
            ('ajaxSpider','view','optionBrowserId'):{'optionBrowserId':'firefox-headless' if self.browser else 'other'},
            ('ajaxSpider','action','scan'):{'Result':'OK'},
            ('ajaxSpider','view','status'):{'status':self.ajax},
        }
        return look.get((c,cat,n),{'Result':'OK'})
    def called(self,name):
        return any(n==name for _,_,n,_ in self.calls)

@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    monkeypatch.delenv('CYBERSEC_EXECUTION_MODE',raising=False)
    monkeypatch.delenv('CYBERSEC_RUNTIME_MODE',raising=False)

@pytest.mark.parametrize('target',['https://example.com/','http://127.0.0.1:8080/',
     'http://day03-target:8080/other','http://day03-target:8080/#x',
     'http://evil@day03-target:8080/','http://day03-target/'])
def test_pinned_lab(target):
    with pytest.raises(d.LabDenied):d._check_target(target)

@pytest.mark.parametrize('url',['http://0.0.0.0:18080','http://localhost:18080','https://127.0.0.1:18080',
  'http://127.0.0.1:8080','http://127.0.0.1:18080/admin'])
def test_api_fixed_loopback(url):
    with pytest.raises(d.LabDenied):d.ZapLabAPI(api_key='A'*32,base=url)

def test_key_required():
    with pytest.raises(d.LabDenied):d.ZapLabAPI(api_key='bad')

@pytest.mark.parametrize('key',[('ascan','action','scan'),('core','action','accessUrl'),('core','view','users')])
def test_action_allowlist(key):
    with pytest.raises(d.LabDenied):d.ZapLabAPI(api_key='A'*32).call(*key)

def test_query_key_refused():
    with pytest.raises(d.LabDenied):
        d.ZapLabAPI(api_key='A'*32).call('spider','action','scan',{'apikey':'dont-leak'})

def test_spider_passive_output_filtered_and_no_active():
    api=FakeAPI()
    result=d.run_lab(api,authorization=True,runtime=True)
    assert result['spider']==100 and len(result['alerts'])==1 and result['discarded_out_of_scope']==1
    assert result['active_scan'] is False and api.called('stop')
    assert not any(c=='ascan' for c,_,_,_ in api.calls)

@pytest.mark.parametrize('authorization,runtime',[(False,True),(True,False)])
def test_preflight_fail_closed_no_call(authorization,runtime):
    api=FakeAPI()
    with pytest.raises(d.LabDenied):d.run_lab(api,authorization=authorization,runtime=runtime)
    assert not api.calls

def test_prod_denied_no_calls(monkeypatch):
    monkeypatch.setenv('CYBERSEC_EXECUTION_MODE','production');api=FakeAPI()
    with pytest.raises(PermissionError):d.run_lab(api,authorization=True,runtime=True)
    assert not api.calls

def test_spider_status_malformed_still_stops():
    api=FakeAPI(status='NaN')
    with pytest.raises(d.LabDenied):d.run_lab(api,authorization=True,runtime=True)
    assert api.called('stop')

def test_spider_timeout_stops():
    api=FakeAPI(status='1'); t=iter([0,1,2,3,4,5,6])
    with pytest.raises(d.LabTimeout):
        d.run_lab(api,authorization=True,runtime=True,
                  limits=d.Limits(max_spider_seconds=1,poll_seconds=.01),
                  clock=lambda:next(t),sleep=lambda _:None)
    assert api.called('stop')

def test_passive_timeout_does_not_mark_pass():
    api=FakeAPI(pending='2');t=iter(range(15))
    with pytest.raises(d.LabTimeout):
        d.run_lab(api,authorization=True,runtime=True,
                  limits=d.Limits(max_passive_seconds=1,poll_seconds=.01),
                  clock=lambda:next(t),sleep=lambda _:None)

def test_ajax_without_isolation_never_starts():
    api=FakeAPI()
    with pytest.raises(d.LabDenied):
        d.run_lab(api,authorization=True,runtime=True,ajax=True,browser_isolated=False)
    assert not api.called('scan') or all(c != 'ajaxSpider' for c,_,_,_ in api.calls if _=='scan')

def test_ajax_without_browser_never_starts():
    api=FakeAPI(browser=False)
    with pytest.raises(d.LabDenied,match='HEADLESS_BROWSER'):
        d.run_lab(api,authorization=True,runtime=True,ajax=True,browser_isolated=True)
    assert not any(c=='ajaxSpider' and n=='scan' for c,_,n,_ in api.calls)

def test_ajax_fake_completion_stops():
    api=FakeAPI()
    result=d.run_lab(api,authorization=True,runtime=True,ajax=True,browser_isolated=True)
    assert result['ajax_spider']=='completed'
    assert any(c=='ajaxSpider' and n=='stop' for c,_,n,_ in api.calls)
    assert not any(c=='ascan' for c,_,_,_ in api.calls)

def test_ajax_unknown_state_stops():
    api=FakeAPI(ajax='unknown')
    with pytest.raises(d.LabDenied):
        d.run_lab(api,authorization=True,runtime=True,ajax=True,browser_isolated=True)
    assert any(c=='ajaxSpider' and n=='stop' for c,_,n,_ in api.calls)

def test_bounds_not_unlimited():
    for kw in ({'depth':0},{'children':0},{'ajax_states':0},{'poll_seconds':0},{'max_spider_seconds':0}):
        with pytest.raises(ValueError):d.Limits(**kw)

def test_docker_missing_does_not_fallback():
    with patch.object(d.subprocess,'run',side_effect=FileNotFoundError):
        with pytest.raises(FileNotFoundError):d.validate_docker_lab()

class APIHandler(BaseHTTPRequestHandler):
    seen=[]
    def do_GET(self):
        type(self).seen.append((self.command,self.path,self.headers.get('X-ZAP-API-Key')))
        body=b'{"version":"MOCK_HTTP"}'
        self.send_response(200);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def do_POST(self):
        type(self).seen.append((self.command,self.path,self.headers.get('X-ZAP-API-Key')))
        self.rfile.read(int(self.headers.get('Content-Length','0')))
        body=b'{"Result":"OK"}'
        self.send_response(200);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass

def test_real_loopback_api_key_header_no_proxy(monkeypatch):
    try:server=ThreadingHTTPServer(('127.0.0.1',18080),APIHandler)
    except OSError:pytest.skip('Port 18080 occupied; cannot independently bind local fixture')
    APIHandler.seen=[]
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        monkeypatch.setenv('HTTP_PROXY','http://invalid.invalid:9999')
        key='private-key-AAAAAAAAAAAAAAAAAAAAAAA'
        api=d.ZapLabAPI(api_key=key)
        assert api.call('core','view','version')['version']=='MOCK_HTTP'
        assert api.call('spider','action','setOptionMaxDepth',{'Integer':'2'})=={'Result':'OK'}
        assert [v[0] for v in APIHandler.seen]==['GET','POST']
        assert all(v[2]==key and key not in v[1] for v in APIHandler.seen)
    finally:server.shutdown();server.server_close();thread.join(timeout=2)

def test_compose_isolated():
    text=(Path(__file__).resolve().parents[1]/'deployment/day03/compose.lab.yml').read_text()
    for part in ('127.0.0.1:18080:8080','internal: true','cap_drop: [ALL]','api.disablekey=false'):
        assert part in text
