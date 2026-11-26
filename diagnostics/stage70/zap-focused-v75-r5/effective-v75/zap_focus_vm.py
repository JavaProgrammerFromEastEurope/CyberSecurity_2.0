#!/usr/bin/env python3
"""Stage 70 ZAP-only VM lab: Docker-internal API, bounded Spider/AJAX/Passive.

This is an independently reviewable lab candidate, NOT production admission.
No active scan, nuclei, arbitrary URL, network change, or Git source rewrite.
"""
from __future__ import annotations
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import secrets
import shutil
import subprocess
import sys
import time
from urllib.parse import urlencode
import zipfile
import fcntl

BASE = '9de9fe0c2fc4e31d695aa9f3bd4594a0a5ecf5dd'
REPO = Path.home() / 'CyberSecurity_2.0_Day03_R6'
MARKER = Path.home() / 'cybersec-day03-lab/stage70_snapshot_confirmed.json'
IMAGES = Path.home() / 'cybersec-day03-lab/images.env'
EVIDENCE = Path.home() / 'cybersec-zap-focused-evidence'
TARGET = 'http://day03-target:8080/'
IMAGE_RE = re.compile(r'[a-z0-9./_-]+@sha256:[a-f0-9]{64}\Z')
# Transient, explicitly reviewed single-field Compose override: no image, net,
# port, UID, caps, seccomp or host-volume changes.
LAB_SHM_BYTES=256*1024*1024
LAB_SHM_OVERRIDE='services:\n  zap:\n    shm_size: 256m\n'


# Runs only inside the pre-existing ZAP container. Token arrives on stdin, never
# in exec argv, saved files or generated evidence; no redirect or proxy allowed.
DOCKER_HTTP_CODE = r'''
import json, sys
from urllib.parse import urlencode
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
class RefuseRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args):
        raise RuntimeError('REDIRECT_REFUSED')
try:
    p=json.loads(sys.stdin.buffer.read(16384))
    base='http://127.0.0.1:8080'
    if p['kind']=='target':
        uri='http://day03-target:8080/'
        req=Request(uri,method='GET')
    else:
        uri=base+'/JSON/'+p['component']+'/'+p['category']+'/'+p['name']+'/'
        data=urlencode(p.get('params',{})).encode('ascii') if p['category']=='action' else None
        if p['category']=='view' and p.get('params'):
            uri+='?'+urlencode(p['params'])
        head={'X-ZAP-API-Key':p['key'],'Accept':'application/json'}
        if data is not None:head['Content-Type']='application/x-www-form-urlencoded'
        req=Request(uri,data=data,headers=head,method='POST' if data is not None else 'GET')
    with build_opener(ProxyHandler({}),RefuseRedirect()).open(req,timeout=6) as r:
        raw=r.read(262145)
        if len(raw)>262144:raise ValueError('OVERSIZED_BODY')
        if p['kind']=='target':
            output={'code':'OK','http':r.status}
        else:
            if r.status!=200 or 'application/json' not in r.headers.get('Content-Type','').lower():
                raise ValueError('NON_JSON_OR_HTTP_NOT_200')
            output=json.loads(raw)
            if not isinstance(output,dict):raise ValueError('MALFORMED_RESPONSE')
    print(json.dumps({'ok':True,'data':output},separators=(',',':')))
except HTTPError as e:
    try:
        detail=''
        try:
            obj=json.loads(e.read(4096))
            if isinstance(obj,dict) and isinstance(obj.get('code'),str):
                c=obj['code']
                if len(c)<=64 and c.replace('_','').isalnum():detail='_'+c
        except (ValueError,UnicodeError):pass
        print(json.dumps({'ok':False,'error':'HTTP_'+str(e.code)+detail}))
    finally:e.close()
except Exception as e:
    print(json.dumps({'ok':False,'error':type(e).__name__}))
'''

class Blocked(Exception): pass

def sha(p:Path)->str:
    h=hashlib.sha256()
    with p.open('rb') as f:
        for part in iter(lambda:f.read(1024*1024),b''):h.update(part)
    return h.hexdigest()

def call(args,*,timeout=25,env=None,input=None,cwd=None):
    return subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          input=input,timeout=timeout,env=env,cwd=cwd,check=False)

def gate(ok:bool,msg:str)->None:
    if not ok:raise Blocked(msg)

def images()->tuple[str,str]:
    gate(IMAGES.is_file() and not IMAGES.is_symlink() and IMAGES.stat().st_size<8192,'IMAGES_ENV_MISSING_OR_UNSAFE')
    values={}
    for line in IMAGES.read_text('utf-8').splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        m=re.fullmatch(r'(?:export\s+)?([A-Z_][A-Z_0-9]*)\s*=\s*(.*?)\s*',line)
        gate(m is not None,'IMAGES_ENV_PARSE_REFUSED')
        k,v=m.groups()
        if v[:1] in ("'",'"'):
            gate(v.endswith(v[0]),'IMAGES_ENV_BAD_QUOTES')
            v=v[1:-1]
        gate(k not in values,'IMAGES_ENV_DUPLICATE')
        values[k]=v
    zap=values.get('CYBERSEC_DAY03_ZAP_IMAGE') or values.get('ZAP_IMAGE','')
    target=values.get('CYBERSEC_DAY03_TARGET_IMAGE') or values.get('TARGET_IMAGE','')
    gate(bool(IMAGE_RE.fullmatch(zap)) and bool(IMAGE_RE.fullmatch(target)),'DIGEST_PIN_REQUIRED')
    return zap,target

def validate_with_pinned_image_environment(validator,zap:str,target:str)->dict:
    """Call unchanged upstream Docker validator with the verified digest refs.

    Compose gets these via a child-only environment, while the upstream
    validator reads os.environ in this parent process. Restore prior values
    on both success and failure; do not touch API keys or any other variables.
    """
    gate(bool(IMAGE_RE.fullmatch(zap)) and bool(IMAGE_RE.fullmatch(target)),
         'PINNED_DIGEST_REQUIRED_FOR_DOCKER_VALIDATOR')
    values={'CYBERSEC_DAY03_ZAP_IMAGE':zap,
            'CYBERSEC_DAY03_TARGET_IMAGE':target}
    before={name:os.environ.get(name) for name in values}
    try:
        os.environ.update(values)
        return validator()
    finally:
        for name,previous in before.items():
            if previous is None:
                os.environ.pop(name,None)
            else:
                os.environ[name]=previous

def snapshot()->str:
    gate(MARKER.is_file() and not MARKER.is_symlink() and MARKER.stat().st_size<=2048,'SNAPSHOT_MARKER_MISSING_OR_UNSAFE')
    x=json.loads(MARKER.read_text('utf-8'))
    gate(x.get('schema')=='stage70-vm-snapshot-operator-attestation-v1' and
         x.get('snapshot_confirmed') is True and x.get('vm_dedicated_to_authorized_lab') is True,
         'SNAPSHOT_OPERATOR_ASSERTION_INVALID')
    return sha(MARKER)

def source(repo:Path)->None:
    gate(repo.is_dir() and not repo.is_symlink(),'REPOSITORY_MISSING_OR_SYMLINK')
    for f in ('src/cybersec/day03_zap.py','deployment/day03/compose.lab.yml','tests/test_stage70_day03_zap.py'):
        gate((repo/f).is_file(),'MISSING_REPOSITORY_FILE_'+f)
    checks=[['git','cat-file','-e',BASE+'^{commit}'],
            ['git','merge-base','--is-ancestor',BASE,'HEAD'],
            ['git','diff','--quiet','HEAD'],
            ['git','diff','--cached','--quiet']]
    for cmd in checks:
        p=subprocess.run(cmd,cwd=repo,capture_output=True,timeout=25)
        gate(p.returncode==0,'GIT_BASE_OR_COMPOSE_INTEGRITY_GATE_FAILED')
    for file in ('src/cybersec/day03_zap.py','deployment/day03/compose.lab.yml'):
        p=subprocess.run(['git','show',BASE+':'+file],cwd=repo,capture_output=True,timeout=20)
        gate(p.returncode==0 and (repo/file).read_bytes()==p.stdout,'PINNED_SOURCE_CONTENT_MISMATCH_'+file)

def docker_image(image:str)->bool:
    p=call(['docker','image','inspect','--format','{{json .}}',image],timeout=25)
    if p.returncode:return False
    try:
        obj=json.loads(p.stdout)
        return obj.get('Os')=='linux' and obj.get('Architecture') in ('arm64','aarch64') and image in obj.get('RepoDigests',[])
    except (ValueError,TypeError):return False

def validate_shm_only_compose_overlay(repo:Path,overlay:Path,env:dict)->dict:
    """Compare Compose rendered configs; allow only ZAP /dev/shm change."""
    gate(overlay.is_file() and not overlay.is_symlink() and
         overlay.read_text('utf-8')==LAB_SHM_OVERRIDE and
         (overlay.stat().st_mode & 0o777)==0o600,'LAB_SHM_OVERRIDE_UNSAFE')
    base=['docker','compose','-f','deployment/day03/compose.lab.yml']
    def rendered(flags):
        out=call(base+flags+['config','--format','json'],timeout=25,env=env,cwd=repo)
        gate(out.returncode==0 and len(out.stdout)<200000,'COMPOSE_RENDERED_CONFIG_FAILED')
        try:return json.loads(out.stdout)
        except (ValueError,TypeError) as e:raise Blocked('COMPOSE_RENDERED_CONFIG_JSON_INVALID') from e
    before=rendered([])
    after=rendered(['-f',str(overlay)])
    gate(type(before) is dict and type(after) is dict and
         before.get('name')=='cybersec-day03' and
         type(before.get('services')) is dict and
         set(before['services'])=={'zap','day03-target'} and
         type(after.get('services')) is dict and
         set(after['services'])=={'zap','day03-target'},
         'COMPOSE_BASE_PROJECT_MISMATCH')
    gate('shm_size' not in before['services']['zap'],
         'COMPOSE_BASE_SHM_UNEXPECTED')
    size=after['services']['zap'].get('shm_size')
    # Compose-go types.UnitBytes.MarshalJSON returns a canonical DECIMAL STRING.
    # Accept only the exact 256 MiB value, either as JSON int or as canonical
    # base-10 ASCII JSON string. No units, whitespace, floats, booleans,
    # prefixes or decimal aliases. Runtime Docker Inspect remains mandatory.
    valid=(type(size) is int and size==LAB_SHM_BYTES) or \
          (type(size) is str and size==str(LAB_SHM_BYTES))
    gate(valid,'COMPOSE_OVERRIDE_SHM_SIZE_MISMATCH')
    copy_of_after=copy.deepcopy(after)
    del copy_of_after['services']['zap']['shm_size']
    gate(copy_of_after==before,'COMPOSE_OVERRIDE_HAS_UNAPPROVED_CHANGES')
    return {'only_change':'ZAP_SHM_SIZE','shm_bytes':LAB_SHM_BYTES,
            'pinned_compose_sha256':sha(repo/'deployment/day03/compose.lab.yml'),
            'override_sha256':sha(overlay)}

def verify_runtime_shm()->dict:
    """Check actual Docker HostConfig, not just YAML or an asserted setting."""
    out=call(['docker','inspect','--format','{{.HostConfig.ShmSize}}',
              'cybersec-day03-zap'],timeout=20)
    gate(out.returncode==0 and out.stdout.strip()==str(LAB_SHM_BYTES).encode(),
         'ZAP_SHM_RUNTIME_NOT_256M')
    return {'docker_shm_bytes':LAB_SHM_BYTES,'verification':'DOCKER_INSPECT_EXACT'}

class ContainerAPI:
    def __init__(self,api_key:str,allowed_actions:set[tuple[str,str,str]],allowed_views:set[tuple[str,str,str]]):
        self.key=api_key
        self.allowed_actions=allowed_actions|{('ajaxSpider','action','setOptionBrowserId'),
                                             ('context','action','newContext'),
                                             ('context','action','includeInContext'),
                                             ('context','action','setContextInScope')}
        self.allowed_views=(allowed_views-{('selenium','view','getBrowserIds')})|{
            ('selenium','view','optionFirefoxDriverPath'),
            ('selenium','view','optionFirefoxBinaryPath'),
            ('ajaxSpider','view','numberOfResults'),
            ('ajaxSpider','view','results')}
        self.records=[]
    def call(self,component:str,category:str,name:str,params:dict|None=None)->dict:
        gate((component,category,name) in (self.allowed_views if category=='view' else self.allowed_actions),
             'UNAPPROVED_API_OPERATION')
        p=params or {}
        gate(all(isinstance(k,str) and isinstance(v,(str,int,bool)) for k,v in p.items()) and 'apikey' not in p,
             'UNAPPROVED_API_PARAMETER')
        payload={'kind':'api','component':component,'category':category,'name':name,'params':p,'key':self.key}
        step=f'{component}.{category}.{name}'
        when=time.monotonic()
        try:
            output=docker_http(payload)
        except subprocess.TimeoutExpired:
            # No command, request, secret, or source code is copied into evidence.
            self.records.append({'operation':step,'result':'TIMEOUT',
                                 'error':'DOCKER_EXEC_TIMEOUT',
                                 'seconds':round(time.monotonic()-when,3)})
            raise Blocked('ZAP_API_BRIDGE_TIMEOUT_'+step) from None
        except Blocked:
            self.records.append({'operation':step,'result':'FAIL',
                                 'error':'DOCKER_EXEC_BRIDGE_FAILURE',
                                 'seconds':round(time.monotonic()-when,3)})
            raise
        self.records.append({'operation':step,'result':'PASS' if output.get('ok') else 'FAIL',
                             'error':output.get('error'),'seconds':round(time.monotonic()-when,3)})
        gate(bool(output.get('ok')),'ZAP_API_'+step+'_'+str(output.get('error','UNKNOWN')))
        result=output.get('data')
        gate(isinstance(result,dict) and ('code' not in result or str(result['code']).lower() in ('ok','0')),
             'ZAP_API_RESPONSE_ERROR_'+step)
        return result

def docker_http(payload:dict)->dict:
    p=call(['docker','exec','-i','--user','1000:1000','cybersec-day03-zap','python3','-c',DOCKER_HTTP_CODE],
           input=json.dumps(payload,separators=(',',':')).encode(),timeout=17)
    if p.returncode:raise Blocked('DOCKER_EXEC_API_BRIDGE_FAILED_EXIT_'+str(p.returncode))
    gate(len(p.stdout)<300000,'DOCKER_API_BRIDGE_OVERSIZED_OUTPUT')
    try:
        value=json.loads(p.stdout)
        gate(isinstance(value,dict) and isinstance(value.get('ok'),bool),'DOCKER_API_BRIDGE_MALFORMED')
        return value
    except (ValueError,TypeError) as e:raise Blocked('DOCKER_API_BRIDGE_INVALID_JSON') from e


# V60: bounded initial ZAP readiness, with retryable *transport* timeout.
# This does not change any later API operation's fail-closed behavior.
def await_zap_api_readiness(api, diagnostic:dict, *, clock=time.monotonic,
                            sleep=time.sleep, budget_seconds=180,
                            retry_seconds=3):
    gate(type(diagnostic) is dict and not diagnostic,
         'API_READINESS_DIAGNOSTIC_NOT_EMPTY')
    gate(type(budget_seconds) in (int,float) and 0<budget_seconds<=180 and
         type(retry_seconds) in (int,float) and 0<retry_seconds<=3,
         'API_READINESS_BOUNDS_INVALID')
    start=clock()
    deadline=start+budget_seconds
    diagnostic.update(attempts=0, api_error_count=0, bridge_timeout_count=0,
                      last_failure='NONE', elapsed_seconds=0,
                      result='NOT_READY')
    while clock()<deadline:
        diagnostic['attempts']+=1
        try:
            response=api.call('core','view','version')
            if isinstance(response,dict) and isinstance(response.get('version'),str) and response['version']:
                diagnostic['elapsed_seconds']=round(max(0,min(180,clock()-start)),3)
                diagnostic['result']='PASS'
                return response['version'][:64]
            diagnostic['api_error_count']+=1
            diagnostic['last_failure']='VERSION_INVALID'
        except subprocess.TimeoutExpired:
            # Never log exc.cmd (contains the Python bridge source) or payload.
            diagnostic['bridge_timeout_count']+=1
            diagnostic['last_failure']='DOCKER_EXEC_TIMEOUT'
        except Blocked as exc:
            diagnostic['api_error_count']+=1
            # Deliberately finite categories; never copy raw exception text.
            diagnostic['last_failure']=('API_URL_UNAVAILABLE' if
               str(exc).startswith('ZAP_API_core.view.version_URLError') else
               'API_REJECTED')
        remaining=deadline-clock()
        if remaining>0:sleep(min(retry_seconds,remaining))
    diagnostic['elapsed_seconds']=round(max(0,min(180,clock()-start)),3)
    diagnostic['result']='TIMEOUT'
    raise Blocked('ZAP_API_READINESS_TIMEOUT_'+diagnostic['last_failure'])

def docker_executable(binary:str)->bool:
    """Check executable inside the pinned running ZAP container without a shell or host tools."""
    gate(binary in ('firefox','geckodriver'),'UNEXPECTED_EXECUTABLE_PROBE')
    p=call(['docker','exec','--user','1000:1000','cybersec-day03-zap',
            '/bin/sh','-c','command -v '+binary+' >/dev/null 2>&1'],timeout=15)
    return p.returncode==0

# V39 read-only diagnostics are restricted to the existing digest-pinned ZAP
# container. They collect ONLY booleans and bounded integers, never paths,
# arbitrary logs, browser history, API keys, or response bodies.
DOCKER_DRIVER_PROBE_CODE = r'''
import json,os,shutil,stat
from pathlib import Path
fixed=('/usr/bin/geckodriver','/usr/local/bin/geckodriver','/opt/geckodriver','/zap/webdrivers/geckodriver')
def executable(p):
    return bool(p and os.path.isfile(p) and os.access(p,os.X_OK))
try:
    path=shutil.which('geckodriver')
    f=shutil.which('firefox')
    try:
        fs=os.statvfs('/dev/shm')
        shm=fs.f_frsize*fs.f_blocks
    except OSError:shm=None
    print(json.dumps({'firefox_in_path':executable(f),
      'geckodriver_in_path':executable(path),
      'geckodriver_fixed_paths_executable':sum(executable(x) for x in fixed),
      'tmp_writable':os.access('/tmp',os.W_OK),
      'dev_shm_capacity_bytes':shm},sort_keys=True))
except Exception:print('{}')
'''

PROXY_ROUTE_PROBE_CODE = r'''
import json
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args):return None
u='http://day03-target:8080/'
results={}
for route,px in (('direct',{}),('through_zap',{'http':'http://127.0.0.1:8080'})):
    outcome={'http_200':False,'error_category':'UNKNOWN'}
    try:
        opener=build_opener(ProxyHandler(px),NoRedirect())
        with opener.open(Request(u,method='GET'),timeout=7) as r:
            outcome={'http_200':r.status==200 and r.geturl()==u,
                     'error_category':'NONE' if r.status==200 and r.geturl()==u else 'UNEXPECTED_RESPONSE'}
    except HTTPError as e:
        code=e.code
        outcome['error_category']='HTTP_'+str(code) if code in (400,401,403,404,407,408,429,500,502,503,504) else 'HTTP_OTHER'
        e.close()
    except URLError:outcome['error_category']='NETWORK_ERROR'
    except TimeoutError:outcome['error_category']='TIMEOUT'
    except Exception:outcome['error_category']='OTHER_ERROR'
    results[route]=outcome
print(json.dumps(results,sort_keys=True,separators=(',',':')))
'''
PROXY_ROUTE_ERRORS={'NONE','UNEXPECTED_RESPONSE','UNKNOWN','HTTP_400','HTTP_401',
  'HTTP_403','HTTP_404','HTTP_407','HTTP_408','HTTP_429','HTTP_500','HTTP_502',
  'HTTP_503','HTTP_504','HTTP_OTHER','NETWORK_ERROR','TIMEOUT','OTHER_ERROR'}

def docker_proxy_route_probe()->dict:
    """Only two bounded GETs to the one pinned internal fixture; never save content."""
    p=call(['docker','exec','--user','1000:1000','-e','PYTHONDONTWRITEBYTECODE=1',
            'cybersec-day03-zap','python3','-c',PROXY_ROUTE_PROBE_CODE],timeout=23)
    gate(p.returncode==0 and len(p.stdout)<2048,'PROXY_ROUTE_PROBE_FAILED')
    try:result=json.loads(p.stdout)
    except (ValueError,TypeError) as e:raise Blocked('PROXY_ROUTE_PROBE_BAD_JSON') from e
    gate(type(result) is dict and set(result)=={'direct','through_zap'},'PROXY_ROUTE_PROBE_FIELDS')
    for name in ('direct','through_zap'):
        x=result[name]
        gate(type(x) is dict and set(x)=={'http_200','error_category'},'PROXY_ROUTE_PROBE_BAD_SHAPE')
        gate(type(x['http_200']) is bool and type(x['error_category']) is str and
             x['error_category'] in PROXY_ROUTE_ERRORS,'PROXY_ROUTE_PROBE_INVALID_RESULT')
        gate(not x['http_200'] or x['error_category']=='NONE','PROXY_ROUTE_PROBE_INCONSISTENT_PASS')
    return result

def docker_driver_probe()->dict:
    """Read-only browser runtime telemetry; no executable paths or secrets leave Docker."""
    p=call(['docker','exec','--user','1000:1000','-e','PYTHONDONTWRITEBYTECODE=1',
            'cybersec-day03-zap','python3','-c',DOCKER_DRIVER_PROBE_CODE],timeout=18)
    gate(p.returncode==0 and len(p.stdout)<2048,'WEBDRIVER_READONLY_PROBE_FAILED')
    try: body=json.loads(p.stdout)
    except (ValueError,TypeError) as e:raise Blocked('WEBDRIVER_READONLY_PROBE_JSON_INVALID') from e
    gate(isinstance(body,dict),'WEBDRIVER_READONLY_PROBE_NOT_OBJECT')
    keys={'firefox_in_path','geckodriver_in_path','geckodriver_fixed_paths_executable',
          'tmp_writable','dev_shm_capacity_bytes'}
    gate(set(body)==keys,'WEBDRIVER_READONLY_PROBE_FIELDS_MISMATCH')
    for k in ('firefox_in_path','geckodriver_in_path','tmp_writable'):
        gate(type(body[k]) is bool,'WEBDRIVER_READONLY_PROBE_BAD_BOOLEAN')
    c=body['geckodriver_fixed_paths_executable']
    gate(type(c) is int and 0<=c<=4,'WEBDRIVER_READONLY_PROBE_BAD_DRIVER_COUNT')
    c=body['dev_shm_capacity_bytes']
    gate(c is None or (type(c) is int and 0<c<=2**34),'WEBDRIVER_READONLY_PROBE_BAD_SHM')
    return body

def safe_selenium_view_fields(payload:dict)->dict:
    """Classify only response field presence and nonempty scalar, never disclose values."""
    gate(isinstance(payload,dict),'SELENIUM_VIEW_NOT_OBJECT')
    keys=[k for k in payload if type(k) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,47}',k)]
    return {'safe_field_names':sorted(keys)[:8],
            'has_configured_path':any(type(v) is str and bool(v.strip()) for v in payload.values())}

DRIVER_SESSION_PROBE_CODE = r'''
import json,sys,os,re,stat,struct,subprocess,socket,time,signal,tempfile,shutil
import threading
from urllib.request import Request,build_opener,ProxyHandler,HTTPRedirectHandler
from urllib.error import HTTPError,URLError

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args):return None

def http_error_signal(raw,*,phase):
    """Finite allowlisted classification; never emit the remote message."""
    try:
        obj=json.loads(raw)
        value=obj.get('value') if isinstance(obj,dict) else None
        message=value.get('message','') if isinstance(value,dict) else ''
    except (ValueError,TypeError,UnicodeError):message=''
    text=str(message).lower()[:5000]
    if any(x in text for x in ('name or service not known','unknown host','dns',
                                'could not resolve','ns_error_unknown_host')):
        category='DNS_FAILURE'
    elif any(x in text for x in ('proxy','tunnel','bad gateway','http 502')):
        category='PROXY_FAILURE'
    elif any(x in text for x in ('connection refused','connection reset','unreachable')):
        category='CONNECTION_FAILURE'
    elif any(x in text for x in ('page load','timeout','timed out')):
        category='TIMEOUT'
    elif any(x in text for x in ('sandbox','operation not permitted','permission denied')):
        category='SANDBOX_DENIED'
    elif any(x in text for x in ('unexpectedly closed','process unexpectedly','crash','exited')):
        category='BROWSER_PROCESS_CLOSED'
    else:category='UNKNOWN'
    return ('WEBDRIVER_SESSION_HTTP_' if phase=='SESSION' else 'FIXTURE_NAV_HTTP_')+category

# Only finite, preapproved metadata leaves the container. W3C messages,
# stack traces, paths, HTTP bodies and session tokens never enter evidence.
SESSION_HTTP_STATUS={'400','401','403','404','408','409','429','500','502','503','504','OTHER','NOT_SEEN'}
SESSION_W3C_ERRORS={'NOT_SEEN','SESSION_NOT_CREATED','UNKNOWN_ERROR','INVALID_ARGUMENT',
  'INVALID_SESSION_ID','SESSION_NOT_CREATED_OLD','UNSUPPORTED_OPERATION','OTHER'}
SESSION_MESSAGE_SIGNALS={'NOT_SEEN','PROFILE_LOCKED','PROFILE_PERMISSIONS',
  'PROFILE_STARTUP','BROWSER_PROCESS_CLOSED','FIREFOX_BINARY_MISSING',
  'MISSING_LIBRARY','SANDBOX_DENIED','DISPLAY_FAILURE','TIMEOUT',
  'PORT_CONFLICT','PROXY_FAILURE','CAPABILITY_REJECTED',
  'MARIONETTE_HANDSHAKE','RESOURCE_LIMIT','UNKNOWN'}

def classify_session_response(http_code, raw):
    code=str(http_code) if str(http_code) in SESSION_HTTP_STATUS else 'OTHER'
    kind='OTHER'
    hint='UNKNOWN'
    try:
        obj=json.loads(raw[:8192])
        value=obj.get('value') if isinstance(obj,dict) else None
        error=value.get('error') if isinstance(value,dict) else None
        message=value.get('message') if isinstance(value,dict) else None
        names={'session not created':'SESSION_NOT_CREATED',
            'unknown error':'UNKNOWN_ERROR','invalid argument':'INVALID_ARGUMENT',
            'invalid session id':'INVALID_SESSION_ID',
            'session not created exception':'SESSION_NOT_CREATED_OLD',
            'unsupported operation':'UNSUPPORTED_OPERATION'}
        kind=names.get(error,'OTHER') if type(error) is str else 'OTHER'
        m=message.lower()[:4096] if type(message) is str else ''
        if 'profile' in m and any(x in m for x in ('already in use','locked','being used')):
            hint='PROFILE_LOCKED'
        elif 'profile' in m and any(x in m for x in ('permission denied','not writable','access denied')):
            hint='PROFILE_PERMISSIONS'
        elif 'profile' in m and any(x in m for x in ('cannot create','failed to create','unable to create')):
            hint='PROFILE_STARTUP'
        elif any(x in m for x in ('process unexpectedly closed','process exited','exited with status','crashed','failed to start browser')):
            hint='BROWSER_PROCESS_CLOSED'
        elif any(x in m for x in ('binary is not a firefox','cannot find firefox binary','firefox binary not found')):
            hint='FIREFOX_BINARY_MISSING'
        elif any(x in m for x in ('error while loading shared libraries','shared object file','cannot open shared object')):
            hint='MISSING_LIBRARY'
        elif any(x in m for x in ('sandbox','operation not permitted','seccomp','namespace')):
            hint='SANDBOX_DENIED'
        elif any(x in m for x in ('display', 'x11', 'wayland')):
            hint='DISPLAY_FAILURE'
        elif any(x in m for x in ('timed out','timeout')):
            hint='TIMEOUT'
        elif any(x in m for x in ('address already in use','port is already allocated')):
            hint='PORT_CONFLICT'
        elif any(x in m for x in ('failed to decode response from marionette',
                                  'marionette handshake','unable to connect to marionette')):
            hint='MARIONETTE_HANDSHAKE'
        elif any(x in m for x in ('out of memory','cannot allocate memory',
                                  'no space left on device','resource temporarily unavailable')):
            hint='RESOURCE_LIMIT'
        elif any(x in m for x in ('proxy','tunnel','bad gateway')):
            hint='PROXY_FAILURE'
        elif any(x in m for x in ('capabilities','invalid argument','incompatible')):
            hint='CAPABILITY_REJECTED'
    except (ValueError,TypeError,UnicodeError,AttributeError):pass
    return {'session_http_status':code,'session_w3c_error':kind,
            'session_message_signal':hint}

# W3C navigation errors are not equivalent to transport errors. Record a
# bounded, closed vocabulary only; no error body, session identifier,
# hostnames, browser paths or free-form GeckoDriver messages are persisted.
NAV_HTTP_CODES={'400','401','403','404','408','409','429','500','502','503','504','OTHER'}
NAV_W3C_CODES={'UNKNOWN_ERROR','INVALID_SESSION_ID','NO_SUCH_WINDOW',
  'UNEXPECTED_ALERT_OPEN','INVALID_ARGUMENT','TIMEOUT','SCRIPT_TIMEOUT',
  'UNKNOWN_COMMAND','UNSUPPORTED_OPERATION','INSECURE_CERTIFICATE',
  'JAVASCRIPT_ERROR','NO_SUCH_FRAME','OTHER'}
NAV_SIGNALS={'UNKNOWN','DNS_FAILURE','PROXY_FAILURE','CONNECTION_FAILURE',
  'NO_SUCH_WINDOW','INVALID_SESSION','BROWSER_PROCESS_CLOSED','TIMEOUT',
  'SANDBOX_DENIED','MARIONETTE_HANDSHAKE','CERTIFICATE_ERROR',
  'RESOURCE_LIMIT','NETWORK_ERROR_PAGE'}
NAV_BODY_SHAPES={'VALUE_OBJECT','VALUE_OTHER','VALUE_MISSING',
  'BODY_NOT_OBJECT','INVALID_JSON'}

def classify_nav_http_error(http_code,raw):
    code=str(http_code) if str(http_code) in NAV_HTTP_CODES else 'OTHER'
    result={'navigation_http_status':code,'navigation_w3c_error':'OTHER',
            'navigation_message_signal':'UNKNOWN','navigation_response_shape':'INVALID_JSON'}
    try:
        obj=json.loads(raw[:8192])
        if not isinstance(obj,dict):
            result['navigation_response_shape']='BODY_NOT_OBJECT'
            return result
        if 'value' not in obj:
            result['navigation_response_shape']='VALUE_MISSING'
            return result
        value=obj['value']
        if not isinstance(value,dict):
            result['navigation_response_shape']='VALUE_OTHER'
            return result
        result['navigation_response_shape']='VALUE_OBJECT'
        code_map={'unknown error':'UNKNOWN_ERROR',
          'invalid session id':'INVALID_SESSION_ID',
          'no such window':'NO_SUCH_WINDOW',
          'unexpected alert open':'UNEXPECTED_ALERT_OPEN',
          'invalid argument':'INVALID_ARGUMENT','timeout':'TIMEOUT',
          'script timeout':'SCRIPT_TIMEOUT','unknown command':'UNKNOWN_COMMAND',
          'unsupported operation':'UNSUPPORTED_OPERATION',
          'insecure certificate':'INSECURE_CERTIFICATE',
          'javascript error':'JAVASCRIPT_ERROR','no such frame':'NO_SUCH_FRAME'}
        error=value.get('error')
        if isinstance(error,str):result['navigation_w3c_error']=code_map.get(error,'OTHER')
        message=value.get('message')
        m=message.lower()[:4096] if isinstance(message,str) else ''
        if any(x in m for x in ('unknown host','name or service not known','could not resolve','dns','ns_error_unknown_host')):
            signal='DNS_FAILURE'
        elif any(x in m for x in ('proxy','tunnel','bad gateway','http 502')):
            signal='PROXY_FAILURE'
        elif any(x in m for x in ('connection refused','connection reset','unreachable')):
            signal='CONNECTION_FAILURE'
        elif any(x in m for x in ('no such window','browsing context has been discarded','window is closed')):
            signal='NO_SUCH_WINDOW'
        elif any(x in m for x in ('invalid session id','session does not exist','session not found')):
            signal='INVALID_SESSION'
        elif any(x in m for x in ('unexpectedly closed','process unexpectedly','crash','exited')):
            signal='BROWSER_PROCESS_CLOSED'
        elif any(x in m for x in ('timeout','timed out','page load')):
            signal='TIMEOUT'
        elif any(x in m for x in ('sandbox','operation not permitted','seccomp','permission denied')):
            signal='SANDBOX_DENIED'
        elif any(x in m for x in ('marionette','handshake','failed to decode response')):
            signal='MARIONETTE_HANDSHAKE'
        elif any(x in m for x in ('certificate','ssl_error','sec_error')):
            signal='CERTIFICATE_ERROR'
        elif any(x in m for x in ('out of memory','no space left','resource temporarily unavailable')):
            signal='RESOURCE_LIMIT'
        elif any(x in m for x in ('about:neterror','ns_error_')):
            signal='NETWORK_ERROR_PAGE'
        else:signal='UNKNOWN'
        result['navigation_message_signal']=signal
    except (ValueError,TypeError,UnicodeError,AttributeError):pass
    return result

# W3C handles remain inside the ephemeral probe; never persist handles or
# session IDs. A new session is not evidence of a live browser window.
WINDOW_HTTP_W3C_CATEGORIES={'HTTP_404_NO_SUCH_WINDOW',
  'HTTP_404_INVALID_SESSION_ID','HTTP_500_UNKNOWN_ERROR',
  'HTTP_404_UNKNOWN_COMMAND'}
WINDOW_COUNT_CODES={'NOT_SEEN','ZERO','ONE','MULTIPLE','HTTP_ERROR',
  'TRANSPORT_ERROR','BAD_RESPONSE'} | WINDOW_HTTP_W3C_CATEGORIES

def classified_handles_http_error(status,raw):
    # Classification from the W3C error code only; never retain raw bodies,
    # window handles, session IDs, paths, messages or URL fragments.
    if type(status) is not int or not isinstance(raw,bytes):
        return 'HTTP_ERROR'
    w3c=classify_nav_http_error(status,raw)['navigation_w3c_error']
    value={(404,'NO_SUCH_WINDOW'):'HTTP_404_NO_SUCH_WINDOW',
           (404,'INVALID_SESSION_ID'):'HTTP_404_INVALID_SESSION_ID',
           (500,'UNKNOWN_ERROR'):'HTTP_500_UNKNOWN_ERROR',
           (404,'UNKNOWN_COMMAND'):'HTTP_404_UNKNOWN_COMMAND'}.get((status,w3c))
    return value if value in WINDOW_HTTP_W3C_CATEGORIES else 'HTTP_ERROR'
WINDOW_CURRENT_CODES={'NOT_SEEN','PASS','NO_SUCH_WINDOW','HTTP_ERROR',
  'TRANSPORT_ERROR','BAD_RESPONSE'}

def window_count_category(payload):
    value=payload.get('value') if isinstance(payload,dict) else None
    if not isinstance(value,list) or len(value)>32 or not all(
      isinstance(h,str) and 1<=len(h)<=256 for h in value):
        return 'BAD_RESPONSE'
    if not value:return 'ZERO'
    return 'ONE' if len(value)==1 else 'MULTIPLE'

def window_current_category(payload):
    value=payload.get('value') if isinstance(payload,dict) else None
    return 'PASS' if isinstance(value,str) and 1<=len(value)<=256 else 'BAD_RESPONSE'

def driver_window_handles(opener,endpoint,session,timeout=6):
    url=endpoint+'/session/'+session+'/window/handles'
    try:
        with opener.open(Request(url),timeout=timeout) as resp:
            payload=json.loads(resp.read(4096))
            return window_count_category(payload) if resp.status==200 else 'BAD_RESPONSE'
    except HTTPError as exc:
        try:
            return classified_handles_http_error(exc.code,exc.read(4096))
        finally:exc.close()
    except (URLError,TimeoutError,socket.timeout,OSError):return 'TRANSPORT_ERROR'
    except (ValueError,TypeError,UnicodeError):return 'BAD_RESPONSE'

def driver_current_window(opener,endpoint,session,timeout=6):
    url=endpoint+'/session/'+session+'/window'
    try:
        with opener.open(Request(url),timeout=timeout) as resp:
            payload=json.loads(resp.read(4096))
            return window_current_category(payload) if resp.status==200 else 'BAD_RESPONSE'
    except HTTPError as exc:
        try:
            metadata=classify_nav_http_error(exc.code,exc.read(4096))
            return ('NO_SUCH_WINDOW' if metadata['navigation_w3c_error']=='NO_SUCH_WINDOW'
                else 'HTTP_ERROR')
        finally:exc.close()
    except (URLError,TimeoutError,socket.timeout,OSError):return 'TRANSPORT_ERROR'
    except (ValueError,TypeError,UnicodeError):return 'BAD_RESPONSE'

# V51: bounded readiness check; W3C may return a session before a usable
# top-level browsing context is observable. No raw window handle leaves Docker.
# No navigation or AJAX API is attempted during this wait.
WINDOW_READY_MAX_CHECKS=10
WINDOW_READY_MAX_SECONDS=8.0
WINDOW_READY_POLL_INTERVAL=0.7

def wait_for_live_window(opener,endpoint,session,*,clock=time.monotonic,sleep=time.sleep):
    started=clock()
    count='NOT_SEEN';current='NOT_SEEN'
    for attempt in range(1,WINDOW_READY_MAX_CHECKS+1):
        count=driver_window_handles(opener,endpoint,session,timeout=1.5)
        if count in ('ONE','MULTIPLE'):
            current=driver_current_window(opener,endpoint,session,timeout=1.5)
            if current=='PASS':
                return {'count':count,'current':current,'attempts':attempt,'outcome':'READY'}
            if current!='NO_SUCH_WINDOW':
                return {'count':count,'current':current,'attempts':attempt,
                        'outcome':'CURRENT_WINDOW_ERROR'}
        elif count!='ZERO':
            return {'count':count,'current':current,'attempts':attempt,
                    'outcome':'WINDOW_HANDLES_ERROR'}
        if attempt==WINDOW_READY_MAX_CHECKS or clock()-started>=WINDOW_READY_MAX_SECONDS:
            return {'count':count,'current':current,'attempts':attempt,
                    'outcome':'TIMEOUT_NO_WINDOWS' if count=='ZERO' else 'TIMEOUT_NO_CURRENT'}
        remaining=WINDOW_READY_MAX_SECONDS-(clock()-started)
        if remaining>0:sleep(min(WINDOW_READY_POLL_INTERVAL,remaining))
    raise AssertionError('UNREACHABLE_BOUNDED_LOOP')

# Driver stderr is read in memory from an unlinked TemporaryFile only after
# forced process-group shutdown. No raw stderr, paths, profiles, IDs or browser
# messages cross the Docker boundary; only allowlisted fixed labels.
DRIVER_LOG_CODES={'MARIONETTE','FIREFOX_CRASH','SANDBOX_DENIED',
  'PROFILE_ERROR','DISPLAY_ERROR','MISSING_LIBRARY','RESOURCE_ERROR','GECKODRIVER_ERROR'}
def safe_driver_stderr_signals(raw):
    if not isinstance(raw,bytes):return []
    text=raw[:65536].decode('utf-8','replace').lower()
    patterns={
      'MARIONETTE':(r'marionette',r'failed to decode response'),
      'FIREFOX_CRASH':(r'crash',r'process unexpectedly closed',r'segmentation fault',r'\bsigsegv\b'),
      'SANDBOX_DENIED':(r'operation not permitted',r'seccomp',r'sandbox',r'permission denied'),
      'PROFILE_ERROR':(r'profile.*locked',r'profile.*permission',r'profile.*startup'),
      'DISPLAY_ERROR':(r'no display',r'x11',r'wayland',r'gtk.*error'),
      'MISSING_LIBRARY':(r'shared object file',r'cannot open shared librar'),
      'RESOURCE_ERROR':(r'out of memory',r'cannot allocate memory',r'no space left on device'),
      'GECKODRIVER_ERROR':(r'\berror\b',r'\bfailed\b')}
    return sorted(code for code, expressions in patterns.items()
       if any(re.search(pattern,text) is not None for pattern in expressions))

# V55: observe only process-category counts, never PID, process names,
# command lines, parent IDs, paths, host state, URLs, or raw /proc data.
# A live browser process is NOT a successful Marionette or window check.
FIREFOX_PROCESS_STATES={'NOT_SEEN','NONE','LIVE_ONE','LIVE_MULTIPLE',
                        'ZOMBIE_ONLY','UNAVAILABLE'}
def firefox_os_process_state(proc_root='/proc'):
    try:
        entries=os.listdir(proc_root)
        if len(entries)>4096:return 'UNAVAILABLE'
    except OSError:return 'UNAVAILABLE'
    live=zombie=0
    for entry in entries:
        if not entry.isascii() or not entry.isdecimal():continue
        path=proc_root+'/'+entry
        try:
            with open(path+'/comm','rb') as stream:
                name=stream.read(64).strip().lower()
            if name not in (b'firefox',b'firefox-esr',b'firefox-bin',b'firefox.real'):
                continue
            with open(path+'/status','rb') as stream:
                sample=stream.read(1024)
            m=re.search(rb'(?m)^State:\s*([A-Z])',sample)
            if not m:continue
            if m.group(1)==b'Z':zombie+=1
            else:live+=1
        except (OSError,ValueError):continue
    if live>=2:return 'LIVE_MULTIPLE'
    if live==1:return 'LIVE_ONE'
    if zombie:return 'ZOMBIE_ONLY'
    return 'NONE'

# V56 diagnostic: decode Linux /proc/<pid>/stat field 52 (wait status)
# only for exact Firefox-named zombie processes. Return finite enums only.
# This does NOT attribute a process to a particular WebDriver session.
FIREFOX_ZOMBIE_EXIT_CLASSES={'NOT_SEEN','NONE','EXIT_ZERO','EXIT_NONZERO',
   'SIGNAL_SIGSEGV','SIGNAL_SIGABRT','SIGNAL_SIGBUS','SIGNAL_SIGKILL',
   'SIGNAL_SIGTERM','SIGNAL_OTHER','UNKNOWN','UNAVAILABLE','MIXED'}
def firefox_zombie_exit_class(proc_root='/proc'):
    try:
        entries=os.listdir(proc_root)
        if len(entries)>4096:return 'UNAVAILABLE'
    except OSError:return 'UNAVAILABLE'
    classes=set();unreadable=False
    names={b'firefox',b'firefox-esr',b'firefox-bin',b'firefox.real'}
    for entry in entries:
        if not entry.isascii() or not entry.isdecimal():continue
        path=proc_root+'/'+entry
        try:
            with open(path+'/comm','rb') as fd:name=fd.read(64).strip().lower()
            if name not in names:continue
            with open(path+'/stat','rb') as fd:raw=fd.read(2048)
            right=raw.rfind(b') ')
            if right<0:unreadable=True;continue
            parts=raw[right+2:].split()
            if len(parts)<50:unreadable=True;continue
            if parts[0]!=b'Z':continue
            code=int(parts[49])
            if code<0 or code>65535:classes.add('UNKNOWN');continue
            if os.WIFSIGNALED(code):
                sig=os.WTERMSIG(code)
                signal_map={signal.SIGSEGV:'SIGNAL_SIGSEGV',signal.SIGABRT:'SIGNAL_SIGABRT',
                  signal.SIGBUS:'SIGNAL_SIGBUS',signal.SIGKILL:'SIGNAL_SIGKILL',
                  signal.SIGTERM:'SIGNAL_SIGTERM'}
                classes.add(signal_map.get(sig,'SIGNAL_OTHER'))
            elif os.WIFEXITED(code):
                classes.add('EXIT_ZERO' if os.WEXITSTATUS(code)==0 else 'EXIT_NONZERO')
            else:classes.add('UNKNOWN')
        except (OSError,ValueError,OverflowError):unreadable=True
    if len(classes)>1:return 'MIXED'
    if unreadable:return 'UNAVAILABLE'
    if classes:return next(iter(classes))
    return 'NONE'

# V57: associate a Firefox direct child with this exact GeckoDriver process.
# Numeric pid/starttime are used only transiently in-container, never serialized.
# If no unambiguous child is found, evidence states NO_DIRECT_CHILD.
FIREFOX_CHILD_AFTER={'NOT_SEEN','DIRECT_CHILD_LIVE','DIRECT_CHILD_ZOMBIE',
    'NO_DIRECT_CHILD','AMBIGUOUS','UNAVAILABLE'}
FIREFOX_CHILD_BEFORE={'NOT_SEEN','SAME_LIVE','SAME_ZOMBIE',
    'NO_DIRECT_CHILD','TRACKED_GONE','PID_REUSED','UNAVAILABLE'}
def read_firefox_identity(proc_root,pid):
    try:
        if not isinstance(pid,int) or pid<=0:return None
        path=proc_root+'/'+str(pid)
        with open(path+'/comm','rb') as fd:name=fd.read(64).strip().lower()
        if name not in {b'firefox',b'firefox-esr',b'firefox-bin',b'firefox.real'}:return None
        with open(path+'/stat','rb') as fd:raw=fd.read(2048)
        pos=raw.rfind(b') ')
        if pos<0:return None
        parts=raw[pos+2:].split()
        if len(parts)<50:return None
        state=parts[0]
        if state not in {b'R',b'S',b'D',b'I',b'T',b't',b'Z',b'X'}:return None
        return (int(parts[1]),int(parts[19]),state,int(parts[49]))
    except (OSError,ValueError,OverflowError,IndexError):return None

def firefox_direct_child_identity(geckodriver_pid,proc_root='/proc'):
    try:
        entries=os.listdir(proc_root)
        if len(entries)>4096:return 'UNAVAILABLE',None
    except OSError:return 'UNAVAILABLE',None
    matched=[]
    for entry in entries:
        if not entry.isascii() or not entry.isdecimal():continue
        pid=int(entry)
        identity=read_firefox_identity(proc_root,pid)
        if identity is not None and identity[0]==geckodriver_pid:
            matched.append((pid,identity[1],identity[2]))
            if len(matched)>1:return 'AMBIGUOUS',None
    if not matched:return 'NO_DIRECT_CHILD',None
    pid,start,state=matched[0]
    return ('DIRECT_CHILD_ZOMBIE' if state==b'Z' else 'DIRECT_CHILD_LIVE'),(pid,start)

def firefox_tracked_child_state(identity,proc_root='/proc'):
    if identity is None:return 'NO_DIRECT_CHILD','NONE'
    pid,start=identity
    sample=read_firefox_identity(proc_root,pid)
    if sample is None:return 'TRACKED_GONE','NONE'
    parent,observed_start,state,wait=sample
    if start!=observed_start:return 'PID_REUSED','UNAVAILABLE'
    if state!=b'Z':return 'SAME_LIVE','NONE'
    if not (0<=wait<=65535):return 'SAME_ZOMBIE','UNKNOWN'
    if os.WIFSIGNALED(wait):
        sig=os.WTERMSIG(wait)
        signal_map={signal.SIGSEGV:'SIGNAL_SIGSEGV',signal.SIGABRT:'SIGNAL_SIGABRT',
          signal.SIGBUS:'SIGNAL_SIGBUS',signal.SIGKILL:'SIGNAL_SIGKILL',
          signal.SIGTERM:'SIGNAL_SIGTERM'}
        return 'SAME_ZOMBIE',signal_map.get(sig,'SIGNAL_OTHER')
    if os.WIFEXITED(wait):return 'SAME_ZOMBIE',('EXIT_ZERO' if os.WEXITSTATUS(wait)==0 else 'EXIT_NONZERO')
    return 'SAME_ZOMBIE','UNKNOWN'

# V58: bounded, ephemeral direct-child lifecycle monitor while W3C commands
# are in flight. No PID, process path, argv, thread state, or /proc bytes leave
# this container. Polling is diagnostic only, not a browser admission gate.
FLIGHT_CLASSES={'NOT_RUN','NO_CHILD_OBSERVED','CHILD_LIVE_AT_END',
    'CHILD_ZOMBIE_SEEN','CHILD_GONE','PID_REUSED','AMBIGUOUS','UNAVAILABLE'}
class FirefoxChildFlightRecorder:
    def __init__(self,geckodriver_pid,proc_root='/proc',interval=0.08,max_samples=400):
        self.driver_pid=geckodriver_pid
        self.proc_root=proc_root
        self.interval=interval
        self.max_samples=max_samples
        self.samples=0
        self.seen=None
        self.flags=set()
        self.exit_classes=set()
        self._sample_lock=threading.Lock()
        self._stop=threading.Event()
        self._thread=None
    def sample(self):
        # Serialize periodic, initial, and final observations. Diagnostic
        # state is never exported raw and cannot influence pass admission.
        with self._sample_lock:
            if self.samples>=self.max_samples:return
            self.samples+=1
            try:
                kind,token=firefox_direct_child_identity(self.driver_pid,self.proc_root)
                if kind=='UNAVAILABLE':self.flags.add('UNAVAILABLE')
                elif kind=='AMBIGUOUS':
                    self.flags.update(('AMBIGUOUS','CONCURRENT'))
                elif token is not None:
                    if self.seen is None:self.seen=token
                    elif self.seen!=token:
                        self.flags.update(('AMBIGUOUS','IDENTITY_CHANGED'))
                    if kind=='DIRECT_CHILD_ZOMBIE':self.flags.add('ZOMBIE')
                if self.seen is not None:
                    tracked,cls=firefox_tracked_child_state(self.seen,self.proc_root)
                    if tracked=='TRACKED_GONE':self.flags.add('GONE')
                    elif tracked=='PID_REUSED':self.flags.add('REUSED')
                    elif tracked=='SAME_ZOMBIE':
                        self.flags.add('ZOMBIE')
                        # /proc wait status belongs to the exact tracked
                        # (pid,starttime) Firefox identity, not a global zombie.
                        valid={'EXIT_ZERO','EXIT_NONZERO','SIGNAL_SIGSEGV',
                               'SIGNAL_SIGABRT','SIGNAL_SIGBUS','SIGNAL_SIGKILL',
                               'SIGNAL_SIGTERM','SIGNAL_OTHER','UNKNOWN'}
                        self.exit_classes.add(cls if cls in valid else 'UNKNOWN')
                    elif tracked=='UNAVAILABLE':self.flags.add('UNAVAILABLE')
            except (OSError,ValueError,TypeError):self.flags.add('UNAVAILABLE')
    def _worker(self):
        while not self._stop.is_set() and self.samples<self.max_samples:
            self.sample()
            self._stop.wait(self.interval)
    def start(self):
        self.sample()
        self._thread=threading.Thread(target=self._worker,daemon=True)
        self._thread.start()
        return self
    def stop(self):
        self._stop.set()
        if self._thread is not None:self._thread.join(timeout=1)
        self.sample()
        return self.outcome()
    def details(self):
        # Sanitized, finite classification only; PID and sample history stay
        # inside this short-lived container process.
        if self.samples==0:return {'ambiguity':'NOT_RUN','exit':'NOT_RUN'}
        c='CONCURRENT' in self.flags
        r='IDENTITY_CHANGED' in self.flags
        ambiguity=('BOTH' if c and r else 'CONCURRENT' if c else
                   'IDENTITY_CHANGED' if r else 'NONE')
        if not self.exit_classes:exit_class='NONE'
        elif len(self.exit_classes)>1:exit_class='MIXED'
        else:exit_class=next(iter(self.exit_classes))
        return {'ambiguity':ambiguity,'exit':exit_class}
    def outcome(self):
        if self.samples==0:return 'NOT_RUN'
        if 'AMBIGUOUS' in self.flags:return 'AMBIGUOUS'
        if 'REUSED' in self.flags:return 'PID_REUSED'
        if 'ZOMBIE' in self.flags:return 'CHILD_ZOMBIE_SEEN'
        if 'GONE' in self.flags:return 'CHILD_GONE'
        if 'UNAVAILABLE' in self.flags:return 'UNAVAILABLE'
        if self.seen is not None:return 'CHILD_LIVE_AT_END'
        return 'NO_CHILD_OBSERVED'

result={'configured_path_absolute':False,'driver_is_regular':False,
        'driver_executable':False,'elf_linux_aarch64':False,
        'driver_version_ok':False,'webdriver_server_ready':False,
        'webdriver_session_created':False,'fixture_navigation_confirmed':False,
        'session_http_status':'NOT_SEEN','session_w3c_error':'NOT_SEEN',
        'session_message_signal':'NOT_SEEN','driver_alive_after_session_error':None,
        'navigation_http_status':'NOT_SEEN','navigation_w3c_error':'NOT_SEEN',
        'navigation_message_signal':'NOT_SEEN','navigation_response_shape':'NOT_SEEN',
        'driver_alive_after_navigation_error':None,
        'window_handles_before_navigation':'NOT_SEEN',
        'window_readiness_attempts':0,'window_readiness_outcome':'NOT_SEEN',
        'current_window_before_navigation':'NOT_SEEN',
        'window_handles_after_navigation_error':'NOT_SEEN',
        'private_profile_root_created':False,'private_profile_root_cleaned':False,
        'driver_stderr_signals':[],'driver_stderr_truncated':False,
        'firefox_os_process_observation':{'before_session':'NOT_SEEN',
          'after_session':'NOT_SEEN','before_cleanup':'NOT_SEEN',
          'geckodriver_alive_before_cleanup':None,
          'zombie_exit_after_session':'NOT_SEEN',
          'zombie_exit_before_cleanup':'NOT_SEEN'},
        'firefox_session_process_attribution':{'after_session':'NOT_SEEN',
            'before_cleanup':'NOT_SEEN','tracked_exit_class':'NOT_SEEN'},
        'firefox_child_inflight':{'session':'NOT_RUN','navigation':'NOT_RUN'},
        'firefox_child_inflight_detail':{'session':{'ambiguity':'NOT_RUN','exit':'NOT_RUN'},
            'navigation':{'ambiguity':'NOT_RUN','exit':'NOT_RUN'}},
        'failure_category':'NOT_STARTED'}
process=None;session=None;endpoint=None;profile_root=None;log_stream=None;tracked_firefox=None
try:
    data=json.loads(sys.stdin.buffer.read(2048))
    path=data.get('driver')
    if not isinstance(path,str) or len(path)>500 or not path.startswith('/') or '\x00' in path:
        result['failure_category']='DRIVER_PATH_UNSAFE'
    else:
        result['configured_path_absolute']=True
        try:
            st=os.stat(path)
            result['driver_is_regular']=stat.S_ISREG(st.st_mode)
            result['driver_executable']=result['driver_is_regular'] and os.access(path,os.X_OK)
        except OSError:pass
        if not result['driver_executable']:
            result['failure_category']='DRIVER_PATH_NOT_EXECUTABLE'
        else:
            with open(path,'rb') as stream: head=stream.read(20)
            result['elf_linux_aarch64']=(len(head)>=20 and head[:5]==b'\x7fELF\x02' and
               head[5]==1 and struct.unpack('<H',head[18:20])[0]==183)
            if not result['elf_linux_aarch64']:
                result['failure_category']='DRIVER_ARCH_NOT_ARM64'
            else:
                try:
                    ver=subprocess.run([path,'--version'],stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,timeout=5,check=False)
                    result['driver_version_ok']=(ver.returncode==0 and
                        bool(re.search(rb'geckodriver\s+0\.\d+\.\d+',ver.stdout[:512])))
                except (OSError,subprocess.TimeoutExpired):pass
                if not result['driver_version_ok']:
                    result['failure_category']='DRIVER_VERSION_FAILED'
                else:
                    # No listener on the VM host: this binds only loopback inside
                    # the existing internal Docker ZAP container.
                    with socket.socket() as sock:
                        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
                    endpoint='http://127.0.0.1:'+str(port)
                    # GeckoDriver and Firefox share one private, writable,
                    # disposable profile root in the container's /tmp tmpfs.
                    # Do not weaken Firefox sandbox, Docker caps, or network.
                    profile_root=tempfile.mkdtemp(prefix='stage70-gecko-profile-',dir='/tmp')
                    os.chmod(profile_root,0o700)
                    gate_is_root=(os.stat(profile_root).st_uid==os.geteuid() and
                                  (os.stat(profile_root).st_mode & 0o777)==0o700)
                    if not gate_is_root:
                        result['failure_category']='PROFILE_ROOT_UNSAFE'
                        raise RuntimeError('PRIVATE_PROFILE_ROOT_UNSAFE')
                    result['private_profile_root_created']=True
                    child_env=os.environ.copy()
                    child_env['TMPDIR']=profile_root
                    child_env['MOZ_HEADLESS']='1'
                    # Unlinked, mode-0600 private temporary output; never pack or print.
                    log_stream=tempfile.TemporaryFile(mode='w+b',dir=profile_root)
                    process=subprocess.Popen([path,'--host','127.0.0.1','--port',str(port),
                        '--profile-root',profile_root,'--log','error'],
                        env=child_env,stdout=subprocess.DEVNULL,stderr=log_stream,
                        start_new_session=True)
                    opener=build_opener(ProxyHandler({}),NoRedirect())
                    for i in range(45):
                        if process.poll() is not None:break
                        try:
                            with opener.open(Request(endpoint+'/status'),timeout=0.8) as resp:
                                state=json.loads(resp.read(4096))
                                if resp.status==200 and isinstance(state,dict):
                                    result['webdriver_server_ready']=True;break
                        except Exception:pass
                        time.sleep(0.2)
                    if not result['webdriver_server_ready']:
                        result['failure_category']='WEBDRIVER_SERVER_NOT_READY'
                    else:
                        # This W3C session is representative of ZAP's AJAX
                        # browser: Firefox reaches the exact internal fixture via
                        # the local ZAP proxy, NOT via host networking or the Mac.
                        # ZAP has already proven internal network/target admission.
                        result['firefox_os_process_observation']['before_session']=firefox_os_process_state()
                        payload={'capabilities':{'alwaysMatch':{'browserName':'firefox',
                          'moz:firefoxOptions':{'args':['-headless']},
                          'proxy':{'proxyType':'manual',
                            'httpProxy':'127.0.0.1:8080',
                            'sslProxy':'127.0.0.1:8080','noProxy':[]}}}}
                        req=Request(endpoint+'/session',data=json.dumps(payload).encode(),
                            headers={'Content-Type':'application/json'},method='POST')
                        session_flight=FirefoxChildFlightRecorder(process.pid).start()
                        try:
                            with opener.open(req,timeout=23) as resp:
                                answer=json.loads(resp.read(16384))
                            value=answer.get('value') if isinstance(answer,dict) else None
                            session=value.get('sessionId') if isinstance(value,dict) else None
                            if isinstance(session,str) and re.fullmatch('[A-Za-z0-9-]{1,100}',session):
                                result['webdriver_session_created']=True
                            else:session=None
                        except HTTPError as err:
                            try:
                                raw=err.read(8192)
                                result.update(classify_session_response(err.code,raw))
                                result['driver_alive_after_session_error']=(process.poll() is None)
                                # The failure remains fail-closed. This extra W3C
                                # metadata is for diagnosis, never admission.
                                result['failure_category']=http_error_signal(raw,phase='SESSION')
                            finally:err.close()
                        except Exception:result['failure_category']='WEBDRIVER_SESSION_TRANSPORT_ERROR'
                        finally:
                            result['firefox_child_inflight']['session']=session_flight.stop()
                            result['firefox_child_inflight_detail']['session']=session_flight.details()
                        result['firefox_os_process_observation']['after_session']=firefox_os_process_state()
                        result['firefox_os_process_observation']['zombie_exit_after_session']=firefox_zombie_exit_class()
                        attribution,tracked_firefox=firefox_direct_child_identity(process.pid)
                        result['firefox_session_process_attribution']['after_session']=attribution
                        if result['webdriver_session_created']:
                            readiness=wait_for_live_window(opener,endpoint,session)
                            result['window_handles_before_navigation']=readiness['count']
                            result['current_window_before_navigation']=readiness['current']
                            result['window_readiness_attempts']=readiness['attempts']
                            result['window_readiness_outcome']=readiness['outcome']
                            if result['window_readiness_outcome']!='READY':
                                # Fail closed: a session ID can exist after all browser windows are gone.
                                result['failure_category']='NO_LIVE_WINDOW_AFTER_SESSION'
                            else:
                                # The only navigation is the already authorized internal fixture.
                                # Classify failures; never persist response bodies, URLs or secrets.
                                target='http://day03-target:8080/'
                                nav_flight=FirefoxChildFlightRecorder(process.pid).start()
                                try:
                                    nav=Request(endpoint+'/session/'+session+'/url',
                                       data=json.dumps({'url':target}).encode(),
                                       headers={'Content-Type':'application/json'},method='POST')
                                    with opener.open(nav,timeout=25) as resp:
                                        v=json.loads(resp.read(8000))
                                        ok=(resp.status==200 and isinstance(v,dict) and v.get('value') is None)
                                    if not ok:
                                        result['failure_category']='FIXTURE_NAV_POST_RESPONSE_INVALID'
                                    else:
                                        current=Request(endpoint+'/session/'+session+'/url')
                                        with opener.open(current,timeout=7) as resp:
                                            obj=json.loads(resp.read(8000))
                                        url=obj.get('value') if isinstance(obj,dict) else None
                                        result['fixture_navigation_confirmed']=(url==target)
                                        if result['fixture_navigation_confirmed']:
                                            result['failure_category']='NONE'
                                        elif isinstance(url,str) and url.startswith('about:neterror'):
                                            result['failure_category']='FIXTURE_BROWSER_NETWORK_ERROR_PAGE'
                                        else:
                                            result['failure_category']='FIXTURE_NAV_CURRENT_URL_MISMATCH'
                                except HTTPError as err:
                                    try:
                                        raw=err.read(8192)
                                        result.update(classify_nav_http_error(err.code,raw))
                                        result['driver_alive_after_navigation_error']=(process.poll() is None)
                                        # Retain previous fail-closed category logic; W3C
                                        # metadata refines diagnostics, not admission.
                                        result['window_handles_after_navigation_error']=driver_window_handles(opener,endpoint,session)
                                        kind=result['navigation_w3c_error']
                                        if kind=='TIMEOUT':category='FIXTURE_NAV_WEBDRIVER_TIMEOUT'
                                        elif kind=='INVALID_ARGUMENT':category='FIXTURE_NAV_WEBDRIVER_INVALID_ARGUMENT'
                                        elif kind=='UNKNOWN_ERROR':category='FIXTURE_NAV_WEBDRIVER_UNKNOWN_ERROR'
                                        else:category=http_error_signal(raw,phase='NAV')
                                        result['failure_category']=category
                                    finally:err.close()
                                except (TimeoutError,socket.timeout):
                                    result['failure_category']='FIXTURE_NAV_TRANSPORT_TIMEOUT'
                                except URLError:
                                    result['failure_category']='FIXTURE_NAV_TRANSPORT_ERROR'
                                except (ValueError,TypeError,KeyError):
                                    result['failure_category']='FIXTURE_NAV_RESPONSE_INVALID'
                                except Exception:
                                    result['failure_category']='FIXTURE_NAV_UNEXPECTED_EXCEPTION'
                                finally:
                                    result['firefox_child_inflight']['navigation']=nav_flight.stop()
                                    result['firefox_child_inflight_detail']['navigation']=nav_flight.details()
                        elif result['failure_category']=='NOT_STARTED':
                            result['failure_category']='WEBDRIVER_SESSION_UNAVAILABLE'
except Exception:
    result['failure_category']='WEBDRIVER_PROBE_INTERNAL_ERROR'
finally:
    # Observe before DELETE/termination; no PID or command-line emitted.
    if process is not None:
        result['firefox_os_process_observation']['before_cleanup']=firefox_os_process_state()
        result['firefox_os_process_observation']['zombie_exit_before_cleanup']=firefox_zombie_exit_class()
        result['firefox_os_process_observation']['geckodriver_alive_before_cleanup']=(process.poll() is None)
        if result['firefox_session_process_attribution']['after_session']!='NOT_SEEN':
            status,cls=firefox_tracked_child_state(tracked_firefox)
            result['firefox_session_process_attribution']['before_cleanup']=status
            result['firefox_session_process_attribution']['tracked_exit_class']=cls
    if session and endpoint:
        try:
            opener=build_opener(ProxyHandler({}),NoRedirect())
            opener.open(Request(endpoint+'/session/'+session,method='DELETE'),timeout=3).close()
        except Exception:pass
    if process is not None:
        try:
            os.killpg(process.pid,signal.SIGTERM)
        except (ProcessLookupError,PermissionError):pass
        try:process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:os.killpg(process.pid,signal.SIGKILL)
            except (ProcessLookupError,PermissionError):pass
            try:process.wait(timeout=2)
            except subprocess.TimeoutExpired:pass
    if log_stream is not None:
        try:
            log_stream.flush();log_stream.seek(0)
            bounded_log=log_stream.read(65537)
            result['driver_stderr_truncated']=(len(bounded_log)>65536)
            result['driver_stderr_signals']=safe_driver_stderr_signals(bounded_log[:65536])
        except (OSError,ValueError):
            result['driver_stderr_signals']=[]
            result['driver_stderr_truncated']=True
        finally:
            log_stream.close()
    if profile_root is not None:
        try:
            shutil.rmtree(profile_root)
            result['private_profile_root_cleaned']=not os.path.exists(profile_root)
        except OSError:
            result['private_profile_root_cleaned']=False
        if not result['private_profile_root_cleaned']:
            result['failure_category']='PROFILE_ROOT_CLEANUP_FAILED'
            result['fixture_navigation_confirmed']=False
    print(json.dumps(result,sort_keys=True,separators=(',',':')))
'''


# V52: controlled no-proxy Firefox Headless baseline is diagnostics only.
# The primary strict-proxy probe and its admission gate remain untouched.
# Build from the finite W3C classifiers used by the primary probe.
BASELINE_PROBE_CODE=DRIVER_SESSION_PROBE_CODE.split(
    "result={'configured_path_absolute'",1)[0]+r'''

# This control never calls an external site, the fixture, or ZAP scan APIs.
# It uses only local GeckoDriver W3C session/window/url endpoints.
result={'mode':'ABOUT_BLANK_NO_PROXY',
        'server_ready':False,'session_created':False,'window_ready':False,
        'current_window_verified':False,'about_blank_verified':False,
        'session_http_status':'NOT_SEEN','session_w3c_error':'NOT_SEEN',
        'session_message_signal':'NOT_SEEN','driver_stderr_signals':[],
        'private_profile_cleaned':False,'failure_category':'NOT_STARTED'}
process=None;session=None;endpoint=None;root=None;log=None
try:
    obj=json.loads(sys.stdin.buffer.read(2048))
    path=obj.get('driver')
    if not (isinstance(path,str) and path.startswith('/') and len(path)<=500 and
            '\x00' not in path and os.path.isfile(path) and os.access(path,os.X_OK)):
        result['failure_category']='DRIVER_INVALID'
    else:
        # Same private profile-root, same Docker sandbox and same GeckoDriver,
        # but omit the explicit browser proxy capability for comparison.
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        endpoint='http://127.0.0.1:'+str(port)
        root=tempfile.mkdtemp(prefix='stage70-control-profile-',dir='/tmp')
        os.chmod(root,0o700)
        if os.stat(root).st_uid!=os.geteuid() or (os.stat(root).st_mode&0o777)!=0o700:
            result['failure_category']='PROFILE_UNSAFE'
            raise RuntimeError('PROFILE_UNSAFE')
        env=os.environ.copy();env['MOZ_HEADLESS']='1';env['TMPDIR']=root
        log=tempfile.TemporaryFile(mode='w+b',dir=root)
        process=subprocess.Popen([path,'--host','127.0.0.1','--port',str(port),
            '--profile-root',root,'--log','error'],env=env,
            stdout=subprocess.DEVNULL,stderr=log,start_new_session=True)
        opener=build_opener(ProxyHandler({}),NoRedirect())
        for _ in range(45):
            if process.poll() is not None:break
            try:
                with opener.open(Request(endpoint+'/status'),timeout=0.8) as resp:
                    state=json.loads(resp.read(4096))
                    if resp.status==200 and isinstance(state,dict):
                        result['server_ready']=True;break
            except Exception:pass
            time.sleep(0.2)
        if not result['server_ready']:
            result['failure_category']='SERVER_UNAVAILABLE'
        else:
            caps={'capabilities':{'alwaysMatch':{
                'browserName':'firefox','moz:firefoxOptions':{'args':['-headless']}}}}
            req=Request(endpoint+'/session',data=json.dumps(caps).encode(),
                headers={'Content-Type':'application/json'},method='POST')
            try:
                with opener.open(req,timeout=23) as resp:
                    body=json.loads(resp.read(16384))
                val=body.get('value') if isinstance(body,dict) else None
                sess=val.get('sessionId') if isinstance(val,dict) else None
                if isinstance(sess,str) and re.fullmatch('[A-Za-z0-9-]{1,100}',sess):
                    session=sess;result['session_created']=True
                else:result['failure_category']='SESSION_RESPONSE_INVALID'
            except HTTPError as err:
                try:
                    metadata=classify_session_response(err.code,err.read(8192))
                    result.update(metadata);result['failure_category']='SESSION_W3C_ERROR'
                finally:err.close()
            except Exception:result['failure_category']='SESSION_TRANSPORT_ERROR'
            if result['session_created']:
                try:
                    readiness=wait_for_live_window(opener,endpoint,session)
                    result['window_ready']=(readiness['outcome']=='READY' and
                        readiness['count'] in ('ONE','MULTIPLE') and readiness['current']=='PASS')
                    result['current_window_verified']=result['window_ready']
                except Exception:result['window_ready']=False
                if not result['window_ready']:
                    result['failure_category']='NO_LIVE_WINDOW'
                else:
                    try:
                        with opener.open(Request(endpoint+'/session/'+session+'/url'),timeout=6) as resp:
                            url_obj=json.loads(resp.read(4096))
                            page=url_obj.get('value') if isinstance(url_obj,dict) else None
                            result['about_blank_verified']=(resp.status==200 and page=='about:blank')
                        result['failure_category']=('BASELINE_ABOUT_BLANK_PASS_NOT_ADMISSION'
                            if result['about_blank_verified'] else 'ABOUT_BLANK_MISMATCH')
                    except Exception:result['failure_category']='ABOUT_BLANK_W3C_ERROR'
except Exception:
    if result['failure_category']=='NOT_STARTED':result['failure_category']='BASELINE_INTERNAL_ERROR'
finally:
    if session and endpoint:
        try:
            build_opener(ProxyHandler({}),NoRedirect()).open(
                Request(endpoint+'/session/'+session,method='DELETE'),timeout=3).close()
        except Exception:pass
    if process is not None:
        try:os.killpg(process.pid,signal.SIGTERM)
        except (ProcessLookupError,PermissionError):pass
        try:process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:os.killpg(process.pid,signal.SIGKILL)
            except (ProcessLookupError,PermissionError):pass
            try:process.wait(timeout=2)
            except subprocess.TimeoutExpired:pass
    if log is not None:
        try:
            log.flush();log.seek(0)
            result['driver_stderr_signals']=safe_driver_stderr_signals(log.read(65536))
        except (OSError,ValueError):result['driver_stderr_signals']=[]
        finally:log.close()
    if root is not None:
        try:
            shutil.rmtree(root)
            result['private_profile_cleaned']=not os.path.exists(root)
        except OSError:result['private_profile_cleaned']=False
        if not result['private_profile_cleaned']:
            result['failure_category']='PROFILE_CLEANUP_FAILED'
            result['about_blank_verified']=False
    print(json.dumps(result,sort_keys=True,separators=(',',':')))
'''


# V53 Firefox Headless CLI diagnostic. Exact about:blank; no URL, proxy or credentials.
HEADLESS_CLI_CONTROL_CODE=r'''

import os,sys,json,shutil,tempfile,stat,signal,subprocess
result={'mode':'FIREFOX_HEADLESS_CLI_ABOUT_BLANK','binary_executable':False,
        'private_root_created':False,'private_root_cleaned':False,
        'png_created':False,'exit_class':'NOT_RUN','classification':'NOT_RUN'}
root=None;child=None
try:
    binary='/usr/bin/firefox'
    try:
        st=os.stat(binary)
        result['binary_executable']=stat.S_ISREG(st.st_mode) and os.access(binary,os.X_OK)
    except OSError:pass
    if not result['binary_executable']:
        result['classification']='BINARY_NOT_EXECUTABLE'
    else:
        root=tempfile.mkdtemp(prefix='stage70-cli-headless-',dir='/tmp')
        os.chmod(root,0o700)
        st=os.stat(root)
        if st.st_uid!=os.geteuid() or st.st_mode & 0o777 != 0o700:
            result['classification']='PRIVATE_ROOT_UNSAFE'
        else:
            result['private_root_created']=True
            env=os.environ.copy()
            env.update({'MOZ_HEADLESS':'1','HOME':root,'TMPDIR':root})
            for var in ('http_proxy','HTTP_PROXY','https_proxy','HTTPS_PROXY',
                        'all_proxy','ALL_PROXY','no_proxy','NO_PROXY'):
                env.pop(var,None)
            output=os.path.join(root,'about_blank.png')
            try:
                child=subprocess.Popen([binary,'--headless','--screenshot',
                    output,'about:blank'],cwd=root,env=env,stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                    start_new_session=True)
                try:
                    rc=child.wait(timeout=30)
                    result['exit_class']='ZERO' if rc==0 else ('SIGNALED' if rc<0 else 'NONZERO')
                except subprocess.TimeoutExpired:
                    result['exit_class']='TIMEOUT'
                if result['exit_class']=='ZERO':
                    try:
                        with open(output,'rb') as fp:head=fp.read(8)
                        result['png_created']=(head==b'\x89PNG\r\n\x1a\n' and
                            os.stat(output).st_size>64)
                    except OSError:pass
                result['classification']=('CLI_SCREENSHOT_PASS_DIAGNOSTIC_ONLY'
                    if result['exit_class']=='ZERO' and result['png_created']
                    else 'CLI_SCREENSHOT_FAILED')
            except OSError:
                result['exit_class']='LAUNCH_ERROR'
                result['classification']='CLI_LAUNCH_FAILED'
except Exception:
    if result['classification']=='NOT_RUN':result['classification']='CLI_INTERNAL_ERROR'
finally:
    if child is not None:
        # Kill the *entire* transient process group even after the parent exits.
        try:os.killpg(child.pid,signal.SIGTERM)
        except (ProcessLookupError,PermissionError):pass
        try:child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:os.killpg(child.pid,signal.SIGKILL)
            except (ProcessLookupError,PermissionError):pass
            try:child.wait(timeout=2)
            except subprocess.TimeoutExpired:pass
    if root is not None:
        try:
            shutil.rmtree(root)
            result['private_root_cleaned']=not os.path.exists(root)
        except OSError:result['private_root_cleaned']=False
        if not result['private_root_cleaned']:
            result['classification']='CLI_CLEANUP_FAILED'
            result['png_created']=False
    print(json.dumps(result,separators=(',',':'),sort_keys=True))

'''

HEADLESS_CLI_FIELDS={'mode','binary_executable','private_root_created',
    'private_root_cleaned','png_created','exit_class','classification'}
HEADLESS_CLI_EXIT_CLASSES={'NOT_RUN','ZERO','NONZERO','SIGNALED','TIMEOUT','LAUNCH_ERROR'}
HEADLESS_CLI_CLASSIFICATIONS={'NOT_RUN','BINARY_NOT_EXECUTABLE',
    'PRIVATE_ROOT_UNSAFE','CLI_SCREENSHOT_PASS_DIAGNOSTIC_ONLY',
    'CLI_SCREENSHOT_FAILED','CLI_LAUNCH_FAILED','CLI_INTERNAL_ERROR',
    'CLI_CLEANUP_FAILED'}

def validate_headless_cli_control(report):
    gate(type(report) is dict and set(report)==HEADLESS_CLI_FIELDS,
         'CLI_CONTROL_SCHEMA_UNSAFE')
    gate(report['mode']=='FIREFOX_HEADLESS_CLI_ABOUT_BLANK',
         'CLI_CONTROL_MODE_UNSAFE')
    for field in ('binary_executable','private_root_created','private_root_cleaned',
                  'png_created'):
        gate(type(report[field]) is bool,'CLI_CONTROL_BOOL_UNSAFE')
    gate(type(report['exit_class']) is str and
         report['exit_class'] in HEADLESS_CLI_EXIT_CLASSES,
         'CLI_CONTROL_EXIT_CLASS_UNSAFE')
    gate(type(report['classification']) is str and
         report['classification'] in HEADLESS_CLI_CLASSIFICATIONS,
         'CLI_CONTROL_CLASSIFICATION_UNSAFE')
    gate(not report['private_root_cleaned'] or report['private_root_created'],
         'CLI_CONTROL_CLEANUP_WITHOUT_ROOT')
    gate(not report['png_created'] or
         (report['binary_executable'] and report['private_root_created'] and
          report['private_root_cleaned'] and report['exit_class']=='ZERO' and
          report['classification']=='CLI_SCREENSHOT_PASS_DIAGNOSTIC_ONLY'),
         'CLI_CONTROL_FAKE_SCREENSHOT_PASS')
    if report['classification']=='CLI_SCREENSHOT_PASS_DIAGNOSTIC_ONLY':
        gate(all(report[k] for k in ('binary_executable','private_root_created',
             'private_root_cleaned','png_created')) and report['exit_class']=='ZERO',
             'CLI_CONTROL_INCONSISTENT_SUCCESS')
    if report['classification']=='CLI_CLEANUP_FAILED':
        gate(report['private_root_created'] and not report['private_root_cleaned']
             and not report['png_created'],'CLI_CONTROL_FALSE_CLEANUP_FAILURE')
    return report

def docker_headless_cli_control():
    proc=call(['docker','exec','--user','1000:1000',
         '--env','PYTHONDONTWRITEBYTECODE=1',
         'cybersec-day03-zap','python3','-c',HEADLESS_CLI_CONTROL_CODE],
         timeout=60)
    gate(proc.returncode==0 and 0<len(proc.stdout)<=1600,
         'CLI_CONTROL_EXEC_FAILED')
    try:parsed=json.loads(proc.stdout)
    except (ValueError,TypeError) as exc:
        raise Blocked('CLI_CONTROL_JSON_UNSAFE') from exc
    return validate_headless_cli_control(parsed)

BASELINE_KEYS={'mode','server_ready','session_created','window_ready',
    'current_window_verified','about_blank_verified','session_http_status',
    'session_w3c_error','session_message_signal','driver_stderr_signals',
    'private_profile_cleaned','failure_category'}
MARIONETTE_NATIVE_CONTROL_CODE = r'''
import json,os,re,shutil,socket,stat,subprocess,tempfile,time,signal
r={'mode':'FIREFOX_NATIVE_MARIONETTE_ABOUT_BLANK',
   'binary_executable':False,'private_root_created':False,'private_root_cleaned':False,
   'active_port_file_observed':False,'loopback_connected':False,
   'handshake_verified':False,'launch_state':'NOT_RUN','classification':'NOT_RUN'}
process=None;root=None
try:
    binary='/usr/bin/firefox'
    if not (os.path.isfile(binary) and os.access(binary,os.X_OK)):
        r['classification']='FIREFOX_NOT_EXECUTABLE'
    else:
        r['binary_executable']=True
        root=tempfile.mkdtemp(prefix='stage70-native-marionette-',dir='/tmp')
        os.chmod(root,0o700)
        if os.stat(root).st_uid!=os.geteuid() or (os.stat(root).st_mode&0o777)!=0o700:
            r['classification']='PRIVATE_ROOT_UNSAFE'
        else:
            profile=os.path.join(root,'profile')
            home=os.path.join(root,'home')
            os.mkdir(profile,0o700);os.mkdir(home,0o700)
            r['private_root_created']=True
            env=os.environ.copy()
            env['HOME']=home;env['TMPDIR']=root;env['MOZ_HEADLESS']='1'
            # About:blank only. No proxy, external URL, altered sandbox flags,
            # Linux capabilities or image layers. Output is fully suppressed.
            process=subprocess.Popen([binary,'--headless','--no-remote','--marionette',
                '--profile',profile,'about:blank'],env=env,stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,start_new_session=True)
            r['launch_state']='LIVE'
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                exit_code=process.poll()
                if exit_code is not None:
                    r['launch_state']=('EXIT_ZERO' if exit_code==0 else
                                       'SIGNALLED' if exit_code<0 else 'EXIT_NONZERO')
                    r['classification']='FIREFOX_EARLY_EXIT'
                    break
                active=os.path.join(profile,'MarionetteActivePort')
                try:
                    with open(active,'rb') as f:content=f.read(32)
                    m=re.fullmatch(rb'([0-9]{1,5})\s*',content)
                    if not m:
                        time.sleep(0.25);continue
                    port=int(m.group(1))
                    if not 1<=port<=65535:
                        time.sleep(0.25);continue
                    r['active_port_file_observed']=True
                except OSError:
                    time.sleep(0.25)
                    continue
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=0.5) as sock:
                        r['loopback_connected']=True
                        sock.settimeout(0.8)
                        # Bound the frame, not the size of a single recv().
                        # A partial TCP greeting is not a malformed protocol.
                        frame=b'';frame_deadline=time.monotonic()+2
                        while b':' not in frame and len(frame)<6 and time.monotonic()<frame_deadline:
                            chunk=sock.recv(6-len(frame))
                            if not chunk:break
                            frame+=chunk
                        prefix,sep,rest=frame.partition(b':')
                        if not (sep and re.fullmatch(rb'[0-9]{1,3}',prefix)):
                            raise ValueError('FRAME_HEADER_INVALID')
                        length=int(prefix)
                        if not 2<=length<=450:raise ValueError('FRAME_LENGTH_INVALID')
                        while len(rest)<length and time.monotonic()<frame_deadline:
                            chunk=sock.recv(length-len(rest))
                            if not chunk:break
                            rest+=chunk
                        if len(rest)!=length:raise ValueError('FRAME_INCOMPLETE')
                    # The content is never logged or transferred to macOS.
                    obj=json.loads(rest)
                    if isinstance(obj,dict) and obj.get('applicationType')=='gecko' and \
                      type(obj.get('marionetteProtocol')) is int and obj['marionetteProtocol']>=3:
                        r['handshake_verified']=True
                        r['classification']='DIRECT_HANDSHAKE_PASS_DIAGNOSTIC_ONLY'
                        break
                    r['classification']='HANDSHAKE_UNVERIFIED'
                except (OSError,ValueError,TypeError):
                    r['classification']='TCP_OR_HANDSHAKE_UNAVAILABLE'
                time.sleep(0.25)
            else:
                if r['classification']=='NOT_RUN':
                    r['classification']=('TCP_OR_HANDSHAKE_UNAVAILABLE'
                        if r['active_port_file_observed'] else 'ACTIVE_PORT_UNAVAILABLE')
except Exception:
    r['classification']='CONTROL_INTERNAL_ERROR'
finally:
    if process is not None:
        if process.poll() is None:
            try:os.killpg(process.pid,signal.SIGTERM)
            except (OSError,ProcessLookupError):pass
        try:process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:os.killpg(process.pid,signal.SIGKILL)
            except (OSError,ProcessLookupError):pass
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:pass
    if root is not None:
        try:shutil.rmtree(root)
        except OSError:pass
        r['private_root_cleaned']=not os.path.exists(root)
        if not r['private_root_cleaned']:
            r['classification']='PRIVATE_ROOT_CLEANUP_FAILED'
            r['handshake_verified']=False
    print(json.dumps(r,sort_keys=True,separators=(',',':')))
'''
MARIONETTE_NATIVE_KEYS={'mode','binary_executable','private_root_created',
 'private_root_cleaned','active_port_file_observed','loopback_connected',
 'handshake_verified','launch_state','classification'}
MARIONETTE_NATIVE_STATES={'NOT_RUN','LIVE','EXIT_ZERO','EXIT_NONZERO','SIGNALLED'}
MARIONETTE_NATIVE_RESULTS={'NOT_RUN','FIREFOX_NOT_EXECUTABLE','PRIVATE_ROOT_UNSAFE',
 'FIREFOX_EARLY_EXIT','ACTIVE_PORT_UNAVAILABLE',
 'TCP_OR_HANDSHAKE_UNAVAILABLE','HANDSHAKE_UNVERIFIED',
 'DIRECT_HANDSHAKE_PASS_DIAGNOSTIC_ONLY','CONTROL_INTERNAL_ERROR',
 'PRIVATE_ROOT_CLEANUP_FAILED'}
def validate_native_marionette_control(r):
    gate(type(r) is dict and set(r)==MARIONETTE_NATIVE_KEYS,
         'MARIONETTE_NATIVE_SCHEMA_INVALID')
    gate(r['mode']=='FIREFOX_NATIVE_MARIONETTE_ABOUT_BLANK',
         'MARIONETTE_NATIVE_MODE_INVALID')
    for key in ('binary_executable','private_root_created','private_root_cleaned',
                'active_port_file_observed','loopback_connected','handshake_verified'):
        gate(type(r[key]) is bool,'MARIONETTE_NATIVE_BOOLEAN_INVALID_'+key)
    gate(type(r['launch_state']) is str and r['launch_state'] in MARIONETTE_NATIVE_STATES,
         'MARIONETTE_NATIVE_STATE_INVALID')
    gate(type(r['classification']) is str and r['classification'] in MARIONETTE_NATIVE_RESULTS,
         'MARIONETTE_NATIVE_CLASS_INVALID')
    gate(not r['private_root_cleaned'] or r['binary_executable'],
         'MARIONETTE_NATIVE_CLEANED_WITHOUT_EXECUTABLE')
    gate(not r['private_root_created'] or r['binary_executable'],
         'MARIONETTE_NATIVE_ROOT_WITHOUT_EXECUTABLE')
    gate(not r['loopback_connected'] or r['active_port_file_observed'],
         'MARIONETTE_NATIVE_TCP_WITHOUT_PORT')
    gate(not r['handshake_verified'] or r['loopback_connected'],
         'MARIONETTE_NATIVE_HANDSHAKE_WITHOUT_TCP')
    gate(not r['handshake_verified'] or
         (r['classification']=='DIRECT_HANDSHAKE_PASS_DIAGNOSTIC_ONLY' and
          r['binary_executable'] and r['private_root_created'] and
          r['private_root_cleaned'] and r['launch_state']=='LIVE'),
         'MARIONETTE_NATIVE_FALSE_SUCCESS')
    gate(r['classification']!='DIRECT_HANDSHAKE_PASS_DIAGNOSTIC_ONLY' or
         r['handshake_verified'], 'MARIONETTE_NATIVE_SUCCESS_NOT_PROVEN')
    gate(r['classification']!='PRIVATE_ROOT_CLEANUP_FAILED' or
         (r['private_root_created'] and not r['private_root_cleaned'] and
          not r['handshake_verified']), 'MARIONETTE_NATIVE_CLEANUP_CONTRADICTION')
    return r

def docker_native_marionette_control():
    p=call(['docker','exec','-i','--user','1000:1000',
       '--env','PYTHONDONTWRITEBYTECODE=1','cybersec-day03-zap',
       'python3','-c',MARIONETTE_NATIVE_CONTROL_CODE],
       input=b'',timeout=45)
    gate(p.returncode==0 and len(p.stdout)<=1600,
         'MARIONETTE_NATIVE_EXEC_FAILED')
    try:result=json.loads(p.stdout)
    except (ValueError,TypeError) as exc:
        raise Blocked('MARIONETTE_NATIVE_BAD_JSON') from exc
    return validate_native_marionette_control(result)

BASELINE_FAILURE_CATEGORIES={'NOT_STARTED','DRIVER_INVALID','PROFILE_UNSAFE',
    'SERVER_UNAVAILABLE','SESSION_RESPONSE_INVALID','SESSION_W3C_ERROR',
    'SESSION_TRANSPORT_ERROR','NO_LIVE_WINDOW',
    'BASELINE_ABOUT_BLANK_PASS_NOT_ADMISSION','ABOUT_BLANK_MISMATCH',
    'ABOUT_BLANK_W3C_ERROR','BASELINE_INTERNAL_ERROR','PROFILE_CLEANUP_FAILED'}

def validate_no_proxy_baseline(evidence):
    gate(type(evidence) is dict and set(evidence)==BASELINE_KEYS,
         'BASELINE_SCHEMA_INVALID')
    gate(evidence['mode']=='ABOUT_BLANK_NO_PROXY','BASELINE_MODE_INVALID')
    for name in ('server_ready','session_created','window_ready',
                 'current_window_verified','about_blank_verified','private_profile_cleaned'):
        gate(type(evidence[name]) is bool,'BASELINE_BOOLEAN_INVALID_'+name)
    gate(type(evidence['failure_category']) is str and
         evidence['failure_category'] in BASELINE_FAILURE_CATEGORIES,
         'BASELINE_FAILURE_CATEGORY_INVALID')
    gate(type(evidence['session_http_status']) is str and
         evidence['session_http_status'] in {'NOT_SEEN','400','401','403','404',
           '408','409','429','500','502','503','504','OTHER'},
         'BASELINE_HTTP_CODE_INVALID')
    gate(type(evidence['session_w3c_error']) is str and
         evidence['session_w3c_error'] in {'NOT_SEEN','SESSION_NOT_CREATED',
           'UNKNOWN_ERROR','INVALID_ARGUMENT','INVALID_SESSION_ID',
           'SESSION_NOT_CREATED_OLD','UNSUPPORTED_OPERATION','OTHER'},
         'BASELINE_W3C_CODE_INVALID')
    gate(type(evidence['session_message_signal']) is str and
         evidence['session_message_signal'] in {'NOT_SEEN','PROFILE_LOCKED',
           'PROFILE_PERMISSIONS','PROFILE_STARTUP','BROWSER_PROCESS_CLOSED',
           'FIREFOX_BINARY_MISSING','MISSING_LIBRARY','SANDBOX_DENIED',
           'DISPLAY_FAILURE','TIMEOUT','PORT_CONFLICT','PROXY_FAILURE',
           'CAPABILITY_REJECTED','MARIONETTE_HANDSHAKE','RESOURCE_LIMIT','UNKNOWN'},
         'BASELINE_MESSAGE_SIGNAL_INVALID')
    signals=evidence['driver_stderr_signals']
    gate(type(signals) is list and signals==sorted(set(signals)) and
         len(signals)<=8 and all(type(v) is str and v in
            {'MARIONETTE','FIREFOX_CRASH','SANDBOX_DENIED','PROFILE_ERROR',
             'DISPLAY_ERROR','MISSING_LIBRARY','RESOURCE_ERROR','GECKODRIVER_ERROR'}
             for v in signals),'BASELINE_STDERR_SIGNALS_INVALID')
    if evidence['session_http_status']!='NOT_SEEN':
        gate(not evidence['session_created'] and
             evidence['session_w3c_error']!='NOT_SEEN' and
             evidence['session_message_signal']!='NOT_SEEN',
             'BASELINE_SESSION_HTTP_INCONSISTENT')
    else:
        gate(evidence['session_w3c_error']=='NOT_SEEN' and
             evidence['session_message_signal']=='NOT_SEEN',
             'BASELINE_STRAY_W3C_METADATA')
    gate(not evidence['window_ready'] or evidence['session_created'],
         'BASELINE_WINDOW_WITHOUT_SESSION')
    gate(evidence['current_window_verified']==evidence['window_ready'],
         'BASELINE_CURRENT_WINDOW_INCONSISTENT')
    gate(not evidence['about_blank_verified'] or
         (evidence['session_created'] and evidence['window_ready'] and
          evidence['current_window_verified'] and evidence['private_profile_cleaned'] and
          evidence['failure_category']=='BASELINE_ABOUT_BLANK_PASS_NOT_ADMISSION'),
         'BASELINE_FALSE_PASS')
    if evidence['failure_category']=='BASELINE_ABOUT_BLANK_PASS_NOT_ADMISSION':
        gate(evidence['about_blank_verified'],'BASELINE_SUCCESS_NOT_CONFIRMED')
    if evidence['session_created']:
        gate(evidence['server_ready'],'BASELINE_SESSION_WITHOUT_SERVER')
    return evidence

def docker_no_proxy_headless_baseline(driver_path):
    gate(type(driver_path) is str and 0<len(driver_path)<=500,
         'BASELINE_DRIVER_PATH_INVALID')
    payload=json.dumps({'driver':driver_path},separators=(',',':')).encode()
    p=call(['docker','exec','-i','--user','1000:1000',
        '--env','PYTHONDONTWRITEBYTECODE=1',
        'cybersec-day03-zap','python3','-c',BASELINE_PROBE_CODE],
        input=payload,timeout=110)
    gate(p.returncode==0 and len(p.stdout)<1600,'BASELINE_EXEC_FAILED')
    try:result=json.loads(p.stdout)
    except (ValueError,TypeError) as exc:
        raise Blocked('BASELINE_INVALID_JSON') from exc
    return validate_no_proxy_baseline(result)

DRIVER_SESSION_KEYS={'configured_path_absolute','driver_is_regular','driver_executable',
    'elf_linux_aarch64','driver_version_ok','webdriver_server_ready',
    'webdriver_session_created','fixture_navigation_confirmed','failure_category',
    'session_http_status','session_w3c_error','session_message_signal',
    'driver_alive_after_session_error','private_profile_root_created',
    'private_profile_root_cleaned','navigation_http_status','navigation_w3c_error',
    'navigation_message_signal','navigation_response_shape',
    'driver_alive_after_navigation_error',
    'window_handles_before_navigation','current_window_before_navigation',
    'window_handles_after_navigation_error','driver_stderr_signals','driver_stderr_truncated',
    'window_readiness_attempts','window_readiness_outcome',
    'firefox_os_process_observation','firefox_session_process_attribution',
    'firefox_child_inflight','firefox_child_inflight_detail'}
DRIVER_FAILURE_CATEGORIES={'NOT_STARTED','DRIVER_PATH_UNSAFE','DRIVER_PATH_NOT_EXECUTABLE',
    'DRIVER_ARCH_NOT_ARM64','DRIVER_VERSION_FAILED','WEBDRIVER_SERVER_NOT_READY',
    'FIREFOX_BINARY_INCOMPATIBLE','FIREFOX_PROCESS_CLOSED','FIREFOX_SANDBOX_DENIED',
    'WEBDRIVER_SESSION_HTTP_ERROR','WEBDRIVER_SESSION_TRANSPORT_ERROR',
    'WEBDRIVER_SESSION_UNAVAILABLE','FIXTURE_NAVIGATION_NOT_CONFIRMED',
    'FIXTURE_NAVIGATION_FAILED','FIXTURE_NAV_POST_RESPONSE_INVALID',
    'FIXTURE_BROWSER_NETWORK_ERROR_PAGE','FIXTURE_NAV_CURRENT_URL_MISMATCH',
    'FIXTURE_NAV_WEBDRIVER_TIMEOUT','FIXTURE_NAV_WEBDRIVER_INVALID_ARGUMENT',
    'FIXTURE_NAV_WEBDRIVER_UNKNOWN_ERROR','FIXTURE_NAV_WEBDRIVER_HTTP_ERROR',
    'FIXTURE_NAV_TRANSPORT_TIMEOUT','FIXTURE_NAV_TRANSPORT_ERROR',
    'FIXTURE_NAV_RESPONSE_INVALID','FIXTURE_NAV_UNEXPECTED_EXCEPTION',
    'WEBDRIVER_PROBE_INTERNAL_ERROR','NO_LIVE_WINDOW_AFTER_SESSION','PROFILE_ROOT_UNSAFE',
    'PROFILE_ROOT_CLEANUP_FAILED','NONE'} | {
    phase+code for phase in ('WEBDRIVER_SESSION_HTTP_','FIXTURE_NAV_HTTP_')
    for code in ('DNS_FAILURE','PROXY_FAILURE','CONNECTION_FAILURE','TIMEOUT',
                 'SANDBOX_DENIED','BROWSER_PROCESS_CLOSED','UNKNOWN')}

def configured_firefox_driver_path(payload:dict)->str:
    """Read only the documented GeckoDriver option; no path is saved in evidence."""
    gate(type(payload) is dict,'GECKODRIVER_OPTION_NOT_OBJECT')
    matches=[k for k in ('FirefoxDriverPath','optionFirefoxDriverPath') if k in payload]
    gate(len(matches)==1,'GECKODRIVER_OPTION_SCHEMA_UNRECOGNIZED')
    v=payload[matches[0]]
    gate(type(v) is str and 0<len(v)<=500,'GECKODRIVER_OPTION_PATH_EMPTY_OR_INVALID')
    return v

def validated_driver_session_probe(result:dict)->dict:
    gate(type(result) is dict and set(result)==DRIVER_SESSION_KEYS,'DRIVER_SESSION_PROBE_FIELDS')
    for field in DRIVER_SESSION_KEYS-{'failure_category','session_http_status',
                                      'session_w3c_error','session_message_signal',
                                      'driver_alive_after_session_error',
                                      'navigation_http_status','navigation_w3c_error',
                                      'navigation_message_signal','navigation_response_shape',
                                      'driver_alive_after_navigation_error',
                                      'window_handles_before_navigation',
                                      'current_window_before_navigation',
                                      'window_handles_after_navigation_error','driver_stderr_signals','driver_stderr_truncated',
                                      'window_readiness_attempts','window_readiness_outcome',
                                      'firefox_os_process_observation',
                                      'firefox_session_process_attribution',
                                      'firefox_child_inflight','firefox_child_inflight_detail'}:
        gate(type(result[field]) is bool,'DRIVER_SESSION_PROBE_BAD_BOOLEAN')
    # V58: phase-labelled, finite direct-child observations. No raw /proc,
    # PID, paths or sample histories may enter the schema.
    flight=result['firefox_child_inflight']
    gate(type(flight) is dict and set(flight)=={'session','navigation'},
         'DRIVER_INFLIGHT_SCHEMA_INVALID')
    for name in ('session','navigation'):
        gate(type(flight[name]) is str and flight[name] in {
            'NOT_RUN','NO_CHILD_OBSERVED','CHILD_LIVE_AT_END',
            'CHILD_ZOMBIE_SEEN','CHILD_GONE','PID_REUSED',
            'AMBIGUOUS','UNAVAILABLE'},'DRIVER_INFLIGHT_UNSAFE_'+name)
    gate(result['webdriver_server_ready'] or flight=={'session':'NOT_RUN','navigation':'NOT_RUN'},
         'DRIVER_INFLIGHT_WITHOUT_SERVER')
    gate(result['webdriver_session_created'] or flight['navigation']=='NOT_RUN',
         'DRIVER_INFLIGHT_NAV_WITHOUT_SESSION')
    gate(flight['navigation']=='NOT_RUN' or result['window_readiness_outcome']=='READY',
         'DRIVER_INFLIGHT_NAV_WITHOUT_WINDOW')
    # V59: disambiguate the historical V58 AMBIGUOUS classification,
    # independently attributing any observed zombie exit to the exact child.
    details=result['firefox_child_inflight_detail']
    gate(type(details) is dict and set(details)=={'session','navigation'},
         'DRIVER_INFLIGHT_DETAIL_FIELDS')
    for name in ('session','navigation'):
        value=details[name]
        gate(type(value) is dict and set(value)=={'ambiguity','exit'},
             'DRIVER_INFLIGHT_DETAIL_SHAPE_'+name)
        gate(type(value['ambiguity']) is str and value['ambiguity'] in {
            'NOT_RUN','NONE','CONCURRENT','IDENTITY_CHANGED','BOTH'},
            'DRIVER_INFLIGHT_AMBIGUITY_INVALID_'+name)
        gate(type(value['exit']) is str and value['exit'] in {
            'NOT_RUN','NONE','MIXED','EXIT_ZERO','EXIT_NONZERO',
            'SIGNAL_SIGSEGV','SIGNAL_SIGABRT','SIGNAL_SIGBUS','SIGNAL_SIGKILL',
            'SIGNAL_SIGTERM','SIGNAL_OTHER','UNKNOWN'},
            'DRIVER_INFLIGHT_EXIT_INVALID_'+name)
        gate((flight[name]=='NOT_RUN') == (value=={'ambiguity':'NOT_RUN','exit':'NOT_RUN'}),
             'DRIVER_INFLIGHT_DETAIL_PHASE_MISMATCH_'+name)
        gate(flight[name]=='AMBIGUOUS' or value['ambiguity'] in {'NOT_RUN','NONE'},
             'DRIVER_INFLIGHT_UNRELATED_AMBIGUITY_'+name)
        gate(flight[name]!='AMBIGUOUS' or value['ambiguity']!='NONE',
             'DRIVER_INFLIGHT_AMBIGUITY_MISSING_'+name)
        gate(value['exit'] in {'NONE','NOT_RUN'} or flight[name] in
             {'CHILD_ZOMBIE_SEEN','AMBIGUOUS'},
             'DRIVER_INFLIGHT_EXIT_WITHOUT_ZOMBIE_'+name)
    # V57: only finite process lineage states leave the container; identity
    # tokens and unredacted /proc records are never part of the report.
    att=result['firefox_session_process_attribution']
    gate(type(att) is dict and set(att)=={'after_session','before_cleanup','tracked_exit_class'},
         'DRIVER_FIREFOX_ATTRIBUTION_SCHEMA')
    gate(type(att['after_session']) is str and att['after_session'] in {
        'NOT_SEEN','DIRECT_CHILD_LIVE','DIRECT_CHILD_ZOMBIE','NO_DIRECT_CHILD',
        'AMBIGUOUS','UNAVAILABLE'},'DRIVER_FIREFOX_ATTRIBUTION_AFTER_UNSAFE')
    gate(type(att['before_cleanup']) is str and att['before_cleanup'] in {
        'NOT_SEEN','SAME_LIVE','SAME_ZOMBIE','NO_DIRECT_CHILD','TRACKED_GONE',
        'PID_REUSED','UNAVAILABLE'},'DRIVER_FIREFOX_ATTRIBUTION_CLEANUP_UNSAFE')
    gate(type(att['tracked_exit_class']) is str and att['tracked_exit_class'] in {
        'NOT_SEEN','NONE','EXIT_ZERO','EXIT_NONZERO','SIGNAL_SIGSEGV',
        'SIGNAL_SIGABRT','SIGNAL_SIGBUS','SIGNAL_SIGKILL','SIGNAL_SIGTERM',
        'SIGNAL_OTHER','UNKNOWN','UNAVAILABLE'},'DRIVER_FIREFOX_ATTRIBUTION_EXIT_UNSAFE')
    gate((att['after_session']=='NOT_SEEN') == (att['before_cleanup']=='NOT_SEEN') ==
         (att['tracked_exit_class']=='NOT_SEEN'),'DRIVER_FIREFOX_ATTRIBUTION_SAMPLE_MISMATCH')
    gate(att['before_cleanup']=='SAME_ZOMBIE' or att['tracked_exit_class'] in
         {'NONE','NOT_SEEN','UNAVAILABLE'},'DRIVER_FIREFOX_ATTRIBUTION_UNRELATED_EXIT')
    gate((att['before_cleanup']=='SAME_ZOMBIE') ==
         (att['tracked_exit_class'] in {'EXIT_ZERO','EXIT_NONZERO','SIGNAL_SIGSEGV',
            'SIGNAL_SIGABRT','SIGNAL_SIGBUS','SIGNAL_SIGKILL','SIGNAL_SIGTERM',
            'SIGNAL_OTHER','UNKNOWN'}),'DRIVER_FIREFOX_ATTRIBUTION_ZOMBIE_MISMATCH')
    gate(att['after_session'] in {'DIRECT_CHILD_LIVE','DIRECT_CHILD_ZOMBIE'} or
         att['before_cleanup'] in {'NOT_SEEN','NO_DIRECT_CHILD'},
         'DRIVER_FIREFOX_ATTRIBUTION_TRACKING_WITHOUT_CHILD')
    # A strict, finite on-container /proc observation.  These labels are
    # diagnostic only; they never influence Firefox/AJAX admission.
    pstate=result['firefox_os_process_observation']
    gate(type(pstate) is dict and set(pstate)=={'before_session',
         'after_session','before_cleanup','geckodriver_alive_before_cleanup',
         'zombie_exit_after_session','zombie_exit_before_cleanup'},
         'DRIVER_FIREFOX_PROC_FIELDS')
    for phase in ('before_session','after_session','before_cleanup'):
        gate(type(pstate[phase]) is str and
             pstate[phase] in {'NOT_SEEN','NONE','LIVE_ONE','LIVE_MULTIPLE',
                               'ZOMBIE_ONLY','UNAVAILABLE'},
             'DRIVER_FIREFOX_PROC_VALUE')
    for phase in ('zombie_exit_after_session','zombie_exit_before_cleanup'):
        gate(type(pstate[phase]) is str and pstate[phase] in {
            'NOT_SEEN','NONE','EXIT_ZERO','EXIT_NONZERO','SIGNAL_SIGSEGV',
            'SIGNAL_SIGABRT','SIGNAL_SIGBUS','SIGNAL_SIGKILL',
            'SIGNAL_SIGTERM','SIGNAL_OTHER','UNKNOWN','UNAVAILABLE','MIXED'},
            'DRIVER_FIREFOX_ZOMBIE_EXIT_UNSAFE')
    gate((pstate['after_session']=='NOT_SEEN') ==
         (pstate['zombie_exit_after_session']=='NOT_SEEN'),
         'DRIVER_FIREFOX_ZOMBIE_AFTER_SAMPLE_MISMATCH')
    gate((pstate['before_cleanup']=='NOT_SEEN') ==
         (pstate['zombie_exit_before_cleanup']=='NOT_SEEN'),
         'DRIVER_FIREFOX_ZOMBIE_CLEANUP_SAMPLE_MISMATCH')
    gate(pstate['geckodriver_alive_before_cleanup'] is None or
         type(pstate['geckodriver_alive_before_cleanup']) is bool,
         'DRIVER_FIREFOX_PROC_DRIVER_TYPE')
    if pstate['before_cleanup']=='NOT_SEEN':
        gate(pstate['geckodriver_alive_before_cleanup'] is None,
             'DRIVER_FIREFOX_PROC_DRIVER_WITHOUT_OBSERVATION')
    else:
        gate(type(pstate['geckodriver_alive_before_cleanup']) is bool,
             'DRIVER_FIREFOX_PROC_MISSING_DRIVER_OBSERVATION')
    if pstate['after_session']!='NOT_SEEN':
        gate(result['webdriver_server_ready'] and
             pstate['before_session']!='NOT_SEEN',
             'DRIVER_FIREFOX_PROC_UNPROVEN_SESSION')
    if result['webdriver_session_created']:
        gate(pstate['after_session']!='NOT_SEEN' and
             pstate['before_cleanup']!='NOT_SEEN',
             'DRIVER_FIREFOX_PROC_SUCCESS_WITHOUT_SAMPLING')
    gate(result['driver_alive_after_session_error'] is None or
         type(result['driver_alive_after_session_error']) is bool,
         'DRIVER_SESSION_PROBE_BAD_ALIVE_SIGNAL')
    gate(type(result['session_http_status']) is str and result['session_http_status'] in {'400','401','403','404','408','409',
        '429','500','502','503','504','OTHER','NOT_SEEN'},'DRIVER_SESSION_PROBE_BAD_HTTP_STATUS')
    gate(type(result['session_w3c_error']) is str and result['session_w3c_error'] in {'NOT_SEEN','SESSION_NOT_CREATED','UNKNOWN_ERROR',
        'INVALID_ARGUMENT','INVALID_SESSION_ID','SESSION_NOT_CREATED_OLD',
        'UNSUPPORTED_OPERATION','OTHER'},'DRIVER_SESSION_PROBE_BAD_W3C_CODE')
    gate(type(result['session_message_signal']) is str and result['session_message_signal'] in {'NOT_SEEN','PROFILE_LOCKED','PROFILE_PERMISSIONS',
        'PROFILE_STARTUP','BROWSER_PROCESS_CLOSED','FIREFOX_BINARY_MISSING',
        'MISSING_LIBRARY','SANDBOX_DENIED','DISPLAY_FAILURE','TIMEOUT',
        'PORT_CONFLICT','PROXY_FAILURE','CAPABILITY_REJECTED',
  'MARIONETTE_HANDSHAKE','RESOURCE_LIMIT','UNKNOWN'},
        'DRIVER_SESSION_PROBE_BAD_MESSAGE_SIGNAL')
    gate(type(result['navigation_http_status']) is str and result['navigation_http_status'] in
         {'400','401','403','404','408','409','429','500','502','503','504','OTHER','NOT_SEEN'},
         'DRIVER_NAV_BAD_HTTP_STATUS')
    gate(type(result['navigation_w3c_error']) is str and result['navigation_w3c_error'] in
         {'NOT_SEEN','UNKNOWN_ERROR','INVALID_SESSION_ID','NO_SUCH_WINDOW',
          'UNEXPECTED_ALERT_OPEN','INVALID_ARGUMENT','TIMEOUT','SCRIPT_TIMEOUT',
          'UNKNOWN_COMMAND','UNSUPPORTED_OPERATION','INSECURE_CERTIFICATE',
          'JAVASCRIPT_ERROR','NO_SUCH_FRAME','OTHER'},'DRIVER_NAV_BAD_W3C_ERROR')
    gate(type(result['navigation_message_signal']) is str and result['navigation_message_signal'] in
         {'NOT_SEEN','UNKNOWN','DNS_FAILURE','PROXY_FAILURE','CONNECTION_FAILURE',
          'NO_SUCH_WINDOW','INVALID_SESSION','BROWSER_PROCESS_CLOSED','TIMEOUT',
          'SANDBOX_DENIED','MARIONETTE_HANDSHAKE','CERTIFICATE_ERROR',
          'RESOURCE_LIMIT','NETWORK_ERROR_PAGE'},'DRIVER_NAV_BAD_MESSAGE_SIGNAL')
    gate(type(result['navigation_response_shape']) is str and result['navigation_response_shape'] in
         {'NOT_SEEN','VALUE_OBJECT','VALUE_OTHER','VALUE_MISSING',
          'BODY_NOT_OBJECT','INVALID_JSON'},'DRIVER_NAV_BAD_RESPONSE_SHAPE')
    gate(type(result['window_handles_before_navigation']) is str and
         result['window_handles_before_navigation'] in
         {'NOT_SEEN','ZERO','ONE','MULTIPLE','HTTP_ERROR',
          'TRANSPORT_ERROR','BAD_RESPONSE'} | {
          'HTTP_404_NO_SUCH_WINDOW','HTTP_404_INVALID_SESSION_ID',
          'HTTP_500_UNKNOWN_ERROR','HTTP_404_UNKNOWN_COMMAND'},
         'DRIVER_BAD_WINDOW_COUNT')
    gate(result['current_window_before_navigation'] in {'NOT_SEEN','PASS',
         'NO_SUCH_WINDOW','HTTP_ERROR','TRANSPORT_ERROR','BAD_RESPONSE'},
         'DRIVER_BAD_CURRENT_WINDOW')
    gate(type(result['window_handles_after_navigation_error']) is str and
         result['window_handles_after_navigation_error'] in
         {'NOT_SEEN','ZERO','ONE','MULTIPLE','HTTP_ERROR',
          'TRANSPORT_ERROR','BAD_RESPONSE','HTTP_404_NO_SUCH_WINDOW',
          'HTTP_404_INVALID_SESSION_ID','HTTP_500_UNKNOWN_ERROR',
          'HTTP_404_UNKNOWN_COMMAND'},
         'DRIVER_BAD_POST_NAV_WINDOWS')
    # A successful session must have undergone exactly this bounded preflight.
    gate(type(result['window_readiness_attempts']) is int and
         0<=result['window_readiness_attempts']<=10,
         'DRIVER_WINDOW_READINESS_ATTEMPTS_INVALID')
    gate(type(result['window_readiness_outcome']) is str and
         result['window_readiness_outcome'] in {'NOT_SEEN','READY','TIMEOUT_NO_WINDOWS',
            'TIMEOUT_NO_CURRENT','WINDOW_HANDLES_ERROR','CURRENT_WINDOW_ERROR'},
         'DRIVER_WINDOW_READINESS_OUTCOME_INVALID')
    if result['webdriver_session_created']:
        gate(result['window_readiness_attempts']>=1 and
             result['window_readiness_outcome']!='NOT_SEEN',
             'DRIVER_WINDOW_READINESS_UNPROVEN')
    else:
        gate(result['window_readiness_attempts']==0 and
             result['window_readiness_outcome']=='NOT_SEEN' and
             result['window_handles_before_navigation']=='NOT_SEEN' and
             result['current_window_before_navigation']=='NOT_SEEN',
             'DRIVER_WINDOW_READINESS_WITHOUT_SESSION')
    category=result['window_readiness_outcome']
    if category=='READY':
        gate(result['window_handles_before_navigation'] in ('ONE','MULTIPLE') and
             result['current_window_before_navigation']=='PASS',
             'DRIVER_WINDOW_FALSE_READY')
    elif category=='TIMEOUT_NO_WINDOWS':
        gate(result['window_handles_before_navigation']=='ZERO' and
             result['current_window_before_navigation'] in ('NOT_SEEN','NO_SUCH_WINDOW') and
             result['window_readiness_attempts']>=1 and
             not result['fixture_navigation_confirmed'],
             'DRIVER_WINDOW_FALSE_TIMEOUT')
    elif category=='TIMEOUT_NO_CURRENT':
        gate(result['window_handles_before_navigation'] in ('ONE','MULTIPLE') and
             result['current_window_before_navigation']=='NO_SUCH_WINDOW' and
             not result['fixture_navigation_confirmed'],
             'DRIVER_CURRENT_FALSE_TIMEOUT')
    elif category=='WINDOW_HANDLES_ERROR':
        gate(result['window_handles_before_navigation'] in ({'HTTP_ERROR',
             'TRANSPORT_ERROR','BAD_RESPONSE','HTTP_404_NO_SUCH_WINDOW',
             'HTTP_404_INVALID_SESSION_ID','HTTP_500_UNKNOWN_ERROR',
             'HTTP_404_UNKNOWN_COMMAND'}) and not result['fixture_navigation_confirmed'],
             'DRIVER_WINDOW_FALSE_ERROR')
    elif category=='CURRENT_WINDOW_ERROR':
        gate(result['window_handles_before_navigation'] in ('ONE','MULTIPLE') and
             result['current_window_before_navigation'] in ('HTTP_ERROR',
             'TRANSPORT_ERROR','BAD_RESPONSE') and not result['fixture_navigation_confirmed'],
             'DRIVER_CURRENT_FALSE_ERROR')
    if result['fixture_navigation_confirmed']:
        gate(category=='READY','DRIVER_SUCCESS_WITHOUT_READY_WINDOW')
    if result['current_window_before_navigation']=='PASS':
        gate(result['window_handles_before_navigation'] in ('ONE','MULTIPLE'),
             'DRIVER_CURRENT_WITHOUT_HANDLES')
    if result['window_handles_after_navigation_error']!='NOT_SEEN':
        gate(result['navigation_http_status']!='NOT_SEEN' and
             result['webdriver_session_created'] and
             not result['fixture_navigation_confirmed'],
             'DRIVER_POST_NAV_WITHOUT_ERROR')
    if result['fixture_navigation_confirmed']:
        gate(result['current_window_before_navigation']=='PASS' and
             result['window_handles_before_navigation'] in ('ONE','MULTIPLE'),
             'DRIVER_SUCCESS_WITHOUT_WINDOW_PREFLIGHT')
    gate(result['driver_alive_after_navigation_error'] is None or
         type(result['driver_alive_after_navigation_error']) is bool,
         'DRIVER_NAV_BAD_ALIVE_SIGNAL')
    gate(type(result['driver_stderr_truncated']) is bool and
         type(result['driver_stderr_signals']) is list and
         len(result['driver_stderr_signals'])<=len({'MARIONETTE','FIREFOX_CRASH','SANDBOX_DENIED',
             'PROFILE_ERROR','DISPLAY_ERROR','MISSING_LIBRARY','RESOURCE_ERROR','GECKODRIVER_ERROR'}) and
         result['driver_stderr_signals']==sorted(set(result['driver_stderr_signals'])) and
         all(type(x) is str and x in {'MARIONETTE','FIREFOX_CRASH','SANDBOX_DENIED',
             'PROFILE_ERROR','DISPLAY_ERROR','MISSING_LIBRARY','RESOURCE_ERROR','GECKODRIVER_ERROR'}
             for x in result['driver_stderr_signals']), 'DRIVER_STDERR_METADATA_UNSAFE')
    gate(type(result['failure_category']) is str and result['failure_category'] in DRIVER_FAILURE_CATEGORIES,
        'DRIVER_SESSION_PROBE_BAD_FAILURE_CATEGORY')
    # Exactly one set of metadata may describe the stage that failed. A W3C
    # navigation HTTP error cannot be treated as a confirmed navigation.
    if result['navigation_http_status']!='NOT_SEEN':
        gate(result['webdriver_session_created'] and not result['fixture_navigation_confirmed']
             and result['session_http_status']=='NOT_SEEN'
             and result['navigation_w3c_error']!='NOT_SEEN'
             and result['navigation_message_signal']!='NOT_SEEN'
             and result['navigation_response_shape']!='NOT_SEEN'
             and result['driver_alive_after_navigation_error'] is not None
             and result['failure_category']!='NONE',
             'DRIVER_NAV_HTTP_RESULT_INCONSISTENT')
    else:
        gate(result['navigation_w3c_error']=='NOT_SEEN'
             and result['navigation_message_signal']=='NOT_SEEN'
             and result['navigation_response_shape']=='NOT_SEEN'
             and result['driver_alive_after_navigation_error'] is None,
             'DRIVER_NAV_STRAY_HTTP_DIAGNOSTICS')
    gate(not result['private_profile_root_cleaned'] or
         result['private_profile_root_created'],
         'DRIVER_PROFILE_CLEANED_WITHOUT_CREATION')
    gate(not result['private_profile_root_created'] or
         result['private_profile_root_cleaned'],
         'DRIVER_PROFILE_NOT_CLEANED')
    # Never let an inconsistent probe response confer admission.
    if result['fixture_navigation_confirmed']:
        gate(all(result[x] for x in DRIVER_SESSION_KEYS-{'failure_category',
                'session_http_status','session_w3c_error','session_message_signal',
                'driver_alive_after_session_error',
                'navigation_http_status','navigation_w3c_error',
                'navigation_message_signal','navigation_response_shape',
                'driver_alive_after_navigation_error',
                'window_handles_before_navigation','current_window_before_navigation',
                'window_handles_after_navigation_error','driver_stderr_signals',
                'driver_stderr_truncated','window_readiness_attempts',
                'window_readiness_outcome','firefox_child_inflight','firefox_child_inflight_detail'}) and
             result['session_http_status']=='NOT_SEEN' and
             result['session_w3c_error']=='NOT_SEEN' and
             result['session_message_signal']=='NOT_SEEN' and
             result['driver_alive_after_session_error'] is None and
             result['failure_category']=='NONE','DRIVER_SESSION_PROBE_INCONSISTENT_PASS')
    if result['session_http_status']!='NOT_SEEN':
        gate(not result['webdriver_session_created'] and
             result['driver_alive_after_session_error'] is not None and
             result['session_w3c_error']!='NOT_SEEN' and
             result['session_message_signal']!='NOT_SEEN',
             'DRIVER_SESSION_PROBE_INCONSISTENT_HTTP_FAILURE')
    else:
        gate(result['session_w3c_error']=='NOT_SEEN' and
             result['session_message_signal']=='NOT_SEEN' and
             result['driver_alive_after_session_error'] is None,
             'DRIVER_SESSION_PROBE_STRAY_HTTP_DIAGNOSTICS')
    return result

def docker_driver_session_probe(driver_path:str)->dict:
    gate(type(driver_path) is str and 0<len(driver_path)<=500,'GECKODRIVER_CONFIG_PATH_INVALID')
    payload=json.dumps({'driver':driver_path},separators=(',',':')).encode()
    p=call(['docker','exec','-i','--user','1000:1000','--env','PYTHONDONTWRITEBYTECODE=1',
            'cybersec-day03-zap','python3','-c',DRIVER_SESSION_PROBE_CODE],
            input=payload,timeout=110)
    gate(p.returncode==0 and len(p.stdout)<2048,'DRIVER_SESSION_PROBE_EXEC_FAILED')
    try:result=json.loads(p.stdout)
    except (ValueError,TypeError) as e:raise Blocked('DRIVER_SESSION_PROBE_INVALID_JSON') from e
    return validated_driver_session_probe(result)


# V63: independent GeckoDriver --connect-existing control against a Firefox
# instance started with its ordinary sandbox. The container remains pinned,
# UID 1000:1000, loopback-only, about:blank only, no remote navigation.
# Does NOT grant AJAX/WebDriver admission under any circumstances.
GECKO_ATTACH_CONTROL_CODE = r'''
import json,os,re,stat,struct,sys,socket,time,signal,tempfile,subprocess,shutil
from urllib.request import Request,build_opener,ProxyHandler,HTTPRedirectHandler
from urllib.error import HTTPError,URLError
class RefuseRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args):return None

def safe_signals(raw):
    t=raw[:65536].decode('utf-8','replace').lower()
    categories={
       'SANDBOX_DENIED':('operation not permitted','seccomp','sandbox','permission denied'),
       'MARIONETTE':('marionette','failed to decode response'),
       'PROFILE_ERROR':('profile locked','profile is in use','could not create profile'),
       'MISSING_LIBRARY':('shared object file','cannot open shared librar'),
       'RESOURCE_ERROR':('out of memory','cannot allocate memory','no space left on device'),
       'CRASH':('crash','segmentation fault','sigsegv'),
       'ERROR':('error','failed'),
    }
    return sorted(k for k,values in categories.items() if any(v in t for v in values))

def check_driver(path):
    if not isinstance(path,str) or not 1<=len(path)<=500 or not path.startswith('/') or '\x00' in path:return False
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            st=os.fstat(fd);h=os.read(fd,20)
        finally:os.close(fd)
        return (stat.S_ISREG(st.st_mode) and os.access(path,os.X_OK) and
                len(h)>=20 and h[:5]==b'\x7fELF\x02' and h[5]==1 and
                struct.unpack('<H',h[18:20])[0]==183)
    except OSError:return False

def terminate(child):
    if child is None:return
    if child.poll() is None:
        try:os.killpg(child.pid,signal.SIGTERM)
        except (ProcessLookupError,PermissionError):pass
    try:child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:os.killpg(child.pid,signal.SIGKILL)
        except (ProcessLookupError,PermissionError):pass
        try:child.wait(timeout=2)
        except subprocess.TimeoutExpired:pass

r={'mode':'GECKODRIVER_CONNECT_EXISTING_ABOUT_BLANK','driver_arm64_executable':False,
   'firefox_executable':False,'private_root_created':False,'private_root_cleaned':False,
   'firefox_started':False,'native_port_observed':False,'driver_server_ready':False,
   'session_created':False,'window_verified':False,'about_blank_verified':False,
   'session_http_status':'NOT_SEEN','session_w3c_error':'NOT_SEEN',
   'session_message_signal':'NOT_SEEN','driver_log_signals':[],
   'firefox_log_signals':[],'classification':'NOT_RUN'}
firefox=None;gecko=None;root=None;session=None;endpoint=None;dlog=None;flog=None
try:
    data=json.loads(sys.stdin.buffer.read(2048))
    driver=data.get('driver') if isinstance(data,dict) else None
    r['driver_arm64_executable']=check_driver(driver)
    binary='/usr/bin/firefox'
    r['firefox_executable']=os.path.isfile(binary) and os.access(binary,os.X_OK)
    if not r['driver_arm64_executable']:
        r['classification']='DRIVER_INVALID'
    elif not r['firefox_executable']:
        r['classification']='FIREFOX_INVALID'
    else:
        root=tempfile.mkdtemp(prefix='stage70-attach-',dir='/tmp')
        os.chmod(root,0o700)
        st=os.lstat(root)
        if not (stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and
                (st.st_mode&0o777)==0o700):
            r['classification']='PRIVATE_ROOT_UNSAFE'
        else:
            r['private_root_created']=True
            profile=os.path.join(root,'profile');home=os.path.join(root,'home')
            os.mkdir(profile,0o700);os.mkdir(home,0o700)
            env=os.environ.copy();env['HOME']=home;env['TMPDIR']=root;env['MOZ_HEADLESS']='1'
            flog=tempfile.TemporaryFile(mode='w+b',dir=root)
            dlog=tempfile.TemporaryFile(mode='w+b',dir=root)
            # No disabled sandbox flags, host port exposure, extra caps,
            # privileged launch, external URI, proxy, or changed seccomp.
            firefox=subprocess.Popen([binary,'--headless','--no-remote','--marionette',
                  '--profile',profile,'about:blank'],env=env,stdout=subprocess.DEVNULL,
                  stderr=flog,start_new_session=True)
            r['firefox_started']=True
            native_port=None
            deadline=time.monotonic()+16
            while time.monotonic()<deadline:
                if firefox.poll() is not None:break
                active=os.path.join(profile,'MarionetteActivePort')
                try:
                    fd=os.open(active,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
                    try:
                        fs=os.fstat(fd)
                        content=os.read(fd,33) if stat.S_ISREG(fs.st_mode) and fs.st_uid==os.geteuid() and fs.st_size<=32 else b''
                    finally:os.close(fd)
                    match=re.fullmatch(rb'([0-9]{1,5})\s*',content)
                    if match and 1<=int(match.group(1))<=65535:
                        native_port=int(match.group(1));r['native_port_observed']=True;break
                except OSError:pass
                time.sleep(0.2)
            if native_port is None:
                r['classification']='FIREFOX_EARLY_EXIT' if firefox.poll() is not None else 'NATIVE_PORT_UNAVAILABLE'
            else:
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1',0));wd_port=sock.getsockname()[1]
                endpoint='http://127.0.0.1:'+str(wd_port)
                gecko=subprocess.Popen([driver,'--connect-existing','--marionette-port',
                   str(native_port),'--host','127.0.0.1','--port',str(wd_port),
                   '--log','error'],env=env,stdout=subprocess.DEVNULL,stderr=dlog,
                   start_new_session=True)
                opener=build_opener(ProxyHandler({}),RefuseRedirect())
                for _ in range(35):
                    if gecko.poll() is not None or firefox.poll() is not None:break
                    try:
                        with opener.open(Request(endpoint+'/status'),timeout=0.5) as res:
                            obj=json.loads(res.read(4096))
                            if res.status==200 and isinstance(obj,dict):
                                r['driver_server_ready']=True;break
                    except (URLError,TimeoutError,ValueError,OSError):pass
                    time.sleep(0.2)
                if not r['driver_server_ready']:
                    r['classification']='DRIVER_SERVER_UNAVAILABLE'
                else:
                    payload={'capabilities':{'alwaysMatch':{'browserName':'firefox'}}}
                    req=Request(endpoint+'/session',data=json.dumps(payload).encode(),
                        headers={'Content-Type':'application/json'},method='POST')
                    try:
                        with opener.open(req,timeout=18) as response:
                            body=json.loads(response.read(8192))
                        value=body.get('value') if isinstance(body,dict) else None
                        sid=value.get('sessionId') if isinstance(value,dict) else None
                        if isinstance(sid,str) and re.fullmatch(r'[A-Za-z0-9-]{1,100}',sid):
                            session=sid;r['session_created']=True
                        else:r['classification']='ATTACH_SESSION_INVALID_RESPONSE'
                    except HTTPError as err:
                        r['session_http_status']=str(err.code) if err.code in (400,403,404,408,409,500,502,503,504) else 'OTHER'
                        try:
                            raw=err.read(4096)
                            v=json.loads(raw).get('value',{})
                            msg=v.get('message','').lower()[:2048] if isinstance(v,dict) else ''
                            er=v.get('error','') if isinstance(v,dict) else ''
                            r['session_w3c_error']=('UNKNOWN_ERROR' if er=='unknown error' else
                               'SESSION_NOT_CREATED' if er=='session not created' else 'OTHER')
                            r['session_message_signal']=('SANDBOX_DENIED' if any(x in msg for x in ('sandbox','seccomp','operation not permitted')) else
                               'MARIONETTE_HANDSHAKE' if 'marionette' in msg else
                               'BROWSER_PROCESS_CLOSED' if any(x in msg for x in ('crash','closed','exited')) else 'UNKNOWN')
                        except (ValueError,TypeError,AttributeError):
                            r['session_w3c_error']='OTHER';r['session_message_signal']='UNKNOWN'
                        finally:err.close()
                        r['classification']='ATTACH_SESSION_HTTP_ERROR'
                    except (URLError,OSError,TimeoutError,ValueError,TypeError):
                        r['classification']='ATTACH_SESSION_TRANSPORT_ERROR'
                    if r['session_created']:
                        try:
                            with opener.open(Request(endpoint+'/session/'+session+'/window/handles'),timeout=5) as resp:
                                value=json.loads(resp.read(4096)).get('value')
                                r['window_verified']=(resp.status==200 and isinstance(value,list) and
                                    1<=len(value)<=32 and all(isinstance(x,str) and 1<=len(x)<=256 for x in value))
                            if r['window_verified']:
                                with opener.open(Request(endpoint+'/session/'+session+'/url'),timeout=5) as resp:
                                    value=json.loads(resp.read(4096)).get('value')
                                    r['about_blank_verified']=(resp.status==200 and value=='about:blank')
                        except (URLError,OSError,TimeoutError,ValueError,TypeError):pass
                        r['classification']=('ATTACH_PASS_DIAGNOSTIC_ONLY' if r['about_blank_verified'] else 'ATTACH_WINDOW_UNVERIFIED')
except Exception:
    r['classification']='CONTROL_INTERNAL_ERROR'
finally:
    if session is not None and endpoint is not None:
        try:
            with build_opener(ProxyHandler({}),RefuseRedirect()).open(
                Request(endpoint+'/session/'+session,method='DELETE'),timeout=2):pass
        except (URLError,OSError,TimeoutError,ValueError):pass
    terminate(gecko);terminate(firefox)
    for handle,key in ((dlog,'driver_log_signals'),(flog,'firefox_log_signals')):
        if handle is not None:
            try:
                handle.flush();handle.seek(0)
                r[key]=safe_signals(handle.read(65537))
            except (OSError,ValueError):r[key]=[]
            finally:handle.close()
    if root is not None:
        try:shutil.rmtree(root)
        except OSError:pass
        r['private_root_cleaned']=not os.path.exists(root)
        if not r['private_root_cleaned']:
            r['classification']='PRIVATE_ROOT_CLEANUP_FAILED';r['about_blank_verified']=False
    print(json.dumps(r,sort_keys=True,separators=(',',':')))
'''
GECKO_ATTACH_KEYS={'mode','driver_arm64_executable','firefox_executable',
 'private_root_created','private_root_cleaned','firefox_started','native_port_observed',
 'driver_server_ready','session_created','window_verified','about_blank_verified',
 'session_http_status','session_w3c_error','session_message_signal',
 'driver_log_signals','firefox_log_signals','classification'}
GECKO_ATTACH_CLASSES={'NOT_RUN','DRIVER_INVALID','FIREFOX_INVALID','PRIVATE_ROOT_UNSAFE',
 'FIREFOX_EARLY_EXIT','NATIVE_PORT_UNAVAILABLE','DRIVER_SERVER_UNAVAILABLE',
 'ATTACH_SESSION_INVALID_RESPONSE','ATTACH_SESSION_HTTP_ERROR',
 'ATTACH_SESSION_TRANSPORT_ERROR','ATTACH_WINDOW_UNVERIFIED',
 'ATTACH_PASS_DIAGNOSTIC_ONLY','PRIVATE_ROOT_CLEANUP_FAILED','CONTROL_INTERNAL_ERROR'}
GECKO_ATTACH_LOG_SIGNALS={'SANDBOX_DENIED','MARIONETTE','PROFILE_ERROR',
 'MISSING_LIBRARY','RESOURCE_ERROR','CRASH','ERROR'}

def validate_gecko_attach_control(r):
    gate(type(r) is dict and set(r)==GECKO_ATTACH_KEYS,'ATTACH_SCHEMA_INVALID')
    gate(r['mode']=='GECKODRIVER_CONNECT_EXISTING_ABOUT_BLANK','ATTACH_MODE_INVALID')
    for name in ('driver_arm64_executable','firefox_executable',
      'private_root_created','private_root_cleaned','firefox_started','native_port_observed',
      'driver_server_ready','session_created','window_verified','about_blank_verified'):
        gate(type(r[name]) is bool,'ATTACH_BOOLEAN_INVALID_'+name)
    gate(type(r['classification']) is str and r['classification'] in GECKO_ATTACH_CLASSES,
         'ATTACH_CLASS_INVALID')
    gate(r['session_http_status'] in {'NOT_SEEN','400','403','404','408','409','500','502','503','504','OTHER'}
         and type(r['session_http_status']) is str,'ATTACH_HTTP_STATUS_INVALID')
    gate(type(r['session_w3c_error']) is str and r['session_w3c_error'] in {
        'NOT_SEEN','UNKNOWN_ERROR','SESSION_NOT_CREATED','OTHER'},'ATTACH_W3C_INVALID')
    gate(type(r['session_message_signal']) is str and r['session_message_signal'] in {
        'NOT_SEEN','SANDBOX_DENIED','MARIONETTE_HANDSHAKE','BROWSER_PROCESS_CLOSED','UNKNOWN'},
        'ATTACH_SIGNAL_INVALID')
    for name in ('driver_log_signals','firefox_log_signals'):
        value=r[name]
        gate(type(value) is list and len(value)<=len(GECKO_ATTACH_LOG_SIGNALS) and
           len(value)==len(set(value)) and all(type(x) is str and x in GECKO_ATTACH_LOG_SIGNALS for x in value),
           'ATTACH_LOG_UNSAFE_'+name)
    gate(not r['private_root_cleaned'] or r['private_root_created'],'ATTACH_ROOT_NOT_CREATED')
    gate(not r['firefox_started'] or (r['driver_arm64_executable'] and r['firefox_executable'] and r['private_root_created']),
         'ATTACH_FIREFOX_ILLEGAL_START')
    gate(not r['native_port_observed'] or r['firefox_started'],'ATTACH_PORT_WITHOUT_FIREFOX')
    gate(not r['driver_server_ready'] or r['native_port_observed'],'ATTACH_DRIVER_WITHOUT_PORT')
    gate(not r['session_created'] or (r['driver_server_ready'] and r['session_http_status']=='NOT_SEEN'),
         'ATTACH_SESSION_WITHOUT_DRIVER')
    gate(not r['window_verified'] or r['session_created'],'ATTACH_WINDOW_WITHOUT_SESSION')
    gate(not r['about_blank_verified'] or (r['session_created'] and r['window_verified']),
         'ATTACH_URL_WITHOUT_WINDOW')
    gate((r['session_http_status']=='NOT_SEEN') == (r['session_w3c_error']=='NOT_SEEN'
          and r['session_message_signal']=='NOT_SEEN'), 'ATTACH_HTTP_METADATA_CONTRADICTION')
    gate(not r['about_blank_verified'] or r['classification']=='ATTACH_PASS_DIAGNOSTIC_ONLY',
         'ATTACH_FALSE_URL_VERIFICATION')
    if r['classification']=='ATTACH_PASS_DIAGNOSTIC_ONLY':
        gate(all(r[k] for k in ('driver_arm64_executable','firefox_executable','private_root_created',
            'private_root_cleaned','firefox_started','native_port_observed','driver_server_ready',
            'session_created','window_verified','about_blank_verified')),
            'ATTACH_FALSE_SUCCESS')
    if r['classification']=='PRIVATE_ROOT_CLEANUP_FAILED':
        gate(r['private_root_created'] and not r['private_root_cleaned'] and
             not r['about_blank_verified'],'ATTACH_FALSE_CLEANUP_FAILURE')
    return r

def docker_gecko_attach_control(driver_path:str):
    gate(type(driver_path) is str and 0<len(driver_path)<=500,
         'ATTACH_DRIVER_PATH_INVALID')
    payload=json.dumps({'driver':driver_path},separators=(',',':')).encode()
    p=call(['docker','exec','-i','--user','1000:1000','--env','PYTHONDONTWRITEBYTECODE=1',
       'cybersec-day03-zap','python3','-c',GECKO_ATTACH_CONTROL_CODE],
       input=payload,timeout=95)
    gate(p.returncode==0 and 0<len(p.stdout)<=2600,'ATTACH_EXEC_FAILED')
    try:obj=json.loads(p.stdout)
    except (ValueError,TypeError) as e:raise Blocked('ATTACH_INVALID_JSON') from e
    return validate_gecko_attach_control(obj)

# V64: sandbox-preserving trace and PID/Marionette port lifecycle diagnostic.
# This control is diagnostic only, never part of acceptance admission.
GECKO_V64_TRACE_CODE = r'''
# V64: invoked ONLY inside the same already pinned, isolated Docker ZAP service.
# All diagnostics stay on loopback; raw trace, argv, paths, PIDs, tokens and URLs
# are never written to stdout/evidence. A per-run keyed token correlates the
# same Firefox PID+starttime without revealing a globally reusable identifier.
import hashlib,json,os,re,stat,struct,sys,socket,time,signal,tempfile,subprocess,shutil,secrets
from urllib.request import Request,build_opener,ProxyHandler,HTTPRedirectHandler
from urllib.error import HTTPError,URLError

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args):return None

STATUS={'400','401','403','404','408','409','429','500','502','503','504'}
EVENTS={'GECKODRIVER_START','MARIONETTE_CONNECT','WEBDRIVER_NEW_SESSION',
        'WEBDRIVER_GET_HANDLES','SANDBOX_DENIED','FIREFOX_EXIT','HTTP_500',
        'WINDOW_FAILURE','PROFILE_FAILURE','CRASH_SIGNAL'}
PHASES=['FIREFOX_LAUNCH','MARIONETTE_PORT','DRIVER_READY','NEW_SESSION',
        'WINDOW_HANDLES','BEFORE_CLEANUP']

class NoRaw(Exception):pass

def file_opened_elf_arm64(path):
    if type(path) is not str or len(path)>500 or not path.startswith('/') or '\x00' in path:return False
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            s=os.fstat(fd);h=os.read(fd,20)
        finally:os.close(fd)
        return stat.S_ISREG(s.st_mode) and os.access(path,os.X_OK) and len(h)==20 and \
            h[:6]==b'\x7fELF\x02\x01' and struct.unpack('<H',h[18:20])[0]==183
    except OSError:return False

def process_identity(pid):
    # Validates the startup timestamp to detect PID reuse; never serializes
    # `/proc`, PID, PPID, argv or real start timestamp.
    try:
        with open('/proc/'+str(pid)+'/stat','rb') as f:raw=f.read(2048)
        x=raw.rfind(b') ')
        if x<0:return None
        p=raw[x+2:].split()
        if len(p)<20:return None
        return (int(p[19]),p[0])
    except (OSError,ValueError):return None

def exit_class(proc,initial):
    rc=proc.poll()
    if rc is not None:
        if rc==0:return 'EXIT_ZERO'
        if rc<0:return 'SIGNAL_EXIT'
        return 'EXIT_NONZERO'
    actual=process_identity(proc.pid)
    if actual is None:return 'UNAVAILABLE'
    if initial is not None and actual[0]!=initial[0]:return 'PID_REUSED'
    if actual[1]==b'Z':return 'ZOMBIE'
    return 'LIVE'

def trace_codes(fd):
    try:
        n=os.fstat(fd.fileno()).st_size
        raw=os.pread(fd.fileno(),65536,0)
        t=raw.decode('utf-8','replace').lower()
        rules={
          'GECKODRIVER_START':(r'listening on 127\.0\.0\.1',r'geckodriver.*listening'),
          'MARIONETTE_CONNECT':(r'marionette',),
          'WEBDRIVER_NEW_SESSION':(r'newsession',r'post /session(?: |\b)'),
          'WEBDRIVER_GET_HANDLES':(r'getwindowhandles',r'/window/handles'),
          'SANDBOX_DENIED':(r'operation not permitted',r'seccomp',r'sandbox denied',r'permission denied'),
          'FIREFOX_EXIT':(r'process unexpectedly closed',r'browser process stopped',r'process exited'),
          'HTTP_500':(r'500 internal server error',r'<- 500 ',r'-> 500 '),
          'WINDOW_FAILURE':(r'no such window',r'browsing context has been discarded'),
          'PROFILE_FAILURE':(r'profile.*locked',r'profile.*permission'),
          'CRASH_SIGNAL':(r'sigsegv',r'sigabrt',r'segmentation fault')}
        return sorted(k for k,patterns in rules.items() if any(re.search(x,t) for x in patterns)),n>65536
    except (OSError,ValueError):return [],True

def error_class(raw):
    # The WebDriver message is never stored; closed classification only.
    try:
        obj=json.loads(raw[:8192]);v=obj.get('value') if type(obj) is dict else None
        err=v.get('error') if type(v) is dict else None
        msg=v.get('message') if type(v) is dict else None
    except (ValueError,UnicodeError,TypeError):err=msg=None
    s=msg.lower()[:1024] if type(msg) is str else ''
    if any(x in s for x in ('marionette','failed to decode','handshake')):hint='MARIONETTE_HANDSHAKE'
    elif any(x in s for x in ('sandbox','seccomp','operation not permitted')):hint='SANDBOX_DENIED'
    elif any(x in s for x in ('no such window','browsing context')):hint='NO_WINDOW'
    elif any(x in s for x in ('crash','unexpectedly closed','exited')):hint='BROWSER_EXIT'
    elif any(x in s for x in ('timeout','timed out')):hint='TIMEOUT'
    else:hint='UNKNOWN'
    error={'unknown error':'UNKNOWN_ERROR','session not created':'SESSION_NOT_CREATED',
            'no such window':'NO_SUCH_WINDOW','invalid session id':'INVALID_SESSION_ID'}.get(err,'OTHER')
    return error,hint

def stop(proc):
    if proc is None:return
    if proc.poll() is None:
        try:os.killpg(proc.pid,signal.SIGTERM)
        except (ProcessLookupError,PermissionError):pass
    try:proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:os.killpg(proc.pid,signal.SIGKILL)
        except (ProcessLookupError,PermissionError):pass
        try:proc.wait(timeout=2)
        except subprocess.TimeoutExpired:pass

r={'schema':'stage70-v64-geckodriver-trace-v1','mode':'ISOLATED_ATTACH_EXISTING_ABOUT_BLANK',
   'classification':'NOT_RUN','driver_elf_arm64':False,'firefox_executable':False,
   'private_root_created':False,'private_root_cleaned':False,'marionette_port_state':'NOT_SEEN',
   'marionette_port':None,'firefox_pid_ref':None,'firefox_start_identity':'NOT_SEEN',
   'webdriver_ready':False,'session_created':False,'window_handles_verified':False,
   'about_blank_verified':False,'session_http':'NOT_SEEN','handles_http':'NOT_SEEN','about_blank_http':'NOT_SEEN',
   'w3c_error':'NOT_SEEN','message_signal':'NOT_SEEN','trace_truncated':False,
   'trace_events':[],'timeline':[],'firefox_pre_cleanup':'NOT_RUN',
   'firefox_post_cleanup':'NOT_RUN'}
ff=None;gd=None;root=None;glog=None;flog=None;endpoint=None;session=None;initial=None
start=time.monotonic();key=secrets.token_bytes(16)

def record(phase):
    if phase not in PHASES or len(r['timeline'])>=len(PHASES):return
    state=exit_class(ff,initial) if ff is not None else 'NOT_STARTED'
    if ff is not None and r['firefox_pid_ref'] is None and initial is not None:
        r['firefox_pid_ref']=hashlib.blake2s((str(ff.pid)+':'+str(initial[0])).encode(),
                                        digest_size=8,key=key).hexdigest()
    codes,trunc=trace_codes(glog) if glog is not None else ([],False)
    r['trace_truncated']=r['trace_truncated'] or trunc
    r['trace_events']=sorted(set(r['trace_events'])|set(codes))
    r['timeline'].append({'phase':phase,'elapsed_ms':min(120000,max(0,int((time.monotonic()-start)*1000))),
                 'firefox_state':state,'trace_events':codes})

try:
    incoming=json.loads(sys.stdin.buffer.read(2048));driver=incoming.get('driver') if type(incoming) is dict else None
    r['driver_elf_arm64']=file_opened_elf_arm64(driver)
    binary='/usr/bin/firefox'
    r['firefox_executable']=os.path.isfile(binary) and os.access(binary,os.X_OK)
    if not r['driver_elf_arm64']:r['classification']='DRIVER_INVALID'
    elif not r['firefox_executable']:r['classification']='FIREFOX_INVALID'
    else:
        root=tempfile.mkdtemp(prefix='stage70-v64-',dir='/tmp');os.chmod(root,0o700)
        st=os.lstat(root)
        if not (stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and (st.st_mode&0o777)==0o700):
            r['classification']='PRIVATE_ROOT_UNSAFE'
        else:
            r['private_root_created']=True
            profile=os.path.join(root,'profile');home=os.path.join(root,'home')
            os.mkdir(profile,0o700);os.mkdir(home,0o700)
            env=os.environ.copy();env['HOME']=home;env['TMPDIR']=root;env['MOZ_HEADLESS']='1'
            glog=tempfile.TemporaryFile(mode='w+b',dir=root)
            flog=tempfile.TemporaryFile(mode='w+b',dir=root)
            ff=subprocess.Popen([binary,'--headless','--no-remote','--marionette','--profile',profile,'about:blank'],
                                env=env,stdout=subprocess.DEVNULL,stderr=flog,start_new_session=True)
            initial=process_identity(ff.pid)
            r['firefox_start_identity']='VERIFIED' if initial is not None else 'UNAVAILABLE'
            record('FIREFOX_LAUNCH')
            active=os.path.join(profile,'MarionetteActivePort');native_port=None
            deadline=time.monotonic()+16
            while time.monotonic()<deadline and ff.poll() is None:
                try:
                    fd=os.open(active,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
                    try:
                        s=os.fstat(fd)
                        data=os.read(fd,33) if stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_size<=32 else b''
                    finally:os.close(fd)
                    m=re.fullmatch(rb'([0-9]{1,5})\s*',data)
                    if m and 1<=int(m.group(1))<=65535:
                        native_port=int(m.group(1));break
                except OSError:pass
                time.sleep(.2)
            r['marionette_port_state']='PORT_PUBLISHED' if native_port else 'NOT_PUBLISHED'
            if native_port:r['marionette_port']=native_port
            record('MARIONETTE_PORT')
            if native_port is None:r['classification']='FIREFOX_EARLY_EXIT' if ff.poll() is not None else 'MARIONETTE_PORT_MISSING'
            else:
                with socket.socket() as s:
                    s.bind(('127.0.0.1',0));port=s.getsockname()[1]
                endpoint='http://127.0.0.1:'+str(port)
                gd=subprocess.Popen([driver,'--connect-existing','--marionette-port',str(native_port),
                   '--host','127.0.0.1','--port',str(port),'--log','trace'],env=env,
                   stdout=subprocess.DEVNULL,stderr=glog,start_new_session=True)
                op=build_opener(ProxyHandler({}),NoRedirect())
                for _ in range(35):
                    if gd.poll() is not None or ff.poll() is not None:break
                    try:
                        with op.open(Request(endpoint+'/status'),timeout=.5) as resp:
                            if resp.status==200 and type(json.loads(resp.read(4096))) is dict:
                                r['webdriver_ready']=True;break
                    except (URLError,TimeoutError,OSError,ValueError):pass
                    time.sleep(.2)
                record('DRIVER_READY')
                if not r['webdriver_ready']:r['classification']='DRIVER_SERVER_UNAVAILABLE'
                else:
                    payload={'capabilities':{'alwaysMatch':{'browserName':'firefox'}}}
                    req=Request(endpoint+'/session',data=json.dumps(payload).encode(),
                        headers={'Content-Type':'application/json'},method='POST')
                    try:
                        with op.open(req,timeout=18) as response:
                            obj=json.loads(response.read(8192))
                        value=obj.get('value') if type(obj) is dict else None
                        sess=value.get('sessionId') if type(value) is dict else None
                        if type(sess) is str and re.fullmatch('[A-Za-z0-9-]{1,100}',sess):
                            session=sess;r['session_created']=True
                        else:r['classification']='NEW_SESSION_INVALID_RESPONSE'
                    except HTTPError as e:
                        raw=e.read(8192);r['session_http']=str(e.code) if str(e.code) in STATUS else 'OTHER'
                        r['w3c_error'],r['message_signal']=error_class(raw)
                        r['classification']='NEW_SESSION_HTTP_ERROR';e.close()
                    except (URLError,TimeoutError,OSError):r['classification']='NEW_SESSION_TRANSPORT_ERROR'
                    except (ValueError,TypeError):r['classification']='NEW_SESSION_INVALID_RESPONSE'
                    record('NEW_SESSION')
                    if r['session_created']:
                        try:
                            with op.open(Request(endpoint+'/session/'+session+'/window/handles'),timeout=6) as response:
                                data=json.loads(response.read(8192))
                            v=data.get('value') if type(data) is dict else None
                            r['window_handles_verified']=(type(v) is list and 1<=len(v)<=8 and
                                all(type(x) is str and 1<=len(x)<=256 for x in v))
                            if not r['window_handles_verified']:r['classification']='NO_LIVE_WINDOW'
                            else:
                                try:
                                    with op.open(Request(endpoint+'/session/'+session+'/url'),timeout=6) as response:
                                        info=json.loads(response.read(8192))
                                    r['about_blank_verified']=type(info) is dict and info.get('value')=='about:blank'
                                    r['classification']='TRACE_PASS_DIAGNOSTIC_ONLY' if r['about_blank_verified'] else 'ABOUT_BLANK_UNVERIFIED'
                                except HTTPError as err:
                                    r['about_blank_http']=str(err.code) if str(err.code) in STATUS else 'OTHER'
                                    r['w3c_error'],r['message_signal']=error_class(err.read(8192))
                                    r['classification']='ABOUT_BLANK_HTTP_ERROR';err.close()
                                except (URLError,TimeoutError,OSError):
                                    r['classification']='ABOUT_BLANK_TRANSPORT_ERROR'
                                except (ValueError,TypeError):
                                    r['classification']='ABOUT_BLANK_INVALID_RESPONSE'
                        except HTTPError as e:
                            r['handles_http']=str(e.code) if str(e.code) in STATUS else 'OTHER'
                            r['w3c_error'],r['message_signal']=error_class(e.read(8192))
                            r['classification']='WINDOW_HANDLES_HTTP_ERROR';e.close()
                        except (URLError,TimeoutError,OSError):r['classification']='WINDOW_HANDLES_TRANSPORT_ERROR'
                        except (ValueError,TypeError):r['classification']='WINDOW_HANDLES_INVALID_RESPONSE'
                    record('WINDOW_HANDLES')
except Exception:
    r['classification']='CONTROL_INTERNAL_ERROR'
finally:
    if ff is not None:r['firefox_pre_cleanup']=exit_class(ff,initial)
    record('BEFORE_CLEANUP')
    if session and endpoint:
        try:op.open(Request(endpoint+'/session/'+session,method='DELETE'),timeout=2).close()
        except Exception:pass
    stop(gd);stop(ff)
    if ff is not None:r['firefox_post_cleanup']=exit_class(ff,initial)
    if glog is not None:
        codes,trunc=trace_codes(glog)
        r['trace_events']=sorted(set(r['trace_events'])|set(codes))
        r['trace_truncated']=r['trace_truncated'] or trunc
        glog.close()
    if flog is not None:
        codes,trunc=trace_codes(flog)
        r['trace_events']=sorted(set(r['trace_events'])|set(codes))
        r['trace_truncated']=r['trace_truncated'] or trunc
        flog.close()
    if root is not None:
        try:
            shutil.rmtree(root)
            r['private_root_cleaned']=not os.path.exists(root)
        except OSError:r['private_root_cleaned']=False
        if not r['private_root_cleaned']:
            r['classification']='PRIVATE_ROOT_CLEANUP_FAILED';r['about_blank_verified']=False
    # A live window before an immediate browser exit is not a stable success.
    # Distinguish spontaneous pre-cleanup failure from intentional SIGTERM.
    if r['classification']=='TRACE_PASS_DIAGNOSTIC_ONLY' and r['firefox_pre_cleanup']!='LIVE':
        r['classification']='FIREFOX_EXIT_AFTER_WINDOW'
    # Cleanup or trace failure may never appear as a positive diagnostic outcome.
    if r['classification']=='TRACE_PASS_DIAGNOSTIC_ONLY' and not (
       r['session_created'] and r['window_handles_verified'] and r['about_blank_verified'] and
       r['private_root_cleaned']):r['classification']='CONTROL_INTERNAL_ERROR'
    print(json.dumps(r,sort_keys=True,separators=(',',':')))

'''

V64_TRACE_KEYS={'schema','mode','classification','driver_elf_arm64',
 'firefox_executable','private_root_created','private_root_cleaned','marionette_port_state',
 'marionette_port','firefox_pid_ref','firefox_start_identity','webdriver_ready',
 'session_created','window_handles_verified','about_blank_verified','session_http',
 'handles_http','about_blank_http','w3c_error','message_signal','trace_truncated','trace_events','timeline',
 'firefox_pre_cleanup','firefox_post_cleanup'}
V64_TRACE_CLASSES={'NOT_RUN','DRIVER_INVALID','FIREFOX_INVALID','PRIVATE_ROOT_UNSAFE',
 'FIREFOX_EARLY_EXIT','MARIONETTE_PORT_MISSING','DRIVER_SERVER_UNAVAILABLE',
 'NEW_SESSION_INVALID_RESPONSE','NEW_SESSION_HTTP_ERROR','NEW_SESSION_TRANSPORT_ERROR',
 'NO_LIVE_WINDOW','TRACE_PASS_DIAGNOSTIC_ONLY','ABOUT_BLANK_UNVERIFIED',
 'ABOUT_BLANK_HTTP_ERROR','ABOUT_BLANK_TRANSPORT_ERROR',
 'ABOUT_BLANK_INVALID_RESPONSE','FIREFOX_EXIT_AFTER_WINDOW','WINDOW_HANDLES_HTTP_ERROR','WINDOW_HANDLES_TRANSPORT_ERROR',
 'WINDOW_HANDLES_INVALID_RESPONSE','CONTROL_INTERNAL_ERROR','PRIVATE_ROOT_CLEANUP_FAILED'}
V64_TRACE_EVENTS={'GECKODRIVER_START','MARIONETTE_CONNECT','WEBDRIVER_NEW_SESSION',
 'WEBDRIVER_GET_HANDLES','SANDBOX_DENIED','FIREFOX_EXIT','HTTP_500',
 'WINDOW_FAILURE','PROFILE_FAILURE','CRASH_SIGNAL'}
V64_TRACE_PHASES=['FIREFOX_LAUNCH','MARIONETTE_PORT','DRIVER_READY','NEW_SESSION',
 'WINDOW_HANDLES','BEFORE_CLEANUP']
V64_PROCESS_STATES={'NOT_RUN','NOT_STARTED','LIVE','EXIT_ZERO','EXIT_NONZERO',
                    'SIGNAL_EXIT','UNAVAILABLE','PID_REUSED','ZOMBIE'}

def validate_v64_trace_control(r:dict)->dict:
    gate(type(r) is dict and set(r)==V64_TRACE_KEYS,'V64_TRACE_SCHEMA_INVALID')
    gate(r['schema']=='stage70-v64-geckodriver-trace-v1' and
         r['mode']=='ISOLATED_ATTACH_EXISTING_ABOUT_BLANK','V64_TRACE_MODE_INVALID')
    gate(type(r['classification']) is str and r['classification'] in V64_TRACE_CLASSES,
         'V64_TRACE_CLASS_INVALID')
    for k in ('driver_elf_arm64','firefox_executable','private_root_created',
              'private_root_cleaned','webdriver_ready','session_created',
              'window_handles_verified','about_blank_verified','trace_truncated'):
        gate(type(r[k]) is bool,'V64_TRACE_BOOL_INVALID_'+k)
    gate(type(r['marionette_port_state']) is str and
         r['marionette_port_state'] in {'NOT_SEEN','NOT_PUBLISHED','PORT_PUBLISHED'},
         'V64_TRACE_PORT_STATE_INVALID')
    port=r['marionette_port']
    gate((port is None and r['marionette_port_state']!='PORT_PUBLISHED') or
         (type(port) is int and 1<=port<=65535 and
          r['marionette_port_state']=='PORT_PUBLISHED'),
         'V64_TRACE_PORT_INVALID')
    gate(r['firefox_start_identity'] in {'NOT_SEEN','VERIFIED','UNAVAILABLE'} and
         type(r['firefox_start_identity']) is str,'V64_TRACE_PID_STATE_INVALID')
    pid_ref=r['firefox_pid_ref']
    gate(pid_ref is None or (type(pid_ref) is str and
         re.fullmatch('[a-f0-9]{16}',pid_ref) is not None and
         r['firefox_start_identity']=='VERIFIED'),
         'V64_TRACE_PID_REF_INVALID')
    for k in ('firefox_pre_cleanup','firefox_post_cleanup'):
        gate(type(r[k]) is str and r[k] in V64_PROCESS_STATES,'V64_TRACE_LIFECYCLE_INVALID')
    for k in ('session_http','handles_http','about_blank_http'):
        gate(type(r[k]) is str and r[k] in {'NOT_SEEN','400','401','403','404','408',
             '409','429','500','502','503','504','OTHER'},'V64_TRACE_HTTP_INVALID')
    gate(r['w3c_error'] in {'NOT_SEEN','UNKNOWN_ERROR','SESSION_NOT_CREATED',
          'NO_SUCH_WINDOW','INVALID_SESSION_ID','OTHER'} and
         r['message_signal'] in {'NOT_SEEN','MARIONETTE_HANDSHAKE','SANDBOX_DENIED',
          'NO_WINDOW','BROWSER_EXIT','TIMEOUT','UNKNOWN'},'V64_TRACE_W3C_INVALID')
    trace=r['trace_events']
    gate(type(trace) is list and trace==sorted(set(trace)) and len(trace)<=len(V64_TRACE_EVENTS) and
         all(type(t) is str and t in V64_TRACE_EVENTS for t in trace),'V64_TRACE_EVENTS_INVALID')
    timeline=r['timeline']
    gate(type(timeline) is list and len(timeline)<=len(V64_TRACE_PHASES),'V64_TRACE_TIMELINE_INVALID')
    indices=[];ms=[]
    for event in timeline:
        gate(type(event) is dict and set(event)=={'phase','elapsed_ms','firefox_state','trace_events'},
             'V64_TRACE_EVENT_SCHEMA_INVALID')
        gate(type(event['phase']) is str and event['phase'] in V64_TRACE_PHASES,
             'V64_TRACE_PHASE_INVALID')
        gate(type(event['firefox_state']) is str and event['firefox_state'] in V64_PROCESS_STATES,
             'V64_TRACE_STATE_INVALID')
        gate(type(event['elapsed_ms']) is int and 0<=event['elapsed_ms']<=120000,
             'V64_TRACE_TIME_INVALID')
        subset=event['trace_events']
        gate(type(subset) is list and subset==sorted(set(subset)) and
             all(type(t) is str and t in V64_TRACE_EVENTS for t in subset),
             'V64_TRACE_PHASE_EVENTS_INVALID')
        indices.append(V64_TRACE_PHASES.index(event['phase']))
        ms.append(event['elapsed_ms'])
    gate(indices==sorted(set(indices)) and ms==sorted(ms),'V64_TRACE_ORDER_INVALID')
    gate(not r['private_root_cleaned'] or r['private_root_created'],
         'V64_TRACE_ROOT_CLEANED_WITHOUT_CREATION')
    gate(not r['webdriver_ready'] or port is not None,'V64_TRACE_DRIVER_WITHOUT_PORT')
    gate(not r['session_created'] or r['webdriver_ready'],'V64_TRACE_SESSION_WITHOUT_DRIVER')
    gate(not r['window_handles_verified'] or r['session_created'],'V64_TRACE_HANDLES_WITHOUT_SESSION')
    gate(not r['about_blank_verified'] or r['window_handles_verified'],
         'V64_TRACE_ABOUT_BLANK_WITHOUT_HANDLES')
    if r['classification']=='TRACE_PASS_DIAGNOSTIC_ONLY':
        gate(all(r[k] for k in ('driver_elf_arm64','firefox_executable','private_root_created',
            'private_root_cleaned','webdriver_ready','session_created',
            'window_handles_verified','about_blank_verified')) and
            port is not None and len(timeline)==len(V64_TRACE_PHASES) and
            r['session_http']=='NOT_SEEN' and r['handles_http']=='NOT_SEEN' and
            r['about_blank_http']=='NOT_SEEN' and r['firefox_pre_cleanup']=='LIVE' and
            r['w3c_error']=='NOT_SEEN' and r['message_signal']=='NOT_SEEN',
            'V64_TRACE_FALSE_PASS')
    if r['session_http']!='NOT_SEEN':
        gate(not r['session_created'] and r['w3c_error']!='NOT_SEEN' and
             r['message_signal']!='NOT_SEEN','V64_TRACE_SESSION_CONTRADICTION')
    if r['handles_http']!='NOT_SEEN':
        gate(r['session_created'] and not r['window_handles_verified'] and
             r['w3c_error']!='NOT_SEEN','V64_TRACE_HANDLES_CONTRADICTION')
    if r['about_blank_http']!='NOT_SEEN':
        gate(r['session_created'] and r['window_handles_verified'] and
             not r['about_blank_verified'] and r['w3c_error']!='NOT_SEEN',
             'V64_TRACE_ABOUT_BLANK_CONTRADICTION')
    return r

def docker_v64_trace_control(driver_path:str)->dict:
    gate(type(driver_path) is str and 0<len(driver_path)<=500,
         'V64_TRACE_DRIVER_PATH_INVALID')
    payload=json.dumps({'driver':driver_path},separators=(',',':')).encode()
    p=call(['docker','exec','-i','--user','1000:1000',
            '--env','PYTHONDONTWRITEBYTECODE=1',
            'cybersec-day03-zap','python3','-c',GECKO_V64_TRACE_CODE],
            input=payload,timeout=110)
    gate(p.returncode==0 and 0<len(p.stdout)<8192,'V64_TRACE_EXEC_FAILED')
    try:r=json.loads(p.stdout)
    except (ValueError,TypeError,UnicodeError) as exc:
        raise Blocked('V64_TRACE_JSON_INVALID') from exc
    return validate_v64_trace_control(r)

GECKO_V65_PROTOCOL_CODE = r'''
# V65 only: independent diagnostic control within the unchanged pinned ZAP
# container. This probes loopback native greeting before/after GeckoDriver.
# No raw trace, PID, session id, profile path, URL or browser logs emitted.
import json,os,re,stat,struct,sys,socket,time,signal,tempfile,subprocess,shutil
from urllib.request import Request,build_opener,ProxyHandler,HTTPRedirectHandler
from urllib.error import HTTPError,URLError
class NoRedirect(HTTPRedirectHandler):
 def redirect_request(self,*args):return None

def elf_arm64(path):
 if type(path) is not str or not path.startswith('/') or len(path)>500 or '\x00' in path:return False
 try:
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:s=os.fstat(fd);hdr=os.read(fd,20)
  finally:os.close(fd)
  return stat.S_ISREG(s.st_mode) and os.access(path,os.X_OK) and len(hdr)==20 and hdr[:6]==b'\x7fELF\x02\x01' and struct.unpack('<H',hdr[18:20])[0]==183
 except OSError:return False

def state(proc):
 if proc is None:return 'NOT_STARTED'
 r=proc.poll()
 return 'LIVE' if r is None else ('EXIT_ZERO' if r==0 else 'SIGNAL_EXIT' if r<0 else 'EXIT_NONZERO')

def safe_port(path):
 try:
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   s=os.fstat(fd);data=os.read(fd,33) if stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_size<=32 else b''
  finally:os.close(fd)
  m=re.fullmatch(rb'([0-9]{1,5})\s*',data)
  return int(m.group(1)) if m and 1<=int(m.group(1))<=65535 else None
 except OSError:return None

def hello(port):
 if type(port) is not int:return 'NOT_RUN'
 try:
  with socket.create_connection(('127.0.0.1',port),timeout=2) as s:
   s.settimeout(2);buf=b''
   while len(buf)<256 and b':' not in buf:buf+=s.recv(1)
   m=re.fullmatch(rb'([1-9][0-9]{0,2}):',buf)
   if not m:return 'INVALID_GREETING'
   count=int(m.group(1))
   if count>192:return 'INVALID_GREETING'
   body=b''
   while len(body)<count:
    part=s.recv(count-len(body))
    if not part:break
    body+=part
   if len(body)!=count:return 'INVALID_GREETING'
   obj=json.loads(body)
   if type(obj) is dict and obj.get('applicationType')=='gecko' and type(obj.get('marionetteProtocol')) is int and obj.get('marionetteProtocol')>=3:return 'PASS'
   return 'INVALID_GREETING'
 except (OSError,TimeoutError):return 'TRANSPORT_ERROR'
 except (ValueError,TypeError,UnicodeError):return 'INVALID_GREETING'

def proc_security(pid):
 try:
  fd=os.open('/proc/'+str(pid)+'/status',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:body=os.read(fd,16384)
  finally:os.close(fd)
  s=re.search(rb'(?m)^Seccomp:\s*([0-9]+)$',body)
  n=re.search(rb'(?m)^NoNewPrivs:\s*([0-9]+)$',body)
  return {'seccomp':s.group(1).decode() if s and s.group(1) in (b'0',b'1',b'2') else 'UNKNOWN',
          'no_new_privs':n.group(1).decode() if n and n.group(1) in (b'0',b'1') else 'UNKNOWN'}
 except (OSError,ValueError):return {'seccomp':'UNKNOWN','no_new_privs':'UNKNOWN'}

CODES={
 'SANDBOX':(rb'sandbox',), 'SECCOMP':(rb'seccomp',),
 'OPERATION_NOT_PERMITTED':(rb'operation not permitted',),
 'PERMISSION_DENIED':(rb'permission denied',),
 'MARIONETTE':(rb'marionette',),
 'BROWSER_CRASH':(rb'mozcrash',rb'crash reporter',rb'segmentation fault',rb'sigsegv',rb'sigabrt'),
 'PROFILE_ERROR':(rb'profile.*locked',rb'profile.*permission'),
 'WINDOW_ERROR':(rb'no such window',rb'browsing context has been discarded')}
def signals(f):
 if f is None:return [],False
 try:
  size=os.fstat(f.fileno()).st_size
  raw=os.pread(f.fileno(),65536,0).lower()
  return sorted(k for k,patterns in CODES.items() if any(re.search(p,raw) for p in patterns)),size>65536
 except (OSError,ValueError):return [],True

def http_err(raw):
 try:
  obj=json.loads(raw[:4096]);v=obj.get('value') if type(obj) is dict else None
  e=v.get('error') if type(v) is dict else None
  msg=v.get('message') if type(v) is dict else None
 except (TypeError,ValueError,UnicodeError):e=msg=None
 s=msg.lower()[:512] if type(msg) is str else ''
 code={'unknown error':'UNKNOWN_ERROR','session not created':'SESSION_NOT_CREATED','no such window':'NO_SUCH_WINDOW','invalid session id':'INVALID_SESSION_ID'}.get(e,'OTHER')
 signal='MARIONETTE' if ('marionette' in s or 'handshake' in s) else ('SANDBOX' if ('sandbox' in s or 'seccomp' in s) else ('BROWSER_EXIT' if ('exited' in s or 'closed' in s) else ('NO_WINDOW' if 'window' in s else 'UNKNOWN')))
 return code,signal

def stop(p):
 if p is None:return
 if p.poll() is None:
  try:os.killpg(p.pid,signal.SIGTERM)
  except (ProcessLookupError,PermissionError):pass
 try:p.wait(timeout=3)
 except subprocess.TimeoutExpired:
  try:os.killpg(p.pid,signal.SIGKILL)
  except (ProcessLookupError,PermissionError):pass
  try:p.wait(timeout=3)
  except subprocess.TimeoutExpired:pass

r={'schema':'stage70-v65-native-protocol-differential-v1','mode':'ISOLATED_LOOPBACK_ABOUT_BLANK',
   'classification':'NOT_RUN','driver_elf_arm64':False,'firefox_executable':False,
   'private_root_created':False,'private_root_cleaned':False,'marionette_port_published':False,
   'native_before_driver':'NOT_RUN','native_after_newsession':'NOT_RUN',
   'webdriver_ready':False,'session_created':False,'window_verified':False,
   'session_http':'NOT_SEEN','window_http':'NOT_SEEN','w3c_error':'NOT_SEEN','message_signal':'NOT_SEEN',
   'firefox_after_newsession':'NOT_STARTED','firefox_pre_cleanup':'NOT_STARTED','firefox_post_cleanup':'NOT_STARTED',
   'firefox_security':{'seccomp':'UNKNOWN','no_new_privs':'UNKNOWN'},
   'firefox_log_signals':[],'driver_log_signals':[],
   'firefox_log_truncated':False,'driver_log_truncated':False}
ff=gd=None;flog=glog=None;root=None;session=None;endpoint=None;op=build_opener(ProxyHandler({}),NoRedirect())
try:
 data=json.loads(sys.stdin.buffer.read(1024));driver=data.get('driver') if type(data) is dict else None
 r['driver_elf_arm64']=elf_arm64(driver)
 binary='/usr/bin/firefox';r['firefox_executable']=os.path.isfile(binary) and os.access(binary,os.X_OK)
 if not r['driver_elf_arm64']:r['classification']='DRIVER_INVALID'
 elif not r['firefox_executable']:r['classification']='FIREFOX_INVALID'
 else:
  root=tempfile.mkdtemp(prefix='stage70-v65-',dir='/tmp');os.chmod(root,0o700)
  st=os.lstat(root)
  if st.st_uid!=os.geteuid() or not stat.S_ISDIR(st.st_mode) or st.st_mode&0o777!=0o700:r['classification']='PRIVATE_ROOT_UNSAFE'
  else:
   r['private_root_created']=True
   profile=os.path.join(root,'profile');home=os.path.join(root,'home')
   os.mkdir(profile,0o700);os.mkdir(home,0o700)
   env=os.environ.copy();env['HOME']=home;env['TMPDIR']=root;env['MOZ_HEADLESS']='1'
   flog=tempfile.TemporaryFile(mode='w+b',dir=root);glog=tempfile.TemporaryFile(mode='w+b',dir=root)
   ff=subprocess.Popen([binary,'--headless','--no-remote','--marionette','--profile',profile,'about:blank'],
       stdout=subprocess.DEVNULL,stderr=flog,env=env,start_new_session=True)
   r['firefox_security']=proc_security(ff.pid)
   port=None;deadline=time.monotonic()+18
   while time.monotonic()<deadline and ff.poll() is None:
    port=safe_port(os.path.join(profile,'MarionetteActivePort'))
    if port is not None:break
    time.sleep(.2)
   r['marionette_port_published']=port is not None
   if port is None:r['classification']='FIREFOX_EARLY_EXIT' if ff.poll() is not None else 'MARIONETTE_PORT_NOT_PUBLISHED'
   else:
    r['native_before_driver']=hello(port)
    if r['native_before_driver']!='PASS':r['classification']='NATIVE_HANDSHAKE_BEFORE_FAILED'
    else:
     # Connection closes before GeckoDriver starts; never share TCP socket.
     time.sleep(.15)
     with socket.socket() as s:s.bind(('127.0.0.1',0));driver_port=s.getsockname()[1]
     endpoint='http://127.0.0.1:'+str(driver_port)
     gd=subprocess.Popen([driver,'--connect-existing','--marionette-port',str(port),
            '--host','127.0.0.1','--port',str(driver_port),'--log','trace'],
            stdout=subprocess.DEVNULL,stderr=glog,env=env,start_new_session=True)
     for _ in range(35):
      if gd.poll() is not None or ff.poll() is not None:break
      try:
       with op.open(Request(endpoint+'/status'),timeout=.5) as resp:
        if resp.status==200 and type(json.loads(resp.read(2048))) is dict:
         r['webdriver_ready']=True;break
      except (URLError,TimeoutError,OSError,ValueError):pass
      time.sleep(.2)
     if not r['webdriver_ready']:r['classification']='DRIVER_SERVER_UNAVAILABLE'
     else:
      payload={'capabilities':{'alwaysMatch':{'browserName':'firefox'}}}
      request=Request(endpoint+'/session',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'},method='POST')
      try:
       with op.open(request,timeout=18) as resp:doc=json.loads(resp.read(8192))
       v=doc.get('value') if type(doc) is dict else None
       sid=v.get('sessionId') if type(v) is dict else None
       if type(sid) is str and re.fullmatch('[A-Za-z0-9-]{1,100}',sid):session=sid;r['session_created']=True
       else:r['classification']='SESSION_INVALID_RESPONSE'
      except HTTPError as err:
       r['session_http']=str(err.code) if str(err.code) in ('400','401','403','404','408','409','429','500','502','503','504') else 'OTHER'
       r['w3c_error'],r['message_signal']=http_err(err.read(4096));err.close()
       r['classification']='SESSION_HTTP_ERROR'
      except (OSError,URLError,TimeoutError):r['classification']='SESSION_TRANSPORT_ERROR'
      except (ValueError,TypeError):r['classification']='SESSION_INVALID_RESPONSE'
      r['firefox_after_newsession']=state(ff)
      r['native_after_newsession']=hello(port) if r['firefox_after_newsession']=='LIVE' else 'PROCESS_EXITED'
      if r['session_created']:
       try:
        with op.open(Request(endpoint+'/session/'+session+'/window/handles'),timeout=6) as resp:
         obj=json.loads(resp.read(8192));v=obj.get('value') if type(obj) is dict else None
         r['window_verified']=type(v) is list and 1<=len(v)<=8 and all(type(x) is str and 1<=len(x)<=256 for x in v)
         r['classification']='PROTOCOL_PASS_DIAGNOSTIC_ONLY' if r['window_verified'] else 'WINDOW_NOT_READY'
       except HTTPError as err:
        r['window_http']=str(err.code) if str(err.code) in ('400','401','403','404','408','409','429','500','502','503','504') else 'OTHER'
        r['w3c_error'],r['message_signal']=http_err(err.read(4096));err.close()
        r['classification']='WINDOW_HTTP_ERROR'
       except (URLError,TimeoutError,OSError):r['classification']='WINDOW_TRANSPORT_ERROR'
       except (ValueError,TypeError):r['classification']='WINDOW_INVALID_RESPONSE'
except Exception:r['classification']='CONTROL_INTERNAL_ERROR'
finally:
 r['firefox_pre_cleanup']=state(ff)
 if session and endpoint:
  try:op.open(Request(endpoint+'/session/'+session,method='DELETE'),timeout=2).close()
  except (OSError,URLError,TimeoutError):pass
 stop(gd);stop(ff)
 r['firefox_post_cleanup']=state(ff)
 if flog is not None:r['firefox_log_signals'],r['firefox_log_truncated']=signals(flog);flog.close()
 if glog is not None:r['driver_log_signals'],r['driver_log_truncated']=signals(glog);glog.close()
 if root is not None:
  try:shutil.rmtree(root)
  except OSError:pass
  r['private_root_cleaned']=not os.path.exists(root)
 if not r['private_root_cleaned'] and r['private_root_created']:r['classification']='PRIVATE_ROOT_CLEANUP_FAILED'
 if r['classification']=='PROTOCOL_PASS_DIAGNOSTIC_ONLY' and not (
     r['native_before_driver']=='PASS' and r['native_after_newsession']=='PASS' and
     r['firefox_after_newsession']=='LIVE' and r['firefox_pre_cleanup']=='LIVE' and
     r['window_verified'] and r['session_created'] and r['private_root_cleaned']):
  r['classification']='UNSTABLE_DIAGNOSTIC_NOT_PASS'
 print(json.dumps(r,sort_keys=True,separators=(',',':')))
'''

V65_KEYS={'schema','mode','classification','driver_elf_arm64','firefox_executable',
 'private_root_created','private_root_cleaned','marionette_port_published',
 'native_before_driver','native_after_newsession','webdriver_ready','session_created','window_verified',
 'session_http','window_http','w3c_error','message_signal','firefox_after_newsession','firefox_pre_cleanup',
 'firefox_post_cleanup','firefox_security','firefox_log_signals','driver_log_signals',
 'firefox_log_truncated','driver_log_truncated'}
V65_CLASS={'NOT_RUN','DRIVER_INVALID','FIREFOX_INVALID','PRIVATE_ROOT_UNSAFE','FIREFOX_EARLY_EXIT',
 'MARIONETTE_PORT_NOT_PUBLISHED','NATIVE_HANDSHAKE_BEFORE_FAILED','DRIVER_SERVER_UNAVAILABLE',
 'SESSION_INVALID_RESPONSE','SESSION_HTTP_ERROR','SESSION_TRANSPORT_ERROR','WINDOW_NOT_READY',
 'WINDOW_HTTP_ERROR','WINDOW_TRANSPORT_ERROR','WINDOW_INVALID_RESPONSE','CONTROL_INTERNAL_ERROR',
 'PRIVATE_ROOT_CLEANUP_FAILED','PROTOCOL_PASS_DIAGNOSTIC_ONLY','UNSTABLE_DIAGNOSTIC_NOT_PASS'}
V65_HELLO={'NOT_RUN','PASS','TRANSPORT_ERROR','INVALID_GREETING','PROCESS_EXITED'}
V65_PROC={'NOT_STARTED','LIVE','EXIT_ZERO','EXIT_NONZERO','SIGNAL_EXIT'}
V65_SIGNALS={'SANDBOX','SECCOMP','OPERATION_NOT_PERMITTED','PERMISSION_DENIED',
             'MARIONETTE','BROWSER_CRASH','PROFILE_ERROR','WINDOW_ERROR'}
V65_HTTP={'NOT_SEEN','400','401','403','404','408','409','429','500','502','503','504','OTHER'}

def validate_v65_protocol(r):
    gate(type(r) is dict and set(r)==V65_KEYS,'V65_SCHEMA_INVALID')
    gate(r['schema']=='stage70-v65-native-protocol-differential-v1' and
         r['mode']=='ISOLATED_LOOPBACK_ABOUT_BLANK','V65_MODE_INVALID')
    gate(type(r['classification']) is str and r['classification'] in V65_CLASS,'V65_CLASS_INVALID')
    for k in ('driver_elf_arm64','firefox_executable','private_root_created','private_root_cleaned',
              'marionette_port_published','webdriver_ready','session_created','window_verified',
              'firefox_log_truncated','driver_log_truncated'):
        gate(type(r[k]) is bool,'V65_BOOLEAN_INVALID_'+k)
    gate(not r['private_root_cleaned'] or r['private_root_created'],'V65_CLEANUP_WITHOUT_ROOT')
    gate(not r['marionette_port_published'] or r['private_root_created'],'V65_PORT_WITHOUT_ROOT')
    gate(type(r['native_before_driver']) is str and r['native_before_driver'] in V65_HELLO,'V65_HELLO_BEFORE_INVALID')
    gate(type(r['native_after_newsession']) is str and r['native_after_newsession'] in V65_HELLO,'V65_HELLO_AFTER_INVALID')
    gate(r['native_before_driver']=='NOT_RUN' or r['marionette_port_published'],'V65_HELLO_WITHOUT_PORT')
    gate(r['native_after_newsession']=='NOT_RUN' or r['native_before_driver']=='PASS', 'V65_POST_WITHOUT_PRE')
    gate(not r['webdriver_ready'] or r['native_before_driver']=='PASS','V65_DRIVER_WITHOUT_NATIVE')
    gate(not r['session_created'] or r['webdriver_ready'],'V65_SESSION_WITHOUT_DRIVER')
    gate(not r['window_verified'] or r['session_created'],'V65_WINDOW_WITHOUT_SESSION')
    for k in ('firefox_after_newsession','firefox_pre_cleanup','firefox_post_cleanup'):
        gate(type(r[k]) is str and r[k] in V65_PROC,'V65_PROCESS_INVALID_'+k)
    gate(r['native_after_newsession']!='PROCESS_EXITED' or
         r['firefox_after_newsession'] in {'EXIT_ZERO','EXIT_NONZERO','SIGNAL_EXIT'},'V65_EXIT_MISMATCH')
    gate(r['native_after_newsession']=='NOT_RUN' or
         r['firefox_after_newsession']!='NOT_STARTED','V65_POST_BEFORE_START')
    sec=r['firefox_security']
    gate(type(sec) is dict and set(sec)=={'seccomp','no_new_privs'} and
         type(sec['seccomp']) is str and sec['seccomp'] in {'0','1','2','UNKNOWN'} and
         type(sec['no_new_privs']) is str and sec['no_new_privs'] in {'0','1','UNKNOWN'},
         'V65_SECURITY_SCHEMA_INVALID')
    for k in ('firefox_log_signals','driver_log_signals'):
        v=r[k]
        gate(type(v) is list and v==sorted(set(v)) and len(v)<=len(V65_SIGNALS) and
             all(type(e) is str and e in V65_SIGNALS for e in v),'V65_SIGNALS_INVALID_'+k)
    gate(type(r['session_http']) is str and r['session_http'] in V65_HTTP and
         type(r['window_http']) is str and r['window_http'] in V65_HTTP,'V65_HTTP_INVALID')
    gate(type(r['w3c_error']) is str and r['w3c_error'] in {'NOT_SEEN','UNKNOWN_ERROR',
        'SESSION_NOT_CREATED','NO_SUCH_WINDOW','INVALID_SESSION_ID','OTHER'} and
        type(r['message_signal']) is str and r['message_signal'] in
        {'NOT_SEEN','MARIONETTE','SANDBOX','BROWSER_EXIT','NO_WINDOW','UNKNOWN'},'V65_ERROR_INVALID')
    gate(r['session_http']=='NOT_SEEN' or
         (not r['session_created'] and r['w3c_error']!='NOT_SEEN' and r['message_signal']!='NOT_SEEN'),
         'V65_FAILED_SESSION_INCONSISTENT')
    gate(r['window_http']=='NOT_SEEN' or
         (r['session_created'] and not r['window_verified'] and r['w3c_error']!='NOT_SEEN'),
         'V65_FAILED_WINDOW_INCONSISTENT')
    if r['classification']=='PROTOCOL_PASS_DIAGNOSTIC_ONLY':
        gate(all(r[k] for k in ('driver_elf_arm64','firefox_executable','private_root_created',
          'private_root_cleaned','marionette_port_published','webdriver_ready',
          'session_created','window_verified')) and
          r['native_before_driver']=='PASS' and r['native_after_newsession']=='PASS' and
          r['firefox_after_newsession']=='LIVE' and r['firefox_pre_cleanup']=='LIVE' and
          r['session_http']=='NOT_SEEN' and r['window_http']=='NOT_SEEN' and
          r['w3c_error']=='NOT_SEEN' and r['message_signal']=='NOT_SEEN',
          'V65_FALSE_DIAGNOSTIC_PASS')
    return r

def docker_v65_protocol_probe(driver_path:str)->dict:
    gate(type(driver_path) is str and driver_path.startswith('/') and
         0<len(driver_path)<=500 and '\x00' not in driver_path,'V65_DRIVER_PATH_INVALID')
    p=call(['docker','exec','-i','--user','1000:1000',
            '--env','PYTHONDONTWRITEBYTECODE=1','cybersec-day03-zap',
            'python3','-c',GECKO_V65_PROTOCOL_CODE],
           input=json.dumps({'driver':driver_path},separators=(',',':')).encode(),timeout=120)
    gate(p.returncode==0 and 0<len(p.stdout)<8192,'V65_EXEC_FAILED')
    try:data=json.loads(p.stdout)
    except (TypeError,UnicodeError,ValueError) as e:raise Blocked('V65_JSON_INVALID') from e
    return validate_v65_protocol(data)


# V66: paired native-only baseline vs GeckoDriver start/session boundaries.
# All external processes run in the same pinned, unprivileged Docker service.
GECKO_V66_PAIRED_CODE = r'''
# V65 only: independent diagnostic control within the unchanged pinned ZAP
# container. This probes loopback native greeting before/after GeckoDriver.
# No raw trace, PID, session id, profile path, URL or browser logs emitted.
import json,os,re,stat,struct,sys,socket,time,signal,tempfile,subprocess,shutil
from urllib.request import Request,build_opener,ProxyHandler,HTTPRedirectHandler
from urllib.error import HTTPError,URLError
class NoRedirect(HTTPRedirectHandler):
 def redirect_request(self,*args):return None

def elf_arm64(path):
 if type(path) is not str or not path.startswith('/') or len(path)>500 or '\x00' in path:return False
 try:
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:s=os.fstat(fd);hdr=os.read(fd,20)
  finally:os.close(fd)
  return stat.S_ISREG(s.st_mode) and os.access(path,os.X_OK) and len(hdr)==20 and hdr[:6]==b'\x7fELF\x02\x01' and struct.unpack('<H',hdr[18:20])[0]==183
 except OSError:return False

def state(proc):
 if proc is None:return 'NOT_STARTED'
 r=proc.poll()
 return 'LIVE' if r is None else ('EXIT_ZERO' if r==0 else 'SIGNAL_EXIT' if r<0 else 'EXIT_NONZERO')

def safe_port(path):
 try:
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   s=os.fstat(fd);data=os.read(fd,33) if stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_size<=32 else b''
  finally:os.close(fd)
  m=re.fullmatch(rb'([0-9]{1,5})\s*',data)
  return int(m.group(1)) if m and 1<=int(m.group(1))<=65535 else None
 except OSError:return None

def hello(port):
 if type(port) is not int:return 'NOT_RUN'
 try:
  with socket.create_connection(('127.0.0.1',port),timeout=2) as s:
   s.settimeout(2);buf=b''
   while len(buf)<256 and b':' not in buf:buf+=s.recv(1)
   m=re.fullmatch(rb'([1-9][0-9]{0,2}):',buf)
   if not m:return 'INVALID_GREETING'
   count=int(m.group(1))
   if count>192:return 'INVALID_GREETING'
   body=b''
   while len(body)<count:
    part=s.recv(count-len(body))
    if not part:break
    body+=part
   if len(body)!=count:return 'INVALID_GREETING'
   obj=json.loads(body)
   if type(obj) is dict and obj.get('applicationType')=='gecko' and type(obj.get('marionetteProtocol')) is int and obj.get('marionetteProtocol')>=3:return 'PASS'
   return 'INVALID_GREETING'
 except (OSError,TimeoutError):return 'TRANSPORT_ERROR'
 except (ValueError,TypeError,UnicodeError):return 'INVALID_GREETING'

def proc_security(pid):
 try:
  fd=os.open('/proc/'+str(pid)+'/status',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:body=os.read(fd,16384)
  finally:os.close(fd)
  s=re.search(rb'(?m)^Seccomp:\s*([0-9]+)$',body)
  n=re.search(rb'(?m)^NoNewPrivs:\s*([0-9]+)$',body)
  return {'seccomp':s.group(1).decode() if s and s.group(1) in (b'0',b'1',b'2') else 'UNKNOWN',
          'no_new_privs':n.group(1).decode() if n and n.group(1) in (b'0',b'1') else 'UNKNOWN'}
 except (OSError,ValueError):return {'seccomp':'UNKNOWN','no_new_privs':'UNKNOWN'}

CODES={
 'SANDBOX':(rb'sandbox',), 'SECCOMP':(rb'seccomp',),
 'OPERATION_NOT_PERMITTED':(rb'operation not permitted',),
 'PERMISSION_DENIED':(rb'permission denied',),
 'MARIONETTE':(rb'marionette',),
 'BROWSER_CRASH':(rb'mozcrash',rb'crash reporter',rb'segmentation fault',rb'sigsegv',rb'sigabrt'),
 'PROFILE_ERROR':(rb'profile.*locked',rb'profile.*permission'),
 'WINDOW_ERROR':(rb'no such window',rb'browsing context has been discarded')}
def signals(f):
 if f is None:return [],False
 try:
  size=os.fstat(f.fileno()).st_size
  raw=os.pread(f.fileno(),65536,0).lower()
  return sorted(k for k,patterns in CODES.items() if any(re.search(p,raw) for p in patterns)),size>65536
 except (OSError,ValueError):return [],True

def http_err(raw):
 try:
  obj=json.loads(raw[:4096]);v=obj.get('value') if type(obj) is dict else None
  e=v.get('error') if type(v) is dict else None
  msg=v.get('message') if type(v) is dict else None
 except (TypeError,ValueError,UnicodeError):e=msg=None
 s=msg.lower()[:512] if type(msg) is str else ''
 code={'unknown error':'UNKNOWN_ERROR','session not created':'SESSION_NOT_CREATED','no such window':'NO_SUCH_WINDOW','invalid session id':'INVALID_SESSION_ID'}.get(e,'OTHER')
 signal='MARIONETTE' if ('marionette' in s or 'handshake' in s) else ('SANDBOX' if ('sandbox' in s or 'seccomp' in s) else ('BROWSER_EXIT' if ('exited' in s or 'closed' in s) else ('NO_WINDOW' if 'window' in s else 'UNKNOWN')))
 return code,signal

def stop(p):
 if p is None:return
 if p.poll() is None:
  try:os.killpg(p.pid,signal.SIGTERM)
  except (ProcessLookupError,PermissionError):pass
 try:p.wait(timeout=3)
 except subprocess.TimeoutExpired:
  try:os.killpg(p.pid,signal.SIGKILL)
  except (ProcessLookupError,PermissionError):pass
  try:p.wait(timeout=3)
  except subprocess.TimeoutExpired:pass

r={'schema':'stage70-v66-paired-native-driver-v1','mode':'ISOLATED_PAIRED_NATIVE_DRIVER_ABOUT_BLANK',
   'classification':'NOT_RUN','driver_elf_arm64':False,'firefox_executable':False,
   'private_root_created':False,'private_root_cleaned':False,'marionette_port_published':False,
   'native_before_driver':'NOT_RUN','native_after_newsession':'NOT_RUN',
   'native_baseline':[],'native_after_driver_start':'NOT_RUN',
   'firefox_after_driver_start':'NOT_STARTED',
   'driver_after_newsession':'NOT_STARTED',
   'driver_pre_cleanup':'NOT_STARTED','driver_post_cleanup':'NOT_STARTED',
   'webdriver_ready':False,'session_created':False,'window_verified':False,
   'session_http':'NOT_SEEN','window_http':'NOT_SEEN','w3c_error':'NOT_SEEN','message_signal':'NOT_SEEN',
   'firefox_after_newsession':'NOT_STARTED','firefox_pre_cleanup':'NOT_STARTED','firefox_post_cleanup':'NOT_STARTED',
   'firefox_security':{'seccomp':'UNKNOWN','no_new_privs':'UNKNOWN'},
   'firefox_log_signals':[],'driver_log_signals':[],
   'firefox_log_truncated':False,'driver_log_truncated':False}
ff=gd=None;flog=glog=None;root=None;session=None;endpoint=None;op=build_opener(ProxyHandler({}),NoRedirect())
try:
 data=json.loads(sys.stdin.buffer.read(1024));driver=data.get('driver') if type(data) is dict else None
 r['driver_elf_arm64']=elf_arm64(driver)
 binary='/usr/bin/firefox';r['firefox_executable']=os.path.isfile(binary) and os.access(binary,os.X_OK)
 if not r['driver_elf_arm64']:r['classification']='DRIVER_INVALID'
 elif not r['firefox_executable']:r['classification']='FIREFOX_INVALID'
 else:
  root=tempfile.mkdtemp(prefix='stage70-v66-',dir='/tmp');os.chmod(root,0o700)
  st=os.lstat(root)
  if st.st_uid!=os.geteuid() or not stat.S_ISDIR(st.st_mode) or st.st_mode&0o777!=0o700:r['classification']='PRIVATE_ROOT_UNSAFE'
  else:
   r['private_root_created']=True
   profile=os.path.join(root,'profile');home=os.path.join(root,'home')
   os.mkdir(profile,0o700);os.mkdir(home,0o700)
   env=os.environ.copy();env['HOME']=home;env['TMPDIR']=root;env['MOZ_HEADLESS']='1'
   flog=tempfile.TemporaryFile(mode='w+b',dir=root);glog=tempfile.TemporaryFile(mode='w+b',dir=root)
   ff=subprocess.Popen([binary,'--headless','--no-remote','--marionette','--profile',profile,'about:blank'],
       stdout=subprocess.DEVNULL,stderr=flog,env=env,start_new_session=True)
   r['firefox_security']=proc_security(ff.pid)
   port=None;deadline=time.monotonic()+18
   while time.monotonic()<deadline and ff.poll() is None:
    port=safe_port(os.path.join(profile,'MarionetteActivePort'))
    if port is not None:break
    time.sleep(.2)
   r['marionette_port_published']=port is not None
   if port is None:r['classification']='FIREFOX_EARLY_EXIT' if ff.poll() is not None else 'MARIONETTE_PORT_NOT_PUBLISHED'
   else:
    # Three sequential, short-lived native handshakes BEFORE the driver.
    # The baseline is observed with the same Firefox instance and no driver.
    for attempt in range(3):
     r['native_baseline'].append(hello(port) if ff.poll() is None else 'PROCESS_EXITED')
     if attempt<2:time.sleep(.4)
    r['native_before_driver']=r['native_baseline'][-1]
    if r['native_baseline']!=['PASS','PASS','PASS']:
     r['classification']='NATIVE_BASELINE_UNSTABLE'
    elif r['firefox_security']!={'seccomp':'2','no_new_privs':'1'}:
     r['classification']='SECURITY_STATE_UNVERIFIED'
    else:
     # Native socket closes before starting GeckoDriver; never reuse sockets.
     time.sleep(.15)
     with socket.socket() as s:s.bind(('127.0.0.1',0));driver_port=s.getsockname()[1]
     endpoint='http://127.0.0.1:'+str(driver_port)
     gd=subprocess.Popen([driver,'--connect-existing','--marionette-port',str(port),
            '--host','127.0.0.1','--port',str(driver_port),'--log','trace'],
            stdout=subprocess.DEVNULL,stderr=glog,env=env,start_new_session=True)
     for _ in range(35):
      if gd.poll() is not None or ff.poll() is not None:break
      try:
       with op.open(Request(endpoint+'/status'),timeout=.5) as resp:
        if resp.status==200 and type(json.loads(resp.read(2048))) is dict:
         r['webdriver_ready']=True;break
      except (URLError,TimeoutError,OSError,ValueError):pass
      time.sleep(.2)
     r['firefox_after_driver_start']=state(ff)
     r['native_after_driver_start']=hello(port) if r['firefox_after_driver_start']=='LIVE' else 'PROCESS_EXITED'
     if not r['webdriver_ready']:r['classification']='DRIVER_SERVER_UNAVAILABLE'
     elif r['native_after_driver_start']!='PASS':r['classification']='NATIVE_AFTER_DRIVER_START_FAILED'
     else:
      payload={'capabilities':{'alwaysMatch':{'browserName':'firefox'}}}
      request=Request(endpoint+'/session',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'},method='POST')
      try:
       with op.open(request,timeout=18) as resp:doc=json.loads(resp.read(8192))
       v=doc.get('value') if type(doc) is dict else None
       sid=v.get('sessionId') if type(v) is dict else None
       if type(sid) is str and re.fullmatch('[A-Za-z0-9-]{1,100}',sid):session=sid;r['session_created']=True
       else:r['classification']='SESSION_INVALID_RESPONSE'
      except HTTPError as err:
       r['session_http']=str(err.code) if str(err.code) in ('400','401','403','404','408','409','429','500','502','503','504') else 'OTHER'
       r['w3c_error'],r['message_signal']=http_err(err.read(4096));err.close()
       r['classification']='SESSION_HTTP_ERROR'
      except (OSError,URLError,TimeoutError):r['classification']='SESSION_TRANSPORT_ERROR'
      except (ValueError,TypeError):r['classification']='SESSION_INVALID_RESPONSE'
      r['firefox_after_newsession']=state(ff)
      r['driver_after_newsession']=state(gd)
      r['native_after_newsession']=hello(port) if r['firefox_after_newsession']=='LIVE' else 'PROCESS_EXITED'
      if r['session_created']:
       try:
        with op.open(Request(endpoint+'/session/'+session+'/window/handles'),timeout=6) as resp:
         obj=json.loads(resp.read(8192));v=obj.get('value') if type(obj) is dict else None
         r['window_verified']=type(v) is list and 1<=len(v)<=8 and all(type(x) is str and 1<=len(x)<=256 for x in v)
         r['classification']='PAIRED_PASS_DIAGNOSTIC_ONLY' if r['window_verified'] else 'WINDOW_NOT_READY'
       except HTTPError as err:
        r['window_http']=str(err.code) if str(err.code) in ('400','401','403','404','408','409','429','500','502','503','504') else 'OTHER'
        r['w3c_error'],r['message_signal']=http_err(err.read(4096));err.close()
        r['classification']='WINDOW_HTTP_ERROR'
       except (URLError,TimeoutError,OSError):r['classification']='WINDOW_TRANSPORT_ERROR'
       except (ValueError,TypeError):r['classification']='WINDOW_INVALID_RESPONSE'
except Exception:r['classification']='CONTROL_INTERNAL_ERROR'
finally:
 r['firefox_pre_cleanup']=state(ff)
 r['driver_pre_cleanup']=state(gd)
 if session and endpoint:
  try:op.open(Request(endpoint+'/session/'+session,method='DELETE'),timeout=2).close()
  except (OSError,URLError,TimeoutError):pass
 stop(gd);stop(ff)
 r['firefox_post_cleanup']=state(ff)
 r['driver_post_cleanup']=state(gd)
 if flog is not None:r['firefox_log_signals'],r['firefox_log_truncated']=signals(flog);flog.close()
 if glog is not None:r['driver_log_signals'],r['driver_log_truncated']=signals(glog);glog.close()
 if root is not None:
  try:shutil.rmtree(root)
  except OSError:pass
  r['private_root_cleaned']=not os.path.exists(root)
 if not r['private_root_cleaned'] and r['private_root_created']:r['classification']='PRIVATE_ROOT_CLEANUP_FAILED'
 if r['classification']=='PAIRED_PASS_DIAGNOSTIC_ONLY' and not (
     r['native_baseline']==['PASS','PASS','PASS'] and r['native_after_driver_start']=='PASS' and r['native_after_newsession']=='PASS' and
     r['firefox_after_newsession']=='LIVE' and r['firefox_pre_cleanup']=='LIVE' and
     r['window_verified'] and r['session_created'] and r['private_root_cleaned'] and
     r['driver_pre_cleanup']=='LIVE' and r['firefox_security']=={'seccomp':'2','no_new_privs':'1'}):
  r['classification']='UNSTABLE_DIAGNOSTIC_NOT_PASS'
 print(json.dumps(r,sort_keys=True,separators=(',',':')))

'''

V66_ADDED_KEYS={'native_baseline','native_after_driver_start','firefox_after_driver_start',
                'driver_after_newsession','driver_pre_cleanup','driver_post_cleanup'}
V66_CLASS_EXTRA={'NATIVE_BASELINE_UNSTABLE','SECURITY_STATE_UNVERIFIED',
                 'NATIVE_AFTER_DRIVER_START_FAILED','PAIRED_PASS_DIAGNOSTIC_ONLY'}

def validate_v66_paired(r):
    gate(type(r) is dict and set(r)==V65_KEYS|V66_ADDED_KEYS,'V66_SCHEMA_INVALID')
    gate(r.get('schema')=='stage70-v66-paired-native-driver-v1' and
         r.get('mode')=='ISOLATED_PAIRED_NATIVE_DRIVER_ABOUT_BLANK','V66_MODE_INVALID')
    gate(type(r['native_baseline']) is list and len(r['native_baseline'])<=3 and
         all(type(x) is str and x in V65_HELLO for x in r['native_baseline']),
         'V66_BASELINE_INVALID')
    gate(type(r['classification']) is str and
         r['classification'] in V65_CLASS|V66_CLASS_EXTRA,'V66_CLASS_INVALID')
    for k in ('native_after_driver_start',):
        gate(type(r[k]) is str and r[k] in V65_HELLO,'V66_NATIVE_INVALID')
    for k in ('firefox_after_driver_start','driver_after_newsession',
              'driver_pre_cleanup','driver_post_cleanup'):
        gate(type(r[k]) is str and r[k] in V65_PROC,'V66_PROCESS_INVALID')
    # Re-use all V65 shape, HTTP, error, log, security and cleanup checks.
    old={k:r[k] for k in V65_KEYS}
    old['schema']='stage70-v65-native-protocol-differential-v1'
    old['mode']='ISOLATED_LOOPBACK_ABOUT_BLANK'
    old['classification']=('PROTOCOL_PASS_DIAGNOSTIC_ONLY'
          if r['classification']=='PAIRED_PASS_DIAGNOSTIC_ONLY' else
          (r['classification'] if r['classification'] in V65_CLASS else 'CONTROL_INTERNAL_ERROR'))
    validate_v65_protocol(old)
    if r['native_baseline']:
        gate(r['marionette_port_published'] and len(r['native_baseline'])==3 and
             r['native_before_driver']==r['native_baseline'][-1],
             'V66_BASELINE_SEQUENCE_INVALID')
    gate(not r['webdriver_ready'] or
         r['native_baseline']==['PASS','PASS','PASS'],'V66_DRIVER_WITH_UNSTABLE_BASELINE')
    gate(not r['session_created'] or
         (r['native_after_driver_start']=='PASS' and r['webdriver_ready']),
         'V66_SESSION_WITHOUT_POST_DRIVER_NATIVE')
    gate(r['native_after_newsession']=='NOT_RUN' or
         r['native_after_driver_start']=='PASS', 'V66_SESSION_NATIVE_OUT_OF_ORDER')
    gate(r['native_after_driver_start']=='NOT_RUN' or
         r['firefox_after_driver_start']!='NOT_STARTED','V66_NATIVE_DRIVER_OUT_OF_ORDER')
    gate(r['driver_after_newsession']=='NOT_STARTED' or
         r['native_after_driver_start']=='PASS','V66_DRIVER_SESSION_OUT_OF_ORDER')
    gate(not r['private_root_created'] or
         r['driver_post_cleanup']!='LIVE','V66_DRIVER_CLEANUP_FAILED')
    if r['classification']=='NATIVE_BASELINE_UNSTABLE':
        gate(r['native_baseline']!=['PASS','PASS','PASS'] and
             not r['webdriver_ready'],'V66_FALSE_UNSTABLE')
    if r['classification']=='SECURITY_STATE_UNVERIFIED':
        gate(r['firefox_security']!={'seccomp':'2','no_new_privs':'1'} and
             not r['webdriver_ready'],'V66_FALSE_SECURITY_FAIL')
    if r['classification']=='NATIVE_AFTER_DRIVER_START_FAILED':
        gate(r['webdriver_ready'] and r['native_after_driver_start']!='PASS' and
             not r['session_created'],'V66_FALSE_START_FAIL')
    if r['classification']=='PAIRED_PASS_DIAGNOSTIC_ONLY':
        gate(r['native_baseline']==['PASS','PASS','PASS'] and
             r['native_after_driver_start']=='PASS' and
             r['native_after_newsession']=='PASS' and
             r['driver_after_newsession']=='LIVE' and
             r['driver_pre_cleanup']=='LIVE' and
             r['firefox_after_newsession']=='LIVE' and
             r['firefox_pre_cleanup']=='LIVE' and
             r['firefox_security']=={'seccomp':'2','no_new_privs':'1'} and
             r['private_root_cleaned'],'V66_FALSE_DIAGNOSTIC_PASS')
    return r

def docker_v66_paired_probe(driver_path:str)->dict:
    gate(type(driver_path) is str and driver_path.startswith('/') and
         0<len(driver_path)<=500 and '\x00' not in driver_path,'V66_DRIVER_PATH_INVALID')
    p=call(['docker','exec','-i','--user','1000:1000',
            '--env','PYTHONDONTWRITEBYTECODE=1','cybersec-day03-zap',
            'python3','-c',GECKO_V66_PAIRED_CODE],
           input=json.dumps({'driver':driver_path},separators=(',',':')).encode(),timeout=130)
    gate(p.returncode==0 and 0<len(p.stdout)<12000,'V66_EXEC_FAILED')
    try:data=json.loads(p.stdout)
    except (TypeError,UnicodeError,ValueError) as e:raise Blocked('V66_JSON_INVALID') from e
    return validate_v66_paired(data)

# V67: three independent, disjoint Firefox processes and private profiles.
# 0 clients = idle baseline, 1 client = disconnect baseline, 3 clients = replay.
# The container still runs as 1000:1000 under the pinned image and original
# Docker seccomp/NoNewPrivs/caps; no GeckoDriver and no target navigation.
GECKO_V67_NATIVE_COHORT_CODE = r'''
import json,os,stat,subprocess,socket,time,signal,tempfile,shutil,re

ROLES=(('NO_CLIENT',0),('ONE_CLIENT',1),('THREE_CLIENTS',3))
STATES=('NOT_STARTED','LIVE','EXIT_ZERO','EXIT_NONZERO','SIGNAL_EXIT')

def state(proc):
 if proc is None:return 'NOT_STARTED'
 x=proc.poll()
 return 'LIVE' if x is None else ('EXIT_ZERO' if x==0 else 'SIGNAL_EXIT' if x<0 else 'EXIT_NONZERO')

def security(pid):
 try:
  fd=os.open('/proc/'+str(pid)+'/status',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:b=os.read(fd,16384)
  finally:os.close(fd)
  s=re.search(rb'(?m)^Seccomp:\s*([0-9]+)$',b)
  n=re.search(rb'(?m)^NoNewPrivs:\s*([0-9]+)$',b)
  return {'seccomp':s.group(1).decode() if s and s.group(1) in (b'0',b'1',b'2') else 'UNKNOWN',
          'no_new_privs':n.group(1).decode() if n and n.group(1) in (b'0',b'1') else 'UNKNOWN'}
 except (OSError,ValueError):return {'seccomp':'UNKNOWN','no_new_privs':'UNKNOWN'}

def read_file(path,limit=4096):
 try:
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   s=os.fstat(fd)
   if not stat.S_ISREG(s.st_mode) or s.st_size>limit and s.st_size!=0:return None
   return os.read(fd,limit+1)[:limit].decode('ascii','strict')
  finally:os.close(fd)
 except (OSError,UnicodeError,ValueError):return None

def read_port(path):
 raw=read_file(path,32)
 m=re.fullmatch(r'([0-9]{1,5})\s*',raw) if raw is not None else None
 return int(m.group(1)) if m and 1<=int(m.group(1))<=65535 else None

def hello(port):
 if type(port) is not int:return 'NOT_RUN'
 try:
  with socket.create_connection(('127.0.0.1',port),timeout=2) as so:
   so.settimeout(2);h=b''
   while len(h)<5 and b':' not in h:
    q=so.recv(1)
    if not q:break
    h+=q
   m=re.fullmatch(rb'([1-9][0-9]{0,2}):',h)
   if not m or int(m.group(1))>192:return 'INVALID_GREETING'
   count=int(m.group(1));b=b''
   while len(b)<count:
    q=so.recv(count-len(b))
    if not q:break
    b+=q
   if len(b)!=count:return 'INVALID_GREETING'
   obj=json.loads(b)
   return 'PASS' if type(obj) is dict and obj.get('applicationType')=='gecko' and type(obj.get('marionetteProtocol')) is int and obj['marionetteProtocol']>=3 else 'INVALID_GREETING'
 except (OSError,TimeoutError):return 'TRANSPORT_ERROR'
 except (ValueError,TypeError,UnicodeError):return 'INVALID_GREETING'

def cgroup_snapshot():
 root='/sys/fs/cgroup/'
 if read_file(root+'cgroup.controllers',1024) is None:return None
 def counter(file,key):
  raw=read_file(root+file)
  if raw is None:return None
  for line in raw.splitlines():
   parts=line.split()
   if len(parts)==2 and parts[0]==key and parts[1].isdigit():return int(parts[1])
  return None
 def limit(file):
  raw=read_file(root+file,128)
  if raw is None:return 'UNKNOWN'
  raw=raw.strip()
  return 'UNLIMITED' if raw=='max' else ('FINITE' if raw.isdigit() else 'UNKNOWN')
 return {'memory_limit':limit('memory.max'),'pids_limit':limit('pids.max'),
   'oom':counter('memory.events','oom'),'oom_kill':counter('memory.events','oom_kill'),
   'pids_max':counter('pids.events','max')}

def delta(a,b,key):
 if a is None or b is None or a.get(key) is None or b.get(key) is None:return 'UNKNOWN'
 if b[key]<a[key]:return 'UNKNOWN'
 return 'POSITIVE' if b[key]>a[key] else 'ZERO'

def cgroup_summary(a,b):
 return {'version':'V2' if a is not None and b is not None else 'UNKNOWN',
  'memory_limit':a['memory_limit'] if a is not None else 'UNKNOWN',
  'pids_limit':a['pids_limit'] if a is not None else 'UNKNOWN',
  'oom_delta':delta(a,b,'oom'),'oom_kill_delta':delta(a,b,'oom_kill'),
  'pids_max_delta':delta(a,b,'pids_max')}

def group_drained(pgid):
 if pgid is None:return 'UNKNOWN'
 try:
  for name in os.listdir('/proc'):
   if not name.isdigit():continue
   raw=read_file('/proc/'+name+'/stat',4096)
   if raw is None:continue
   ix=raw.rfind(') ')
   if ix<0:continue
   fields=raw[ix+2:].split()
   if len(fields)<3:continue
   if fields[2].isdigit() and int(fields[2])==pgid and fields[0] not in ('Z','X'):
    return 'LIVE'
  return 'DRAINED'
 except (OSError,ValueError):return 'UNKNOWN'

def terminate(proc):
 if proc is None:return 'NONE'
 how='NONE';pgid=proc.pid
 # The session was created by this trial. Always terminate its process group,
 # including orphaned Firefox children if the original leader already exited.
 if group_drained(pgid) in ('LIVE','UNKNOWN'):
  try:os.killpg(pgid,signal.SIGTERM);how='SIGTERM'
  except (ProcessLookupError,PermissionError):how='UNKNOWN'
 try:proc.wait(timeout=3)
 except subprocess.TimeoutExpired:pass
 if group_drained(pgid) in ('LIVE','UNKNOWN'):
  try:os.killpg(pgid,signal.SIGKILL);how='SIGKILL'
  except (ProcessLookupError,PermissionError):how='UNKNOWN'
 try:proc.wait(timeout=3)
 except subprocess.TimeoutExpired:pass
 return how

def log_signal(f):
 if f is None:return 'NONE'
 try:
  raw=os.pread(f.fileno(),65536,0).lower()
  if b'sandbox' in raw:return 'SANDBOX'
  if b'seccomp' in raw:return 'SECCOMP'
  if b'crash' in raw or b'sigsegv' in raw:return 'CRASH'
  if b'permission denied' in raw:return 'PERMISSION'
  return 'NONE'
 except (OSError,ValueError):return 'UNREADABLE'

def blank(role,count):
 return {'role':role,'expected_hellos':count,'profile_private':False,'port_published':False,
  'greetings':[],'states_after_hellos':[],'state_after_launch':'NOT_STARTED',
  'state_after_dwell':'NOT_STARTED','state_before_cleanup':'NOT_STARTED',
  'state_after_cleanup':'NOT_STARTED','security':{'seccomp':'UNKNOWN','no_new_privs':'UNKNOWN'},
  'cgroup':cgroup_summary(None,None),'log_signal':'NONE','termination':'NONE',
  'group_drained':'UNKNOWN','profile_cleaned':False}

r={'schema':'stage70-v67-native-stability-v2','mode':'INDEPENDENT_0_1_3_MARIONETTE_CLIENTS',
 'classification':'NOT_RUN','firefox_executable':False,'trials':[]}
binary='/usr/bin/firefox'
r['firefox_executable']=os.path.isfile(binary) and os.access(binary,os.X_OK)
if not r['firefox_executable']:
 r['classification']='FIREFOX_UNAVAILABLE'
else:
 for role,count in ROLES:
  proc=None;log=None;root=None;t=blank(role,count);before=cgroup_snapshot();port=None
  try:
   root=tempfile.mkdtemp(prefix='stage70-v67-',dir='/tmp');os.chmod(root,0o700)
   st=os.lstat(root)
   if st.st_uid!=os.geteuid() or not stat.S_ISDIR(st.st_mode) or st.st_mode&0o777!=0o700:
    raise OSError('private-profile-check-failed')
   t['profile_private']=True
   profile=os.path.join(root,'profile');home=os.path.join(root,'home')
   os.mkdir(profile,0o700);os.mkdir(home,0o700)
   log=tempfile.TemporaryFile(mode='w+b',dir=root)
   env=os.environ.copy();env['HOME']=home;env['TMPDIR']=root;env['MOZ_HEADLESS']='1'
   proc=subprocess.Popen([binary,'--headless','--no-remote','--marionette','--profile',profile,'about:blank'],
       stdout=subprocess.DEVNULL,stderr=log,env=env,start_new_session=True)
   t['security']=security(proc.pid)
   deadline=time.monotonic()+14
   while time.monotonic()<deadline and proc.poll() is None:
    port=read_port(os.path.join(profile,'MarionetteActivePort'))
    if port is not None:break
    time.sleep(.2)
   t['state_after_launch']=state(proc);t['port_published']=port is not None
   for i in range(count):
    t['greetings'].append(hello(port) if proc.poll() is None else 'PROCESS_EXITED')
    t['states_after_hellos'].append(state(proc))
    if i+1<count:time.sleep(.35)
   # All three independent processes dwell at least the same time.
   time.sleep(1.8)
   t['state_after_dwell']=state(proc)
  except (OSError,subprocess.SubprocessError,ValueError):
   t['state_after_launch']=state(proc)
  finally:
   while len(t['greetings'])<count:
    t['greetings'].append('NOT_RUN')
    t['states_after_hellos'].append(state(proc))
   t['state_before_cleanup']=state(proc);t['log_signal']=log_signal(log)
   t['termination']=terminate(proc)
   t['state_after_cleanup']=state(proc)
   t['group_drained']=group_drained(proc.pid if proc is not None else None)
   if log is not None:log.close()
   if root is not None:
    try:shutil.rmtree(root)
    except (OSError,ValueError):pass
   t['profile_cleaned']=root is not None and not os.path.exists(root)
   t['cgroup']=cgroup_summary(before,cgroup_snapshot())
   r['trials'].append(t)
 if any(not t['profile_private'] or not t['profile_cleaned'] or
        t['state_after_cleanup'] in ('LIVE','NOT_STARTED') or t['group_drained']!='DRAINED' for t in r['trials']):
  r['classification']='COHORT_CLEANUP_FAILED'
 elif any(t['security']!={'seccomp':'2','no_new_privs':'1'} for t in r['trials']):
  r['classification']='COHORT_SECURITY_UNVERIFIED'
 elif any(t['cgroup']['oom_kill_delta']=='POSITIVE' for t in r['trials']):
  r['classification']='COHORT_OOM_KILL_OBSERVED'
 elif any(t['cgroup']['oom_delta']=='POSITIVE' or t['cgroup']['pids_max_delta']=='POSITIVE' for t in r['trials']):
  r['classification']='COHORT_RESOURCE_PRESSURE_OBSERVED'
 elif any(t['cgroup']['version']!='V2' or t['cgroup']['oom_kill_delta']=='UNKNOWN' or
          t['cgroup']['oom_delta']=='UNKNOWN' or t['cgroup']['pids_max_delta']=='UNKNOWN' or
          t['cgroup']['memory_limit']=='UNKNOWN' or t['cgroup']['pids_limit']=='UNKNOWN' for t in r['trials']):
  r['classification']='COHORT_CGROUP_UNVERIFIED'
 elif any(not t['port_published'] for t in r['trials']):
  r['classification']='COHORT_PORT_MISSING'
 elif any(t['state_after_launch']!='LIVE' for t in r['trials']):
  r['classification']='COHORT_LAUNCH_EXIT'
 elif any(t['state_after_dwell']!='LIVE' for t in r['trials']):
  r['classification']='COHORT_DWELL_EXIT'
 elif any(any(g!='PASS' for g in t['greetings']) for t in r['trials']):
  r['classification']='COHORT_GREETING_FAILURE'
 elif any(any(x!='LIVE' for x in t['states_after_hellos']) for t in r['trials']):
  r['classification']='COHORT_AFTER_GREETING_EXIT'
 else:
  r['classification']='COHORT_STABLE_DIAGNOSTIC_ONLY'
print(json.dumps(r,separators=(',',':'),sort_keys=True))
'''

V67_ROLES=(('NO_CLIENT',0),('ONE_CLIENT',1),('THREE_CLIENTS',3))
V67_STATES={'NOT_STARTED','LIVE','EXIT_ZERO','EXIT_NONZERO','SIGNAL_EXIT'}
V67_GREETINGS={'NOT_RUN','PASS','INVALID_GREETING','TRANSPORT_ERROR','PROCESS_EXITED'}
V67_CLASSES={'NOT_RUN','FIREFOX_UNAVAILABLE','COHORT_CLEANUP_FAILED','COHORT_SECURITY_UNVERIFIED',
 'COHORT_OOM_KILL_OBSERVED','COHORT_RESOURCE_PRESSURE_OBSERVED','COHORT_CGROUP_UNVERIFIED',
 'COHORT_PORT_MISSING','COHORT_LAUNCH_EXIT','COHORT_DWELL_EXIT',
 'COHORT_GREETING_FAILURE','COHORT_AFTER_GREETING_EXIT','COHORT_STABLE_DIAGNOSTIC_ONLY'}
V67_KEYS={'role','expected_hellos','profile_private','port_published','greetings','states_after_hellos',
 'state_after_launch','state_after_dwell','state_before_cleanup','state_after_cleanup','security',
 'cgroup','log_signal','termination','group_drained','profile_cleaned'}
V67_CGROUP_KEYS={'version','memory_limit','pids_limit','oom_delta','oom_kill_delta','pids_max_delta'}

def v67_derived_class(r):
 if not r['firefox_executable']:return 'FIREFOX_UNAVAILABLE'
 ts=r['trials']
 if any(not t['profile_private'] or not t['profile_cleaned'] or
        t['state_after_cleanup'] in ('LIVE','NOT_STARTED') or t['group_drained']!='DRAINED' for t in ts):
  return 'COHORT_CLEANUP_FAILED'
 if any(t['security']!={'seccomp':'2','no_new_privs':'1'} for t in ts):return 'COHORT_SECURITY_UNVERIFIED'
 if any(t['cgroup']['oom_kill_delta']=='POSITIVE' for t in ts):return 'COHORT_OOM_KILL_OBSERVED'
 if any(t['cgroup']['oom_delta']=='POSITIVE' or t['cgroup']['pids_max_delta']=='POSITIVE' for t in ts):
  return 'COHORT_RESOURCE_PRESSURE_OBSERVED'
 if any(t['cgroup']['version']!='V2' or t['cgroup']['oom_kill_delta']=='UNKNOWN' or
        t['cgroup']['oom_delta']=='UNKNOWN' or t['cgroup']['pids_max_delta']=='UNKNOWN' or
        t['cgroup']['memory_limit']=='UNKNOWN' or t['cgroup']['pids_limit']=='UNKNOWN' for t in ts):
  return 'COHORT_CGROUP_UNVERIFIED'
 if any(not t['port_published'] for t in ts):return 'COHORT_PORT_MISSING'
 if any(t['state_after_launch']!='LIVE' for t in ts):return 'COHORT_LAUNCH_EXIT'
 if any(t['state_after_dwell']!='LIVE' for t in ts):return 'COHORT_DWELL_EXIT'
 if any(any(g!='PASS' for g in t['greetings']) for t in ts):return 'COHORT_GREETING_FAILURE'
 if any(any(x!='LIVE' for x in t['states_after_hellos']) for t in ts):return 'COHORT_AFTER_GREETING_EXIT'
 return 'COHORT_STABLE_DIAGNOSTIC_ONLY'

def validate_v67_cohort(r):
 gate(type(r) is dict and set(r)=={'schema','mode','classification','firefox_executable','trials'},'V67_SCHEMA_INVALID')
 gate(r['schema']=='stage70-v67-native-stability-v2' and
      r['mode']=='INDEPENDENT_0_1_3_MARIONETTE_CLIENTS','V67_MODE_INVALID')
 gate(type(r['firefox_executable']) is bool and type(r['classification']) is str and
      r['classification'] in V67_CLASSES,'V67_CLASS_INVALID')
 gate(type(r['trials']) is list and len(r['trials'])==(3 if r['firefox_executable'] else 0),'V67_TRIAL_COUNT_INVALID')
 for index,t in enumerate(r['trials']):
  gate(type(t) is dict and set(t)==V67_KEYS,'V67_TRIAL_SCHEMA_INVALID')
  role,count=V67_ROLES[index]
  gate(t['role']==role and type(t['expected_hellos']) is int and t['expected_hellos']==count,'V67_TRIAL_ROLE_INVALID')
  for key in ('profile_private','port_published','profile_cleaned'):
   gate(type(t[key]) is bool,'V67_TRIAL_BOOLEAN_INVALID')
  gate(type(t['greetings']) is list and len(t['greetings'])==count and
       all(type(x) is str and x in V67_GREETINGS for x in t['greetings']),'V67_GREETINGS_INVALID')
  gate(type(t['states_after_hellos']) is list and len(t['states_after_hellos'])==count and
       all(type(x) is str and x in V67_STATES for x in t['states_after_hellos']),'V67_HELLO_STATES_INVALID')
  for key in ('state_after_launch','state_after_dwell','state_before_cleanup','state_after_cleanup'):
   gate(type(t[key]) is str and t[key] in V67_STATES,'V67_PROCESS_STATE_INVALID')
  gate(type(t['security']) is dict and set(t['security'])=={'seccomp','no_new_privs'},'V67_SECURITY_SCHEMA_INVALID')
  gate(type(t['security']['seccomp']) is str and t['security']['seccomp'] in {'0','1','2','UNKNOWN'} and
       type(t['security']['no_new_privs']) is str and t['security']['no_new_privs'] in {'0','1','UNKNOWN'},
       'V67_SECURITY_VALUE_INVALID')
  c=t['cgroup'];gate(type(c) is dict and set(c)==V67_CGROUP_KEYS,'V67_CGROUP_SCHEMA_INVALID')
  gate(type(c['version']) is str and c['version'] in {'V2','UNKNOWN'},'V67_CGROUP_VERSION_INVALID')
  for k in ('memory_limit','pids_limit'):
   gate(type(c[k]) is str and c[k] in {'FINITE','UNLIMITED','UNKNOWN'},'V67_CGROUP_LIMIT_INVALID')
  for k in ('oom_delta','oom_kill_delta','pids_max_delta'):
   gate(type(c[k]) is str and c[k] in {'ZERO','POSITIVE','UNKNOWN'},'V67_CGROUP_DELTA_INVALID')
  gate(type(t['log_signal']) is str and t['log_signal'] in {'NONE','SANDBOX','SECCOMP','CRASH','PERMISSION','UNREADABLE'},
       'V67_LOG_SIGNAL_INVALID')
  gate(type(t['termination']) is str and t['termination'] in {'NONE','SIGTERM','SIGKILL','UNKNOWN'},
       'V67_TERMINATION_INVALID')
  gate(type(t['group_drained']) is str and t['group_drained'] in {'DRAINED','LIVE','UNKNOWN'},
       'V67_GROUP_INVALID')
  gate(not t['port_published'] or t['profile_private'],'V67_PORT_WITHOUT_PRIVATE_PROFILE')
  gate(not t['profile_cleaned'] or t['profile_private'],'V67_PROFILE_CLEANUP_INCONSISTENT')
  gate(t['state_after_cleanup']!='LIVE','V67_ORPHAN_FIREFOX_PROCESS')
  gate(all(x!='PASS' for x in t['greetings']) or t['port_published'],'V67_HELLO_WITHOUT_PORT')
  gate(all(g!='PASS' or s in {'LIVE','EXIT_ZERO','EXIT_NONZERO','SIGNAL_EXIT'}
           for g,s in zip(t['greetings'],t['states_after_hellos'])),'V67_HELLO_WITHOUT_PROCESS')
 gate(r['classification']==v67_derived_class(r),'V67_FORGED_CLASSIFICATION')
 return r

def docker_v67_native_cohort_probe():
 p=call(['docker','exec','-i','--user','1000:1000',
          '--env','PYTHONDONTWRITEBYTECODE=1','cybersec-day03-zap',
          'python3','-c',GECKO_V67_NATIVE_COHORT_CODE],
        input=b'',timeout=145)
 gate(p.returncode==0 and 0<len(p.stdout)<9500,'V67_EXEC_FAILED')
 try:result=json.loads(p.stdout)
 except (TypeError,UnicodeError,ValueError) as e:raise Blocked('V67_JSON_INVALID') from e
 return validate_v67_cohort(result)


# V68: phase-resolved cgroup PID pressure and Firefox native stability.
# Evolve V67's identical independent 0/1/3 cohort WITHOUT repeating a second
# cohort and without changing image, seccomp, caps, UID, network or privileges.
# Only categorized deltas/headroom leave the container. Group counters can be
# shared with unrelated processes, therefore temporal correlation != causality.
def v68_cohort_code():
    s=GECKO_V67_NATIVE_COHORT_CODE
    def patch(old,new):
        nonlocal s
        if s.count(old)!=1:raise RuntimeError('V68_INNER_PATCH_SIGNATURE_MISMATCH')
        s=s.replace(old,new)
    patch("'pids_max':counter('pids.events','max')}",
          "'pids_max':counter('pids.events','max'),\n   'pids_current':number('pids.current'),'pids_ceiling':ceiling('pids.max')}")
    patch(" def limit(file):\n", """ def number(file):
  v=read_file(root+file,128)
  return int(v.strip()) if v is not None and v.strip().isdigit() else None
 def ceiling(file):
  v=read_file(root+file,128)
  if v is None:return None
  v=v.strip()
  return 'UNLIMITED' if v=='max' else (int(v) if v.isdigit() else None)
 def limit(file):
""")
    patch('def group_drained(pgid):', """def headroom(s):
 if s is None:return 'UNKNOWN'
 maxn=s.get('pids_ceiling');cur=s.get('pids_current')
 if maxn=='UNLIMITED':return 'UNLIMITED'
 if type(maxn) is not int or type(cur) is not int:return 'UNKNOWN'
 remaining=maxn-cur
 return 'EXHAUSTED' if remaining<=0 else ('LOW' if remaining<=16 else 'AVAILABLE')

def phase(a,b):
 return {'pids_max_delta':delta(a,b,'pids_max'),
  'oom_delta':delta(a,b,'oom'),
  'oom_kill_delta':delta(a,b,'oom_kill'),
  'headroom_before':headroom(a),'headroom_after':headroom(b)}

def group_drained(pgid):""")
    patch("'group_drained':'UNKNOWN','profile_cleaned':False}",
          "'group_drained':'UNKNOWN','profile_cleaned':False,'pressure_phases':{}}")
    patch("t=blank(role,count);before=cgroup_snapshot();port=None", "t=blank(role,count);before=cgroup_snapshot();port=None;after_port=None;after_hello=None;after_dwell=None")
    patch("t['state_after_launch']=state(proc);t['port_published']=port is not None", "t['state_after_launch']=state(proc);t['port_published']=port is not None\n   after_port=cgroup_snapshot()")
    patch("   # All three independent processes dwell at least the same time.", "   after_hello=cgroup_snapshot()\n   # All three independent processes dwell at least the same time.")
    patch("   t['state_after_dwell']=state(proc)", "   t['state_after_dwell']=state(proc)\n   after_dwell=cgroup_snapshot()")
    patch("   t['cgroup']=cgroup_summary(before,cgroup_snapshot())\n   r['trials'].append(t)",
          "   after_cleanup=cgroup_snapshot()\n   t['cgroup']=cgroup_summary(before,after_cleanup)\n   t['pressure_phases']={'LAUNCH':phase(before,after_port),\n      'GREETINGS':phase(after_port,after_hello),\n      'DWELL':phase(after_hello,after_dwell),\n      'CLEANUP':phase(after_dwell,after_cleanup)}\n   r['trials'].append(t)")
    patch("r={'schema':'stage70-v67-native-stability-v2'", "r={'schema':'stage70-v68-native-pids-phase-v1'")
    patch("print(json.dumps(r,separators=(',',':'),sort_keys=True))", """def phase_class(trials):
 if not r['firefox_executable']:return 'UNVERIFIED'
 observed=set()
 for t in trials:
  for key in ('LAUNCH','GREETINGS','DWELL','CLEANUP'):
   p=t['pressure_phases'][key]
   if 'UNKNOWN' in p.values():return 'UNVERIFIED'
   if p['pids_max_delta']=='POSITIVE':observed.add(key)
 if not observed:return 'NO_EVENT'
 return next(iter(observed))+'_EVENT' if len(observed)==1 else 'MULTIPLE_PHASES'
r['phase_classification']=phase_class(r['trials'])
print(json.dumps(r,separators=(',',':'),sort_keys=True))""")
    return s

GECKO_V68_PHASE_CODE=v68_cohort_code()
V68_PHASES=('LAUNCH','GREETINGS','DWELL','CLEANUP')
V68_PHASE_FIELDS={'pids_max_delta','oom_delta','oom_kill_delta','headroom_before','headroom_after'}
V68_HEADROOM={'UNKNOWN','UNLIMITED','EXHAUSTED','LOW','AVAILABLE'}
V68_DELTA={'ZERO','POSITIVE','UNKNOWN'}
V68_CLASSES={'NO_EVENT','LAUNCH_EVENT','GREETINGS_EVENT','DWELL_EVENT','CLEANUP_EVENT','MULTIPLE_PHASES','UNVERIFIED'}

def v68_phase_classification(r):
 if not r['firefox_executable']:return 'UNVERIFIED'
 observed=[]
 for t in r['trials']:
  for phase_name in V68_PHASES:
   p=t['pressure_phases'][phase_name]
   if any(p[k]=='UNKNOWN' for k in ('pids_max_delta','oom_delta','oom_kill_delta')) or \
      any(p[k]=='UNKNOWN' for k in ('headroom_before','headroom_after')):
    return 'UNVERIFIED'
   if p['pids_max_delta']=='POSITIVE':observed.append(phase_name)
 if not observed:return 'NO_EVENT'
 return (next(iter(set(observed)))+'_EVENT') if len(set(observed))==1 else 'MULTIPLE_PHASES'

def validate_v68_phase(r):
 gate(type(r) is dict and set(r)=={'schema','mode','classification','firefox_executable','trials','phase_classification'},'V68_SCHEMA_INVALID')
 gate(r['schema']=='stage70-v68-native-pids-phase-v1' and r['mode']=='INDEPENDENT_0_1_3_MARIONETTE_CLIENTS','V68_MODE_INVALID')
 gate(type(r['phase_classification']) is str and r['phase_classification'] in V68_CLASSES,'V68_PHASE_CLASS_INVALID')
 gate(type(r['trials']) is list and len(r['trials'])==(3 if r['firefox_executable'] else 0),'V68_TRIALS_INVALID')
 restored=[]
 for t in r['trials']:
  gate(type(t) is dict and set(t)==V67_KEYS|{'pressure_phases'},'V68_TRIAL_SCHEMA_INVALID')
  p=t['pressure_phases']
  gate(type(p) is dict and set(p)==set(V68_PHASES),'V68_PHASES_INVALID')
  for name in V68_PHASES:
   part=p[name]
   gate(type(part) is dict and set(part)==V68_PHASE_FIELDS,'V68_PHASE_FIELDS_INVALID')
   for field in ('pids_max_delta','oom_delta','oom_kill_delta'):
    gate(type(part[field]) is str and part[field] in V68_DELTA,'V68_PHASE_DELTA_INVALID')
   for field in ('headroom_before','headroom_after'):
    gate(type(part[field]) is str and part[field] in V68_HEADROOM,'V68_HEADROOM_INVALID')
  # The phases must form one contiguous observed timeline; missing or changed
  # headroom is a fail-closed UNVERIFIED classification, never a successful gate.
  for first,second in zip(V68_PHASES,V68_PHASES[1:]):
   a,b=p[first],p[second]
   gate(a['headroom_after']==b['headroom_before'],'V68_HEADROOM_TIMELINE_INVALID')
  for event,aggregate in (('pids_max_delta','pids_max_delta'),('oom_delta','oom_delta'),('oom_kill_delta','oom_kill_delta')):
   sequence=[p[name][event] for name in V68_PHASES]
   if 'UNKNOWN' in sequence:combined='UNKNOWN'
   else:combined='POSITIVE' if 'POSITIVE' in sequence else 'ZERO'
   gate(t['cgroup'][aggregate]==combined,'V68_CGROUP_AGGREGATE_MISMATCH')
  restored.append({k:t[k] for k in V67_KEYS})
 legacy={'schema':'stage70-v67-native-stability-v2','mode':r['mode'],'firefox_executable':r['firefox_executable'],
         'classification':r['classification'],'trials':restored}
 validate_v67_cohort(legacy)
 gate(r['phase_classification']==v68_phase_classification(r),'V68_FORGED_PHASE_CLASSIFICATION')
 return r,legacy

def docker_v68_pid_phase_probe():
 p=call(['docker','exec','-i','--user','1000:1000','--env','PYTHONDONTWRITEBYTECODE=1',
         'cybersec-day03-zap','python3','-c',GECKO_V68_PHASE_CODE],input=b'',timeout=145)
 gate(p.returncode==0 and 0<len(p.stdout)<13500,'V68_EXEC_FAILED')
 try:r=json.loads(p.stdout)
 except (ValueError,TypeError,UnicodeError) as e:raise Blocked('V68_JSON_INVALID') from e
 return validate_v68_phase(r)



# V69: four bounded 450-ms DWELL windows INSIDE the exact V68 three-cohort
# experiment. No extra Firefox instances, no GeckoDriver and no sandbox changes.
# Correlation at interval granularity is not process-level or causal attribution.
def v69_cohort_code():
    s=GECKO_V68_PHASE_CODE
    def patch(old,new):
        nonlocal s
        if s.count(old)!=1:raise RuntimeError('V69_INNER_PATCH_SIGNATURE_MISMATCH_'+str(s.count(old)))
        s=s.replace(old,new)
    patch("'group_drained':'UNKNOWN','profile_cleaned':False,'pressure_phases':{}}",
          "'group_drained':'UNKNOWN','profile_cleaned':False,'pressure_phases':{},'dwell_windows':[]}")
    patch("   # All three independent processes dwell at least the same time.\n   time.sleep(1.8)\n   t['state_after_dwell']=state(proc)\n   after_dwell=cgroup_snapshot()", """   # Exactly 1.8 seconds total: no extra Firefox processes or UID changes.
   last=after_hello
   for _ in range(4):
    before_state=state(proc)
    time.sleep(.45)
    current=cgroup_snapshot()
    after_state=state(proc)
    t['dwell_windows'].append({'pids_max_delta':delta(last,current,'pids_max'),
      'oom_delta':delta(last,current,'oom'),
      'oom_kill_delta':delta(last,current,'oom_kill'),
      'headroom_before':headroom(last),'headroom_after':headroom(current),
      'firefox_before':before_state,'firefox_after':after_state})
    last=current
   t['state_after_dwell']=after_state
   after_dwell=last""")
    patch("r={'schema':'stage70-v68-native-pids-phase-v1'", "r={'schema':'stage70-v69-native-dwell-timeline-v1'")
    patch("r['phase_classification']=phase_class(r['trials'])", """r['phase_classification']=phase_class(r['trials'])
def dwell_class(trials):
 if not r['firefox_executable']:return 'UNVERIFIED'
 observed=set()
 for t in trials:
  if len(t['dwell_windows'])!=4:return 'UNVERIFIED'
  for w in t['dwell_windows']:
   if w['pids_max_delta']=='UNKNOWN' or 'UNKNOWN' in (w['headroom_before'],w['headroom_after']):return 'UNVERIFIED'
   if w['pids_max_delta']=='POSITIVE':
    if w['firefox_before']=='LIVE' and w['firefox_after']!='LIVE':observed.add('EVENT_EXIT_SAME_WINDOW')
    elif w['firefox_before']=='LIVE':observed.add('EVENT_WHILE_LIVE')
    else:observed.add('EVENT_AFTER_EXIT')
 if not observed:return 'NO_EVENT'
 return next(iter(observed)) if len(observed)==1 else 'MIXED_EVENTS'
r['dwell_classification']=dwell_class(r['trials'])""")
    return s

GECKO_V69_DWELL_CODE=v69_cohort_code()
V69_FIELDS=V68_PHASE_FIELDS|{'firefox_before','firefox_after'}
V69_CLASSES={'UNVERIFIED','NO_EVENT','EVENT_EXIT_SAME_WINDOW','EVENT_WHILE_LIVE','EVENT_AFTER_EXIT','MIXED_EVENTS'}
V69_STATES={'NOT_STARTED','LIVE','EXIT_ZERO','EXIT_NONZERO','SIGNAL_EXIT'}

def v69_dwell_classification(r):
 if not r['firefox_executable']:return 'UNVERIFIED'
 observed=set()
 for t in r['trials']:
  if len(t['dwell_windows'])!=4:return 'UNVERIFIED'
  for w in t['dwell_windows']:
   if w['pids_max_delta']=='UNKNOWN' or 'UNKNOWN' in (w['headroom_before'],w['headroom_after']):return 'UNVERIFIED'
   if w['pids_max_delta']=='POSITIVE':
    if w['firefox_before']=='LIVE' and w['firefox_after']!='LIVE':observed.add('EVENT_EXIT_SAME_WINDOW')
    elif w['firefox_before']=='LIVE':observed.add('EVENT_WHILE_LIVE')
    else:observed.add('EVENT_AFTER_EXIT')
 if not observed:return 'NO_EVENT'
 return next(iter(observed)) if len(observed)==1 else 'MIXED_EVENTS'

def validate_v69_dwell(r):
 gate(type(r) is dict and set(r)=={'schema','mode','classification','firefox_executable','trials','phase_classification','dwell_classification'},'V69_SCHEMA_INVALID')
 gate(r['schema']=='stage70-v69-native-dwell-timeline-v1' and type(r['dwell_classification']) is str and
      r['dwell_classification'] in V69_CLASSES,'V69_DWELL_SCHEMA_INVALID')
 gate(type(r['trials']) is list and type(r['firefox_executable']) is bool,'V69_TRIALS_INVALID')
 old_trials=[]
 for t in r['trials']:
  gate(type(t) is dict and set(t)==V67_KEYS|{'pressure_phases','dwell_windows'},'V69_TRIAL_SCHEMA_INVALID')
  windows=t['dwell_windows']
  gate(type(windows) is list and len(windows) in (0,4),'V69_DWELL_COUNT_INVALID')
  for w in windows:
   gate(type(w) is dict and set(w)==V69_FIELDS,'V69_DWELL_FIELDS_INVALID')
   for field in ('pids_max_delta','oom_delta','oom_kill_delta'):
    gate(type(w[field]) is str and w[field] in V68_DELTA,'V69_DELTA_INVALID')
   for field in ('headroom_before','headroom_after'):
    gate(type(w[field]) is str and w[field] in V68_HEADROOM,'V69_HEADROOM_INVALID')
   for field in ('firefox_before','firefox_after'):
    gate(type(w[field]) is str and w[field] in V69_STATES,'V69_FIREFOX_STATE_INVALID')
  if windows:
   phase=t['pressure_phases']['DWELL']
   gate(windows[0]['headroom_before']==phase['headroom_before'] and
        windows[-1]['headroom_after']==phase['headroom_after'],'V69_DWELL_HEADROOM_BOUNDARY_INVALID')
   gate(windows[-1]['firefox_after']==t['state_after_dwell'],'V69_DWELL_STATE_BOUNDARY_INVALID')
   for prev,nxt in zip(windows,windows[1:]):
    gate(prev['headroom_after']==nxt['headroom_before'],'V69_DWELL_HEADROOM_TIMELINE_INVALID')
    # Polling can race between adjacent snapshots: LIVE->terminal permitted;
    # terminated Firefox must NEVER become LIVE or a different terminal class.
    if prev['firefox_after']!='LIVE':gate(nxt['firefox_before']==prev['firefox_after'],'V69_FIREFOX_RESURRECTION_INVALID')
   for w in windows:
    if w['firefox_before']!='LIVE':gate(w['firefox_after']==w['firefox_before'],'V69_FIREFOX_RESURRECTION_INVALID')
   for event in ('pids_max_delta','oom_delta','oom_kill_delta'):
    sequence=[w[event] for w in windows]
    combined='UNKNOWN' if 'UNKNOWN' in sequence else ('POSITIVE' if 'POSITIVE' in sequence else 'ZERO')
    gate(phase[event]==combined,'V69_DWELL_CGROUP_MISMATCH')
  old_trials.append({k:t[k] for k in V67_KEYS|{'pressure_phases'}})
 legacy={'schema':'stage70-v68-native-pids-phase-v1','mode':r['mode'],
  'classification':r['classification'],'firefox_executable':r['firefox_executable'],
  'trials':old_trials,'phase_classification':r['phase_classification']}
 validate_v68_phase(legacy)
 gate(r['dwell_classification']==v69_dwell_classification(r),'V69_FORGED_DWELL_CLASSIFICATION')
 return r,legacy

def docker_v69_dwell_probe():
 p=call(['docker','exec','-i','--user','1000:1000','--env','PYTHONDONTWRITEBYTECODE=1',
         'cybersec-day03-zap','python3','-c',GECKO_V69_DWELL_CODE],input=b'',timeout=145)
 gate(p.returncode==0 and 0<len(p.stdout)<17500,'V69_EXEC_FAILED')
 try:r=json.loads(p.stdout)
 except (ValueError,TypeError,UnicodeError) as e:raise Blocked('V69_JSON_INVALID') from e
 return validate_v69_dwell(r)



# V70: read-only process-group quiescence observations following the original
# V69 cleanup attempt. Do not conceal or normalize the first V69 group_drained
# snapshot: a delayed drain must remain visible as an initial cleanup failure.
# No added Firefox instance, no extra killpg, no PID/session/path in evidence.
def v70_cohort_code():
    s=GECKO_V69_DWELL_CODE
    def patch(old,new):
        nonlocal s
        if s.count(old)!=1:raise RuntimeError('V70_INNER_PATCH_SIGNATURE_MISMATCH_'+str(s.count(old)))
        s=s.replace(old,new)
    patch("'dwell_windows':[]}", "'dwell_windows':[],'cleanup_observations':[]}")
    patch("   t['group_drained']=group_drained(proc.pid if proc is not None else None)", """   t['group_drained']=group_drained(proc.pid if proc is not None else None)
   # Read-only verification after V69's completed SIGTERM/SIGKILL policy.
   # The first observation retains the original V69 result.
   t['cleanup_observations']=[t['group_drained']]
   for delay in (.2,.3):
    time.sleep(delay)
    t['cleanup_observations'].append(group_drained(proc.pid if proc is not None else None))""")
    patch("r={'schema':'stage70-v69-native-dwell-timeline-v1'", "r={'schema':'stage70-v70-process-group-quiescence-v1'")
    patch("r['dwell_classification']=dwell_class(r['trials'])", """r['dwell_classification']=dwell_class(r['trials'])
def cleanup_class(trials):
 if not r['firefox_executable']:return 'UNVERIFIED'
 if any(len(t['cleanup_observations'])!=3 or 'UNKNOWN' in t['cleanup_observations'] for t in trials):return 'UNVERIFIED'
 if any(t['cleanup_observations'][-1]=='LIVE' for t in trials):return 'PERSISTENT_RESIDUAL'
 if any(t['cleanup_observations'][0]=='LIVE' for t in trials):return 'DELAYED_QUIESCENCE'
 return 'ALL_DRAINED'
r['cleanup_classification']=cleanup_class(r['trials'])""")
    return s

GECKO_V70_QUIESCENCE_CODE=v70_cohort_code()
V70_GROUP_STATES={'DRAINED','LIVE','UNKNOWN'}
V70_CLASSES={'ALL_DRAINED','DELAYED_QUIESCENCE','PERSISTENT_RESIDUAL','UNVERIFIED'}

def v70_cleanup_classification(r):
 if not r['firefox_executable']:return 'UNVERIFIED'
 if any(len(t['cleanup_observations'])!=3 or 'UNKNOWN' in t['cleanup_observations'] for t in r['trials']):return 'UNVERIFIED'
 if any(t['cleanup_observations'][-1]=='LIVE' for t in r['trials']):return 'PERSISTENT_RESIDUAL'
 if any(t['cleanup_observations'][0]=='LIVE' for t in r['trials']):return 'DELAYED_QUIESCENCE'
 return 'ALL_DRAINED'

def validate_v70_quiescence(r):
 gate(type(r) is dict and set(r)=={'schema','mode','classification','firefox_executable','trials',
   'phase_classification','dwell_classification','cleanup_classification'},'V70_SCHEMA_INVALID')
 gate(r['schema']=='stage70-v70-process-group-quiescence-v1' and type(r['cleanup_classification']) is str
      and r['cleanup_classification'] in V70_CLASSES,'V70_CLASS_SCHEMA_INVALID')
 gate(type(r['trials']) is list and type(r['firefox_executable']) is bool,'V70_TRIAL_SCHEMA_INVALID')
 old=[]
 for t in r['trials']:
  gate(type(t) is dict and set(t)==V67_KEYS|{'pressure_phases','dwell_windows','cleanup_observations'},'V70_FIELDS_INVALID')
  obs=t['cleanup_observations']
  gate(type(obs) is list and len(obs)==3 and all(type(x) is str and x in V70_GROUP_STATES for x in obs),'V70_OBSERVATIONS_INVALID')
  gate(obs[0]==t['group_drained'],'V70_ORIGINAL_CLEANUP_NOT_PRESERVED')
  # A genuinely drained process group must not spontaneously reappear. PID/PGID
  # reuse or a contradictory sample blocks rather than assuming success.
  for p,n in zip(obs,obs[1:]):
   gate(not (p=='DRAINED' and n=='LIVE'),'V70_CLEANUP_RESURRECTION_INVALID')
  old.append({k:t[k] for k in V67_KEYS|{'pressure_phases','dwell_windows'}})
 legacy={'schema':'stage70-v69-native-dwell-timeline-v1','mode':r['mode'],
  'classification':r['classification'],'firefox_executable':r['firefox_executable'],'trials':old,
  'phase_classification':r['phase_classification'],'dwell_classification':r['dwell_classification']}
 validate_v69_dwell(legacy)
 gate(r['cleanup_classification']==v70_cleanup_classification(r),'V70_FORGED_CLEANUP_CLASSIFICATION')
 return r,legacy

def docker_v70_quiescence_probe():
 p=call(['docker','exec','-i','--user','1000:1000','--env','PYTHONDONTWRITEBYTECODE=1',
   'cybersec-day03-zap','python3','-c',GECKO_V70_QUIESCENCE_CODE],input=b'',timeout=150)
 gate(p.returncode==0 and 0<len(p.stdout)<19000,'V70_EXEC_FAILED')
 try:r=json.loads(p.stdout)
 except (ValueError,TypeError,UnicodeError) as e:raise Blocked('V70_JSON_INVALID') from e
 return validate_v70_quiescence(r)



# V71: Categorized cgroup PID-budget / Firefox leader thread diagnostics.
# Exactly the same native 0/1/3 cohort; preserve V70 cleanup samples, V69
# dwell, and all legacy fields. No raw PID/thread count or stderr is emitted.
# The Linux cgroup pids.events counter is SHARED, not causal attribution.
def v71_cohort_code():
    s=GECKO_V70_QUIESCENCE_CODE
    def patch(old,new):
        nonlocal s
        if s.count(old)!=1:raise RuntimeError('V71_INNER_PATCH_SIGNATURE_MISMATCH_'+str(s.count(old)))
        s=s.replace(old,new)
    patch('import json,os,stat,subprocess,socket,time,signal,tempfile,shutil,re',
          'import json,os,stat,subprocess,socket,time,signal,tempfile,shutil,re,resource')
    patch('def log_signal(f):', """def nproc_soft():
 try:
  soft,_=resource.getrlimit(resource.RLIMIT_NPROC)
  if soft==resource.RLIM_INFINITY or soft<0:return 'UNLIMITED'
  if type(soft) is int:return 'FINITE'
 except (OSError,ValueError,AttributeError):pass
 return 'UNKNOWN'

def leader_threads(proc):
 if proc is None or proc.poll() is not None:return 'NOT_LIVE'
 raw=read_file('/proc/'+str(proc.pid)+'/status',16384)
 if raw is None:return 'UNKNOWN'
 m=re.search(r'(?m)^Threads:\\s*([0-9]+)$',raw)
 if not m:return 'UNKNOWN'
 n=int(m.group(1))
 return 'LOW' if n<=16 else ('MEDIUM' if n<=64 else 'HIGH')

def thread_error_signal(f):
 if f is None:return 'UNKNOWN'
 try:
  raw=os.pread(f.fileno(),65536,0).lower()
  if any(k in raw for k in (b'pthread_create',b'thread creation failed',b'resource temporarily unavailable',b'fork failed',b'cannot allocate thread')):
   return 'TASK_CREATION_ERROR'
  if b'sandbox' in raw:return 'SANDBOX_ONLY'
  if b'seccomp' in raw:return 'SECCOMP_ONLY'
  return 'NONE'
 except (OSError,ValueError):return 'UNKNOWN'

def budget_class(trials):
 if not r['firefox_executable']:return 'UNVERIFIED'
 observed=set()
 for t in trials:
  b=t['pid_budget'];event=t['cgroup']['pids_max_delta'];signal=b['task_creation_signal']
  if event=='UNKNOWN' or signal=='UNKNOWN' or b['nproc_soft_limit']=='UNKNOWN':return 'UNVERIFIED'
  if signal=='TASK_CREATION_ERROR':observed.add('TASK_ERROR')
  if event=='POSITIVE':observed.add('CGROUP_EVENT')
 if not observed:return 'NO_EVENT_OR_TASK_SIGNAL'
 if len(observed)==2:return 'CGROUP_EVENT_AND_TASK_ERROR_SIGNAL'
 return 'CGROUP_EVENT_ONLY' if 'CGROUP_EVENT' in observed else 'TASK_ERROR_ONLY'

def log_signal(f):""")
    patch("'cleanup_observations':[]}", "'cleanup_observations':[],'pid_budget':{}}")
    patch('before=cgroup_snapshot();port=None;after_port=None',
          "before=cgroup_snapshot();t['pid_budget']={'nproc_soft_limit':nproc_soft(),'leader_threads_launch':'NOT_LIVE','leader_threads_before_cleanup':'NOT_LIVE','headroom_before_launch':headroom(before),'headroom_after_launch':'UNKNOWN','headroom_after_dwell':'UNKNOWN','headroom_after_cleanup':'UNKNOWN','task_creation_signal':'UNKNOWN'};port=None;after_port=None")
    patch('   after_port=cgroup_snapshot()', "   after_port=cgroup_snapshot()\n   t['pid_budget']['leader_threads_launch']=leader_threads(proc)\n   t['pid_budget']['headroom_after_launch']=headroom(after_port)")
    patch("   t['state_before_cleanup']=state(proc);t['log_signal']=log_signal(log)",
          "   t['state_before_cleanup']=state(proc);t['log_signal']=log_signal(log)\n   t['pid_budget']['leader_threads_before_cleanup']=leader_threads(proc)\n   t['pid_budget']['task_creation_signal']=thread_error_signal(log)")
    patch("   t['cgroup']=cgroup_summary(before,after_cleanup)",
          "   t['cgroup']=cgroup_summary(before,after_cleanup)\n   t['pid_budget']['headroom_after_dwell']=headroom(after_dwell)\n   t['pid_budget']['headroom_after_cleanup']=headroom(after_cleanup)")
    patch("r={'schema':'stage70-v70-process-group-quiescence-v1'",
          "r={'schema':'stage70-v71-pid-budget-thread-signal-v1'")
    patch("r['cleanup_classification']=cleanup_class(r['trials'])",
          "r['cleanup_classification']=cleanup_class(r['trials'])\nr['pid_budget_classification']=budget_class(r['trials'])")
    return s

GECKO_V71_PID_BUDGET_CODE=v71_cohort_code()
V71_BUDGET_FIELDS={'nproc_soft_limit','leader_threads_launch','leader_threads_before_cleanup',
 'headroom_before_launch','headroom_after_launch','headroom_after_dwell','headroom_after_cleanup','task_creation_signal'}
V71_NPROC={'FINITE','UNLIMITED','UNKNOWN'}
V71_THREADS={'NOT_LIVE','LOW','MEDIUM','HIGH','UNKNOWN'}
V71_TASK_SIG={'TASK_CREATION_ERROR','SANDBOX_ONLY','SECCOMP_ONLY','NONE','UNKNOWN'}
V71_CLASSES={'CGROUP_EVENT_AND_TASK_ERROR_SIGNAL','CGROUP_EVENT_ONLY','TASK_ERROR_ONLY','NO_EVENT_OR_TASK_SIGNAL','UNVERIFIED'}

def v71_pid_budget_classification(r):
 if not r['firefox_executable']:return 'UNVERIFIED'
 observed=set()
 for t in r['trials']:
  b=t['pid_budget'];event=t['cgroup']['pids_max_delta'];signal=b['task_creation_signal']
  if event=='UNKNOWN' or signal=='UNKNOWN' or b['nproc_soft_limit']=='UNKNOWN':return 'UNVERIFIED'
  if event=='POSITIVE':observed.add('CGROUP_EVENT')
  if signal=='TASK_CREATION_ERROR':observed.add('TASK_ERROR')
 if not observed:return 'NO_EVENT_OR_TASK_SIGNAL'
 if len(observed)==2:return 'CGROUP_EVENT_AND_TASK_ERROR_SIGNAL'
 return 'CGROUP_EVENT_ONLY' if 'CGROUP_EVENT' in observed else 'TASK_ERROR_ONLY'

def validate_v71_pid_budget(r):
 gate(type(r) is dict and set(r)=={'schema','mode','classification','firefox_executable','trials',
    'phase_classification','dwell_classification','cleanup_classification','pid_budget_classification'},'V71_SCHEMA_INVALID')
 gate(r['schema']=='stage70-v71-pid-budget-thread-signal-v1' and type(r['pid_budget_classification']) is str
      and r['pid_budget_classification'] in V71_CLASSES,'V71_CLASS_SCHEMA_INVALID')
 gate(type(r['trials']) is list and type(r['firefox_executable']) is bool,'V71_TRIALS_INVALID')
 old=[]
 for t in r['trials']:
  gate(type(t) is dict and set(t)==V67_KEYS|{'pressure_phases','dwell_windows','cleanup_observations','pid_budget'},'V71_FIELDS_INVALID')
  b=t['pid_budget']
  gate(type(b) is dict and set(b)==V71_BUDGET_FIELDS,'V71_BUDGET_FIELDS_INVALID')
  gate(type(b['nproc_soft_limit']) is str and b['nproc_soft_limit'] in V71_NPROC,'V71_NPROC_INVALID')
  for field in ('leader_threads_launch','leader_threads_before_cleanup'):
   gate(type(b[field]) is str and b[field] in V71_THREADS,'V71_THREAD_BAND_INVALID')
  for field in ('headroom_before_launch','headroom_after_launch','headroom_after_dwell','headroom_after_cleanup'):
   gate(type(b[field]) is str and b[field] in V68_HEADROOM,'V71_HEADROOM_INVALID')
  gate(type(b['task_creation_signal']) is str and b['task_creation_signal'] in V71_TASK_SIG,'V71_TASK_SIGNAL_INVALID')
  p=t['pressure_phases']
  gate(b['headroom_before_launch']==p['LAUNCH']['headroom_before'] and
       b['headroom_after_launch']==p['LAUNCH']['headroom_after'] and
       b['headroom_after_dwell']==p['DWELL']['headroom_after'] and
       b['headroom_after_cleanup']==p['CLEANUP']['headroom_after'], 'V71_HEADROOM_PROJECTION_INVALID')
  if t['state_after_launch']!='LIVE':
   gate(b['leader_threads_launch'] in ('NOT_LIVE','UNKNOWN'),'V71_THREADS_EXIT_LAUNCH_INVALID')
  if t['state_before_cleanup']!='LIVE':
   gate(b['leader_threads_before_cleanup'] in ('NOT_LIVE','UNKNOWN'),'V71_THREADS_EXIT_CLEANUP_INVALID')
  old.append({k:t[k] for k in V67_KEYS|{'pressure_phases','dwell_windows','cleanup_observations'}})
 legacy={'schema':'stage70-v70-process-group-quiescence-v1','mode':r['mode'],
  'classification':r['classification'],'firefox_executable':r['firefox_executable'],'trials':old,
  'phase_classification':r['phase_classification'],'dwell_classification':r['dwell_classification'],
  'cleanup_classification':r['cleanup_classification']}
 validate_v70_quiescence(legacy)
 gate(r['pid_budget_classification']==v71_pid_budget_classification(r),'V71_FORGED_CLASSIFICATION')
 return r,legacy

def docker_v71_pid_budget_probe():
 p=call(['docker','exec','-i','--user','1000:1000','--env','PYTHONDONTWRITEBYTECODE=1',
   'cybersec-day03-zap','python3','-c',GECKO_V71_PID_BUDGET_CODE],input=b'',timeout=155)
 gate(p.returncode==0 and 0<len(p.stdout)<22000,'V71_EXEC_FAILED')
 try:r=json.loads(p.stdout)
 except (ValueError,TypeError,UnicodeError) as e:raise Blocked('V71_JSON_INVALID') from e
 return validate_v71_pid_budget(r)



# V72: read-only local-versus-hierarchical PID denial scope, and cgroup lifetime peak.
# Neither file is guaranteed by every Linux kernel. Missing data -> UNAVAILABLE,
# never zero and never evidence of a safe environment. Shared counters are not
# browser-specific; there are no extra Firefox starts or resource changes.
def v72_cohort_code():
    s=GECKO_V71_PID_BUDGET_CODE
    def patch(old,new):
        nonlocal s
        if s.count(old)!=1:raise RuntimeError('V72_INNER_PATCH_SIGNATURE_MISMATCH_'+str(s.count(old)))
        s=s.replace(old,new)
    patch("'pids_ceiling':ceiling('pids.max')}",
          "'pids_ceiling':ceiling('pids.max'),\n   'pids_local_max':counter('pids.events.local','max'),\n   'pids_peak':number('pids.peak')}")
    patch('def group_drained(pgid):', """def local_delta(a,b):
 if a is None or b is None:return 'UNKNOWN'
 aa=a.get('pids_local_max');bb=b.get('pids_local_max')
 if aa is None and bb is None:return 'UNAVAILABLE'
 if aa is None or bb is None or bb<aa:return 'UNKNOWN'
 return 'POSITIVE' if bb>aa else 'ZERO'

def peak_band(s):
 if s is None:return 'UNAVAILABLE'
 p=s.get('pids_peak');limit=s.get('pids_ceiling')
 if p is None:return 'UNAVAILABLE'
 if limit=='UNLIMITED':return 'UNLIMITED'
 if type(p) is not int or type(limit) is not int or limit<=0:return 'UNAVAILABLE'
 return 'AT_LIMIT' if p>=limit else ('NEAR_LIMIT' if p*10>=limit*9 else 'BELOW_90_PERCENT')

def local_class(trials):
 if not r['firefox_executable']:return 'UNVERIFIED'
 local=[];global_events=[]
 for t in trials:
  local.append(t['pid_scope']['local_delta'])
  global_events.append(t['cgroup']['pids_max_delta'])
 if any(x=='UNKNOWN' for x in local+global_events):return 'UNVERIFIED'
 if any(x=='UNAVAILABLE' for x in local):
  if not all(x=='UNAVAILABLE' for x in local):return 'UNVERIFIED'
  return 'LOCAL_UNAVAILABLE_GLOBAL_EVENT' if 'POSITIVE' in global_events else 'LOCAL_UNAVAILABLE_NO_GLOBAL'
 if 'POSITIVE' in local:return 'LOCAL_EVENT_OBSERVED'
 if 'POSITIVE' in global_events:return 'GLOBAL_ONLY_EVENT_OBSERVED'
 return 'NO_EVENT'

def group_drained(pgid):""")
    patch("'cleanup_observations':[],'pid_budget':{}}", "'cleanup_observations':[],'pid_budget':{},'pid_scope':{}}")
    patch("t['pid_budget']['headroom_after_cleanup']=headroom(after_cleanup)",
          "t['pid_budget']['headroom_after_cleanup']=headroom(after_cleanup)\n   t['pid_scope']={'local_delta':local_delta(before,after_cleanup),\n      'local_phases':{'LAUNCH':local_delta(before,after_port),\n       'GREETINGS':local_delta(after_port,after_hello),\n       'DWELL':local_delta(after_hello,after_dwell),\n       'CLEANUP':local_delta(after_dwell,after_cleanup)},\n      'lifetime_peak_band':peak_band(after_cleanup)}")
    patch("r={'schema':'stage70-v71-pid-budget-thread-signal-v1'",
          "r={'schema':'stage70-v72-local-pid-denial-scope-v1'")
    patch("r['pid_budget_classification']=budget_class(r['trials'])",
          "r['pid_budget_classification']=budget_class(r['trials'])\nr['local_event_classification']=local_class(r['trials'])")
    return s

GECKO_V72_LOCAL_SCOPE_CODE=v72_cohort_code()
V72_SCOPE_FIELDS={'local_delta','local_phases','lifetime_peak_band'}
V72_LOCAL={'ZERO','POSITIVE','UNAVAILABLE','UNKNOWN'}
V72_PEAK={'AT_LIMIT','NEAR_LIMIT','BELOW_90_PERCENT','UNLIMITED','UNAVAILABLE'}
V72_CLASSES={'UNVERIFIED','LOCAL_UNAVAILABLE_GLOBAL_EVENT','LOCAL_UNAVAILABLE_NO_GLOBAL',
 'LOCAL_EVENT_OBSERVED','GLOBAL_ONLY_EVENT_OBSERVED','NO_EVENT'}

def v72_local_event_classification(r):
 if not r['firefox_executable']:return 'UNVERIFIED'
 loc=[t['pid_scope']['local_delta'] for t in r['trials']]
 glob=[t['cgroup']['pids_max_delta'] for t in r['trials']]
 if 'UNKNOWN' in loc or 'UNKNOWN' in glob:return 'UNVERIFIED'
 if 'UNAVAILABLE' in loc:
  if any(x!='UNAVAILABLE' for x in loc):return 'UNVERIFIED'
  return 'LOCAL_UNAVAILABLE_GLOBAL_EVENT' if 'POSITIVE' in glob else 'LOCAL_UNAVAILABLE_NO_GLOBAL'
 if 'POSITIVE' in loc:return 'LOCAL_EVENT_OBSERVED'
 if 'POSITIVE' in glob:return 'GLOBAL_ONLY_EVENT_OBSERVED'
 return 'NO_EVENT'

def v72_combine_delta(values):
 if 'UNKNOWN' in values:return 'UNKNOWN'
 if 'UNAVAILABLE' in values:
  return 'UNAVAILABLE' if all(x=='UNAVAILABLE' for x in values) else 'UNKNOWN'
 return 'POSITIVE' if 'POSITIVE' in values else 'ZERO'

def validate_v72_local_scope(r):
 gate(type(r) is dict and set(r)=={'schema','mode','classification','firefox_executable','trials',
    'phase_classification','dwell_classification','cleanup_classification','pid_budget_classification',
    'local_event_classification'},'V72_SCHEMA_INVALID')
 gate(r['schema']=='stage70-v72-local-pid-denial-scope-v1' and type(r['local_event_classification']) is str
      and r['local_event_classification'] in V72_CLASSES,'V72_CLASS_INVALID')
 gate(type(r['trials']) is list,'V72_TRIALS_INVALID')
 old=[]
 for t in r['trials']:
  gate(type(t) is dict and set(t)==V67_KEYS|{'pressure_phases','dwell_windows','cleanup_observations','pid_budget','pid_scope'},'V72_TRIAL_FIELDS_INVALID')
  scope=t['pid_scope']
  gate(type(scope) is dict and set(scope)==V72_SCOPE_FIELDS,'V72_SCOPE_FIELDS_INVALID')
  gate(type(scope['local_delta']) is str and scope['local_delta'] in V72_LOCAL,'V72_LOCAL_DELTA_INVALID')
  gate(type(scope['local_phases']) is dict and set(scope['local_phases'])==set(V68_PHASES),'V72_LOCAL_PHASES_INVALID')
  for phase in V68_PHASES:
   v=scope['local_phases'][phase]
   gate(type(v) is str and v in V72_LOCAL,'V72_PHASE_DELTA_INVALID')
  gate(type(scope['lifetime_peak_band']) is str and scope['lifetime_peak_band'] in V72_PEAK,'V72_PEAK_INVALID')
  gate(scope['local_delta']==v72_combine_delta([scope['local_phases'][p] for p in V68_PHASES]),'V72_LOCAL_PHASE_PROJECTION')
  # Missing local counter must never be treated as evidence for ZERO denial.
  if scope['local_delta']=='UNAVAILABLE':
   gate(all(x=='UNAVAILABLE' for x in scope['local_phases'].values()),'V72_MISSING_LOCAL_COUNTER_FORGED')
  old.append({k:t[k] for k in V67_KEYS|{'pressure_phases','dwell_windows','cleanup_observations','pid_budget'}})
 legacy={k:r[k] for k in ('mode','classification','firefox_executable','phase_classification',
  'dwell_classification','cleanup_classification','pid_budget_classification')}
 legacy.update(schema='stage70-v71-pid-budget-thread-signal-v1',trials=old)
 validate_v71_pid_budget(legacy)
 gate(r['local_event_classification']==v72_local_event_classification(r),'V72_FORGED_CLASSIFICATION')
 return r,legacy

def docker_v72_local_scope_probe():
 p=call(['docker','exec','-i','--user','1000:1000','--env','PYTHONDONTWRITEBYTECODE=1',
   'cybersec-day03-zap','python3','-c',GECKO_V72_LOCAL_SCOPE_CODE],input=b'',timeout=155)
 gate(p.returncode==0 and 0<len(p.stdout)<26000,'V72_EXEC_FAILED')
 try:r=json.loads(p.stdout)
 except (ValueError,TypeError,UnicodeError) as e:raise Blocked('V72_JSON_INVALID') from e
 return validate_v72_local_scope(r)



# V73: read-only local cgroup PID-denial timing on the EXISTING four 450-ms
# DWELL windows. No new Firefox cohorts, timeouts, sandbox flags, permissions,
# kernel settings, or active scan operations. Counts stay inside the container.
# Group-local events do not prove which task failed or why Firefox terminated.
def v73_cohort_code():
 s=GECKO_V72_LOCAL_SCOPE_CODE
 def patch(old,new):
  nonlocal s
  if s.count(old)!=1:raise RuntimeError('V73_INNER_PATCH_SIGNATURE_MISMATCH_'+str(s.count(old)))
  s=s.replace(old,new)
 patch("'pid_scope':{}}", "'pid_scope':{},'dwell_local_windows':[]}")
 patch("    t['dwell_windows'].append({'pids_max_delta':delta(last,current,'pids_max'),",
       "    t['dwell_local_windows'].append(local_delta(last,current))\\n    t['dwell_windows'].append({'pids_max_delta':delta(last,current,'pids_max'),".replace(chr(92)+'n',chr(10)))
 patch("'lifetime_peak_band':peak_band(after_cleanup)}",
       "'lifetime_peak_band':peak_band(after_cleanup),\\n      'dwell_local_windows':t.pop('dwell_local_windows')}".replace(chr(92)+'n',chr(10)))
 patch("r={'schema':'stage70-v72-local-pid-denial-scope-v1'",
       "r={'schema':'stage70-v73-local-dwell-event-correlation-v1'")
 patch("r['local_event_classification']=local_class(r['trials'])",
       "r['local_event_classification']=local_class(r['trials'])\\nr['local_dwell_classification']=local_dwell_class(r['trials'])".replace(chr(92)+'n',chr(10)))
 patch('def group_drained(pgid):', '''def local_dwell_class(trials):
 if not r['firefox_executable']:return 'UNVERIFIED'
 observed=set()
 for t in trials:
  ds=t['pid_scope']['dwell_local_windows']
  if len(ds)!=4:return 'UNVERIFIED'
  if 'UNKNOWN' in ds:return 'UNVERIFIED'
  if 'UNAVAILABLE' in ds:
   if not all(x=='UNAVAILABLE' for x in ds):return 'UNVERIFIED'
   continue
  for value,window in zip(ds,t['dwell_windows']):
   if value!='POSITIVE':continue
   if window['firefox_before']=='LIVE' and window['firefox_after']!='LIVE':observed.add('LOCAL_EVENT_EXIT_SAME_WINDOW')
   elif window['firefox_before']=='LIVE':observed.add('LOCAL_EVENT_WHILE_LIVE')
   else:observed.add('LOCAL_EVENT_AFTER_EXIT')
 if observed:
  return next(iter(observed)) if len(observed)==1 else 'MIXED_LOCAL_EVENTS'
 if any('UNAVAILABLE' in t['pid_scope']['dwell_local_windows'] for t in trials):return 'LOCAL_UNAVAILABLE'
 return 'LOCAL_NO_EVENT'

def group_drained(pgid):''')
 return s

GECKO_V73_LOCAL_DWELL_CODE=v73_cohort_code()
V73_DWELL_CLASSES={'LOCAL_EVENT_WHILE_LIVE','LOCAL_EVENT_EXIT_SAME_WINDOW',
 'LOCAL_EVENT_AFTER_EXIT','MIXED_LOCAL_EVENTS','LOCAL_NO_EVENT','LOCAL_UNAVAILABLE','UNVERIFIED'}

def v73_local_dwell_classification(r):
 if not r['firefox_executable']:return 'UNVERIFIED'
 observed=set();unavailable=False
 for t in r['trials']:
  ds=t['pid_scope']['dwell_local_windows']
  if len(ds)!=4 or 'UNKNOWN' in ds:return 'UNVERIFIED'
  if 'UNAVAILABLE' in ds:
   if any(x!='UNAVAILABLE' for x in ds):return 'UNVERIFIED'
   unavailable=True
   continue
  for value,window in zip(ds,t['dwell_windows']):
   if value!='POSITIVE':continue
   if window['firefox_before']=='LIVE' and window['firefox_after']!='LIVE':observed.add('LOCAL_EVENT_EXIT_SAME_WINDOW')
   elif window['firefox_before']=='LIVE':observed.add('LOCAL_EVENT_WHILE_LIVE')
   else:observed.add('LOCAL_EVENT_AFTER_EXIT')
 if observed:return next(iter(observed)) if len(observed)==1 else 'MIXED_LOCAL_EVENTS'
 return 'LOCAL_UNAVAILABLE' if unavailable else 'LOCAL_NO_EVENT'

def validate_v73_local_dwell(r):
 gate(type(r) is dict and set(r)=={'schema','mode','classification','firefox_executable','trials',
  'phase_classification','dwell_classification','cleanup_classification','pid_budget_classification',
  'local_event_classification','local_dwell_classification'},'V73_ROOT_SCHEMA')
 gate(r['schema']=='stage70-v73-local-dwell-event-correlation-v1' and
      type(r['local_dwell_classification']) is str and
      r['local_dwell_classification'] in V73_DWELL_CLASSES,'V73_CLASS_SCHEMA')
 gate(type(r['trials']) is list,'V73_TRIALS_SCHEMA')
 old=[]
 for t in r['trials']:
  gate(type(t) is dict and set(t)==V67_KEYS|{'pressure_phases','dwell_windows',
   'cleanup_observations','pid_budget','pid_scope'},'V73_TRIAL_SCHEMA')
  scope=t['pid_scope']
  gate(type(scope) is dict and set(scope)==V72_SCOPE_FIELDS|{'dwell_local_windows'},'V73_SCOPE_SCHEMA')
  windows=scope['dwell_local_windows']
  gate(type(windows) is list and len(windows)==len(t['dwell_windows']) and
   len(windows) in (0,4),'V73_DWELL_WINDOW_COUNT')
  for x in windows:gate(type(x) is str and x in V72_LOCAL,'V73_WINDOW_DELTA_SCHEMA')
  if windows:
   gate(v72_combine_delta(windows)==scope['local_phases']['DWELL'],'V73_LOCAL_DWELL_AGGREGATE')
  else:
   gate(scope['local_phases']['DWELL'] in ('UNKNOWN','UNAVAILABLE'),'V73_MISSING_DWELL_WINDOWS')
  old.append({**{k:t[k] for k in t if k!='pid_scope'},
   'pid_scope':{k:v for k,v in scope.items() if k!='dwell_local_windows'}})
 legacy={**{k:v for k,v in r.items() if k not in ('local_dwell_classification','trials')},
  'schema':'stage70-v72-local-pid-denial-scope-v1','trials':old}
 validate_v72_local_scope(legacy)
 gate(r['local_dwell_classification']==v73_local_dwell_classification(r),'V73_FORGED_LOCAL_DWELL_CLASS')
 return r,legacy

def docker_v73_local_dwell_probe():
 p=call(['docker','exec','-i','--user','1000:1000','--env','PYTHONDONTWRITEBYTECODE=1',
   'cybersec-day03-zap','python3','-c',GECKO_V73_LOCAL_DWELL_CODE],input=b'',timeout=155)
 gate(p.returncode==0 and 0<len(p.stdout)<28000,'V73_EXEC_FAILED')
 try:r=json.loads(p.stdout)
 except (ValueError,TypeError,UnicodeError) as e:raise Blocked('V73_JSON_INVALID') from e
 return validate_v73_local_dwell(r)

# V74: strictly derived cross-phase attribution; reuses only V73 readings.
# Neither an independent experiment nor causal proof. No container settings or
# Firefox launches are changed. All accepted data is category-only.
V74_PHASES=('LAUNCH','GREETINGS','DWELL_1','DWELL_2','DWELL_3','DWELL_4')
V74_ASSOCIATIONS={'SAME_OBSERVATION_PHASE','PRIOR_OBSERVATION_PHASE',
 'AFTER_OBSERVED_EXIT','DENIAL_WITHOUT_OBSERVED_EXIT',
 'EXIT_WITHOUT_OBSERVED_LOCAL_DENIAL','NEITHER_OBSERVED','UNVERIFIED'}

def make_v74_attribution(v73):
 validate_v73_local_dwell(v73)
 out=[]
 for t in v73['trials']:
  sc=t['pid_scope']; phases=sc['local_phases']; windows=t['dwell_windows']
  # Historical status only tells where an exit was FIRST SEEN, not its time.
  first_exit='NONE'
  if t['state_after_launch']!='LIVE':first_exit='LAUNCH'
  elif windows and windows[0]['firefox_before']!='LIVE':first_exit='GREETINGS'
  else:
   for i,w in enumerate(windows):
    if w['firefox_before']=='LIVE' and w['firefox_after']!='LIVE':
     first_exit='DWELL_'+str(i+1);break
   if not windows:first_exit='UNVERIFIED'
  values=[phases['LAUNCH'],phases['GREETINGS'],*sc['dwell_local_windows']]
  if len(values)!=6:values=[]
  if any(v not in ('ZERO','POSITIVE') for v in values) or first_exit=='UNVERIFIED':
   first_denial='UNVERIFIED';association='UNVERIFIED'
  else:
   first_denial=next((x for x,v in zip(V74_PHASES,values) if v=='POSITIVE'),'NONE')
   if first_exit=='NONE' and first_denial=='NONE':association='NEITHER_OBSERVED'
   elif first_exit=='NONE':association='DENIAL_WITHOUT_OBSERVED_EXIT'
   elif first_denial=='NONE':association='EXIT_WITHOUT_OBSERVED_LOCAL_DENIAL'
   elif V74_PHASES.index(first_denial)==V74_PHASES.index(first_exit):association='SAME_OBSERVATION_PHASE'
   elif V74_PHASES.index(first_denial)<V74_PHASES.index(first_exit):association='PRIOR_OBSERVATION_PHASE'
   else:association='AFTER_OBSERVED_EXIT'
  out.append({'role':t['role'],'first_local_denial_phase':first_denial,
              'first_observed_exit_phase':first_exit,'association':association})
 classifications={t['association'] for t in out}
 category='MIXED' if len(classifications)>1 else next(iter(classifications))
 return {'schema':'stage70-v74-cross-phase-observed-association-v1',
         'mode':'READ_ONLY_DERIVED_FROM_EXISTING_V73_COHORT',
         'causality':'NOT_ESTABLISHED','classification':category,
         'cohorts':out}

def validate_v74_attribution(v74,v73):
 gate(type(v74) is dict and
      set(v74)=={'schema','mode','causality','classification','cohorts'},
      'V74_ROOT_SCHEMA')
 gate(type(v74.get('cohorts')) is list and len(v74['cohorts'])==3,
      'V74_COHORT_COUNT')
 for t in v74['cohorts']:
  gate(type(t) is dict and set(t)=={'role','first_local_denial_phase',
       'first_observed_exit_phase','association'} and
       all(type(x) is str for x in t.values()),'V74_COHORT_SCHEMA')
 gate(v74==make_v74_attribution(v73),'V74_PROJECTION_MISMATCH')
 return v74

def verified_ajax_browser_option(body:dict)->str:
    """Fail closed on an unexpected ZAP response schema; never fabricate an ID.

    ZAP API docs define the option view but do not specify JSON key casing.
    Only a small set of semantically matching keys is allowed. On an unknown
    schema, emit safe key *names*, not option values or HTTP/API credentials.
    """
    gate(isinstance(body,dict),'AJAX_BROWSER_OPTION_RESPONSE_NOT_OBJECT')
    candidates=('optionBrowserId','browserId','BrowserId','browser')
    matched=[k for k in candidates if k in body]
    if len(matched)!=1:
        safe=[k for k in body if isinstance(k,str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,39}',k)]
        raise Blocked('AJAX_BROWSER_OPTION_SCHEMA_UNRECOGNIZED_KEYS_'+','.join(sorted(safe)[:5]))
    v=body[matched[0]]
    gate(isinstance(v,str) and 0<len(v)<=64,'AJAX_BROWSER_OPTION_VALUE_INVALID')
    return v

def run_ajax_supported_api(api,day03,*,clock=time.monotonic,sleep=time.sleep,diagnostics:dict|None=None,route_proof:dict|None=None,cli_control:bool=False,native_marionette_control:bool=False):
    """Use documented ZAP APIs, never synthesize unavailable browser lists.

    A successful API scan start is NOT sufficient: enforce a bounded live cycle
    and require actual in-scope results. The independent app's full-day pass gate
    is evaluated only once this function completes and the passive queue drains.
    """
    gate(docker_executable('firefox'),'FIREFOX_BINARY_MISSING_IN_PINNED_ZAP_CONTAINER')
    selenium_binary=api.call('selenium','view','optionFirefoxBinaryPath')
    gate(isinstance(selenium_binary,dict),'SELENIUM_BINARY_VIEW_MALFORMED')
    selenium_driver=api.call('selenium','view','optionFirefoxDriverPath')
    gate(isinstance(selenium_driver,dict),'SELENIUM_DRIVER_VIEW_MALFORMED')
    # The driver may be supplied by the pinned ZAP addon and need not be in PATH.
    driver_configured=safe_selenium_view_fields(selenium_driver)['has_configured_path']
    driver_in_path=docker_executable('geckodriver')
    if diagnostics is not None:
        diagnostics['selenium_firefox_binary_view']=safe_selenium_view_fields(selenium_binary)
        diagnostics['selenium_geckodriver_view']=safe_selenium_view_fields(selenium_driver)
        diagnostics['geckodriver_in_path']=driver_in_path
        diagnostics['browser_selected']='PENDING'
        # Validate actual path from ZAP's documented Selenium API instead of
        # guessing a PATH location or installing a new unverified binary.
        configured_path=configured_firefox_driver_path(selenium_driver)
        evidence=docker_driver_session_probe(configured_path)
        diagnostics['real_webdriver_session_probe']=evidence
        if (not evidence['fixture_navigation_confirmed'] and evidence['driver_executable']
                and evidence['elf_linux_aarch64'] and evidence['driver_version_ok']
                and evidence['webdriver_server_ready']
                and evidence['private_profile_root_cleaned']):
            # New process, fresh private profile. Never accept secondary PASS
            # as a substitute for primary failure or admit AJAX after it.
            try:
                second=docker_driver_session_probe(configured_path)
                diagnostics['independent_repeat_probe']=second
                diagnostics['repeat_classification']=(
                    'PRIMARY_FAILED_REPEAT_PASSED' if second['fixture_navigation_confirmed']
                    else 'BOTH_PROBES_FAILED')
            except Blocked:
                diagnostics['repeat_classification']='REPEAT_INFRASTRUCTURE_BLOCKED'
        # V52: counterfactual no-proxy headless about:blank startup only.
        # This has no fixture URL, no scan APIs and cannot replace primary proof.
        if not evidence['fixture_navigation_confirmed'] and evidence['driver_executable'] and evidence['elf_linux_aarch64'] and evidence['driver_version_ok']:
            try:
                control=docker_no_proxy_headless_baseline(configured_path)
                diagnostics['no_proxy_about_blank_control']=control
                diagnostics['no_proxy_control_classification']=(
                    'CONTROL_PASSED_PRIMARY_STILL_BLOCKED'
                    if control['about_blank_verified'] else 'CONTROL_FAILED_PRIMARY_BLOCKED')
            except Blocked:
                diagnostics['no_proxy_control_classification']='CONTROL_INFRASTRUCTURE_BLOCKED'
        # V53 A/B experiment is strictly diagnostic; never changes the
        # primary driver/session/window/navigation admission evidence.
        if cli_control and not evidence['fixture_navigation_confirmed']:
            try:
                cli_proof=docker_headless_cli_control()
                diagnostics['firefox_headless_cli_about_blank_control']=cli_proof
                diagnostics['headless_cli_classification']=(
                    'CLI_PASSED_PRIMARY_STILL_BLOCKED'
                    if cli_proof['classification']=='CLI_SCREENSHOT_PASS_DIAGNOSTIC_ONLY'
                    else 'CLI_FAILED_PRIMARY_BLOCKED')
            except (Blocked,OSError,subprocess.TimeoutExpired):
                diagnostics['headless_cli_classification']='CLI_INFRASTRUCTURE_BLOCKED'
        # V61: independent native Marionette startup control, not GeckoDriver.
        # Diagnostic only after primary admission failure; no scan or network URL.
        if native_marionette_control and not evidence['fixture_navigation_confirmed']:
            if 'direct_marionette_classification' not in diagnostics:
                try:
                    native=docker_native_marionette_control()
                    diagnostics['direct_marionette_about_blank_control']=native
                    diagnostics['direct_marionette_classification']=(
                        'DIRECT_MARIONETTE_AVAILABLE_PRIMARY_BLOCKED' if native['handshake_verified']
                        else 'DIRECT_MARIONETTE_UNAVAILABLE_PRIMARY_BLOCKED')
                except (Blocked,OSError,subprocess.TimeoutExpired):
                    diagnostics['direct_marionette_classification']='DIRECT_MARIONETTE_INFRASTRUCTURE_BLOCKED'
        # V63: only if primary proxy/session failed; independently attach to an
        # already-live Firefox using GeckoDriver's documented local switch.
        # It never changes the acceptance gate below and never navigates.
        if (not evidence['fixture_navigation_confirmed'] and evidence['driver_executable']
                and evidence['elf_linux_aarch64'] and evidence['driver_version_ok']):
            try:
                attach=docker_gecko_attach_control(configured_path)
                diagnostics['geckodriver_attach_existing_control']=attach
                diagnostics['geckodriver_attach_classification']=(
                    'ATTACH_SUCCEEDED_PRIMARY_STILL_BLOCKED'
                    if attach['classification']=='ATTACH_PASS_DIAGNOSTIC_ONLY'
                    else 'ATTACH_FAILED_PRIMARY_STILL_BLOCKED')
            except (Blocked,OSError,subprocess.TimeoutExpired):
                diagnostics['geckodriver_attach_classification']='ATTACH_INFRASTRUCTURE_BLOCKED'
        # V64: a *new* isolated attachment probe records bounded trace and
        # Firefox PID identity, Marionette port, W3C and crash lifecycle.
        # It never supplies an admission result, never changes sandbox/UID and
        # never attempts an in-scope navigation or any AJAX request.
        if (not evidence['fixture_navigation_confirmed'] and evidence['driver_executable']
                and evidence['elf_linux_aarch64'] and evidence['driver_version_ok']):
            try:
                trace=docker_v64_trace_control(configured_path)
                diagnostics['geckodriver_v64_trace_control']=trace
                diagnostics['geckodriver_v64_trace_classification']=(
                    'TRACE_SUCCEEDED_PRIMARY_STILL_BLOCKED'
                    if trace['classification']=='TRACE_PASS_DIAGNOSTIC_ONLY'
                    else 'TRACE_FAILED_PRIMARY_STILL_BLOCKED')
            except (Blocked,OSError,subprocess.TimeoutExpired):
                diagnostics['geckodriver_v64_trace_classification']='TRACE_INFRASTRUCTURE_BLOCKED'
        # V65: two native Marionette greetings *in the same Firefox lifetime*,
        # separated by GeckoDriver newSession. Fixed-category sandbox evidence;
        # never overrides the original fixture navigation admission gate.
        if (not evidence['fixture_navigation_confirmed'] and evidence['driver_executable']
                and evidence['elf_linux_aarch64'] and evidence['driver_version_ok']):
            try:
                differential=docker_v65_protocol_probe(configured_path)
                diagnostics['geckodriver_v65_protocol_control']=differential
                diagnostics['geckodriver_v65_protocol_classification']=(
                    'PROTOCOL_SUCCEEDED_PRIMARY_STILL_BLOCKED'
                    if differential['classification']=='PROTOCOL_PASS_DIAGNOSTIC_ONLY'
                    else 'PROTOCOL_FAILED_PRIMARY_STILL_BLOCKED')
            except (Blocked,OSError,subprocess.TimeoutExpired):
                diagnostics['geckodriver_v65_protocol_classification']='PROTOCOL_INFRASTRUCTURE_BLOCKED'
        # V66: paired control of stable standalone native greetings, then
        # GeckoDriver server startup, then newSession and post-session native.
        # Diagnostic only: primary WebDriver/AJAX/second-passive gates unchanged.
        if (not evidence['fixture_navigation_confirmed'] and evidence['driver_executable']
                and evidence['elf_linux_aarch64'] and evidence['driver_version_ok']):
            try:
                paired=docker_v66_paired_probe(configured_path)
                diagnostics['geckodriver_v66_paired_control']=paired
                diagnostics['geckodriver_v66_paired_classification']=(
                    'PAIRED_SUCCEEDED_PRIMARY_STILL_BLOCKED'
                    if paired['classification']=='PAIRED_PASS_DIAGNOSTIC_ONLY'
                    else 'PAIRED_FAILED_PRIMARY_STILL_BLOCKED')
            except (Blocked,OSError,subprocess.TimeoutExpired):
                diagnostics['geckodriver_v66_paired_classification']='PAIRED_INFRASTRUCTURE_BLOCKED'
        # V67: native-only isolated cohort when the primary WebDriver fails.
        # Every trial creates a NEW Firefox process/profile with 0, 1, or 3 greetings.
        # No diagnostic outcome grants permission for AJAX or production.
        if not evidence['fixture_navigation_confirmed']:
            try:
                local_dwell,local_scope=docker_v73_local_dwell_probe()
                budget=validate_v72_local_scope(local_scope)[1]
                _,quiescence=validate_v71_pid_budget(budget)
                _,timeline=validate_v70_quiescence(quiescence)
                diagnostics['firefox_v73_local_dwell_control']=local_dwell
                diagnostics['firefox_v74_cross_phase_control']=validate_v74_attribution(
                    make_v74_attribution(local_dwell),local_dwell)
                diagnostics['firefox_v73_local_dwell_classification']=local_dwell['local_dwell_classification']
                diagnostics['firefox_v72_local_pid_scope_control']=local_scope
                diagnostics['firefox_v72_local_pid_scope_classification']=local_scope['local_event_classification']
                _,phase=validate_v69_dwell(timeline)
                _,cohort=validate_v68_phase(phase)
                diagnostics['firefox_v71_pid_budget_control']=budget
                diagnostics['firefox_v71_pid_budget_classification']=budget['pid_budget_classification']
                diagnostics['firefox_v70_group_quiescence_control']=quiescence
                diagnostics['firefox_v70_cleanup_classification']=quiescence['cleanup_classification']
                diagnostics['firefox_v69_dwell_timeline_control']=timeline
                diagnostics['firefox_v69_dwell_classification']=timeline['dwell_classification']
                diagnostics['firefox_v68_pid_phase_control']=phase
                diagnostics['firefox_v67_native_cohort_control']=cohort
                diagnostics['firefox_v67_native_cohort_classification']=(
                    'COHORT_STABLE_PRIMARY_STILL_BLOCKED'
                    if cohort['classification']=='COHORT_STABLE_DIAGNOSTIC_ONLY'
                    else 'COHORT_UNSTABLE_PRIMARY_STILL_BLOCKED')
            except (Blocked,OSError,subprocess.TimeoutExpired):
                diagnostics['firefox_v67_native_cohort_classification']='COHORT_INFRASTRUCTURE_BLOCKED'
        gate(evidence['driver_executable'],'CONFIGURED_GECKODRIVER_NOT_EXECUTABLE')
        gate(evidence['elf_linux_aarch64'],'CONFIGURED_GECKODRIVER_NOT_ARM64')
        gate(evidence['driver_version_ok'],'CONFIGURED_GECKODRIVER_VERSION_FAILED')
        gate(evidence['webdriver_server_ready'],'GECKODRIVER_SERVER_UNAVAILABLE')
        gate(evidence['webdriver_session_created'],'FIREFOX_WEBDRIVER_SESSION_FAILED')
        gate(evidence['fixture_navigation_confirmed'],'FIREFOX_WEBDRIVER_FIXTURE_NAVIGATION_FAILED')
    # Never start AJAX when the independently tested direct or proxied route
    # to the one authorized fixture is not proven. Keep WebDriver forensics.
    if route_proof is not None:
        gate(type(route_proof) is dict and
             route_proof.get('direct',{}).get('http_200') is True and
             route_proof.get('through_zap',{}).get('http_200') is True,
             'INTERNAL_FIXTURE_PROXY_PATH_NOT_PROVEN')
    # V37 evidence: the *unconfigured* view returned HTTP 200 but no
    # `optionBrowserId` key. Explicitly configure the documented ID first.
    # Never infer successful selection from HTTP 200 alone: demand a follow-up
    # view containing the exact expected value under a known schema key.
    api.call('ajaxSpider','action','setOptionBrowserId',{'String':'firefox-headless'})
    selected=verified_ajax_browser_option(api.call('ajaxSpider','view','optionBrowserId'))
    gate(selected=='firefox-headless','AJAX_FIREFOX_HEADLESS_OPTION_NOT_APPLIED')
    if diagnostics is not None: diagnostics['browser_selected']='firefox-headless'
    # All requests must be in the exact Docker-internal ZAP context, even if
    # the AJAX add-on interprets inScope differently when a context is supplied.
    limits=day03.Limits(max_ajax_seconds=90)
    for method,args in (
        ('setOptionMaxCrawlDepth',{'Integer':str(limits.depth)}),
        ('setOptionMaxCrawlStates',{'Integer':str(limits.ajax_states)}),
        ('setOptionMaxDuration',{'Integer':'1'}),
        ('setOptionNumberOfBrowsers',{'Integer':'1'}),
        ('setOptionRandomInputs',{'Boolean':'false'}),
        ('setOptionScopeCheck',{'String':'Strict'}),
    ):
        api.call('ajaxSpider','action',method,args)
    started=False
    observed_running=False
    status_history=[]
    try:
        launch=api.call('ajaxSpider','action','scan',
            {'url':TARGET,'inScope':'true','subtreeOnly':'true',
             'contextName':'Stage70_Day03_Fixture'})
        gate(launch.get('Result') in ('OK','ok'),'AJAX_START_NOT_CONFIRMED')
        started=True
        deadline=clock()+limits.max_ajax_seconds
        while clock()<=deadline:
            status=api.call('ajaxSpider','view','status').get('status')
            gate(status in ('running','stopped'),'AJAX_UNKNOWN_STATE')
            if len(status_history)<12 and (not status_history or status_history[-1]!=status):
                status_history.append(status)
            if status=='running':observed_running=True
            if status=='stopped':break
            sleep(max(0.5,limits.poll_seconds))
        else:
            raise day03.LabTimeout('AJAX_DEADLINE_EXCEEDED')
        count_raw=api.call('ajaxSpider','view','numberOfResults').get('numberOfResults')
        count=day03._positive_number(count_raw,1000)
        if diagnostics is not None:
            diagnostics['scan_started_api']='PASS'
            diagnostics['ajax_status_history']=list(status_history)
            diagnostics['ajax_observed_running']=observed_running
            diagnostics['ajax_number_of_results']=count
            diagnostics['driver_path_configured']=driver_configured
        gate(count>0,'AJAX_NO_RESULT_URLS_BROWSER_LAUNCH_UNPROVEN')
        gate(count<=200,'AJAX_RESULT_SET_EXCEEDS_LAB_LIMIT')
        from urllib.parse import urlsplit
        verified=[]
        # Verify *every* discovered result, not only the first page. A hidden
        # out-of-scope URL must never be counted as evidence for an accepted run.
        for start in range(0,count,25):
            results=api.call('ajaxSpider','view','results',
                             {'start':str(start),'count':str(min(25,count-start))}).get('results')
            gate(isinstance(results,list) and len(results)>0,'AJAX_RESULTS_NOT_AVAILABLE')
            for item in results:
                url=item if isinstance(item,str) else item.get('url') if isinstance(item,dict) else None
                gate(isinstance(url,str),'AJAX_RESULT_URL_MALFORMED')
                parsed=urlsplit(url)
                gate(parsed.scheme=='http' and parsed.hostname=='day03-target' and parsed.port==8080
                     and parsed.username is None and parsed.password is None
                     and parsed.path.startswith('/') and not parsed.fragment,
                     'AJAX_OUT_OF_SCOPE_RESULT_REFUSED')
                verified.append(url)
        gate(len(verified)==count,'AJAX_RESULT_COUNT_MISMATCH')
        return {'ajax_spider':'completed','browser':'firefox-headless',
                'ajax_result_count':count,'ajax_in_scope_results':verified,
                'ajax_observed_running':observed_running,
                'ajax_status_history':status_history,
                'firefox_driver_path_configured':driver_configured,
                'geckodriver_in_path':driver_in_path}
    finally:
        if started:
            api.call('ajaxSpider','action','stop')

def monitor_state()->dict:
    ans={}
    for name in ('cybersec-day03-zap','cybersec-day03-target'):
        p=call(['docker','inspect','--format','{{json .State}}',name],timeout=20)
        if p.returncode:ans[name]={'present':False};continue
        try:
            state=json.loads(p.stdout)
            ans[name]={'present':True,'running':state.get('Running') is True,
                       'exit_code':state.get('ExitCode'),'oom_killed':state.get('OOMKilled') is True}
        except (ValueError,TypeError):ans[name]={'present':True,'inspect':'MALFORMED'}
    return ans

def classify_webdriver_log(raw:str)->dict:
    """Only predefined labels/counters. Do not persist log lines or their substrings."""
    categories={
      'FAILED_START_BROWSER':r'failed to start browser',
      'NO_SUCH_DRIVER_EXCEPTION':r'NoSuchDriverException',
      'GECKODRIVER_OBTAIN_FAILURE':r'unable to obtain:?[ ]*geckodriver|unable to obtain driver',
      'GECKODRIVER_NOT_FOUND':r'geckodriver[^\n]{0,80}(not found|no such file|could not find)',
      'SESSION_NOT_CREATED':r'SessionNotCreatedException',
      'WEBDRIVER_EXCEPTION':r'WebDriverException',
      'WEBDRIVER_CONNECT_FAILURE':r'ConnectException|connection refused',
      'WEBDRIVER_TIMEOUT':r'TimeoutException|timed out waiting for driver',
      'WEBDRIVER_PERMISSION_DENIED':r'permission denied|Operation not permitted',
      'FIREFOX_CRASH':r'Process unexpectedly closed|browser process exited|Firefox exited',
      'FIREFOX_BINARY_MISSING':r'Unable to find Firefox|Firefox binary not found',
      'ZAP_UNKNOWN_HOST_EXCEPTION':r'ZapUnknownHostException',
      'JAVA_UNKNOWN_HOST_EXCEPTION':r'UnknownHostException',
      'SELENIUM_MENTION':r'selenium',
      'GECKODRIVER_MENTION':r'geckodriver',
      'ERROR_TOKEN':r'\berror\b',
      'EXCEPTION_TOKEN':r'exception',
    }
    return {'classification':'FIXED_CATEGORY_COUNTS_NO_RAW_LOGS',
            'lines_examined':len(raw.splitlines()),
            'signals':{k:len(re.findall(pattern,raw,re.I)) for k,pattern in categories.items()}}

def record_log_signals()->dict:
    p=call(['docker','logs','--tail','1200','cybersec-day03-zap'],timeout=20)
    if p.returncode:return {'classification':'UNAVAILABLE'}
    raw=(p.stdout+p.stderr).decode('utf-8','replace')
    return classify_webdriver_log(raw)


def pack(evd:Path)->tuple[Path,Path]:
    files=[p for p in sorted(evd.rglob('*')) if p.is_file() and p.name!='SHA256SUMS.txt']
    (evd/'SHA256SUMS.txt').write_text(''.join(f'{sha(p)}  {p.relative_to(evd).as_posix()}\n' for p in files),'utf-8')
    zipname=evd.with_suffix('.zip')
    with zipfile.ZipFile(zipname,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for p in sorted(evd.rglob('*')):
            if p.is_file():z.write(p,p.relative_to(evd.parent))
    with zipfile.ZipFile(zipname) as z:gate(z.testzip() is None,'EVIDENCE_ZIP_CRC_FAILED')
    side=zipname.with_suffix('.zip.sha256')
    side.write_text(f'{sha(zipname)}  {zipname.name}\n','utf-8')
    return zipname,side

def run(*,pid_budget=None,ab_label=None,ab_replicate=None)->int:
    gate(sys.platform=='linux' and os.geteuid()!=0 and os.uname().machine in ('aarch64','arm64'),
         'NONROOT_LINUX_ARM64_REQUIRED')
    gate(not any(os.environ.get(x,'').lower().strip() in ('production','prod')
                 for x in ('CYBERSEC_RUNTIME_MODE','CYBERSEC_EXECUTION_MODE')),'PRODUCTION_REFUSED')
    EVIDENCE.mkdir(mode=0o700,parents=True,exist_ok=True)
    os.chmod(EVIDENCE,0o700)
    sid='stage70_zap_focused_v75pid_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+secrets.token_hex(4)
    evd=EVIDENCE/sid
    evd.mkdir(mode=0o700)
    state={'schema':'stage70-zap-focused-v75pid-v1','run_id':sid,'overall':'BLOCKED/NO-GO',
           'production':'BLOCKED/NO-GO','stage71':'NOT_OPENED','day04':'NOT_RUN',
           'active_scan':False,'target':TARGET,'checks':{},'zaproxy_api_transport':'DOCKER_EXEC_IN_CONTAINER_LOOPBACK',
           'spider':'NOT_RUN','ajax_spider':'NOT_RUN','passive':'NOT_RUN'}
    lock=None;started=False;api=None;compose_env=None
    from pid_recovery import numeric_telemetry,admissible_budgets,compose_pid_delta,verify_runtime_budget,CONTAINER_TELEMETRY_CODE,BudgetBlocked
    rc=4
    state['checks']['v75_ab']={'arm':ab_label or 'NONE','replicate':ab_replicate,
                                'pid_budget':pid_budget,'status':'NOT_RUN' if pid_budget is None else 'PENDING'}
    try:
        lockfile=EVIDENCE/'.zap_focus.lock' 
        lock=lockfile.open('a+')
        try:fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise Blocked('ANOTHER_ZAP_FOCUSED_RUN_IN_PROGRESS')
        state['checks']['snapshot_marker_sha256']=snapshot()
        source(REPO)
        state['checks']['git_pinned']='PASS'
        zap,target=images()
        state['checks']['pinned_image_digests']={'zap_sha256':zap.split('sha256:')[1],
                                                  'target_sha256':target.split('sha256:')[1]}
        gate(docker_image(zap) and docker_image(target),'PINNED_ARM64_IMAGES_NOT_IN_DOCKER')
        state['checks']['docker_images']='PASS'
        old=monitor_state()
        gate(not any(v['present'] for v in old.values()),'PREEXISTING_LAB_CONTAINERS_REFUSE_TO_MODIFY')
        other=call(['docker','ps','-a','--filter','label=com.docker.compose.project=cybersec-day03',
                    '--format','{{.ID}}'],timeout=20)
        gate(other.returncode==0 and not other.stdout.strip(),
             'PREEXISTING_COMPOSE_PROJECT_REFUSE_TO_MODIFY')
        head=call(['git','-C',str(REPO),'rev-parse','HEAD'],timeout=20)
        gate(head.returncode==0,'GIT_HEAD_MISSING')
        state['checks']['original_head']=head.stdout.decode().strip()
        py=REPO/'.venv/bin/python'
        gate(py.is_file(),'REPO_VENV_PYTHON_UNAVAILABLE')
        # Use the pinned source's own ZAP-oriented unit tests, not 450 unrelated tests.
        tests=['tests/test_stage70_day03_zap.py','tests/test_zap_adapter.py']
        cmd=[str(py),'-m','pytest','-q','-W','error::ResourceWarning',
             '-W','error::DeprecationWarning','-W','error::pytest.PytestUnraisableExceptionWarning']+tests
        u=subprocess.run(cmd,cwd=REPO,capture_output=True,timeout=240)
        (evd/'zap_targeted_pytest.stdout.txt').write_bytes(u.stdout)
        (evd/'zap_targeted_pytest.stderr.txt').write_bytes(u.stderr)
        (evd/'zap_targeted_pytest.exitcode').write_text(str(u.returncode)+'\n')
        gate(u.returncode==0,'ZAP_TARGETED_TESTS_FAILED')
        gate(not u.stderr.strip(),'ZAP_TARGETED_TESTS_NONEMPTY_STDERR')
        summary=u.stdout.decode('utf-8','replace')
        gate(not re.search(r'\b\d+\s+(skipped|warnings?)\b',summary), 'ZAP_TARGETED_TESTS_SKIPPED_OR_WARNINGS')
        state['checks']['targeted_tests']='PASS_NO_SKIPS_OR_WARNINGS'
        # A new transient key, never written to evidence or command argv.
        key=secrets.token_urlsafe(40)
        compose_env=os.environ.copy()
        compose_env.update(CYBERSEC_DAY03_ZAP_IMAGE=zap,CYBERSEC_DAY03_TARGET_IMAGE=target,
                           CYBERSEC_DAY03_ZAP_API_KEY=key)
        # V75: host-level PID telemetry; no pids.max writes. If A/B is requested,
        # require finite parent-cgroup capacity before any Docker mutation.
        state['checks']['v75_host_pid_numeric']=numeric_telemetry()
        if pid_budget is not None:
            parent=state['checks']['v75_host_pid_numeric'].get('ancestor_budgets')
            if parent is None:
                raise Blocked('V75_PARENT_CGROUP_NOT_VISIBLE')
            # Parent capacity includes all siblings. The operator's two arms are
            # validated by mac_pid_ab_runner before this VM invocation; here
            # validate this trial's upper budget conservatively again.
            host=state['checks']['v75_host_pid_numeric']
            if not host['ancestors_visible']:
                raise Blocked('V75_PARENT_CGROUP_UNVERIFIED')
            finite=[x['max']-x['current'] for x in parent if
                    type(x.get('max')) is int and type(x.get('current')) is int]
            if not finite or min(finite)<pid_budget+24:
                raise Blocked('V75_PARENT_PID_HEADROOM_INSUFFICIENT')
        # The original pinned YAML remains untouched. A fresh, single-field
        # override increases only ZAP's /dev/shm from Docker's 64 MiB default.
        shm_overlay=evd/'lab_shm_override.yml'
        if pid_budget is None:
            shm_overlay.write_text(LAB_SHM_OVERRIDE,encoding='utf-8')
            shm_overlay.chmod(0o600)
            state['checks']['compose_only_shm_override']=validate_shm_only_compose_overlay(
                REPO,shm_overlay,compose_env)
        else:
            # Only the ZAP service's finite PID limit is changed, alongside
            # the already-vetted 256 MiB /dev/shm field. No caps/sandbox diff.
            shm_overlay.write_text(LAB_SHM_OVERRIDE+'    pids_limit: '+str(pid_budget)+'\n',encoding='utf-8')
            shm_overlay.chmod(0o600)
            base=['docker','compose','-f','deployment/day03/compose.lab.yml']
            before=call(base+['config','--format','json'],cwd=REPO,env=compose_env,timeout=25)
            after=call(base+['-f',str(shm_overlay),'config','--format','json'],cwd=REPO,env=compose_env,timeout=25)
            gate(before.returncode==0 and after.returncode==0 and
                 len(before.stdout)<200000 and len(after.stdout)<200000,
                 'V75_COMPOSE_CONFIG_UNAVAILABLE')
            try:
                projection=compose_pid_delta(json.loads(before.stdout),json.loads(after.stdout),pid_budget)
            except (ValueError,TypeError,BudgetBlocked):
                raise Blocked('V75_COMPOSE_DELTA_INVALID')
            state['checks']['v75_compose_delta']=projection
        cmd=['docker','compose','-f','deployment/day03/compose.lab.yml',
             '-f',str(shm_overlay),'up','-d','--pull','never','--no-build']
        # Attempted start may leave a partial compose project: always perform
        # down on the same owned project after preexisting-container checks.
        started=True
        x=subprocess.run(cmd,cwd=REPO,env=compose_env,capture_output=True,timeout=170)
        gate(x.returncode==0,'DOCKER_COMPOSE_LAB_START_FAILED')
        state['checks']['compose_up']='PASS'
        state['checks']['zap_shm_runtime']=verify_runtime_shm()
        # Numeric, bounded, read-only cgroup observation in ZAP's own namespace.
        if pid_budget is not None:
            insp=call(['docker','inspect','--format','{{.HostConfig.PidsLimit}}',
                       'cybersec-day03-zap'],timeout=20)
            gate(insp.returncode==0 and insp.stdout.strip()==str(pid_budget).encode(),
                 'V75_DOCKER_RUNTIME_PID_BUDGET_MISMATCH')
        measurement=call(['docker','exec','-i','--user','1000:1000',
                 'cybersec-day03-zap','python3','-c',CONTAINER_TELEMETRY_CODE],timeout=25)
        gate(measurement.returncode==0 and len(measurement.stdout)<8192,
             'V75_CONTAINER_TELEMETRY_UNAVAILABLE')
        try: measured=json.loads(measurement.stdout)
        except (ValueError,TypeError):raise Blocked('V75_NUMERIC_TELEMETRY_INVALID')
        gate(type(measured) is dict and
             measured.get('schema')=='stage70-v75-container-pid-numeric-v1',
             'V75_CONTAINER_TELEMETRY_SCHEMA_INVALID')
        if pid_budget is not None:
            try:verify_runtime_budget(measured.get('pids_max'),pid_budget,
                        {'seccomp':measured.get('seccomp'),
                         'no_new_privs':measured.get('no_new_privs')})
            except BudgetBlocked:raise Blocked('V75_PID_BUDGET_OR_SANDBOX_UNVERIFIED')
        state['checks']['v75_container_pid_numeric']=measured
        state['checks']['v75_ab']['status']='BUDGET_ENFORCED' if pid_budget is not None else 'PASSIVE_NUMERIC_ONLY'

        sys.path.insert(0,str(REPO/'src'))
        from cybersec import day03_zap as day03
        # The pinned upstream validator checks the caller process environment, not
        # docker-compose's child-only environment. Temporarily bind the *same*
        # previously validated digest refs for this independent Docker inspection.
        # Never relax or bypass any validation performed by validate_docker_lab().
        proof=validate_with_pinned_image_environment(day03.validate_docker_lab,zap,target)
        gate(proof.get('docker_isolated') is True,'LAB_ISOLATION_NOT_PROVEN')
        state['checks']['internal_docker_network']='PASS'
        api=ContainerAPI(key,day03.ALLOWED_ACTIONS,day03.ALLOWED_VIEWS)
        state['checks']['api_readiness_diagnostic']={}
        state['checks']['api_version']=await_zap_api_readiness(
            api,state['checks']['api_readiness_diagnostic'])
        state['checks']['api_ready']='PASS'
        target_response=docker_http({'kind':'target'})
        gate(target_response.get('ok') and target_response.get('data',{}).get('http')==200,
             'PINNED_TARGET_NOT_REACHABLE_FROM_ZAP')
        state['checks']['internal_target_http']='PASS'
        state['checks']['docker_state_after_ready']=monitor_state()
        # V62/V63: perform direct Marionette before ZAP context, Spider and WebDriver.
        # Earlier V61 failed in context setup and never reached native control.
        state['checks']['phase']='NATIVE_MARIONETTE_PREFLIGHT'
        state['checks']['native_marionette_preflight']={'result':'NOT_RUN'}
        try:
            direct=docker_native_marionette_control()
            state['checks']['native_marionette_preflight']={
                'result':'DIAGNOSTIC_PASS' if direct['handshake_verified'] else 'DIAGNOSTIC_BLOCKED',
                'proof':direct}
        except (Blocked,OSError,subprocess.TimeoutExpired):
            state['checks']['native_marionette_preflight']={
                'result':'INFRASTRUCTURE_BLOCKED'}
        # The diagnostic is independent and NEVER permits WebDriver or AJAX.
        # AJAX `inScope=true` must not silently become an empty or global scope.
        # Context is restricted to the exact isolated nginx fixture hostname.
        ctx='Stage70_Day03_Fixture'
        state['checks']['phase']='CONTEXT_CREATE'
        api.call('context','action','newContext',{'contextName':ctx})
        state['checks']['phase']='CONTEXT_INCLUDE'
        api.call('context','action','includeInContext',
                 {'contextName':ctx,'regex':r'^http://day03-target:8080/.*'})
        state['checks']['phase']='CONTEXT_SET_SCOPE'
        api.call('context','action','setContextInScope',
                 {'contextName':ctx,'booleanInScope':'true'})
        state['checks']['zap_fixture_context']='PASS_EXACT_INTERNAL_TARGET_REGEX'
        state['checks']['phase']='SPIDER_AND_FIRST_PASSIVE'
        report=day03.run_lab(api,authorization=True,runtime=True,ajax=False,
                              browser_isolated=True)
        gate(report['spider']==100 and report['passive_drained'] is True,'SPIDER_PASSIVE_NOT_COMPLETE')
        (evd/'spider_passive_proof.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        state['spider']='PASS_100_PERCENT'
        state['passive']='PASS_DRAINED_AFTER_SPIDER'
        # Read-only container diagnostics for ARM64 Selenium/geckodriver.
        state['checks']['webdriver_environment']=docker_driver_probe()
        # Direct vs ZAP proxy: requests remain exclusively on the pinned
        # internal HTTP fixture. No response bodies or user-provided URLs.
        state['checks']['internal_fixture_http_routes']=docker_proxy_route_probe()
        # We still collect real WebDriver behavior even if the proxy route is
        # unavailable, but never allow AJAX admission on a failed route.
        state['checks']['phase']='WEBDRIVER_AND_AJAX'
        state['checks']['ajax_diagnostic']={}
        # Reuse early proof; avoid duplicate direct browser startup.
        pre=state['checks']['native_marionette_preflight']
        if pre.get('result')=='DIAGNOSTIC_PASS':
            state['checks']['ajax_diagnostic']['direct_marionette_about_blank_control']=pre['proof']
            state['checks']['ajax_diagnostic']['direct_marionette_classification']='DIRECT_MARIONETTE_AVAILABLE_PRIMARY_BLOCKED'
        elif pre.get('result')=='DIAGNOSTIC_BLOCKED':
            state['checks']['ajax_diagnostic']['direct_marionette_about_blank_control']=pre['proof']
            state['checks']['ajax_diagnostic']['direct_marionette_classification']='DIRECT_MARIONETTE_UNAVAILABLE_PRIMARY_BLOCKED'
        else:
            state['checks']['ajax_diagnostic']['direct_marionette_classification']='DIRECT_MARIONETTE_INFRASTRUCTURE_BLOCKED'
        # ZAP 2.17 Selenium API does not expose selenium.view.getBrowserIds.
        # Use documented Selenium/AJAX APIs and require observed crawl results.
        result=run_ajax_supported_api(api,day03,
             diagnostics=state['checks']['ajax_diagnostic'],
             route_proof=state['checks']['internal_fixture_http_routes'],
             cli_control=True,native_marionette_control=True)
        gate(result.get('ajax_spider')=='completed' and result.get('ajax_result_count',0)>0,
             'AJAX_NOT_COMPLETED_WITH_ACTUAL_RESULTS')
        state['checks']['ajax_number_of_results']=result['ajax_result_count']
        state['checks']['ajax_in_scope_result_count']=len(result['ajax_in_scope_results'])
        state['checks']['ajax_browser']='firefox-headless'
        state['checks']['firefox_driver_path_configured']=result['firefox_driver_path_configured']
        state['checks']['geckodriver_in_path']=result['geckodriver_in_path']
        state['checks']['ajax_observed_running']=result['ajax_observed_running']
        state['ajax_spider']='PASS_COMPLETED_FIREFOX_HEADLESS'
        state['checks']['phase']='SECOND_PASSIVE'
        day03._wait_passive(api,limits=day03.Limits(),clock=time.monotonic,sleep=time.sleep)
        state['passive']='PASS_DRAINED_AFTER_SPIDER_AND_AJAX'
        report.update(result)
        report['passive_drained_after_ajax']=True
        report['api_transport']='DOCKER_EXEC_IN_CONTAINER_LOOPBACK'
        (evd/'day03_lab.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        state['checks']['complete_proof_sha256']=sha(evd/'day03_lab.json')
        state['checks']['phase']='COMPLETE'
        state['overall']='ZAP_FOCUSED_LAB_PASS_NOT_PRODUCTION'
        rc=0
    except subprocess.TimeoutExpired:
        state['error']='SUBPROCESS_TIMEOUT_REDACTED'
    except (Blocked,ValueError,OSError,RuntimeError) as e:
        msg=str(e)
        state['error']=(type(e).__name__+': '+msg if re.fullmatch(
            r'[A-Za-z0-9_.-]{1,140}',msg) else type(e).__name__+': REDACTED')
    except Exception as e:
        state['error']='UNEXPECTED_'+type(e).__name__
    finally:
        # Final numeric snapshot from the same authorized container, if it
        # still exists. Unavailable readings remain explicit UNKNOWN.
        if started:
            try:
                p=call(['docker','exec','-i','--user','1000:1000',
                        'cybersec-day03-zap','python3','-c',CONTAINER_TELEMETRY_CODE],timeout=25)
                state['checks']['v75_container_pid_numeric_after']=(
                    json.loads(p.stdout) if p.returncode==0 and len(p.stdout)<8192
                    else {'status':'UNAVAILABLE'})
            except (OSError,ValueError,TypeError,subprocess.TimeoutExpired):
                state['checks']['v75_container_pid_numeric_after']={'status':'UNAVAILABLE'}
        try:state['checks']['v75_host_pid_numeric_after']=numeric_telemetry()
        except (OSError,ValueError):
            state['checks']['v75_host_pid_numeric_after']={'status':'UNAVAILABLE'}
        state['checks']['docker_before_cleanup']=monitor_state() if started else 'NOT_STARTED'
        if started:
            state['checks']['redacted_zap_log_signals']=record_log_signals()
            try:
                c=subprocess.run(['docker','compose','-f','deployment/day03/compose.lab.yml',
                                  '-f',str(shm_overlay),'down'],
                                  cwd=REPO,env=compose_env,capture_output=True,timeout=100)
                state['checks']['cleanup']='PASS' if c.returncode==0 else 'FAIL'
                if c.returncode:rc=4;state['overall']='BLOCKED/NO-GO'
            except (OSError,subprocess.TimeoutExpired):
                state['checks']['cleanup']='FAIL_OR_TIMEOUT';rc=4;state['overall']='BLOCKED/NO-GO'
        state['checks']['docker_after_cleanup']=monitor_state()
        state['checks']['v75_compose_quiescence']='PASS' if not any(
            t.get('present',True) for t in state['checks']['docker_after_cleanup'].values()) else 'FAIL'
        if state['checks']['v75_compose_quiescence']!='PASS':
            rc=4;state['overall']='BLOCKED/NO-GO'

        if REPO.is_dir() and (REPO/'.git').exists():
            check=call(['git','-C',str(REPO),'diff','--quiet','HEAD'],timeout=20)
            head_after=call(['git','-C',str(REPO),'rev-parse','HEAD'],timeout=20)
            same_head=(head_after.returncode==0 and
                       head_after.stdout.decode().strip()==state.get('checks',{}).get('original_head'))
            if 'original_head' in state.get('checks',{}):
                state['checks']['original_git_postcheck']='PASS' if check.returncode==0 and same_head else 'FAIL'
                if state['checks']['original_git_postcheck']!='PASS':
                    rc=4;state['overall']='BLOCKED/NO-GO'
        if api is not None:
            state['api_trace']=api.records
        if rc:state['overall']='BLOCKED/NO-GO'
        state['completed_utc']=datetime.now(timezone.utc).isoformat()
        (evd/'ZAP_FOCUSED_STATUS.json').write_text(json.dumps(state,indent=2,ensure_ascii=False,sort_keys=True)+'\n')
        try:
            target_zip,side=pack(evd)
            print('FOCUSED_EVIDENCE_ZIP='+str(target_zip),flush=True)
            print('FOCUSED_EVIDENCE_SHA256='+str(side),flush=True)
        except Exception as e:
            print('FOCUSED_ZIP_FAILED='+type(e).__name__,flush=True)
            rc=4
        if lock:
            fcntl.flock(lock.fileno(),fcntl.LOCK_UN)
            lock.close()
    print('ZAP_FOCUSED_RESULT='+ ('LAB_PASS' if rc==0 else 'BLOCKED')+'; PRODUCTION=BLOCKED/NO-GO; STAGE71=NOT_OPENED',flush=True)
    return rc

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--apply',action='store_true')
    ap.add_argument('--pid-budget',type=int,default=None)
    ap.add_argument('--ab-label',choices=('A','B'),default=None)
    ap.add_argument('--ab-replicate',type=int,choices=(1,2,3),default=None)
    args=ap.parse_args()
    if not args.apply:
        print('REVIEW_ONLY: ZAP API, traditional Spider, Firefox Headless AJAX, Passive Scan; no active, no day04, no production')
        return 0
    if args.pid_budget is not None:
        if not (64<=args.pid_budget<=512 and args.ab_label in ('A','B') and
                args.ab_replicate in (1,2,3)):
            print('BLOCKED: finite A/B parameters required',flush=True)
            return 4
    elif args.ab_label is not None or args.ab_replicate is not None:
        print('BLOCKED: partial A/B parameters',flush=True)
        return 4
    return run(pid_budget=args.pid_budget,ab_label=args.ab_label,ab_replicate=args.ab_replicate)

if __name__=='__main__' :raise SystemExit(main())
