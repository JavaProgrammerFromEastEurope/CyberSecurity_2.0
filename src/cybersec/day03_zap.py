"""Stage70 Day03 WP07–WP09: approved, bounded, isolated ZAP lab only.

Not a production scanner. Never added to the normal worker adapter registry.
"""
from __future__ import annotations
import argparse
from dataclasses import dataclass
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler
from cybersec.day02 import require_scope
from cybersec.production_admission import require_production_admission

TARGET = 'http://day03-target:8080/'
API_HOST = '127.0.0.1'
API_PORT = 18080
API_BASE = f'http://{API_HOST}:{API_PORT}'
ALLOWED_COMPONENTS = {'core', 'spider', 'pscan', 'ajaxSpider', 'selenium'}
ALLOWED_ACTIONS = {
    ('spider', 'action', 'setOptionMaxDepth'),
    ('spider', 'action', 'setOptionMaxChildren'),
    ('spider', 'action', 'setOptionMaxDuration'),
    ('spider', 'action', 'setOptionThreadCount'),
    ('spider', 'action', 'scan'),
    ('spider', 'action', 'stop'),
    ('ajaxSpider', 'action', 'setOptionMaxCrawlDepth'),
    ('ajaxSpider', 'action', 'setOptionMaxCrawlStates'),
    ('ajaxSpider', 'action', 'setOptionMaxDuration'),
    ('ajaxSpider', 'action', 'setOptionNumberOfBrowsers'),
    ('ajaxSpider', 'action', 'setOptionRandomInputs'),
    ('ajaxSpider', 'action', 'setOptionScopeCheck'),
    ('ajaxSpider', 'action', 'scan'),
    ('ajaxSpider', 'action', 'stop'),
}
ALLOWED_VIEWS = {
    ('core', 'view', 'version'),
    ('core', 'view', 'alerts'),
    ('spider', 'view', 'status'),
    ('pscan', 'view', 'recordsToScan'),
    ('ajaxSpider', 'view', 'status'),
    ('ajaxSpider', 'view', 'optionBrowserId'),
    ('selenium', 'view', 'getBrowserIds'),
}

class LabDenied(PermissionError):
    """Fail closed: no further lab calls."""

class LabTimeout(TimeoutError):
    """The bounded scan has exceeded its hard budget."""

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise LabDenied('ZAP_API_REDIRECT_REFUSED')

def _check_target(target: str) -> str:
    if target != TARGET:
        raise LabDenied('ONLY_PINNED_INTERNAL_DOCKER_LAB_TARGET_ALLOWED')
    if urlsplit(target).fragment or urlsplit(target).username or urlsplit(target).password:
        raise LabDenied('CREDENTIAL_OR_FRAGMENT_TARGET_REFUSED')
    if require_scope(TARGET, target) != TARGET:
        raise LabDenied('OUT_OF_SCOPE_TARGET')
    return target

def _production_gate() -> None:
    require_production_admission(action='Stage70.Day03.LabZap')
    for name in ('CYBERSEC_EXECUTION_MODE', 'CYBERSEC_RUNTIME_MODE'):
        if os.environ.get(name, '').strip().casefold() in ('prod', 'production'):
            raise LabDenied('PRODUCTION_DENIED_' + name)

def _api_endpoint(base: str) -> None:
    p = urlsplit(base)
    if (p.scheme != 'http' or p.hostname != API_HOST or p.port != API_PORT or
        p.path not in ('', '/') or p.query or p.fragment or p.username or p.password):
        raise LabDenied('ZAP_API_MUST_BE_FIXED_LOOPBACK_PORT')

class ZapLabAPI:
    """Authenticated loopback API, no redirects, no ambient proxy, size bounded."""
    def __init__(self, *, api_key: str, base: str = API_BASE, timeout: float = 4):
        _api_endpoint(base)
        if (not isinstance(api_key, str) or not 24 <= len(api_key) <= 256 or
            any(c.isspace() or ord(c) < 33 for c in api_key)):
            raise LabDenied('ZAP_API_KEY_REQUIRED_MIN_24_NONSPACE')
        if not 0 < timeout <= 10:
            raise ValueError('BOUNDED_API_TIMEOUT_REQUIRED')
        self.base = base.rstrip('/')
        self.timeout = timeout
        self.key = api_key
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def call(self, component: str, category: str, name: str, params: dict | None = None) -> dict:
        key = (component, category, name)
        if component not in ALLOWED_COMPONENTS or key not in (ALLOWED_VIEWS if category == 'view' else ALLOWED_ACTIONS):
            raise LabDenied('UNAPPROVED_ZAP_API_OPERATION')
        args = params or {}
        if not all(isinstance(k, str) and isinstance(v, (str, int, bool)) for k, v in args.items()):
            raise ValueError('INVALID_ZAP_PARAMETER')
        if 'apikey' in args:
            raise LabDenied('ZAP_KEY_IN_URL_REFUSED')
        uri = self.base + '/JSON/' + component + '/' + category + '/' + name + '/'
        data = urlencode(args).encode('ascii') if category == 'action' else None
        if category == 'view' and args:
            uri += '?' + urlencode(args)
        headers = {'X-ZAP-API-Key': self.key, 'Accept': 'application/json'}
        if data is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        req = Request(uri, data=data, headers=headers, method='POST' if data is not None else 'GET')
        with self.opener.open(req, timeout=self.timeout) as resp:
            if resp.status != 200 or not resp.headers.get('Content-Type', '').lower().startswith('application/json'):
                raise LabDenied('ZAP_NON_JSON_OR_NON_200')
            raw = resp.read(262145)
        if len(raw) > 262144:
            raise LabDenied('ZAP_RESPONSE_TOO_LARGE')
        body = json.loads(raw)
        if not isinstance(body, dict) or ('code' in body and str(body['code']).lower() not in ('ok', '0')):
            raise LabDenied('ZAP_API_RETURNED_ERROR')
        return body

@dataclass(frozen=True)
class Limits:
    max_spider_seconds: float = 35
    max_passive_seconds: float = 20
    max_ajax_seconds: float = 35
    poll_seconds: float = 0.15
    depth: int = 2
    children: int = 8
    ajax_states: int = 8
    def __post_init__(self) -> None:
        if not (1 <= self.max_spider_seconds <= 120 and 1 <= self.max_passive_seconds <= 120
                and 1 <= self.max_ajax_seconds <= 120 and 0.01 <= self.poll_seconds <= 3
                and 1 <= self.depth <= 5 and 1 <= self.children <= 20
                and 1 <= self.ajax_states <= 20):
            raise ValueError('LAB_BOUNDS_OUT_OF_RANGE')

def _positive_number(value: object, limit: int) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)) or not re.fullmatch(r'\d+', str(value)):
        raise LabDenied('MALFORMED_ZAP_COUNTER')
    result = int(value)
    if result > limit:
        raise LabDenied('ZAP_COUNTER_OUT_OF_RANGE')
    return result

def _wait_spider(api, *, scan_id: str, limits: Limits, clock: Callable[[], float], sleep: Callable[[float], None]) -> int:
    deadline = clock() + limits.max_spider_seconds
    while clock() <= deadline:
        response = api.call('spider', 'view', 'status', {'scanId': scan_id})
        status = _positive_number(response.get('status'), 100)
        if status == 100:
            return status
        sleep(limits.poll_seconds)
    raise LabTimeout('SPIDER_DEADLINE_EXCEEDED')

def _wait_passive(api, *, limits: Limits, clock: Callable[[], float], sleep: Callable[[float], None]) -> None:
    deadline = clock() + limits.max_passive_seconds
    while clock() <= deadline:
        pending = _positive_number(api.call('pscan', 'view', 'recordsToScan').get('recordsToScan'), 100000)
        if pending == 0:
            return
        sleep(limits.poll_seconds)
    raise LabTimeout('PASSIVE_DEADLINE_EXCEEDED')

def _stop_spider(api, scan_id: str) -> None:
    api.call('spider', 'action', 'stop', {'scanId': scan_id})

def _run_ajax(api, *, limits: Limits, clock: Callable[[], float], sleep: Callable[[float], None], browser_isolated: bool) -> dict:
    if not browser_isolated:
        raise LabDenied('AJAX_REQUIRES_ISOLATED_BROWSER_ATTESTATION')
    ids = api.call('selenium', 'view', 'getBrowserIds').get('browserIds')
    current = api.call('ajaxSpider', 'view', 'optionBrowserId').get('optionBrowserId')
    if not isinstance(ids, list) or 'firefox-headless' not in ids or current != 'firefox-headless':
        raise LabDenied('AJAX_HEADLESS_BROWSER_NOT_AVAILABLE')
    settings = (
        ('setOptionMaxCrawlDepth', {'Integer': str(limits.depth)}),
        ('setOptionMaxCrawlStates', {'Integer': str(limits.ajax_states)}),
        ('setOptionMaxDuration', {'Integer': '1'}),
        ('setOptionNumberOfBrowsers', {'Integer': '1'}),
        ('setOptionRandomInputs', {'Boolean': 'false'}),
        ('setOptionScopeCheck', {'String': 'Strict'}),
    )
    for method, options in settings:
        api.call('ajaxSpider', 'action', method, options)
    started = False
    try:
        response = api.call('ajaxSpider', 'action', 'scan', {'url': TARGET, 'inScope': 'true', 'subtreeOnly': 'true'})
        if response.get('Result') not in ('OK', 'ok'):
            raise LabDenied('AJAX_START_NOT_CONFIRMED')
        started = True
        deadline = clock() + limits.max_ajax_seconds
        while clock() <= deadline:
            status = api.call('ajaxSpider', 'view', 'status').get('status')
            if status == 'stopped':
                return {'ajax_spider': 'completed', 'browser': 'firefox-headless'}
            if status != 'running':
                raise LabDenied('AJAX_UNKNOWN_STATE')
            sleep(limits.poll_seconds)
        raise LabTimeout('AJAX_DEADLINE_EXCEEDED')
    finally:
        if started:
            api.call('ajaxSpider', 'action', 'stop')

def run_lab(api, *, authorization: bool, runtime: bool, ajax: bool = False,
            browser_isolated: bool = False, limits: Limits | None = None,
            clock: Callable[[], float] = time.monotonic,
            sleep: Callable[[float], None] = time.sleep) -> dict:
    _production_gate()
    _check_target(TARGET)
    if not authorization or not runtime:
        raise LabDenied('EXPLICIT_AUTHORIZATION_AND_DOCKER_ATTESTATION_REQUIRED')
    limits = limits or Limits()
    api.call('core', 'view', 'version')
    for method, args in (
        ('setOptionMaxDepth', {'Integer': str(limits.depth)}),
        ('setOptionMaxChildren', {'Integer': str(limits.children)}),
        ('setOptionMaxDuration', {'Integer': '1'}),
        ('setOptionThreadCount', {'Integer': '1'}),
    ):
        api.call('spider', 'action', method, args)
    scan_id = None
    try:
        response = api.call('spider', 'action', 'scan', {'url': TARGET, 'recurse': 'false', 'subtreeOnly': 'true'})
        scan_id = str(response.get('scan', ''))
        if not re.fullmatch(r'[0-9]{1,9}', scan_id):
            raise LabDenied('SPIDER_SCAN_ID_INVALID')
        completed = _wait_spider(api, scan_id=scan_id, limits=limits, clock=clock, sleep=sleep)
    finally:
        if scan_id:
            _stop_spider(api, scan_id)
    _wait_passive(api, limits=limits, clock=clock, sleep=sleep)
    alerts = api.call('core', 'view', 'alerts', {'baseurl': TARGET, 'start': '0', 'count': '100'}).get('alerts')
    if not isinstance(alerts, list) or len(alerts) > 100:
        raise LabDenied('ALERTS_MALFORMED_OR_UNBOUNDED')
    accepted = []
    discarded = 0
    for alert in alerts:
        if not isinstance(alert, dict):
            raise LabDenied('ALERT_NOT_AN_OBJECT')
        try:
            url = require_scope(TARGET, str(alert['url']))
        except (ValueError, KeyError):
            discarded += 1
            continue
        accepted.append({'url': url, 'title': str(alert.get('alert', 'ZAP passive finding'))[:256],
                         'riskcode': str(alert.get('riskcode', '0'))[:4],
                         'source_tool': 'zap', 'verification': 'UNCONFIRMED_PASSIVE'})
    result = {'mode': 'AUTHORIZED_INTERNAL_LAB_ONLY', 'target': TARGET, 'spider': completed,
              'passive_drained': True, 'alerts': accepted, 'discarded_out_of_scope': discarded,
              'active_scan': False, 'production': 'BLOCKED/NO-GO'}
    if ajax:
        result.update(_run_ajax(api, limits=limits, clock=clock, sleep=sleep, browser_isolated=browser_isolated))
        _wait_passive(api, limits=limits, clock=clock, sleep=sleep)
    else:
        result['ajax_spider'] = 'NOT_REQUESTED'
    return result

def validate_docker_lab() -> dict:
    """Independent Docker inspect proof: two confined containers on one internal network."""
    proc = subprocess.run(['docker', 'inspect', 'cybersec-day03-zap', 'cybersec-day03-target'],
                          capture_output=True, text=True, timeout=8, check=False)
    if proc.returncode:
        raise LabDenied('LAB_CONTAINERS_NOT_RUNNING_OR_DOCKER_UNAVAILABLE')
    records = json.loads(proc.stdout)
    if not isinstance(records, list) or len(records) != 2:
        raise LabDenied('DOCKER_INSPECT_INVALID')
    by_name = {x.get('Name', '').lstrip('/'): x for x in records if isinstance(x, dict)}
    if set(by_name) != {'cybersec-day03-zap', 'cybersec-day03-target'}:
        raise LabDenied('UNEXPECTED_DOCKER_CONTAINERS')
    zap, target = by_name['cybersec-day03-zap'], by_name['cybersec-day03-target']
    network_ids = []
    for item, image_env in ((zap, 'CYBERSEC_DAY03_ZAP_IMAGE'),
                            (target, 'CYBERSEC_DAY03_TARGET_IMAGE')):
        pinned = os.environ.get(image_env, '')
        if not re.fullmatch(r'[a-z0-9./_-]+@sha256:[0-9a-f]{64}', pinned) or item.get('Config', {}).get('Image') != pinned:
            raise LabDenied('IMAGE_DIGEST_NOT_PINNED_' + image_env)
        if item.get('State', {}).get('Running') is not True:
            raise LabDenied('DOCKER_CONTAINER_NOT_RUNNING')
        config = item.get('HostConfig', {})
        if config.get('Privileged') or config.get('NetworkMode') in ('host', 'none'):
            raise LabDenied('UNSAFE_DOCKER_CONTAINER_SETTINGS')
        if 'ALL' not in config.get('CapDrop', []) or item.get('Config', {}).get('User') == '0':
            raise LabDenied('CONTAINER_CAPABILITIES_OR_ROOT_NOT_CONFINED')
        if not config.get('SecurityOpt') or not any('no-new-privileges' in x for x in config['SecurityOpt']):
            raise LabDenied('MISSING_NO_NEW_PRIVILEGES')
        networks = item.get('NetworkSettings', {}).get('Networks', {})
        if len(networks) != 1:
            raise LabDenied('UNEXPECTED_MULTIPLE_NETWORKS')
        network_ids.append(next(iter(networks.values())).get('NetworkID'))
    if not network_ids[0] or network_ids[0] != network_ids[1]:
        raise LabDenied('LAB_NETWORK_NOT_SHARED')
    bindings = zap.get('HostConfig', {}).get('PortBindings', {}).get('8080/tcp')
    if bindings != [{'HostIp': '127.0.0.1', 'HostPort': '18080'}]:
        raise LabDenied('ZAP_API_NOT_BOUND_TO_HOST_LOOPBACK')
    if target.get('HostConfig', {}).get('PortBindings'):
        raise LabDenied('TARGET_PORT_EXPOSED')
    nr = subprocess.run(['docker', 'network', 'inspect', network_ids[0]], capture_output=True,
                        text=True, timeout=8, check=False)
    if nr.returncode:
        raise LabDenied('DOCKER_NETWORK_INSPECTION_FAILED')
    net = json.loads(nr.stdout)
    if not isinstance(net, list) or len(net) != 1 or net[0].get('Internal') is not True:
        raise LabDenied('DOCKER_NETWORK_NOT_INTERNAL')
    members = net[0].get('Containers', {})
    if not isinstance(members, dict) or {v.get('Name') for v in members.values()} != set(by_name):
        raise LabDenied('UNEXPECTED_LAB_NETWORK_MEMBER')
    return {'docker_isolated': True, 'network_id': network_ids[0],
            'api_binding': API_BASE, 'target': TARGET}

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--review', action='store_true')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--authorize-local-lab', action='store_true')
    parser.add_argument('--ajax', action='store_true')
    parser.add_argument('--evidence-dir', type=Path)
    args = parser.parse_args(argv)
    try:
        _production_gate()
        if sum((args.review, args.check, args.run)) != 1:
            raise LabDenied('SELECT_EXACTLY_ONE_MODE')
        if args.review:
            print('DAY03=LAB_ONLY; ACTIVE_SCAN=DENIED; PRODUCTION=BLOCKED/NO-GO; STAGE71=NOT_OPENED')
            return 0
        if args.check:
            print(json.dumps(validate_docker_lab(), sort_keys=True))
            return 0
        if not args.authorize_local_lab or args.evidence_dir is None:
            raise LabDenied('EXPLICIT_AUTHORIZATION_AND_EVIDENCE_DIR_REQUIRED')
        verified = validate_docker_lab()
        api = ZapLabAPI(api_key=os.getenv('CYBERSEC_DAY03_ZAP_API_KEY', ''))
        report = run_lab(api, authorization=True, runtime=verified['docker_isolated'], ajax=args.ajax,
                         browser_isolated=verified['docker_isolated'])
        dest = args.evidence_dir.resolve()
        if dest.exists():
            raise LabDenied('REFUSE_OVERWRITE_EVIDENCE')
        dest.mkdir(parents=True, mode=0o700)
        (dest / 'day03_lab.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print('DAY03_LAB_PASS; PASSIVE_FINDINGS_UNCONFIRMED; NO_ACTIVE_SCANS')
        return 0
    except (LabDenied, LabTimeout, ValueError, OSError, json.JSONDecodeError) as exc:
        print('DAY03_BLOCKED: ' + type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        return 4

if __name__ == '__main__':
    raise SystemExit(main())
