"""Stage70 Day02: additive evidence schema, scope-checked ingestion, demo-only controller.
Not a production scanner authority, distributed queue or external scanner admission.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, unquote

from cybersec.db import connect
from cybersec.scope import normalize_target_url, ScopeError

MIGRATION_ID = 'stage70-day02-wp04-06-v1'
VERSION = 1
MAX_RAW_BYTES = 131072
MAX_ASSET_BYTES = 1048576
METHODS = frozenset({'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'})
TOOLS = frozenset({'demo'})  # deliberate: external scanner dispatch remains blocked


@dataclass(frozen=True)
class RecordedFinding:
    raw_id: int
    finding_id: int
    source_tool: str
    sha256: str
    target_id: int
    job_id: int


def apply_migration(db: sqlite3.Connection) -> None:
    """One idempotent, atomic, forward-only SQLite schema migration."""
    db.execute('SAVEPOINT day02_migration')
    db.execute('''CREATE TABLE IF NOT EXISTS day02_schema_migrations (
        migration_id TEXT PRIMARY KEY, version INTEGER NOT NULL CHECK(version > 0),
        applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')))''')
    row = db.execute('SELECT version FROM day02_schema_migrations WHERE migration_id=?', (MIGRATION_ID,)).fetchone()
    if row:
        if row['version'] != VERSION:
            raise RuntimeError('MIGRATION_VERSION_DRIFT')
        db.execute('RELEASE SAVEPOINT day02_migration')
        return
    extensions = {
        'http_method': "TEXT NOT NULL DEFAULT 'GET' CHECK(http_method IN ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'))",
        'reproduction_steps': 'TEXT',
        'raw_ref': 'INTEGER',
        'confidence_basis': 'TEXT',
    }
    columns = {row['name'] for row in db.execute('PRAGMA table_info(normalized_findings)')}
    for name, declaration in extensions.items():
        if name not in columns:
            db.execute(f'ALTER TABLE normalized_findings ADD COLUMN {name} {declaration}')
    db.execute('''CREATE TABLE IF NOT EXISTS raw_findings (
        id INTEGER PRIMARY KEY,
        target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
        job_id INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
        source_tool TEXT NOT NULL,
        source_id TEXT,
        raw_json TEXT NOT NULL,
        sha256 TEXT NOT NULL CHECK(length(sha256)=64),
        observed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
        UNIQUE(job_id,source_tool,sha256)
    )''')
    db.execute('CREATE INDEX IF NOT EXISTS idx_day02_raw_job ON raw_findings(job_id,id)')
    db.execute('''CREATE TABLE IF NOT EXISTS report_assets (
        id INTEGER PRIMARY KEY,
        finding_id INTEGER NOT NULL REFERENCES normalized_findings(id) ON DELETE CASCADE,
        filename TEXT NOT NULL,
        media_type TEXT NOT NULL CHECK(media_type IN ('image/png','image/jpeg','text/plain','application/json')),
        content BLOB NOT NULL,
        sha256 TEXT NOT NULL CHECK(length(sha256)=64),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
        UNIQUE(finding_id,sha256)
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS controller_plans (
        id INTEGER PRIMARY KEY,
        request_key TEXT NOT NULL UNIQUE,
        target_id INTEGER NOT NULL REFERENCES targets(id),
        spec_sha256 TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','succeeded','blocked')),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
        changed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS controller_steps (
        plan_id INTEGER NOT NULL REFERENCES controller_plans(id) ON DELETE CASCADE,
        ordinal INTEGER NOT NULL CHECK(ordinal>=0),
        tool TEXT NOT NULL CHECK(tool='demo'),
        job_id INTEGER UNIQUE REFERENCES scan_jobs(id),
        PRIMARY KEY(plan_id,ordinal)
    )''')
    db.execute('INSERT INTO day02_schema_migrations(migration_id,version) VALUES (?,?)', (MIGRATION_ID,VERSION))
    db.execute('RELEASE SAVEPOINT day02_migration')


def _origin(url: str):
    p = urlsplit(url)
    if p.scheme not in {'http','https'} or p.hostname is None or p.username is not None or p.password is not None:
        raise ScopeError('Invalid or credential-bearing URL')
    try:
        port = p.port or (443 if p.scheme == 'https' else 80)
    except ValueError as ex:
        raise ScopeError('Invalid port') from ex
    if p.fragment:
        raise ScopeError('URL fragments not allowed')
    raw_path = p.path or '/'
    decoded = unquote(raw_path)
    if '%' in raw_path or '\\' in decoded or any(x in ('.','..') for x in decoded.split('/')):
        raise ScopeError('Ambiguous URL path encoding/traversal refused')
    if not decoded.startswith('//') and decoded.startswith('/') and not any(ord(c)<32 for c in decoded):
        return p.scheme.lower(), p.hostname.lower().rstrip('.'), port, decoded
    raise ScopeError('Ambiguous path rejected')


def require_scope(registered_url: str, candidate_url: str) -> str:
    """Same origin AND path segment prefix, excluding redirects and scheme upgrades."""
    if urlsplit(candidate_url).fragment or candidate_url.endswith("#"):
        raise ScopeError("FRAGMENT_NOT_ALLOWED")
    canonical, _ = normalize_target_url(candidate_url)
    base = _origin(registered_url)
    got = _origin(canonical)
    if got[:3] != base[:3]:
        raise ScopeError('OUT_OF_SCOPE_ORIGIN')
    prefix = base[3].rstrip('/') or '/'
    if prefix != '/' and not (got[3] == prefix or got[3].startswith(prefix + '/')):
        raise ScopeError('OUT_OF_SCOPE_PATH')
    return canonical


def _canonical_json(data: dict) -> str:
    if not isinstance(data, dict):
        raise TypeError('Finding payload must be an object')
    blob = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    if len(blob.encode('utf-8')) > MAX_RAW_BYTES:
        raise ValueError('RAW_FINDING_TOO_LARGE')
    return blob


def ingest_raw_finding(repository, *, job_id: int, raw: dict,
                       finding_url: str, title: str, vuln_type: str, severity: str='Info',
                       confidence: str='Unknown', method: str='GET', parameter: str | None=None,
                       reproduction_steps: str | None=None, confidence_basis: str | None=None,
                       source_id: str | None=None) -> RecordedFinding:
    """Persist one source result with server-side auth, strict scope, atomic raw+normalized link."""
    if method not in METHODS:
        raise ValueError('INVALID_HTTP_METHOD')
    if severity not in ('Critical','High','Medium','Low','Info') or confidence not in ('Certain','Firm','Tentative','Unknown'):
        raise ValueError('INVALID_SEVERITY_CONFIDENCE')
    if confidence == 'Certain' and not confidence_basis:
        raise ValueError('CERTAIN_REQUIRES_EVIDENCE_BASIS')
    if not title or len(title)>300 or not vuln_type or len(vuln_type)>160:
        raise ValueError('INVALID_FINDING_IDENTITY')
    if reproduction_steps and len(reproduction_steps)>12000:
        raise ValueError('REPRODUCTION_TOO_LARGE')
    json_blob = _canonical_json(raw)
    raw_digest = hashlib.sha256(json_blob.encode()).hexdigest()
    from cybersec.risk import normalize_vuln_type
    kind = normalize_vuln_type(vuln_type)
    with connect(repository.db_path) as db:
        db.execute('BEGIN IMMEDIATE')
        job = db.execute('''SELECT j.id,j.target_id,j.tool,t.url,t.authorized
            FROM scan_jobs j JOIN targets t ON t.id=j.target_id WHERE j.id=?''', (job_id,)).fetchone()
        if job is None or not job['authorized']:
            raise PermissionError('JOB_TARGET_NOT_AUTHORIZED')
        if job['tool'] not in {'demo','zap','nuclei','sqlmap'}:
            raise PermissionError('UNKNOWN_SOURCE_TOOL')
        safe_url = require_scope(job['url'], finding_url)
        if source_id and len(source_id)>256:
            raise ValueError('SOURCE_ID_TOO_LONG')
        db.execute('''INSERT OR IGNORE INTO raw_findings(target_id,job_id,source_tool,source_id,raw_json,sha256)
                      VALUES (?,?,?,?,?,?)''', (job['target_id'],job_id,job['tool'],source_id,json_blob,raw_digest))
        row = db.execute('SELECT id FROM raw_findings WHERE job_id=? AND source_tool=? AND sha256=?',
                         (job_id,job['tool'],raw_digest)).fetchone()
        raw_id = row['id']
        fingerprint = repository._fingerprint(job['target_id'],safe_url,parameter,kind)
        existing = db.execute('SELECT id,raw_ref FROM normalized_findings WHERE fingerprint=?',(fingerprint,)).fetchone()
        if existing:
            finding_id = existing['id']
            if existing['raw_ref'] is None:
                db.execute('''UPDATE normalized_findings SET raw_ref=?,http_method=?,
                           reproduction_steps=COALESCE(reproduction_steps,?),
                           confidence_basis=COALESCE(confidence_basis,?) WHERE id=?''',
                           (raw_id,method,reproduction_steps,confidence_basis,finding_id))
        else:
            cur = db.execute('''INSERT INTO normalized_findings
                (target_id,job_id,title,severity,confidence,url,vuln_type,parameter,evidence,
                 recommendation,source_tool,fingerprint,source_id,http_method,reproduction_steps,raw_ref,confidence_basis)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (job['target_id'],job_id,title,severity,confidence,safe_url,kind,parameter,
                 None,None,job['tool'],fingerprint,source_id,method,reproduction_steps,raw_id,confidence_basis))
            finding_id = cur.lastrowid
        return RecordedFinding(raw_id,finding_id,job['tool'],raw_digest,job['target_id'],job_id)


def add_report_asset(repository, *, finding_id: int, filename: str, media_type: str, content: bytes) -> int:
    """Bounded binary evidence in local DB. Reject filename traversal and unexpected media."""
    if not isinstance(content,bytes) or not content or len(content)>MAX_ASSET_BYTES:
        raise ValueError('INVALID_ASSET_SIZE')
    if not filename or len(filename)>128 or Path(filename).name!=filename or '/' in filename or '\\' in filename or filename in {'.','..'}:
        raise ValueError('INVALID_ASSET_FILENAME')
    if media_type not in ('image/png','image/jpeg','text/plain','application/json'):
        raise ValueError('INVALID_ASSET_MEDIA_TYPE')
    sha = hashlib.sha256(content).hexdigest()
    with connect(repository.db_path) as db:
        row=db.execute('SELECT id FROM normalized_findings WHERE id=?',(finding_id,)).fetchone()
        if not row:
            raise ValueError('FINDING_NOT_FOUND')
        db.execute('INSERT OR IGNORE INTO report_assets(finding_id,filename,media_type,content,sha256) VALUES(?,?,?,?,?)',
                   (finding_id,filename,media_type,content,sha))
        row=db.execute('SELECT id FROM report_assets WHERE finding_id=? AND sha256=?',(finding_id,sha)).fetchone()
        return row['id']


class DemoController:
    """Crash-durable, serial, idempotent demo metadata dispatcher; NEVER executes scanners."""
    def __init__(self, repository):
        self.repository=repository

    def create_plan(self, target_url: str, *, request_key: str, tools: tuple[str,...]=('demo',)) -> int:
        if not re.fullmatch('[A-Za-z0-9_.:-]{12,128}', request_key):
            raise ValueError('INVALID_IDEMPOTENCY_KEY')
        if not 1<=len(tools)<=8 or any(tool not in TOOLS for tool in tools):
            raise PermissionError('EXTERNAL_SCANNER_DISPATCH_NOT_ADMITTED')
        target=self.repository.get_target_by_url(target_url)
        if not target or not target.authorized:
            raise PermissionError('TARGET_NOT_AUTHORIZED')
        digest=hashlib.sha256(json.dumps([target.id,list(tools)],separators=(',',':')).encode()).hexdigest()
        with connect(self.repository.db_path) as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT id,spec_sha256 FROM controller_plans WHERE request_key=?',(request_key,)).fetchone()
            if old:
                if old['spec_sha256'] != digest:
                    raise ValueError('IDEMPOTENCY_KEY_CONFLICT')
                return old['id']
            cur=db.execute('INSERT INTO controller_plans(request_key,target_id,spec_sha256) VALUES(?,?,?)',
                           (request_key,target.id,digest))
            for ordinal,tool in enumerate(tools):
                db.execute('INSERT INTO controller_steps(plan_id,ordinal,tool) VALUES(?,?,?)',
                           (cur.lastrowid,ordinal,tool))
            return cur.lastrowid

    def advance(self, plan_id: int) -> dict:
        """Atomically queue at most one step; fail-closed on failed/uncertain preceding step."""
        with connect(self.repository.db_path) as db:
            db.execute('BEGIN IMMEDIATE')
            plan=db.execute('''SELECT p.*,t.url,t.authorized FROM controller_plans p
                               JOIN targets t ON t.id=p.target_id WHERE p.id=?''', (plan_id,)).fetchone()
            if plan is None:
                raise ValueError('PLAN_NOT_FOUND')
            if plan['status'] in ('succeeded','blocked'):
                return {'plan_id':plan_id,'status':plan['status'],'job_id':None}
            if not plan['authorized']:
                db.execute("UPDATE controller_plans SET status='blocked' WHERE id=?",(plan_id,))
                return {'plan_id':plan_id,'status':'blocked','reason':'AUTHORIZATION_REVOKED','job_id':None}
            steps=db.execute('''SELECT s.ordinal,s.tool,s.job_id,j.status AS job_status FROM controller_steps s
                                LEFT JOIN scan_jobs j ON j.id=s.job_id WHERE s.plan_id=? ORDER BY s.ordinal''',(plan_id,)).fetchall()
            for step in steps:
                if step['tool'] not in TOOLS:
                    db.execute("UPDATE controller_plans SET status='blocked' WHERE id=?",(plan_id,))
                    return {'plan_id':plan_id,'status':'blocked','reason':'UNSAFE_TOOL','job_id':None}
                if step['job_id'] is None:
                    cur=db.execute('INSERT INTO scan_jobs(target_id,tool) VALUES (?,?)',(plan['target_id'],step['tool']))
                    db.execute('UPDATE controller_steps SET job_id=? WHERE plan_id=? AND ordinal=?',
                               (cur.lastrowid,plan_id,step['ordinal']))
                    db.execute("UPDATE controller_plans SET status='running',changed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?",(plan_id,))
                    return {'plan_id':plan_id,'status':'running','job_id':cur.lastrowid,'tool':step['tool'],'queued_now':True}
                if step['job_status'] in ('queued','running'):
                    return {'plan_id':plan_id,'status':'running','job_id':step['job_id'],'queued_now':False}
                if step['job_status'] != 'completed':
                    db.execute("UPDATE controller_plans SET status='blocked' WHERE id=?",(plan_id,))
                    return {'plan_id':plan_id,'status':'blocked','job_id':step['job_id'],'reason':'NON_COMPLETED_STEP_NO_RETRY'}
            db.execute("UPDATE controller_plans SET status='succeeded' WHERE id=?",(plan_id,))
            return {'plan_id':plan_id,'status':'succeeded','job_id':None}


def get_enriched_finding(repository, finding_id: int) -> dict:
    """Opt-in finding contract; legacy Finding.to_dict() remains byte-level compatible."""
    with connect(repository.db_path) as db:
        row=db.execute('''SELECT f.*,r.sha256 AS raw_sha256,r.source_tool AS raw_source_tool
              FROM normalized_findings f LEFT JOIN raw_findings r ON r.id=f.raw_ref
              WHERE f.id=?''', (finding_id,)).fetchone()
    if row is None:
        raise ValueError('FINDING_NOT_FOUND')
    return dict(row)
