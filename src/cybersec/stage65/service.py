"""Review-only independent broker/witness service entrypoint.

Never enables production launch from environment alone. Broker uses the hard
NO-GO HostAdmission and its Unix API never calls scanners on this release.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import sys
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .broker import AdmissionBroker, KernelCgroupBroker, UnixAdmissionServer
from .contracts import PermitVerifier
from .host import actual_role_map, protected_file, HostAdmission
from .ledger import WitnessLedger, LedgerBlocked
from .witness import WitnessStore, WitnessServer, SocketWitnessAnchor


def _read_config(path: Path) -> dict:
    if not protected_file(path):
        raise LedgerBlocked('Root-owned immutable service config required')
    data=json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data,dict) or set(data)!={
            'broker_socket','witness_socket','broker_ledger','witness_ledger',
            'installed_broker_unit','installed_policy','delegated_cgroup','pinned_public_key_hex',
            'attester_issuer','broker_profile','pinned_policy_sha256',
            'executable_allowlist','broker_socket_group_gid','witness_socket_group_gid'}:
        raise LedgerBlocked('Stage65 config schema mismatch')
    if not all(type(x) is str and x.startswith('/') for x in
               (data['broker_socket'],data['witness_socket'],data['broker_ledger'],
                data['witness_ledger'],data['installed_broker_unit'],data['installed_policy'],data['delegated_cgroup'])):
        raise LedgerBlocked('Stage65 config paths must be absolute')
    if not all(type(data[x]) is int and data[x]>0 for x in
               ('broker_socket_group_gid','witness_socket_group_gid')):
        raise LedgerBlocked('Service socket groups must be explicit')
    if not isinstance(data['executable_allowlist'],dict) or not data['executable_allowlist']:
        raise LedgerBlocked('Empty server-owned immutable allowlist')
    return data


def main(argv=None)->int:
    p=argparse.ArgumentParser()
    p.add_argument('--role',choices=['broker','witness'],required=True)
    p.add_argument('--config',default='/etc/cybersec/stage65.json')
    p.add_argument('--lab-opt-in',action='store_true')
    args=p.parse_args(argv)
    try:
        roles=actual_role_map()
        if os.geteuid()!=getattr(roles,args.role):
            raise LedgerBlocked('Wrong OS service UID')
        config=_read_config(Path(args.config))
        stop=threading.Event()
        def shutdown(_signum,_frame): stop.set()
        signal.signal(signal.SIGTERM,shutdown)
        signal.signal(signal.SIGINT,shutdown)
        os.umask(0o077)
        if args.role=='witness':
            if not args.lab_opt_in or os.environ.get('CYBERSEC_STAGE65_WITNESS_LAB')!='1':
                raise LedgerBlocked('Witness launch requires lab-only explicit opt-in')
            # This is a separate UID and fsync-backed state, not a trusted TPM root.
            server=WitnessServer(Path(config['witness_socket']),
                WitnessStore(Path(config['witness_ledger'])),
                allowed_broker_uid=roles.broker,
                socket_group_gid=config['witness_socket_group_gid'])
        else:
            pub=Ed25519PublicKey.from_public_bytes(bytes.fromhex(config['pinned_public_key_hex']))
            gate=HostAdmission(expected_profile=config['broker_profile'],
                fixed_cgroup=Path(config['delegated_cgroup']),
                installed_unit=Path(config['installed_broker_unit']),
                approved_policy_digest=config['pinned_policy_sha256'],
                installed_policy=Path(config['installed_policy']))
            # Fail before publishing a broker production socket. Even if policy
            # appears present, Stage 65 requires independent negative evidence.
            gate.check(roles=roles)
            verifier=PermitVerifier(pub,issuer=config['attester_issuer'])
            anchor=SocketWitnessAnchor(Path(config['witness_socket']),expected_witness_uid=roles.witness)
            ledger=WitnessLedger(Path(config['broker_ledger']),anchor)
            broker=AdmissionBroker(roles=roles,host=gate,verifier=verifier,ledger=ledger,
                kernel=KernelCgroupBroker(Path(config['delegated_cgroup'])),
                executable_allowlist=config['executable_allowlist'])
            server=UnixAdmissionServer(Path(config['broker_socket']),broker,
                socket_group_gid=config['broker_socket_group_gid'])
        server.serve(stop)
        return 0
    except (LedgerBlocked,ValueError,OSError,KeyError,json.JSONDecodeError) as exc:
        print('BLOCKED/NO-GO: '+str(exc),file=sys.stderr)
        return 3

if __name__=='__main__':
    sys.exit(main())
