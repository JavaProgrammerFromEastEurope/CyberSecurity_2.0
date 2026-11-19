"""CLI commands for the loopback API client; never executes scanners."""
from __future__ import annotations

import json
from typing import Any

from cybersec.api_client import CyberSecAPIClient, client_from_env


def _print(value: Any) -> None:
    if hasattr(value, "items") and hasattr(value, "total") and hasattr(value, "limit"):
        value = {"items": value.items, "total": value.total, "limit": value.limit, "offset": value.offset}
    print(json.dumps(value, indent=2, ensure_ascii=False))


def run_remote_command(args, *, client: CyberSecAPIClient | None = None) -> int:
    """Execute one remote metadata operation using an injectable client for tests."""
    api = client or client_from_env()
    if args.remote_command == "health":
        result = api.health()
    elif args.remote_command == "targets":
        result = api.list_targets(limit=args.limit, offset=args.offset)
    elif args.remote_command == "jobs":
        result = api.list_jobs(limit=args.limit, offset=args.offset, status=args.status, tool=args.tool)
    elif args.remote_command == "findings":
        result = api.list_findings(limit=args.limit, offset=args.offset, severity=args.severity, source_tool=args.source_tool)
    elif args.remote_command == "queue":
        result = api.queue_stats()
    elif args.remote_command == "target-add":
        if not args.confirm_authorized:
            raise PermissionError("target-add requires --confirm-authorized after verifying permission to assess the target")
        result = api.create_target(args.url, authorized=True)
    elif args.remote_command == "job-create":
        if not args.confirm_authorized:
            raise PermissionError("job-create requires --confirm-authorized after verifying permission to assess the target")
        result = api.create_job(args.target_url, tool=args.tool)
    else:
        raise ValueError(f"Unsupported remote command: {args.remote_command}")
    _print(result)
    return 0
