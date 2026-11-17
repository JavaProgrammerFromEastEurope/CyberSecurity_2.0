"""Command-line interface."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cybersec.config import database_path
from cybersec.artifacts import import_artifact_file, replay_artifact
from cybersec.repository import Repository
from cybersec.runner import JobRunner
from cybersec.risk import assess_risk
from cybersec.scope import ScopeError
from cybersec.reports import filter_report_data, write_html_report
from cybersec.validation import validate_payload, build_export_manifest, verify_export_manifest
from cybersec.comparison import compare_jobs
from cybersec.analytics import build_history_analytics, render_history_html
from cybersec.notifications import add_policy, list_policies, evaluate_comparison, list_events, update_event_status, preview_event, deliver_event, list_deliveries, check_delivery_config, retry_failed_delivery
from cybersec.delivery_queue import queue_stats, claim_next, finish_claim, release_claim, list_dead_letters, resolve_dead_letter
from cybersec.worker import run_worker
from cybersec.observability import queue_metrics, queue_diagnostics


def _repository() -> Repository:
    return Repository(database_path())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybersec",
        description="Authorized security assessment orchestrator with evidence auditing and bounded scanner workers.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Initialize local database")

    scan_worker = sub.add_parser("scanner-worker", help="Run a dedicated durable scanner-job worker")
    scan_worker.add_argument("--worker-id", required=True, help="Unique stable worker identifier")
    scan_worker.add_argument("--lease-seconds", type=int, default=60)
    scan_worker.add_argument("--idle-seconds", type=float, default=2.0)
    scan_worker.add_argument("--max-jobs", type=int, default=0, help="Stop after this many claimed jobs; 0 runs until interrupted")
    scan_worker.add_argument("--max-attempts", type=int, default=3)

    evidence = sub.add_parser("evidence", help="Verify portable evidence artifacts offline without database access")
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)
    offline_verify = evidence_sub.add_parser("verify-offline", help="Verify a JSON evidence bundle or custody checkpoint using an explicitly trusted public key")
    offline_verify.add_argument("input", help="Path to the bundle or checkpoint JSON file")
    offline_verify.add_argument("--public-key", help="Path to a base64-encoded Ed25519 public key (required for signed verification)")
    offline_verify.add_argument("--custody-events", help="Optional JSON array of exported custody events to verify checkpoint chain prefix")
    snapshot_export = evidence_sub.add_parser("trust-snapshot-export", help="Export a signed trust registry snapshot and key audit history")
    snapshot_export.add_argument("--output", required=True, help="Destination JSON path")
    snapshot_export.add_argument("--signing-key", required=True, help="Path to base64 Ed25519 private key; never copied into output")
    snapshot_export.add_argument("--key-id", required=True, help="Registered, active key ID matching the private key")
    snapshot_export.add_argument("--actor", default="security-auditor")
    snapshot_verify = evidence_sub.add_parser("trust-snapshot-verify", help="Verify a signed trust registry snapshot offline")
    snapshot_verify.add_argument("input", help="Snapshot JSON path")
    snapshot_verify.add_argument("--public-key", required=True, help="Explicitly trusted base64 Ed25519 public key path")
    audit_portable = evidence_sub.add_parser("audit-portable", help="Validate an evidence bundle against a signed trust-registry snapshot")
    audit_portable.add_argument("--evidence-bundle", required=True, help="Portable evidence bundle JSON path")
    audit_portable.add_argument("--trust-snapshot", required=True, help="Signed trust-registry snapshot JSON path")
    audit_portable.add_argument("--registry-public-key", required=True, help="Explicitly trusted registry signer public key path")
    revalidate = evidence_sub.add_parser("revalidate", help="Revalidate evidence bundles against the current signed trust registry")
    revalidate.add_argument("--evidence-dir", required=True, help="Directory containing portable evidence bundle JSON files")
    revalidate.add_argument("--trust-snapshot", required=True, help="Current signed trust-registry snapshot JSON path")
    revalidate.add_argument("--registry-public-key", required=True, help="Explicitly trusted registry signer public key path")
    revalidate.add_argument("--previous-report", help="Optional previous revalidation report for transition comparison")
    revalidate.add_argument("--output", help="Optional path to write the complete JSON report")
    registry_diff = evidence_sub.add_parser("trust-diff", help="Compare two signed trust-registry snapshots")
    registry_diff.add_argument("--previous-snapshot", required=True, help="Earlier signed snapshot JSON path")
    registry_diff.add_argument("--current-snapshot", required=True, help="Later signed snapshot JSON path")
    registry_diff.add_argument("--registry-public-key", required=True, help="Explicitly trusted registry signer public key path")
    registry_diff.add_argument("--output", help="Optional path to write the JSON report")
    history_append = evidence_sub.add_parser("history-append", help="Append a revalidation report to a tamper-evident offline chain")
    history_append.add_argument("--report", required=True, help="Previously generated revalidation report JSON")
    history_append.add_argument("--history", required=True, help="JSONL history chain path")
    history_verify = evidence_sub.add_parser("history-verify", help="Verify report hashes, sequence and predecessor links offline")
    history_verify.add_argument("--history", required=True, help="JSONL history chain path")
    package_export = evidence_sub.add_parser("history-export", help="Export history and verification result as a portable audit package")
    package_export.add_argument("--history", required=True, help="JSONL history chain path")
    package_export.add_argument("--output", required=True, help="Audit package JSON output path")
    package_verify = evidence_sub.add_parser("history-package-verify", help="Verify a portable audit package without database access")
    package_verify.add_argument("input", help="Audit package JSON path")

    target = sub.add_parser("target", help="Manage authorized assessment targets")
    target_sub = target.add_subparsers(dest="target_command", required=True)
    add = target_sub.add_parser("add", help="Register a target URL")
    add.add_argument("url")
    add.add_argument("--authorized", action="store_true",
                     help="Acknowledge that you have explicit permission to test this target")
    target_sub.add_parser("list", help="List registered targets")

    job = sub.add_parser("job", help="Manage scan jobs")
    job_sub = job.add_subparsers(dest="job_command", required=True)
    create = job_sub.add_parser("create", help="Create a queued scan job (does not run a scanner)")
    create.add_argument("target_url")
    create.add_argument("--tool", default="demo", choices=["demo", "zap", "nuclei", "sqlmap"])
    run = job_sub.add_parser("run", help="Run a queued job using demo, passive ZAP, or conservative Nuclei")
    run.add_argument("job_id", type=int)
    cancel = job_sub.add_parser("cancel", help="Cancel a queued job")
    cancel.add_argument("job_id", type=int)
    job_sub.add_parser("list", help="List jobs")
    compare = job_sub.add_parser("compare", help="Compare retained results from two jobs without running scanners")
    compare.add_argument("--before", type=int, required=True, help="Earlier job ID")
    compare.add_argument("--after", type=int, required=True, help="Later job ID")
    compare.add_argument("--output", help="Optional path for a JSON comparison report")
    history = job_sub.add_parser("history", help="List saved scan-job comparisons")
    history.add_argument("--limit", type=int, default=100, help="Maximum rows to list (1-1000)")
    history.add_argument("--output", help="Optional JSON export path")
    history_show = job_sub.add_parser("history-show", help="Show a saved comparison snapshot")
    history_show.add_argument("comparison_id", type=int)
    analytics = job_sub.add_parser("analytics", help="Analyze saved comparison trends and reappearing findings")
    analytics.add_argument("--target-id", type=int, help="Restrict analytics to one registered target")
    analytics.add_argument("--limit", type=int, default=1000, help="Maximum saved comparisons to inspect (1-1000)")
    analytics.add_argument("--since", help="Include comparisons from this ISO-8601 timestamp/date")
    analytics.add_argument("--until", help="Include comparisons up to this ISO-8601 timestamp/date")
    analytics.add_argument("--output", help="Optional JSON output path")

    finding = sub.add_parser("finding", help="Manage normalized findings")
    finding_sub = finding.add_subparsers(dest="finding_command", required=True)
    add_finding = finding_sub.add_parser("add", help="Manually add a finding")
    add_finding.add_argument("target_url")
    add_finding.add_argument("--title", required=True)
    add_finding.add_argument("--severity", required=True, choices=["Critical", "High", "Medium", "Low", "Info"])
    add_finding.add_argument("--confidence", default="Unknown", choices=["Certain", "Firm", "Tentative", "Unknown"])
    add_finding.add_argument("--type", dest="vuln_type", required=True)
    add_finding.add_argument("--url")
    add_finding.add_argument("--parameter")
    add_finding.add_argument("--evidence")
    add_finding.add_argument("--recommendation")
    add_finding.add_argument("--source-tool", default="manual")
    finding_sub.add_parser("list", help="List findings by severity")

    artifact = sub.add_parser("artifact", help="Import, search, inspect, and replay stored scanner artifacts")
    artifact_sub = artifact.add_subparsers(dest="artifact_command", required=True)
    artifact_import = artifact_sub.add_parser("import", help="Import a scanner output file into an existing job")
    artifact_import.add_argument("job_id", type=int)
    artifact_import.add_argument("input")
    artifact_import.add_argument("--source-tool", required=True)
    artifact_import.add_argument("--status", choices=["complete", "partial", "corrupt"], default="complete")
    artifact_list = artifact_sub.add_parser("list", help="List or search stored artifacts")
    artifact_list.add_argument("--job-id", type=int)
    artifact_list.add_argument("--source-tool")
    artifact_list.add_argument("--status", choices=["complete", "partial", "corrupt"])
    artifact_list.add_argument("--query", help="Substring search in payload, metadata, or hash")
    artifact_show = artifact_sub.add_parser("show", help="Show one stored artifact")
    artifact_show.add_argument("artifact_id", type=int)
    artifact_show.add_argument("--output", help="Write raw payload to a file instead of stdout")
    artifact_replay = artifact_sub.add_parser("replay", help="Normalize findings from a stored artifact without network access")
    artifact_replay.add_argument("artifact_id", type=int)
    artifact_validate = artifact_sub.add_parser("validate", help="Validate stored artifact structure and report import candidates")
    artifact_validate.add_argument("artifact_id", type=int)

    report = sub.add_parser("report", help="Export project data")
    report_sub = report.add_subparsers(dest="report_command", required=True)
    export = report_sub.add_parser("export", help="Export targets, jobs and findings to JSON")
    export.add_argument("--output", default="reports/stage11.json")
    export.add_argument("--manifest-output", help="Write SHA-256 integrity manifest (default: OUTPUT.manifest.json)")
    verify = report_sub.add_parser("verify", help="Verify a JSON export against its integrity manifest")
    verify.add_argument("--input", required=True)
    verify.add_argument("--manifest", required=True)
    html_report = report_sub.add_parser("html", help="Generate a filtered self-contained HTML assessment report")
    html_report.add_argument("--output", default="reports/cybersec-report.html")
    html_report.add_argument("--target-id", type=int, help="Include only one registered target and its findings")
    html_report.add_argument("--job-id", type=int, help="Include only findings associated with one scan job")
    html_report.add_argument("--severity", action="append", choices=["Critical", "High", "Medium", "Low", "Info"], help="Filter severity; repeat to select multiple")
    html_report.add_argument("--priority", action="append", choices=["P1", "P2", "P3", "P4"], help="Filter triage priority; repeat to select multiple")
    html_report.add_argument("--profile", choices=["technical", "executive"], default="technical", help="Report detail level")
    html_report.add_argument("--project-name", default="Cyber Security Assessment", help="Display name in report")
    html_report.add_argument("--assessment-start", help="Assessment window start label/date")
    html_report.add_argument("--assessment-end", help="Assessment window end label/date")
    pdf_report = report_sub.add_parser("pdf", help="Generate offline A4 PDF assessment report and SHA-256 manifest")
    pdf_report.add_argument("--output", default="reports/cybersec-report.pdf")
    pdf_report.add_argument("--target-id", type=int)
    pdf_report.add_argument("--job-id", type=int)
    pdf_report.add_argument("--severity", action="append", choices=["Critical", "High", "Medium", "Low", "Info"])
    pdf_report.add_argument("--priority", action="append", choices=["P1", "P2", "P3", "P4"])
    pdf_report.add_argument("--profile", choices=["technical", "executive"], default="technical")
    pdf_report.add_argument("--project-name", default="Cyber Security Assessment")
    pdf_report.add_argument("--assessment-start")
    pdf_report.add_argument("--assessment-end")
    pdf_report.add_argument("--font-path", help="Local Unicode TrueType font; no download")
    history_html = report_sub.add_parser("history-html", help="Generate a self-contained HTML report from saved comparison history")
    history_html.add_argument("--output", default="reports/security-history.html")
    history_html.add_argument("--target-id", type=int, help="Restrict history to one target")
    history_html.add_argument("--limit", type=int, default=1000, help="Maximum saved comparisons to inspect (1-1000)")
    history_html.add_argument("--since", help="Include comparisons from this ISO-8601 timestamp/date")
    history_html.add_argument("--until", help="Include comparisons up to this ISO-8601 timestamp/date")

    alert = sub.add_parser("alert", help="Manage local alert policies, queue, and opt-in webhook delivery")
    alert_sub = alert.add_subparsers(dest="alert_command", required=True)
    policy_add = alert_sub.add_parser("policy-add", help="Create or update an alert policy")
    policy_add.add_argument("name")
    policy_add.add_argument("--severity", action="append", choices=["Critical", "High", "Medium", "Low", "Info"], help="Repeat for multiple severities; defaults to Critical and High")
    policy_add.add_argument("--event", action="append", choices=["added", "reappeared", "changed"], help="Repeat for multiple event types; defaults to all supported types")
    alert_sub.add_parser("policy-list", help="List configured alert policies")
    evaluate = alert_sub.add_parser("evaluate", help="Queue matching events from a saved comparison")
    evaluate.add_argument("comparison_id", type=int)
    events = alert_sub.add_parser("events", help="List local notification events")
    events.add_argument("--status", choices=["pending", "acknowledged", "suppressed"])
    events.add_argument("--limit", type=int, default=100)
    acknowledge = alert_sub.add_parser("acknowledge", help="Mark a queue event as reviewed")
    acknowledge.add_argument("event_id", type=int)
    suppress = alert_sub.add_parser("suppress", help="Suppress a queue event without deleting its history")
    suppress.add_argument("event_id", type=int)
    preview = alert_sub.add_parser("preview", help="Preview the exact JSON payload for a queued event; no network request")
    preview.add_argument("event_id", type=int)
    deliver = alert_sub.add_parser("deliver", help="Send one event to CYBERSEC_WEBHOOK_URL after explicit confirmation")
    deliver.add_argument("event_id", type=int)
    deliver.add_argument("--confirm", action="store_true", help="Confirm external transmission of the event payload")
    alert_sub.add_parser("deliveries", help="List delivery attempts and outcomes")
    alert_sub.add_parser("delivery-config", help="Validate webhook configuration locally; no network requests")
    retry_delivery = alert_sub.add_parser("retry", help="Retry an event only after a failed delivery; explicit confirmation required")
    retry_delivery.add_argument("event_id", type=int)
    retry_delivery.add_argument("--confirm", action="store_true", help="Confirm external transmission of the event payload")
    alert_sub.add_parser("queue-stats", help="Show due, delayed, leased, and status counts; local only")
    alert_sub.add_parser("metrics", help="Show durable delivery counters and queue metrics; local only")
    alert_sub.add_parser("diagnostics", help="Check SQLite integrity, expired leases, queue backlog, and recent errors; local only")
    worker_once = alert_sub.add_parser("worker-once", help="Claim and process at most one queued event; external delivery requires --confirm")
    worker_once.add_argument("--worker-id", help="Stable worker identifier (generated if omitted)")
    worker_once.add_argument("--lease-seconds", type=int, default=60)
    worker_once.add_argument("--confirm", action="store_true", help="Confirm possible external webhook delivery")
    queue_claim = alert_sub.add_parser("claim", help="Claim one due event for a worker; local only")
    queue_claim.add_argument("--worker-id", required=True)
    queue_claim.add_argument("--lease-seconds", type=int, default=60)
    queue_release = alert_sub.add_parser("release", help="Release a worker's pending event lease")
    queue_release.add_argument("event_id", type=int)
    queue_release.add_argument("--worker-id", required=True)
    worker = alert_sub.add_parser("worker", help="Run a graceful queue worker; external delivery requires --confirm")
    worker.add_argument("--worker-id", required=True, help="Unique stable ID for this worker process")
    worker.add_argument("--lease-seconds", type=int, default=60)
    worker.add_argument("--idle-seconds", type=float, default=2.0)
    worker.add_argument("--max-events", type=int, default=0, help="Stop after this many processed events; 0 runs until interrupted")
    worker.add_argument("--max-attempts", type=int, default=5, help="Quarantine after this many failed delivery attempts")
    worker.add_argument("--confirm", action="store_true", help="Confirm possible external webhook transmission")
    dead = alert_sub.add_parser("dead-letters", help="List quarantined notification events; local only")
    dead.add_argument("--all", action="store_true", help="Include resolved quarantine entries")
    dead.add_argument("--limit", type=int, default=100)
    resolve_dead = alert_sub.add_parser("resolve-dead-letter", help="Release a quarantined event for deliberate retry")
    resolve_dead.add_argument("event_id", type=int)

    api = sub.add_parser("api", help="Serve the token-protected loopback HTTP API; does not run scanners")
    api_sub = api.add_subparsers(dest="api_command", required=True)
    api_serve = api_sub.add_parser("serve", help="Serve local API for targets, jobs, findings, and queue metadata")
    api_serve.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1", "localhost", "::1"])
    api_serve.add_argument("--port", type=int, default=8765)

    remote = sub.add_parser("remote", help="Use the token-protected loopback API client; metadata operations only")
    remote_sub = remote.add_subparsers(dest="remote_command", required=True)
    remote_sub.add_parser("health", help="Check API health")
    remote_sub.add_parser("queue", help="Read notification queue statistics")
    for name, help_text in (("targets", "List registered targets"), ("jobs", "List jobs"), ("findings", "List findings")):
        item = remote_sub.add_parser(name, help=help_text)
        item.add_argument("--limit", type=int, default=100)
        item.add_argument("--offset", type=int, default=0)
        if name == "jobs":
            item.add_argument("--status")
            item.add_argument("--tool")
        if name == "findings":
            item.add_argument("--severity", choices=["Critical", "High", "Medium", "Low", "Info"])
            item.add_argument("--source-tool")
    remote_add = remote_sub.add_parser("target-add", help="Register a target after explicit authorization confirmation")
    remote_add.add_argument("url")
    remote_add.add_argument("--confirm-authorized", action="store_true", help="Confirm you have permission to assess this target")
    remote_job = remote_sub.add_parser("job-create", help="Queue a metadata-only job for an authorized target")
    remote_job.add_argument("target_url")
    remote_job.add_argument("--tool", default="demo", choices=["demo", "zap", "nuclei", "sqlmap"])
    remote_job.add_argument("--confirm-authorized", action="store_true", help="Confirm permission to assess this target")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "alert" and getattr(args, "alert_command", None) == "worker":
        from cybersec.logging_setup import configure_logging
        configure_logging()
    try:
        if args.command == "evidence" and args.evidence_command == "verify-offline":
            from cybersec.evidence_offline import verify_file
            result = verify_file(args.input, args.public_key, args.custody_events)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0 if result.get("valid") else 1
        if args.command == "evidence" and args.evidence_command == "trust-snapshot-verify":
            from cybersec.trust_registry import verify_file
            report = verify_file(args.input, args.public_key)
            print(json.dumps(report, indent=2, ensure_ascii=False))
            return 0 if report["verification"].get("valid") else 1
        if args.command == "evidence" and args.evidence_command == "audit-portable":
            from cybersec.evidence_audit import verify_files
            report = verify_files(args.evidence_bundle, args.trust_snapshot, args.registry_public_key)
            print(json.dumps(report, indent=2, ensure_ascii=False))
            return 0 if report.get("valid") else 1
        if args.command == "evidence" and args.evidence_command == "revalidate":
            from cybersec.trust_monitor import revalidate_bundle_files
            report = revalidate_bundle_files(args.evidence_dir, args.trust_snapshot, args.registry_public_key, args.previous_report)
            rendered = json.dumps(report, indent=2, ensure_ascii=False)
            if args.output:
                output = Path(args.output)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(rendered + "\n", encoding="utf-8")
            print(rendered)
            return 0 if report.get("valid") else 1
        if args.command == "evidence" and args.evidence_command == "history-append":
            from cybersec.revalidation_history import append_report
            result = append_report(args.history, args.report)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0 if result.get("appended") else 1
        if args.command == "evidence" and args.evidence_command == "history-verify":
            from cybersec.revalidation_history import verify_history_file
            result = verify_history_file(args.history)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0 if result.get("valid") else 1
        if args.command == "evidence" and args.evidence_command == "history-export":
            from cybersec.revalidation_history import export_audit_package
            result = export_audit_package(args.history, args.output)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0 if result.get("exported") and result.get("history_valid") else 1
        if args.command == "evidence" and args.evidence_command == "history-package-verify":
            from cybersec.revalidation_history import verify_audit_package
            result = verify_audit_package(args.input)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0 if result.get("valid") else 1
        if args.command == "evidence" and args.evidence_command == "trust-diff":
            from cybersec.trust_monitor import compare_registry_snapshots
            previous = json.loads(Path(args.previous_snapshot).read_text(encoding="utf-8"))
            current = json.loads(Path(args.current_snapshot).read_text(encoding="utf-8"))
            public = Path(args.registry_public_key).read_text(encoding="utf-8").strip()
            report = compare_registry_snapshots(previous, current, public)
            rendered = json.dumps(report, indent=2, ensure_ascii=False)
            if args.output:
                output = Path(args.output)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(rendered + "\n", encoding="utf-8")
            print(rendered)
            return 0 if report.get("valid") and report.get("audit_history_monotonic") else 1
        if args.command == "remote":
            from cybersec.api_client_cli import run_remote_command
            return run_remote_command(args)
        repo = _repository()
        if args.command == "init":
            print(f"Initialized database at: {repo.db_path}")
        elif args.command == "evidence" and args.evidence_command == "trust-snapshot-export":
            private_key = Path(args.signing_key).read_text(encoding="utf-8").strip()
            snapshot = repo.export_trust_registry_snapshot(private_key, args.key_id, args.actor)
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print(json.dumps({"exported": True, "output": str(output), "key_count": len(snapshot["keys"]), "audit_event_count": len(snapshot["audit_events"]), "snapshot_sha256": snapshot["snapshot_sha256"], "private_key_exported": False}, indent=2, ensure_ascii=False))
        elif args.command == "scanner-worker":
            from cybersec.scan_worker import run_scan_worker, worker_signal_handlers
            import threading
            stop_event = threading.Event()
            with worker_signal_handlers(stop_event):
                summary = run_scan_worker(
                    repo, worker_id=args.worker_id, lease_seconds=args.lease_seconds,
                    idle_seconds=args.idle_seconds, max_jobs=args.max_jobs,
                    max_attempts=args.max_attempts, stop_event=stop_event,
                )
            print(json.dumps(summary.__dict__, indent=2))
        elif args.command == "api":
            if args.api_command == "serve":
                from cybersec.api import serve_api
                serve_api(repo, host=args.host, port=args.port)
        elif args.command == "target":
            if args.target_command == "add":
                target = repo.add_target(args.url, args.authorized)
                print(f"Target #{target.id}: {target.url} | authorized={target.authorized}")
                if not target.authorized:
                    print("NOTE: No scan job can be created until authorization is acknowledged.")
            else:
                targets = repo.list_targets()
                if not targets:
                    print("No targets registered.")
                for target in targets:
                    print(f"#{target.id} {target.url} | authorized={target.authorized} | host={target.hostname}")
        elif args.command == "job":
            if args.job_command == "create":
                job = repo.create_job(args.target_url, args.tool)
                print(f"Created queued job #{job.id}: tool={job.tool}, status={job.status}")
            elif args.job_command == "run":
                result = JobRunner(repo).run(args.job_id)
                print(f"Job #{args.job_id}: {result.status}")
                print(result.summary)
                print(json.dumps(result.raw_output, indent=2, ensure_ascii=False))
                for item in result.findings:
                    # Store scanner output in the shared findings table; confidence remains conservative.
                    try:
                        source_tool = str(item.get("source_tool", result.tool)).lower()
                        external_id = item.get("plugin_id") or item.get("template_id") or "finding"
                        raw_confidence = str(item.get("confidence", "Unknown")).lower()
                        confidence = {"high": "Firm", "medium": "Tentative", "low": "Tentative",
                                      "certain": "Certain", "firm": "Firm", "tentative": "Tentative"}.get(
                                          raw_confidence, "Unknown")
                        repo.add_finding(
                            target_url=result.raw_output.get("target_url", ""),
                            title=item.get("title", f"{source_tool} finding"),
                            severity=item.get("severity", "Info"), confidence=confidence,
                            vuln_type=str(item.get("vuln_type") or item.get("category") or item.get("name") or item.get("title") or external_id),
                            url=item.get("url"), parameter=item.get("parameter"), evidence=item.get("evidence"),
                            recommendation=item.get("solution"), source_tool=source_tool,
                            job_id=args.job_id,
                            source_id=str(item.get("id") or item.get("alert_ref") or "") or None,
                            template_id=str(item.get("template_id") or item.get("plugin_id") or "") or None,
                            observed_at=str(item.get("timestamp") or "") or None,
                        )
                    except ValueError as exc:
                        print(f"Warning: could not store scanner finding: {exc}", file=sys.stderr)
                if result.findings:
                    print(f"Stored {len(result.findings)} in-scope {result.tool} finding(s).")
            elif args.job_command == "compare":
                comparison = compare_jobs(repo, args.before, args.after)
                saved = repo.save_comparison(comparison)
                comparison["history_id"] = saved["id"]
                rendered = json.dumps(comparison, indent=2, ensure_ascii=False)
                if args.output:
                    output = Path(args.output)
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text(rendered + "\n", encoding="utf-8")
                    print(f"Wrote comparison report to: {output}")
                print(f"Saved comparison history #{saved['id']}.")
                print(rendered)
            elif args.job_command == "history":
                items = repo.list_comparisons(limit=args.limit)
                rendered = json.dumps({"schema_version": 1, "comparisons": items}, indent=2, ensure_ascii=False)
                if args.output:
                    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text(rendered + "\n", encoding="utf-8")
                    print(f"Wrote comparison history to: {output}")
                print(rendered)
            elif args.job_command == "history-show":
                item = repo.get_comparison(args.comparison_id)
                if item is None:
                    raise ValueError(f"Comparison history #{args.comparison_id} does not exist.")
                print(json.dumps(item, indent=2, ensure_ascii=False))
            elif args.job_command == "analytics":
                data = build_history_analytics(repo, target_id=args.target_id, limit=args.limit, since=args.since, until=args.until)
                rendered = json.dumps(data, indent=2, ensure_ascii=False)
                if args.output:
                    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text(rendered + "\n", encoding="utf-8")
                    print(f"Wrote comparison analytics to: {output}")
                print(rendered)
            elif args.job_command == "cancel":
                job = repo.cancel_scan_job(args.job_id)
                print(f"Cancellation state for job #{job.id}: status={job.status}")
            else:
                jobs = repo.list_jobs()
                if not jobs:
                    print("No jobs found.")
                for job in jobs:
                    print(f"#{job.id} target_id={job.target_id} tool={job.tool} status={job.status} "
                          f"created={job.created_at} started={job.started_at or '-'} finished={job.finished_at or '-'}")
        elif args.command == "finding":
            if args.finding_command == "add":
                finding = repo.add_finding(
                    target_url=args.target_url, title=args.title, severity=args.severity,
                    confidence=args.confidence, vuln_type=args.vuln_type, url=args.url,
                    parameter=args.parameter, evidence=args.evidence,
                    recommendation=args.recommendation, source_tool=args.source_tool,
                )
                print(f"Recorded finding #{finding.id}: [{finding.severity}/{finding.confidence}] {finding.title} (deduplicated by fingerprint)")
            else:
                findings = repo.list_findings()
                if not findings:
                    print("No findings recorded.")
                for item in findings:
                    assessment = assess_risk(item.severity, item.confidence, item.vuln_type)
                    print(f"#{item.id} [{assessment.priority} {assessment.risk_score:.2f}/10; "
                          f"{item.severity}/{item.confidence}] {item.title} — {item.url}")
                    print(f"   {assessment.rationale}")
        elif args.command == "artifact":
            if args.artifact_command == "import":
                artifact = import_artifact_file(repo, args.job_id, args.source_tool, args.input, status=args.status)
                print(f"Artifact #{artifact['id']}: {artifact['status']} {artifact['payload_format']} sha256={artifact['content_hash']}")
                try:
                    parsed = json.loads(artifact["payload"]) if artifact["payload_format"] == "json" else artifact["payload"]
                except json.JSONDecodeError:
                    parsed = artifact["payload"]
                summary = validate_payload(parsed, artifact["payload_format"])
                print(json.dumps(summary, indent=2, ensure_ascii=False))
            elif args.artifact_command == "list":
                items = repo.search_scan_artifacts(job_id=args.job_id, source_tool=args.source_tool, status=args.status, query=args.query)
                for item in items:
                    print(f"#{item['id']} job=#{item['job_id']} tool={item['source_tool']} status={item['status']} format={item['payload_format']} bytes={len(item['payload'].encode('utf-8'))} sha256={item['content_hash']}")
                if not items: print("No artifacts match the selected filters.")
            elif args.artifact_command == "show":
                item = repo.get_scan_artifact(args.artifact_id)
                if item is None: raise ValueError(f"Artifact #{args.artifact_id} does not exist.")
                if args.output:
                    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text(item['payload'], encoding="utf-8")
                    print(f"Wrote artifact #{item['id']} payload to: {output}")
                else:
                    print(json.dumps({key: value for key, value in item.items() if key != "payload"}, indent=2, ensure_ascii=False))
                    print("--- PAYLOAD ---")
                    print(item["payload"])
            elif args.artifact_command == "replay":
                result = replay_artifact(repo, args.artifact_id)
                print(f"Replayed artifact #{result['artifact_id']}: imported={result['accepted']} skipped_out_of_scope={result['skipped_out_of_scope']}")
            else:
                artifact = repo.get_scan_artifact(args.artifact_id)
                if artifact is None: raise ValueError(f"Artifact #{args.artifact_id} does not exist.")
                try:
                    payload = json.loads(artifact["payload"]) if artifact["payload_format"] == "json" else artifact["payload"]
                except json.JSONDecodeError:
                    payload = artifact["payload"]
                summary = validate_payload(payload, artifact["payload_format"])
                summary["artifact_id"] = artifact["id"]
                summary["artifact_status"] = artifact["status"]
                print(json.dumps(summary, indent=2, ensure_ascii=False))
                if not summary["valid"]: return 1
        elif args.command == "alert":
            if args.alert_command == "policy-add":
                policy = add_policy(repo, args.name, args.severity or ("Critical", "High"),
                                    args.event or ("added", "reappeared", "changed"))
                print(json.dumps(policy, indent=2, ensure_ascii=False))
            elif args.alert_command == "policy-list":
                print(json.dumps(list_policies(repo), indent=2, ensure_ascii=False))
            elif args.alert_command == "evaluate":
                print(json.dumps(evaluate_comparison(repo, args.comparison_id), indent=2, ensure_ascii=False))
            elif args.alert_command == "events":
                print(json.dumps(list_events(repo, args.status, args.limit), indent=2, ensure_ascii=False))
            elif args.alert_command == "acknowledge":
                print(json.dumps(update_event_status(repo, args.event_id, "acknowledged"), indent=2, ensure_ascii=False))
            elif args.alert_command == "suppress":
                print(json.dumps(update_event_status(repo, args.event_id, "suppressed"), indent=2, ensure_ascii=False))
            elif args.alert_command == "preview":
                print(json.dumps(preview_event(repo, args.event_id), indent=2, ensure_ascii=False))
            elif args.alert_command == "deliver":
                print(json.dumps(deliver_event(repo, args.event_id, confirmed=args.confirm), indent=2, ensure_ascii=False))
            elif args.alert_command == "retry":
                print(json.dumps(retry_failed_delivery(repo, args.event_id, confirmed=args.confirm), indent=2, ensure_ascii=False))
            elif args.alert_command == "delivery-config":
                result = check_delivery_config()
                print(json.dumps(result, indent=2, ensure_ascii=False))
                return 0 if result["valid"] else 1
            elif args.alert_command == "queue-stats":
                print(json.dumps(queue_stats(repo), indent=2, ensure_ascii=False))
            elif args.alert_command == "metrics":
                print(json.dumps(queue_metrics(repo), indent=2, ensure_ascii=False))
            elif args.alert_command == "diagnostics":
                result = queue_diagnostics(repo)
                print(json.dumps(result, indent=2, ensure_ascii=False))
                return 0 if result["healthy"] else 1
            elif args.alert_command == "claim":
                print(json.dumps(claim_next(repo, args.worker_id, args.lease_seconds), indent=2, ensure_ascii=False))
            elif args.alert_command == "release":
                print(json.dumps({"event_id": args.event_id, "released": release_claim(repo, args.event_id, args.worker_id)}, indent=2, ensure_ascii=False))
            elif args.alert_command == "worker-once":
                if not args.confirm:
                    raise PermissionError("worker-once requires --confirm because it may transmit an event to the configured webhook.")
                worker_id = args.worker_id or f"cli-worker-{Path(repo.db_path).name}"
                claimed = claim_next(repo, worker_id, args.lease_seconds)
                if claimed is None:
                    print(json.dumps({"claimed": False, "message": "No due notification events."}, indent=2, ensure_ascii=False))
                else:
                    try:
                        result = deliver_event(repo, claimed["id"], confirmed=True)
                        finished = finish_claim(repo, claimed["id"], worker_id, outcome=result["outcome"], error=result.get("error"))
                        print(json.dumps({"claimed": True, "delivery": result, "queue": finished}, indent=2, ensure_ascii=False))
                    except Exception:
                        release_claim(repo, claimed["id"], worker_id)
                        raise
            elif args.alert_command == "worker":
                if not args.confirm:
                    raise PermissionError("worker requires --confirm because it may transmit event payloads externally.")
                try:
                    result = run_worker(repo, worker_id=args.worker_id, lease_seconds=args.lease_seconds,
                                        max_events=args.max_events, idle_seconds=args.idle_seconds,
                                        max_attempts=args.max_attempts, confirmed=True)
                except KeyboardInterrupt:
                    print("Worker interrupted; active lease will expire and can be reclaimed.", file=sys.stderr)
                    return 130
                print(json.dumps(result, indent=2, ensure_ascii=False))
            elif args.alert_command == "dead-letters":
                print(json.dumps(list_dead_letters(repo, include_resolved=args.all, limit=args.limit), indent=2, ensure_ascii=False))
            elif args.alert_command == "resolve-dead-letter":
                print(json.dumps({"event_id": args.event_id, "resolved": resolve_dead_letter(repo, args.event_id)}, indent=2, ensure_ascii=False))
            else:
                print(json.dumps(list_deliveries(repo), indent=2, ensure_ascii=False))
        elif args.command == "report":
            if args.report_command == "verify":
                result = verify_export_manifest(args.input, args.manifest)
                print(json.dumps(result, indent=2, ensure_ascii=False))
                return 0 if result["valid"] else 1
            elif args.report_command == "history-html":
                data = build_history_analytics(repo, target_id=args.target_id, limit=args.limit, since=args.since, until=args.until)
                output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(render_history_html(data), encoding="utf-8")
                print(f"Exported security history HTML report to: {output}")
            elif args.report_command == "pdf":
                from cybersec.pdf_reports import write_pdf_report
                data = filter_report_data(repo.export_data(), target_id=args.target_id, job_id=args.job_id, severities=args.severity, priorities=args.priority)
                if args.target_id is not None and not data["targets"]:
                    raise ValueError(f"Target #{args.target_id} does not exist or has no match for the selected filters.")
                if args.job_id is not None and not data["jobs"]:
                    raise ValueError(f"Job #{args.job_id} does not exist or has no match for the selected target.")
                output, manifest = write_pdf_report(data, args.output, profile=args.profile, project_name=args.project_name, assessment_start=args.assessment_start, assessment_end=args.assessment_end, font_path=args.font_path)
                print(f"Exported PDF assessment report to: {output}; manifest: {manifest}")
            elif args.report_command == "html":
                data = filter_report_data(
                    repo.export_data(), target_id=args.target_id, job_id=args.job_id,
                    severities=args.severity, priorities=args.priority,
                )
                if args.target_id is not None and not data["targets"]:
                    raise ValueError(f"Target #{args.target_id} does not exist or has no match for the selected filters.")
                if args.job_id is not None and not data["jobs"]:
                    raise ValueError(f"Job #{args.job_id} does not exist or has no match for the selected target.")
                output = write_html_report(
                    data, args.output, profile=args.profile, project_name=args.project_name,
                    assessment_start=args.assessment_start, assessment_end=args.assessment_end,
                )
                print(f"Exported {args.profile} HTML assessment report to: {output}")
            else:
                output = Path(args.output)
                output.parent.mkdir(parents=True, exist_ok=True)
                data = repo.export_data()
                output.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                manifest_path = Path(args.manifest_output) if args.manifest_output else Path(str(output) + ".manifest.json")
                manifest_path.parent.mkdir(parents=True, exist_ok=True)
                manifest = build_export_manifest(output, data)
                manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                print(f"Exported JSON report to: {output}")
                print(f"Wrote integrity manifest to: {manifest_path} (sha256={manifest['sha256']})")
        return 0
    except (ValueError, PermissionError, ScopeError, LookupError, RuntimeError, TimeoutError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
