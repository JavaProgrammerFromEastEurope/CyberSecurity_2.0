"""Long-running, graceful notification worker loop."""
from __future__ import annotations

import json
import logging
import time
from typing import Callable

from cybersec.delivery_queue import claim_next, finish_claim, release_claim
from cybersec.notifications import deliver_event

_LOG = logging.getLogger("cybersec.worker")

def _log(event: str, **fields) -> None:
    """Emit one structured JSON log line; never include webhook payloads."""
    _LOG.info(json.dumps({"component": "notification_worker", "event": event, **fields},
                          sort_keys=True, separators=(",", ":")))


def run_worker(repo, *, worker_id: str, lease_seconds: int = 60, max_events: int = 0,
               idle_seconds: float = 2.0, max_attempts: int = 5, confirmed: bool = False,
               stop_requested: Callable[[], bool] | None = None,
               sleeper: Callable[[float], None] = time.sleep) -> dict:
    """Process queue events until stopped or max_events reached. max_events=0 means unlimited."""
    if not confirmed:
        raise PermissionError("Worker requires explicit confirmation because it may transmit webhook payloads.")
    if max_events < 0:
        raise ValueError("max_events must be zero (unlimited) or positive.")
    if idle_seconds < 0.1 or idle_seconds > 300:
        raise ValueError("Idle interval must be between 0.1 and 300 seconds.")
    if max_attempts < 1 or max_attempts > 100:
        raise ValueError("Maximum attempts must be between 1 and 100.")
    started = time.monotonic()
    processed = 0
    sent = 0
    failed = 0
    idle_polls = 0
    stopped = False
    while not (stop_requested and stop_requested()):
        if max_events and processed >= max_events:
            break
        event = claim_next(repo, worker_id, lease_seconds)
        if event is None:
            idle_polls += 1
            if max_events and processed >= max_events:
                break
            sleeper(idle_seconds)
            continue
        processed += 1
        _log("event_claimed", worker_id=worker_id, event_id=event["id"])
        try:
            delivery = deliver_event(repo, event["id"], confirmed=True)
            outcome = delivery.get("outcome", "failed")
            error = delivery.get("error")
        except Exception as exc:  # turn configuration/runtime failures into bounded retries
            outcome = "failed"
            error = f"{type(exc).__name__}: {exc}"
        try:
            result = finish_claim(repo, event["id"], worker_id, outcome=outcome,
                                  error=error, max_attempts=max_attempts)
            if outcome == "sent":
                sent += 1
            else:
                failed += 1
            _log("event_finished", worker_id=worker_id, event_id=event["id"],
                 outcome=outcome, attempts=result["delivery_attempts"],
                 quarantined=result["quarantined"])
        except Exception:
            release_claim(repo, event["id"], worker_id)
            raise
    else:
        stopped = True
    summary = {"worker_id": worker_id, "processed": processed, "sent": sent,
               "failed": failed, "idle_polls": idle_polls, "stopped": stopped,
               "max_events": max_events, "duration_seconds": round(time.monotonic() - started, 3)}
    _log("worker_stopped", **summary)
    return summary
