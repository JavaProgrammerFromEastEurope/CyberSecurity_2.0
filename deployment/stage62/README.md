# Stage 62: independent host admission (not installed)

This unit is a **proposal**, not a working production deployment. `Delegate=yes`
requests systemd cgroup delegation; cgroup ownership and `cgroup.kill` must be
independently verified. A mandatory AppArmor/SELinux policy must prevent scanner
and legacy same-UID processes from writing `cgroup.procs` or escaping the
scanner's delegated cgroup. The worker may need cgroup writes; the scanner
MUST transition into a separate, restricted LSM domain before any target request.
There is **no audited MAC policy or separate production UID services** in this
artifact. Do not install or enable the unit on a customer network.

Four different non-root service UIDs are required: `cybersec-worker`,
`cybersec-attester`, `cybersec-witness`, and `cybersec-publisher`. Creating
accounts alone is not evidence of separation or attested recovery.

The Stage 62 read-only diagnostic command never grants admission:

```
PYTHONPATH=src python -m cybersec.stage62_audit
# Expected exit code 3, BLOCKED/NO-GO
```

An independently issued Ed25519 ticket is bound to `job_id`, `attempt`, exact
loopback-IP target URL, Nuclei tool, nonce, issued_at and expiry (< 1 hour).
Trust key and ticket are loaded from root-owned files under `/etc/cybersec/`.
Neither this project nor its tests issue a real permit or private key.

Manual recovery remains mandatory after SIGKILL until independent confirmation
that all scanner processes were killed via kernel cgroup.kill. ZAP remote daemon
work and SQLmap production execution are disabled. An environment flag is not a
security boundary: the **same-UID legacy bypass remains a production blocker**
until independent OS MAC enforces all scanner entrypoints.
