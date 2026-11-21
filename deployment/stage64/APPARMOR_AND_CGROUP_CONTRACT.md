# Stage 64 OS-enforcement contract (not an installed policy)

An independent privileged administrator must provide: four distinct non-root
UIDs (worker, attester, witness, publisher), individually labelled systemd
services, profiles enforced by the kernel, and read-only/deny permissions for
all scanner-user invocation paths to bypass the controlled broker.

**Acceptance requires negative evidence** under real AppArmor `enforce` or
independently audited SELinux: an unprivileged scanner UID cannot execute a
legacy direct Nuclei/sqlmap/ZAP path; cannot run an unconfined Python shell to
bypass the broker; cannot access other roles' keys or report signing material;
cannot write `cgroup.procs`, `cgroup.kill` or move itself to an ancestor or
sibling cgroup; cannot replace unit files, sockets, lease databases or permits.
An AppArmor profile filename or `/proc/self/attr/current` is not proof.

The systemd manager must retain ownership of the worker scope and kill all
processes in its cgroup, including `setsid` and `double-fork` descendants.
Verify `cgroup.events` populated=0 and independent `/proc`/journal evidence
post-stop; check PID/starttime before and after restart to detect PID reuse.
Do not grant the worker delegation or cgroup management privileges in this
candidate. Future direct cgroup executors need a separately designed broker
with independently controlled delegation and one-use task authority.

Signed per-attempt target scope, nonce, TTL, and an independently managed
monotonic rollback root are not implemented. Code-side environment variables,
SQLite flags, JSON snapshots and mock signatures cannot replace OS admission.
Current state: **BLOCKED/NO-GO**.
