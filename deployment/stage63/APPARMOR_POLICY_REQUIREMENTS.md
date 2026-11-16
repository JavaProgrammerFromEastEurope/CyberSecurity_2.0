# MAC/LSM requirements — not an installed AppArmor/SELinux profile

**No deployable policy is supplied:** a policy requires concrete exact executable
paths, distribution-specific syntax, `aa-enforce`/`semodule` verification, trusted
policy hashes and separate independently observed UIDs. A permissive example
would create an illusion of OS protection.

Mandatory denied operations for **scanner domain**, as observed in kernel
negative tests, not merely policy text:

- write/move into any `cgroup.procs`, `cgroup.threads`, `cgroup.kill` or sibling cgroup;
- execute arbitrary shells/interpreters, alternate Nuclei binaries or escape into
  an unconfined same-UID profile; create namespaces with escaping privileges;
- read `/etc/cybersec/trust` private authority artifacts, witness state, Git
  credentials or the worker's SQLite recovery state;
- write/alter installed unit files, AppArmor/SELinux policy or publisher state;
- network access except to a verified, owner-approved isolated loopback lab;
  this last property typically requires separate network policy/netns/nftables.

Worker domain: can create and kill *only* its delegated scan cgroups; does not
possess any signing keys or production Git credentials. Witness/publisher and
attester services have distinct identities and immutable service configuration.

Required evidence includes observed kernel denial of a live same-UID legacy
process, scanner attempts to migrate out of cgroup, the process identity
before/after restart, and post-SIGKILL descendant extinction. A readable LSM
label is insufficient. Stage 63 does not claim that these proofs exist.
