# Stage70 LAB-ONLY: exact named service profile. NO PRODUCTION GO.
# Must be reviewed against actual Ubuntu 26.10 executable tree and syscall audit.
abi <abi/5.0>,
include <tunables/global>
profile cybersec-stage70-witness {
  # Python runtime and pinned root-owned code are read-only.
  /usr/bin/python3* ix,
  /usr/lib/** mr,
  /usr/local/lib/** mr,
  /lib/** mr,
  /lib64/** mr,
  /etc/ld.so.cache r,
  /etc/nsswitch.conf r,
  /etc/passwd r,
  /etc/group r,
  /etc/host.conf r,
  /etc/locale/** r,
  /usr/share/locale/** r,
  /usr/share/zoneinfo/** r,
  /opt/cybersec/stage70/** r,
  # Root-owned pinned venv: map only the cryptography Rust extension executable.
  /opt/cybersec/stage70/.venv/lib/python3.*/site-packages/cryptography/hazmat/bindings/_rust.abi3.so mr,
  # Ubuntu 26.10 / CPython 3.14 / aarch64: root-owned CFFI native extension.
  /opt/cybersec/stage70/.venv/lib/python3.14/site-packages/_cffi_backend.cpython-314-aarch64-linux-gnu.so mr,
  /proc/self/** r,
  # AppArmor resolves /proc/self to /proc/<PID> during path mediation.
  # Owner-only READ of this single attribute allows independent label checks.
  # No write, no arbitrary /proc access and no privilege transition.
  owner /proc/[0-9]*/attr/current r,
  # Self /proc aliases are resolved to numeric PIDs under AppArmor mediation.
  # Owner-only, read-only: required for NoNewPrivs and exact cgroup admission.
  owner /proc/[0-9]*/status r,
  owner /proc/[0-9]*/cgroup r,
  /proc/sys/kernel/random/** r,
  /sys/fs/cgroup/** r,

  # AF_UNIX is the only allowed transport. systemd also PrivateNetwork=yes.
  network unix stream,

  # Only this role's disposable runtime directory can be written.
  /run/cybersec-stage70-witness/ rw,
  /run/cybersec-stage70-witness/probe.sock rw,

  # Only explicitly named peer domains can be reached via AF_UNIX.
  /run/cybersec-stage70-broker/probe.sock rw,
  deny /etc/cybersec/** rwklmx,
  deny /var/lib/cybersec*/** rwklmx,
  deny /run/cybersec-stage70-public/** r,
}
