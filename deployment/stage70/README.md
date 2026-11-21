# Stage 70 — laboratory AppArmor reference profiles

**LAB ONLY. PRODUCTION BLOCKED/NO-GO. Stage 71 NOT_OPENED.**

These five AppArmor policy snapshots were copied byte-for-byte from the v23.3 candidate bundle, whose installed LAB counterparts were reported as applied in verified v23.3 VM evidence. They are reference fixtures, NOT production policies.

The v16 wide signal receive rule `peer=unconfined` was removed after v17 verified five same-UID unauthorized SIGTERM attempts. v20 profiled controller tests passed, but v21 verified 5/5 same-UID controller impersonations through `aa-exec`. v23.3 tested narrow LAB policies. The protected production lifecycle controller is still missing. v24 is a locally tested bounded systemd probe; its execution on the user's VM is not confirmed.

Neither these policies nor the VM-only `host.py` stacked-label lab relaxation are promoted into production admission. These snapshots are useful for review and reproducible negative checks only.

Never commit raw host logs, collected evidence archives, passwords, private keys or private filesystem inventories. SHA-256 verifies integrity, not authenticity.
