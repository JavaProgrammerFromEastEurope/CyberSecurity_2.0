# Cyber Security 2.0 — Stage 70 / v2.50.0: verified status

**Status: BLOCKED / NO-GO — laboratory evidence only.**

## Source provenance
- Cumulative package: `cyber_securuty_2.0_stage_70_crypto_mmap_hotfix.zip`
- Package SHA-256: `5a53d945de881a418cc2d61bbf0f43bdb1df8df0769acf38662193fa295a6e46`
- Package integrity verified: 762 entries, ZIP CRC PASS.
- Previous cumulative archive: 739 inherited entries; 499 historical evidence files SHA-preserved.
- Version remains Stage 70 / v2.50.0; **no new Stage**.

## Verified local regression evidence
| Run | Passed | Skipped | Failed | Exit |
| --- | ---: | ---: | ---: | ---: |
| strict #1 | 639 | 69 | 0 | 0 |
| strict #2 | 639 | 69 | 0 | 0 |
| strict #3 | 639 | 69 | 0 | 0 |

Warning filters: `ResourceWarning` and `DeprecationWarning` as errors. The 69 Ubuntu opt-in tests were *not* run in the local environment. Historical PASS/FAIL and diagnostics remain preserved in the private cumulative archive.

## Actual Ubuntu observations, 2026-11-18
- Ubuntu 26.10 and Python 3.14.8; five separate service UIDs.
- Six Stage 70 AppArmor policies passed Ubuntu 26.10 strict offline parse with `--Werror`; `kernel_mac_evidence=false` at that stage.
- Current hotfix contains a nine-file approval manifest requirement; the earlier installed baseline verified eight pinned files as `LAB_MANIFEST_VERIFIED_NOT_ATTESTED`. Approval/installation of the nine-file hotfix has **not** been proven.
- Earlier Ubuntu runtime evidence showed **five failed laboratory systemd services** (`start-limit-hit`) caused by import-time `cryptography` Rust shared object executable mapping failure.
- Current source hotfix narrows the AppArmor `m` permission to the required Rust extension and includes a guarded `upgrade` path, but **no post-upgrade Ubuntu runtime success evidence has yet been received**.

## Follow-up Ubuntu lab snapshots — 2026-11-18 (private originals)
Validated both outer SHA-256 sidecars, ZIP CRC and all three internal SHA records in each snapshot.

| Capture UTC | Archive SHA-256 | Services active | PID/label/cgroup | Kernel DENIED |
| --- | --- | ---: | --- | ---: |
| 16:30:50 | `9cdc7c372256fdb94b50001dde707f6429e2af58d3568274556363db6571d8ab` | 0/5 | unavailable for all five | 0 |
| 18:07:43 | `92edab1305ee1c07dbe7e19b4238439bc048a01263eb2d2cb9ad6bbf85404433` | 0/5 | unavailable for all five | 0 |

Both archive reports state `BLOCKED/NO-GO`. Their structured observations match apart from capture timestamp. A separate uploaded runtime status file (SHA-256 `c02c2a6919da906ef79788a419011c21e9590fbff6d61b3fe4d3ce716174a584`) confirms the earlier `_rust.abi3.so` executable mapping error, `start-limit-hit`, and five `MainPID=0`. **Neither snapshot proves that the guarded `upgrade` ran or that the hotfix failed after a confirmed successful upgrade.** Zero observed `DENIED` is not a PASS for the required negative MAC test.

## Git repository publication boundary
As of this evidence update, the default branch contains this sanitized status report, but the complete Stage 70 application source ZIP has **not** been verified as published in the default branch. Do not equate this evidence commit with the full source push.

## Release blockers
- Five *running* lab service PID/UID/cgroup/enforcing MAC labels are unverified after the hotfix.
- Independent kernel AppArmor DENIED, `SO_PEERCRED`/`SO_PEERSEC` cross-UID/same-UID tests, SIGKILL lifecycle and full Ubuntu opt-in acceptance remain unverified.
- Independent protected monotonic witness root, production service graph and production admission remain absent/unproven.
- The lab-only probe services do not scan, issue permits, mutate witness CAS or publish results. `HostAdmission.check()` continues to deny production.

This public report intentionally excludes raw host journals, private Ubuntu evidence archives, machine-specific diagnostics and secrets. **Publication of a report does not imply publication of the complete 762-file source ZIP or production acceptance.**

## CFFI executable mapping follow-up — source hotfix (still NO-GO)

Ubuntu runtime diagnostic captured **2026-11-18 18:20:18 UTC** (private original SHA-256 `25d8b7d891a733252cc29aeac8e23550381d5a8f44cb2d66f0d538f65ccea9e2`) confirms that the five installed policies have the previously added Rust `mr` permission and valid nine-file root-owned manifest (`verify` exit 0), but all five lab instances still fail to start. The import now fails on the *different* `_cffi_backend.cpython-314-aarch64-linux-gnu.so` native extension (executable mmap). The five failed services remain historical Ubuntu FAIL, not post-remediation PASS.

**New cumulative package prepared locally, NOT yet pushed as source files:** `cyber_securuty_2.0_stage_70_cffi_mmap_hotfix.zip` with SHA-256 `ab28221525fc65b80b77115d4945d4a68db5a03b28a76b3ee35490439a2f6e0c`, 784 files; 762 previous files preserved, 520 historical evidence files byte-identical. Exact `mr` for the identified CPython 3.14/aarch64 CFFI extension is added to the five LAB profiles. The guarded updater recognizes only the five observed previous policy digests, checks root-owned runtime extension and requires fresh pinned approval. No automatic service restart or production admission bypass is included.

**New offline strict cumulative regressions:** 3 runs of **649 PASS / 69 SKIPPED / 0 FAIL**, exit code 0, `ResourceWarning` and `DeprecationWarning` treated as errors. These do not establish Ubuntu kernel enforcement or actual successful service startup. Independent root, production service graph and complete Ubuntu opt-in acceptance still **BLOCKED/NO-GO**. Private Ubuntu journals and host-specific evidence are not published to this public repository.


## November 19: five LAB services fail closed at exact AppArmor self-label check

Independent Ubuntu evidence captured 2026-11-19 02:20 UTC shows **five failed laboratory services** (`MainPID=0`, no AF_UNIX sockets); fresh service logs now report `Exact enforce-mode AppArmor profile missing` (exit 3) rather than the previous CFFI shared-object mapping error. The deployed policies include the narrow Rust and CFFI `mr` rules. The observed nine-file lab manifest verifies (exit 0). **No actual running PID MAC label or successful kernel negative tests were captured.** An empty sampled `kernel_mac_denied.txt` is not evidence of enforcement success.

Private uploaded evidence SHA-256:
- Runtime text: `e0bab55e110de281beefe54c5902773393196583dd6aeaed0060e03572cda408`
- Lab ZIP: `b7ea8ec9234a378a70050e9d6a1adf704d1868df21e411f957c65ef89bf803c8`

A new **candidate only** cumulative Stage 70 v2.50.0 patch changes own-process label observation to `/proc/self/attr/current`, with a five-policy owner-only read exception for numeric procfs `attr/current`, while keeping exact `(enforce)` checks and denial on unreadable/incorrect labels. The root-owned review manifest increases to ten pinned files, including the shared `stage65/host.py` kernel MAC helper. Unknown or mixed existing policies remain refused.

- Cumulative package: `cyber_securuty_2.0_stage_70_mac_label_hotfix.zip`
- SHA-256: `299afaa087b0b10e14d349e527287e351f2716eb4b8b5a5b6fc418201ef03227`
- ZIP integrity: 836 files, all 784 previous files retained; 773 previously existing files are byte-identical; private historical evidence preserved.
- Three **final** full offline strict regressions: **664 PASS / 69 SKIPPED / 0 FAIL, exit 0** each; warning filters are errors. An intermediate failing expectation for nine instead of ten pinned files is retained in private regression evidence.
- The actual cause of the exact MAC-label failure is still unconfirmed until a confined live probe returns the kernel label/read error; candidate profiles have not been proven loaded by Ubuntu AppArmor 6.0 ABI 5.0.
- No post-remediation service startup, cross-UID SO_PEERCRED/SO_PEERSEC, kernel DENIED, SIGKILL/recovery, independently protected monotonic root or production admission GO is claimed.

**BLOCKED/NO-GO remains mandatory.** This publicly available note excludes raw Ubuntu logs and does not signify that the 836-file source archive was pushed to GitHub.


## November 19 probe v2: exact observed stacking and procfs EACCES

- Ubuntu 26.10 capture: **2026-11-19 03:18:31–03:19:12 UTC**.
- Five independently UID-bound transient processes, each root-observed in its systemd cgroup; exact kernel labels were **`cybersec-stage70-ROLE//&unconfined (enforce)`**, not required `cybersec-stage70-ROLE (enforce)`.
- Each of five roles received `errno=13 EACCES` reading its own `/proc/self/attr/current`, numeric `/proc/<pid>/attr/current`, `/proc/self/status`, and `/proc/self/cgroup`. This is a **FAIL**, even though the diagnostic runner returned exit 0.
- Named profiles appear in `aa-status` enforcing; installed per-role digests match the **previous nine-file** version, not the newer ten-file candidate.
- Root report SHA-256: `c1b809b16192e9963a05181776862098dc7b4db02ae186a01d781895e600ae7f`. Earlier repeated snapshot SHA-256: `07dec69ecc196742d77feb038ecac0a08f32b5e38e549ecc25189d1e49530ab1`.

A new **candidate only, not yet deployed to Ubuntu or pushed as source tree** adds owner-read permissions for numeric `/proc/<pid>/status` and `/proc/<pid>/cgroup`, complementing the previous owner-read `attr/current` rule. The exact-label checker deliberately continues to **reject** stacked `//&unconfined` labels. The guarded installer recognizes two complete known prior policy sets; mixed/unknown policy sets fail closed. Neither kernel denies nor production admission are claimed.

- Cumulative package: `cyber_securuty_2.0_stage_70_procfs_stacked_label_hotfix.zip`.
- SHA-256: `7f7a1d9feb5a05b6582eec23e37e08433d7cef7fd8f6d77ee87fbe285883f39d`.
- **868 files**, all 836 previous retained; **592 historical evidence entries byte-identical**.
- **Three completed full strict local runs:** 682 PASS / 69 SKIPPED / 0 FAIL, exit 0 each; ResourceWarning and DeprecationWarning as errors. Original missing-PYTHONPATH collection failure (exit 2) remains in the private package.
- On-host AppArmor parser 6.0 ABI 5.0 confirmation, five running service identities, procfs reads after upgrade, negative MAC logs, cross-UID/same-UID IPC and independent monotonic root are all **UNPROVEN**.

**Production remains BLOCKED/NO-GO.** Raw Ubuntu reports and full private cumulative evidence must not be pushed publicly. Source code changes in the local cumulative ZIP are **not yet published to GitHub**.


## November 19 03:38 UTC — post-upgrade manifest verified; post-upgrade kernel label not retested

Two newly supplied file pairs have matching SHA-256:
- `stage70_procfs_post_upgrade.txt`: `a46575b3b435362b24e4e4837fe080e57305141dddd06bfc352cb5d1aadb91ba`.
- Reuploaded `stage70_exact_mac_probe_v2.txt`: `c1b809b16192e9963a05181776862098dc7b4db02ae186a01d781895e600ae7f`, identical to the prior 03:18–03:19 UTC observation.

The top-level report captured **2026-11-19 03:38 UTC** confirms an installed **10-pinned-file manifest** with `LAB_MANIFEST_VERIFIED_NOT_ATTESTED`, and all five installed AppArmor policy SHA-256 digests exactly match the current 868-file cumulative procfs candidate:
- broker `3fbd378f1f9c26d5df2ed06707f2d5962b10866f3ce485a1ef28f152c171f77c`
- worker `d2f16d78a09308fea3dcaa698940d68cb507d8677e6bf57900dd823fb2836ac6`
- attester `9aa4146e4c649dfb23710cfe7268492904e68886708783ab16ea748cf085e583`
- witness `25bcadacbd169d3ebb45acbe96ae210ec926a6603eae98f0f39f40a43e4edcda`
- publisher `a531b11a2d3135f22c59eb56353199e967329c36b1d1f604d53a139987016d37`

All five persistent lab systemd units still report `failed`, `MainPID=0`, `start-limit-hit` in that snapshot; **no new restarts were attempted**. The embedded **old 03:18 UTC probe results were not rerun after 03:38 UTC**, so both positive procfs permissions and kernel labeling **remain unverified after upgrade**. Previously observed `//&unconfined (enforce)` remains disallowed; no reason to claim it vanished or persisted after upgrade.

A separate **diagnostic-only, timestamped, fail-closed** shell probe was prepared for the next real Ubuntu capture. It preflights the five exact policy SHA-256 hashes, root ownership/mode, loaded enforcing policy names and ten-file manifest. It does not modify persistent services or host policies. No production GO and no new numbered Stage.

**BLOCKED/NO-GO remains mandatory** until real post-upgrade live kernel observations and negative host tests are supplied; private raw evidence stays off public GitHub.


## November 19 03:48:55–03:49:47 UTC — fresh post-upgrade procfs kernel evidence

Actual new Ubuntu 26.10 fresh probe (uploaded report SHA-256 `7a30b2eceb5b738bac00effc301d70a14da970e7dc99d4b17ee052c968b8e793`) independently confirmed:
- Preflight 10 pinned files manifest verified with exit 0; five exact installed and source AppArmor profile hashes match; all five named role profiles are kernel-loaded in enforce mode, root-owned, 0644.
- Five transient processes under separate real/effective UID 999 / 998 / 993 / 992 / 991, each with `NoNewPrivs:1` and independent systemd cgroup. Root independently observed actual process labels.
- **New positive result:** every role now successfully reads `/proc/self/attr/current`, `/proc/<pid>/attr/current`, `/proc/self/status` and `/proc/self/cgroup`. The previously observed procfs EACCES issue was resolved by the installed ten-file candidate.
- **Remaining blocker:** all five labels are `cybersec-stage70-ROLE//&unconfined (enforce)`, not required exact `cybersec-stage70-ROLE (enforce)`; no policy admission change or substitution is approved. Probe runner exit 0 is only diagnostic completion, not security acceptance.
- The fresh report does **not** prove permanent services running or completed negative AppArmor denials, peer-security IPC, or production admission.

A separate lab-only probe for independently checking the `kernel.apparmor_restrict_unprivileged_unconfined` setting and matched same-UID DAC-control versus AppArmor-profiled read denial was locally packaged. It is a *diagnostic candidate*, not executed on Ubuntu; it makes no permanent host changes and must not be treated as kernel test PASS until new private results are received.

**BLOCKED/NO-GO remains in force.** Full source ZIP still not verified as published to GitHub.


## November 19 04:04 UTC — five matched live AppArmor negative checks PASS

New private Ubuntu 26.10 report `stage70_stacking_negative_probe_20261119T040403Z.txt`, independently SHA-256 checked: `2477e785114049056cb3d5d1429a266dc208926d9a278f4c0c8420967231d09f`. The reuploaded 03:48 UTC post-upgrade procfs report is byte-identical to the already reviewed earlier report (SHA-256 `7a30b2eceb5b738bac00effc301d70a14da970e7dc99d4b17ee052c968b8e793`).

- Ubuntu settings are `kernel.apparmor_restrict_unprivileged_unconfined=1` and `kernel.apparmor_restrict_unprivileged_userns=1`. Stacked labels may therefore be expected; no sysctl changes are proposed.
- The ten-pinned-file deployment manifest verified (exit 0); all five installed/source policy hashes match approved policy and file modes are root:root 0644; target file `/etc/hostname` is root-owned mode 0644, parent `/etc` mode 0755.
- For each dedicated UID (broker 999; worker 998; attester 993; witness 992; publisher 991), a matched ephemeral systemd-run control **without** role AppArmorProfile successfully opened `/etc/hostname` (`OPEN_OK`), while the same UID **with** that AppArmorProfile received `EACCES (errno 13)`. All ten transient runners exited 0. Five pairs reported `NEGATIVE_MAC_DAC_CONTROL_PASS`.
- Kernel labels were `unconfined` for control processes and `cybersec-stage70-ROLE//&unconfined (enforce)` for role processes. This establishes one bounded file-open confinement effect under real role profiles; it does **not** certify arbitrary same-UID legacy entrypoint isolation, cross-UID or same-UID IPC/peer-security, or a production service graph.
- The report's recent kernel audit section was empty: an explicit `apparmor="DENIED"` journal record is **not** claimed. Direct syscall observations still support the matched negative result.
- No persistent services were started. The strict kernel exact-label check still rejects stacked labels; any relaxation requires separate contract/security analysis and end-to-end proof. Independent monotonic root and durable recovery remain unverified.

A separate **LAB-ONLY SO_PEERSEC self-socketpair observer** has been statically checked and packaged for the next on-host run. This is only a proposed diagnostic and is not evidence of cross-UID IPC acceptance or successful production admission.

**BLOCKED/NO-GO preserved.** No new numbered Stage, source change, full ZIP GitHub push, or production acceptance is claimed.


## November 19 04:17 UTC — SO_PEERCRED observed, SO_PEERSEC observer bug identified

The supplied Ubuntu lab-only `stage70_so_peersec_observer_20261119T041708Z.txt` report (SHA-256 `94542d5a6a7333c6674cf5e7588ed5ad3e71357a1b19f8c1b467fd19bc63e33e`) verified the existing ten-file manifest and the five installed policy digests. It observed self-socketpair `SO_PEERCRED` (PID/UID/GID) for all five separate dedicated-role transient processes. **0/5 `SO_PEERSEC` observations are valid:** the diagnostic script requested a 4096-byte Python `socket.getsockopt` buffer, which CPython rejects with `OSError('getsockopt buflen out of range')` before any useful kernel peer-security read. This is a **diagnostic implementation defect**, not proof that Ubuntu/AppArmor lacks `SO_PEERSEC`.

Reuploaded earlier post-upgrade and DAC/MAC-negative reports are SHA-identical to previous observations (respectively `7a30b2eceb5b738bac00effc301d70a14da970e7dc99d4b17ee052c968b8e793` and `2477e785114049056cb3d5d1429a266dc208926d9a278f4c0c8420967231d09f`) and add no new kernel result.

A **new diagnostic-only candidate** `CyberSecurity_Stage70_CROSS_UID_PEERSEC_Probe_DOWNLOAD.zip` (SHA-256 `3c7f2c42df5e9756e542889968061bda5378afad6245b15e2c9126a8683a69b9`) uses `SO_PEERSEC` 1024-byte getsockopt and will attempt five self-socketpair observations plus real broker→worker cross-UID and broker→broker same-UID *two-process* observations using ephemeral abstract AF_UNIX streams. Shell/Python syntax, ZIP CRC/SHA-256 and unconfined local socket roundtrip passed, but **Ubuntu execution has NOT occurred**. Separate transient processes share the host network namespace solely for Linux abstract AF_UNIX sockets, while address families remain AF_UNIX-only with IP access denied. This differs from production `PrivateNetwork=yes`, and no production-like namespace gate is claimed.

Current `peer_mac_label` and `exact_enforcing_mac` deliberately continue to reject unapproved stacked labels. No production IPC listener, privileged broker action, permit, root witness, ledger or full source-tree GitHub push has been performed. **BLOCKED/NO-GO** remains mandatory.


## November 19 04:29 UTC — seven real SO_PEERSEC observations, no admission

Private Ubuntu 26.10 lab report `stage70_cross_uid_peersec_20261119T042923Z.txt` has verified SHA-256 `2afb71b70461380136aa42fab7df5c4b9570f166a13ca808337cb585e0bea6f0` and covers 2026-11-19 04:29:23–04:29:26 UTC. Pinned ten-file LAB manifest verified (exit 0); five deployed policy SHA-256 values match the previously documented candidate. Five transient isolated-UID process self-`socketpair` probes successfully read `SO_PEERCRED` and `SO_PEERSEC`. The prior 4096-byte CPython buffer fault was corrected to 1024, and all five same-process `SO_PEERSEC` results match procfs labels.

Two further real two-process AF_UNIX observations succeeded:
- broker server UID 999, worker client UID 998/PID 14396; kernel `SO_PEERSEC` label `cybersec-stage70-worker//&unconfined (enforce)`;
- broker server UID 999, separate broker client UID 999/PID 14438; kernel `SO_PEERSEC` label `cybersec-stage70-broker//&unconfined (enforce)`.

Server kernel peer PIDs exactly matched client-reported PIDs; all processes were temporary and no permanent service was restarted. **These are identity/label observations, not authorization outcomes.** The strict LAB gate continues to reject the composite labels; production remains BLOCKED/NO-GO. The abstract AF_UNIX experiments share the host network namespace and differ from production's private network namespace.

An additional separate, *diagnostic-only candidate* `CyberSecurity_Stage70_IPC_NEGATIVE_Probe_DOWNLOAD.zip` has been prepared, SHA-256 `c40b3ea9d6e38c4283be714f42252d3bac6f6b0d7cdd2d479efe7b991ec8e074`. Its Bash-script SHA-256 is `47e046fcb0811b4139371d5e5c45d79ff062d4416f65ffd40fd1463fb40b1524`. It preflights Ubuntu 26.10, original ten-file hashes and persistent-service inactivity, then attempts six real transient negative admission scenarios by calling existing `peer_uid`, `peer_mac_label`, and `accept_request` functions directly. It requires an exact `BLOCKED/NO-GO` response on each connection and rejects missing peer observations as UNPROVEN. **The six negative scenarios have not been run on Ubuntu.** Offline contract suite: **12 unittest tests PASS, 0 FAIL**; initial test-harness method-binding failure preserved privately.

Core Stage 70 source and cumulative release **were not modified** for this next diagnostic. No new three-run full regressions, production permit issuance, private evidence publication or release readiness are claimed. GitHub update is sanitized metadata only; the private diagnostic ZIP and underlying cumulative source ZIP were not pushed. **BLOCKED/NO-GO retained.**


## November 19 04:53 UTC — real six-scenario IPC test BLOCKED before import; source DAC metadata defect

Uploaded private Ubuntu report `stage70_ipc_admission_negative_20261119T045313Z.txt` SHA-256 `1998f02968949c7e4f0e52ff807bd403f0de1cb73d660bdb57078ab128008bd8`: exact 10-file manifest verified, five SHA-pinned AppArmor policies confirmed, five permanent role services remained failed/inactive. However, **all six candidate negative IPC scenarios are UNPROVEN (0 PASS / 6 UNPROVEN)**. Every transient broker server exited 1 before opening its test socket, with `PermissionError(13)` importing root-owned `/opt/cybersec/stage70/src/cybersec/__init__.py`; clients exited 3. **No real `peer_uid`, `peer_mac_label`, or `accept_request` denial was demonstrated.** Do not count server import/connection failure as security admission PASS.

Independent review of the prior 868-file source ZIP (SHA-256 `7f7a1d9feb5a05b6582eec23e37e08433d7cef7fd8f6d77ee87fbe285883f39d`) found its **all 868 file entries had stored UNIX mode 0600**, including all **72 Python `src/**/*.py` files**. Prior install used archive metadata-preserving copy and root ownership; this may account for the observed non-root import EACCES, but the report contains no direct on-host `stat` of those specific files, so the DAC hypothesis is **not yet confirmed**.

A new LAB-only **pinned Python source DAC remediation candidate** is available as `CyberSecurity_Stage70_PINNED_DAC_REPAIR_DOWNLOAD.zip`, SHA-256 `a5b7083efb1872ad64305d55b632fa875c75ff55196d0bb6ee73f06eefdfc1b7`. The guarded two-step `inspect`/explicitly approved `apply` utility allows only root-owned SHA-256-verified Python source metadata transitions `0600→0644` and source directory `0700→0755` when needed; all unexpected symlinks, hardlinks, modes, policy hashes, UIDs or active permanent services block changes. Source bytes, ownership and AppArmor MAC contracts are unchanged; a best-effort rollback of metadata modes runs on failure. The utility has not yet run on Ubuntu. Six offline fixture tests PASS.

A **new cumulative Stage 70 v2.50.0 candidate** `cyber_securuty_2.0_stage_70_pinned_source_dac_hotfix.zip` has SHA-256 `288be49263852c5f3a542572d49fd538046c763ed04ab09f77d05a5be155b2bd`, **892 entries**, and preserves **all 868 original file CONTENT bytes byte-for-byte** including all historical private evidence. Exactly 72 original ZIP file permission metadata entries change to mode 0644; six new code/docs/private evidence files and 18-plus private regression outputs are additive. The original cumulative ZIP was NOT replaced. A delta ZIP with 96 entries has SHA-256 `9686c3f26eb7ee9e67e03ef2f68cbab65d641e3a95f6c62b9077cc3db65107f8`. Both archives were CRC and SHA checked.

**Three completed strict offline full regression runs of the candidate:** each **688 PASS / 69 SKIPPED / 0 FAIL**, exit 0, with `ResourceWarning` and `DeprecationWarning` treated as errors; stdout, stderr, JUnit, exit code, duration and SHA retained privately. Existing 69 Ubuntu opt-in skips are **not** kernel PASS.

The critical next on-host evidence is a **read-only `inspect` of source ownership, modes and five role-DAC reads** before any guarded repair, followed only after independent operator review by a metadata repair and re-running the original six-case real IPC test. No host repair, successful negative IPC admission, production GO, same-UID legacy fencing, independent monotonic root or SIGKILL recovery is claimed. **BLOCKED/NO-GO preserved.** Private ZIPs and raw host evidence have not been pushed to GitHub; this is sanitized evidence only.


## November 19 05:41–05:45 UTC — independent DAC repair 72/72 and six real negative IPC denials

Three private Ubuntu 26.10 reports arrived and their accompanying external SHA-256 files all verified:
- `stage70_source_dac_inspect_20261119T054100Z.txt`, SHA-256 `ca70ab06ea4936a8a67a4c1f594fe547159d797d99b6943e89293314d7468a49`. Pre-repair inspect: 72 root-owned, SHA-pinned `src/**/*.py` files had mode `0600`; five separate service UIDs failed DAC read. Preflight and ten-file lab manifest PASS; the five permanent lab services all `failed` / no main PID.
- `stage70_source_dac_apply_20261119T054440Z.txt`, SHA-256 `4a8f4e8b5e5bf1a69c4d0d03569ad76e0685d7762aeafdbfa56d45955f5d7050`. Under pinned, explicitly LAB-approved metadata-only repair, all 72 files were chmod `0644`, their SHA-256 content stayed unchanged; five service UID DAC reads became PASS; `REPAIR_METADATA_DONE=1`, `APPLY_EXIT=0`.
- `stage70_ipc_admission_negative_20261119T054549Z.txt`, SHA-256 `a3f65053467e267c0878bad83ae6e1b99da15411a3c86ffc977a2f282f36a919`. After repair, **all six** (worker profiled, broker same-UID, unconfined worker, attester, witness, publisher) ephemeral broker/client AF_UNIX negative tests had server and client exit 0. Each server observed actual kernel `SO_PEERCRED` (PID, UID, GID), `SO_PEERSEC` and invoked the installed `peer_mac_label` gate. All six were **rejected**, client received exact `{"error":"BLOCKED/NO-GO","ok":false}`, `SCENARIOS=6 EXPECTED_DENIAL_PASS=6 FAIL_OR_UNPROVEN=0`.

**Precise boundary:** actual MAC label remains `cybersec-stage70-ROLE//&unconfined (enforce)`, so every real scenario was rejected at the existing MAC-label gate. A *separate* call of installed `accept_request` with kernel-derived UID classified broker-to-broker as `UID_FRAME_ONLY_CONTRACT=DENY`, but full permanent-service positive admission and OS-enforced same-UID *legacy production fencing* remain **UNPROVEN**. Temporary abstract AF_UNIX tests shared host netns rather than permanent `PrivateNetwork`. No permanent services were started; all remained failed. No production GO, new Stage or successful independent monotonic root/SIGKILL recovery is claimed.

Private archival bundle `CyberSecurity_Stage70_DAC_IPC_EVIDENCE_NEXT_AUDIT.zip` has SHA-256 `757c53419eea721ec4aa6c42fd2d997dc891c4375da3df2fb7e4412c4dadb281`, containing the original VM reports, hashes, a structured bounded-evidence summary and a separate **read-only, not yet run on Ubuntu** unit/stacking state audit. Shell syntax, zip CRC and SHA-256 verified. No main Stage 70 source changes were made, and **no new full regressions claimed**; last completed strict cumulative 3×688 PASS / 69 SKIPPED remains the prior candidate's result.

**Production BLOCKED/NO-GO stays in force.** This is sanitized status; private VM logs and cumulative source ZIP have not been pushed publicly.


## November 19 05:58:56 UTC — read-only systemd unit audit after DAC and negative IPC

The newest private Ubuntu 26.10 report `stage70_post_dac_unit_audit_20261119T055856Z.txt` verified SHA-256 `37914a73b91b1d57209734cc0189ab4151820f46fa68aad505a98947d203e3eb`. Reuploaded previous DAC inspect, DAC apply and six-case negative IPC reports have the exact same previously attested SHA-256 hashes (`ca70ab06ea4936a8a67a4c1f594fe547159d797d99b6943e89293314d7468a49`, `4a8f4e8b5e5bf1a69c4d0d03569ad76e0685d7762aeafdbfa56d45955f5d7050`, `a3f65053467e267c0878bad83ae6e1b99da15411a3c86ffc977a2f282f36a919`); **no additional live IPC authorization test was rerun**.

New audit: exact ten-pinned-file manifest verifies; five installed/source AppArmor profile hashes match their pins and all are loaded in enforce mode. Distinct dedicated UIDs: broker 999, worker 998, attester 993, witness 992, publisher 991. Systemd configuration for all five permanent lab services reports `PrivateNetwork=yes`, `NoNewPrivileges=yes`, `RestrictAddressFamilies=AF_UNIX`, `ProtectSystem=strict`, `RestrictNamespaces=yes`, `KillMode=control-group`, `RuntimeDirectoryMode=0755` and denied IP addressing. The services remained **failed / MainPID=0 / Result=start-limit-hit**, so there is no evidence they successfully restarted after DAC repair. Installed Python sources sampled as root:root mode 0644. Kernel `apparmor_restrict_unprivileged_unconfined` and `...userns` remain 1.

A new locally prepared **read-only unit-boundary candidate** `CyberSecurity_Stage70_UNIT_BOUNDARY_Probe_DOWNLOAD.zip` (SHA-256 `7b2257ec8bef0b0237f66faddfc6216605db58a32195b1669d1320e0b3de991b`) includes the original four verified private reports, their SHA manifests, a source-status summary and `stage70_unit_boundary_probe.sh` (SHA-256 `b4445396b1068160fdc0574c1aec625e291cd80f788bb3e64ea1e4569d6424b3`). It is specifically for the still-unchecked effective `ExecStart`, supplementary IPC group, unit fragment/drop-in authority, filesystem socket residue and runtime path. It has **not run on Ubuntu**; syntax, ZIP CRC and SHA-256 only were checked. No source code was changed and no additional full regressions are claimed.

The strict exact-label contract still rejects `cybersec-stage70-ROLE//&unconfined (enforce)`. The prior six negative denials used transient abstract AF_UNIX sockets in a shared network namespace, whereas permanent services have `PrivateNetwork=yes` and use pathname sockets; production-like connectivity and any positive admission are still unproven. Same-UID legacy fencing, independent monotonic root and crash/SIGKILL recovery remain unproven.

**Production BLOCKED/NO-GO retained.** Neither raw VM evidence nor the private/source ZIP was published on GitHub; this update is sanitized evidence metadata only.


### Correction to locally packaged read-only unit-boundary candidate

Before distribution, the diagnostic shell script was corrected to write the output report `.sha256` with a **relative basename** rather than an absolute Ubuntu path, so it can be verified after downloading to macOS. This changes the *diagnostic candidate only*, not any previously verified Ubuntu evidence or production code.

**Final candidate ZIP SHA-256:** `b3b6d72d4bdbc2107d40126008bacd3d34bb37ee08b68a2f9fe6a5f53b0d911e`. **Final embedded shell script SHA-256:** `b2b2d5359b535966ed1d67008a01245b8980d5e26a285ea724a40044285175d2`. The earlier provisional candidate hashes (`7b2257ec...` / `b4445396...`) are superseded and must not be used to verify the distributed ZIP. Final ZIP has 12 entries; Bash syntax, CRC, private report SHA-256 and ZIP SHA-256 validated locally. **Not executed on Ubuntu. Production BLOCKED/NO-GO.**


## November 19 06:12 UTC — five live unit-boundary inventories verified

The private Ubuntu 26.10 report `stage70_unit_boundary_probe_20261119T061215Z.txt` was hash-verified, SHA-256 `c36335a295bbd33e0701c00b2b952da851ed43ac68bc928b7223bf11ddb0a72d`. Four reuploaded older files (source DAC inspect/apply, negative IPC and unit audit) exactly match previously verified SHA-256 and add no independent rerun.

The new report confirms all five effective systemd units are known, root-owned, static, loaded, with no drop-ins; `ExecStart` uses the pinned venv Python `-I -m cybersec.stage70.lab_service --role ROLE`. AppArmor role policies match previous exact SHA pins and are in enforcing mode. Each unit has `SupplementaryGroups=cybersec-stage70-ipc`; the shared IPC GID is 973 with exactly the five dedicated role service accounts. Each unit retains `PrivateNetwork=yes`, `NoNewPrivileges=yes`, `RestrictAddressFamilies=AF_UNIX`, `ProtectSystem=strict`, `RestrictNamespaces=yes`, `KillMode=control-group`, `SendSIGKILL=yes`, and `RuntimeDirectoryMode=0755`. Root-owned template `/etc/systemd/system/cybersec-stage70@.service` SHA-256: `3bfcd363c967de40b48ced161da46071c3008005cdb196a47a5b01003ac32850`.

All five services **remain failed / MainPID=0 / start-limit-hit** from earlier attempts. Runtime directories and `/run/cybersec-stage70-ROLE/probe.sock` paths are absent; therefore **no pathname socket has been opened or authenticated in a permanent unit**. Prior six negative IPC admission denials used separate temporary abstract AF_UNIX sockets in a shared netns, which differs from the service's `PrivateNetwork=yes`. The exact-label MAC gate still refuses stacked `cybersec-stage70-ROLE//&unconfined (enforce)`; positive IPC, same-UID legacy OS confinement, independent monotonic root and SIGKILL recovery remain unproven.

A separate **read-only, not run on Ubuntu** contract-audit candidate was packaged:
- `CyberSecurity_Stage70_PATHNAME_IPC_CONTRACT_AUDIT.zip` SHA-256 `a2e9a3b1ada8bef887f22140df5337d52e4056666ce4ad75f8263cfa0d4aa4e8`.
- `stage70_pathname_ipc_contract_audit.py` SHA-256 `1147f2b0fb2e26a4466cc86c74ae32e2e844d0541b0a416d7bb8280f5794a7e7`.
- Pinned JSON SHA-256 `1ea24c0b2135d5169592a7785828d56f92983bfde272bdf1b3abf4350a649e8c`.
- 7-entry ZIP CRC PASS. Offline exact cumulative ZIP graph PASS for five role-specific permitted pathname edges and 72 SHA-pinned Python source files. Four offline test cases PASS (good baseline accepted, tampered policy rejected, truncated archive rejected, missing archive rejected). **No on-host real pathname IPC or full new strict regression was run or claimed.**

This candidate only inventories policy-to-source-to-unit contracts; it cannot override exact MAC admission. **BLOCKED/NO-GO preserved**. Original private raw logs and full source ZIP were not published to GitHub.


## November 19 06:29 UTC — original pathname-IPC contract audit FAIL; profile-check diagnostic defect

Private Ubuntu 26.10 report `stage70_pathname_ipc_contract_20261119T062922Z.txt` SHA-256 **`496e0ff5c29cbba847ce305c271aa10b545a164b81ef94a6d6d0e8dbfc0a3811`** (sidecar verified) has `AUDIT_EXIT=3`, `FAILED_CONTRACT_CHECKS=5`. All five failures were `CHECK_APPARMOR_LOADED_{BROKER,WORKER,ATTESTER,WITNESS,PUBLISHER}=FAIL`; the script did **not** include the actual `aa-status` human output or kernel profile listing in this report. In the prior diagnostic source, those checks tried to find `name (enforce)` as an exact line in human-readable `aa-status`, which normally displays profile names beneath an enforce-mode section without the suffix. Therefore **these five FAILs are not evidence that all five policies disappeared from the kernel**. Preserve the original evidence and NO-GO pending a fresh direct-kernel check.

All remaining reported checks passed, including 72 installed Python SHA-256s and DAC modes, installed/source policy hashes, approved 5-edge pathname AF_UNIX source/policy matrix, five UID/group checks, five effective systemd unit controls (failed/inactive MainPID=0, no unknown drop-ins), no lingering runtime/socket paths, restricted AppArmor sysctls and the pinned manifest. This is **static and read-only host evidence**, not live production pathname socket admission, positive authorization, same-UID legacy OS fencing or monotonic-root evidence.

A new **diagnostic-only v2** audit was locally packaged: `CyberSecurity_Stage70_PATHNAME_IPC_KERNEL_PROFILE_V2_DOWNLOAD.zip`, SHA-256 **`27d0473df201c6124f7c308c24d221bede44bed41d9a7d8def63daf7129fba54`**, 21 entries. New Python auditor `stage70_pathname_ipc_contract_audit_v2.py`, SHA-256 **`a09ee8c0f98d61c07f83e231cb2917e518429a406191ed6e832544b51d3a1422`**, directly reads `/sys/kernel/security/apparmor/profiles` and requires an exact *loaded kernel policy* `cybersec-stage70-ROLE (enforce)` line for each role, failing closed on missing/unreadable/mismatched modes, duplicate or spoofed names. This does not relax the separate *process MAC* or `SO_PEERSEC` exact-label gate and never authorizes `//&unconfined` stacks.

Locally completed **three strict runs of nine targeted diagnostic tests** with ResourceWarning/DeprecationWarning errors and **three offline archive-graph audits** (all exit 0, `FAILED_CONTRACT_CHECKS=0`), preserving stdout/stderr, source and prior FAIL. **The v2 auditor has not run on Ubuntu**, and there were **no modifications to cumulative Stage 70 source, installed policies or permanent services**, so no fresh full product-regression claims. Original three full strict cumulative runs remain the previously reported 688 PASS / 69 SKIPPED each.

**Production BLOCKED/NO-GO.** Raw private report and artifact not uploaded to public GitHub; this is sanitized status only. Next: transfer v2 diagnostic with SHA-256 and run the read-only real Ubuntu host audit, with no service start/reset.
