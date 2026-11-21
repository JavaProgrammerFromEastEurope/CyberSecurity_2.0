# Local fixture correction during Stage 64 development

An early profile test invocation returned exit code 1: one failure and ten
passing tests. `test_proc_parser_cgroup_and_pid_reuse` supplied a synthetic
`/proc/PID/stat` line whose PID prefix check incorrectly rejected `900`.
The fake line also placed `start_ticks` one index too far to the right.
Both the parser's PID syntax check and the test fixture were corrected.
Subsequent profile test: **11/11 PASS**, then expanded final profile: **13/13 PASS**.
The original console failure was displayed during development but its raw
stdout/stderr was not saved to disk at that time; do not treat this summary
as a contemporaneous original transcript.
No scanner was involved.
