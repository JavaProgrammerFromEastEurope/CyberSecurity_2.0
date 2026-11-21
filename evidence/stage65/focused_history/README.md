Historical focused iterations are retained: initial import failure caused by
not setting PYTHONPATH (exit 2, command output originally console only); next
focused run discovered unclosed SQLite connections (ResourceWarning shown in
pytest warnings), and a concurrent test barrier race (exit 1). The subsequent
focused rerun passed with no warnings. These were **not** full regressions and
are not counted as one of the three required complete successful runs.
