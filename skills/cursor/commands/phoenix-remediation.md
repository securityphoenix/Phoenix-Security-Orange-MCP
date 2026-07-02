Provide remediation guidance from Phoenix Security for described in the user's message (ask if missing).

Find the matching finding(s) (phoenix_search_findings / `phx findings list`),
then fetch details (phoenix_get_finding / `phx findings get`). The remedy is
in data[].remedy; context in data[].description; where to fix in location;
owning app/component in parents[]. Report per finding: what it is, where it
lives (asset + application), the concrete fix, and references (CVE/CWE).
Order by severity × EPSS. If many findings share a remedy, group them.
