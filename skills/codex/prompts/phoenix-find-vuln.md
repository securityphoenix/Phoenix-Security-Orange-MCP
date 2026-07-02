Search Phoenix Security findings for: $ARGUMENTS

Use phoenix_search_findings (or `phx findings list -o json`). If the query
contains CVE IDs pass them as cves; map words like "critical" to
severity_score_from 900 and "high" to 700 (search scale is 0-1000); default
to status OPEN. Scope by application/team when named. Report a ranked table:
finding id, CVE, severityScore, EPSS, status, asset, application, location —
then one-line takeaways.
