Produce a full Phoenix Security report for the application described in the user's message (ask if missing).

Steps (phoenix_* MCP tools or phx CLI): 1) resolve the application by name
(phoenix_list_applications); 2) posture (phoenix_get_application_posture —
risk, threshold, open findings by bucket, asset totals); 3) components
(phoenix_list_components parent_id=<app>); 4) assets
(phoenix_search_assets application_environment_id=<app>); 5) OPEN findings
scoped the same way. Deliver: executive summary (risk vs threshold),
riskiest components, asset inventory summary by type, top 10 findings
(severity/EPSS, with remedies), and a prioritised remediation shortlist.
