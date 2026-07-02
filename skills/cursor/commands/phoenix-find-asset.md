Locate assets in Phoenix Security matching described in the user's message (ask if missing).

Use the phoenix-security MCP tools (or `phx assets list -o json`). Search by
asset type if implied (INFRA, CLOUD, WEB, CONTAINER, REPOSITORY, BUILD,
CODE) and match the query against asset `key`, `attributes` (ip, hostname,
fqdn, repository, dockerfile, providerAccountId) and `tags`. For the best
match, fetch full details. Report: id, key, type, locality, key attributes,
tags, and which application/component owns it if determinable.
