# Phoenix Security × ChatGPT / OpenAI

Two supported paths, depending on your ChatGPT plan.

## Path A — MCP connector (recommended: full 31-tool access)

ChatGPT connectors talk to **remote** MCP servers. Run `phoenix-mcp` with
the HTTP transport behind HTTPS:

```bash
# on a host reachable by ChatGPT (put TLS + auth in front, e.g. a reverse proxy)
PHOENIX_CLIENT_ID=... PHOENIX_CLIENT_SECRET=... \
PHOENIX_MCP_READ_ONLY=true \
phoenix-mcp --transport streamable-http --host 0.0.0.0 --port 8848
# MCP endpoint: https://your-host/mcp
```

Then in ChatGPT: **Settings → Connectors → Add custom connector** (requires
a plan with custom connectors / developer mode) and point it at
`https://your-host/mcp`.

> ⚠️ The server holds your Phoenix credentials. Never expose it without
> TLS and an authenticating proxy; start with `PHOENIX_MCP_READ_ONLY=true`.

Paste [`custom-gpt-instructions.md`](custom-gpt-instructions.md) into the
conversation/system instructions (or a Project) so ChatGPT follows the
canonical workflows.

## Path B — Custom GPT with Actions (no hosting, read-mostly)

1. Create a GPT (chatgpt.com → My GPTs → Create).
2. **Instructions**: paste [`custom-gpt-instructions.md`](custom-gpt-instructions.md).
3. **Actions**: import the OpenAPI spec from the CLI repo —
   `openapi/phoenix-security-api-v1.27.yaml`
   (github.com/Security-Phoenix-demo/Phoenix-Security-CLI). Trim to the
   operations you need if you hit the Actions operation limit.
4. **Authentication caveat**: Phoenix uses a two-step flow (Basic →
   short-lived Bearer). GPT Actions can't chain those automatically, so
   either:
   - set Actions auth to **API Key / Bearer** and paste a token minted with
     `phx auth token` (expires — fine for demos), or
   - front the API with a tiny proxy that injects a fresh Bearer token
     (recommended for real use), or
   - use Path A instead, which handles tokens natively.

## Path C — Codex CLI

OpenAI Codex supports stdio MCP directly — see [`../codex/`](../codex/).
