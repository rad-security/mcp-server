# RAD Security MCP Server

[![npm version](https://img.shields.io/npm/v/@rad-security/mcp-server)](https://npmjs.com/package/@rad-security/mcp-server)

A Model Context Protocol (MCP) server for RAD Security, providing AI-powered security insights for Kubernetes and cloud environments.

<a href="https://glama.ai/mcp/servers/@rad-security/mcp-server">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/@rad-security/mcp-server/badge" alt="RAD Security MCP server" />
</a>

## Connect (hosted — recommended)

RAD Security runs the MCP server for you, so most users don't need to install or host anything. Point your MCP client at the hosted endpoint and authenticate with your RAD Security credentials.

- **Endpoint:** `https://api.rad.security/mcp/` — note the **trailing slash**.
- **Transport:** Streamable HTTP.
- **Authentication:** send your credential in the `Authorization` header:

  ```
  Authorization: Bearer <access_key_id>:<secret_key>:<account_id>
  ```

  `<access_key_id>` and `<secret_key>` are a RAD Security API access key (create one in the RAD Security console); `<account_id>` is your account ID. The server authenticates every request against the RAD Security API — no credentials are stored server-side.

> A short-lived form `Bearer ory_st_<session_token>:<account_id>` also works, but session tokens expire — prefer an access key for anything long-lived (e.g. Slack / Claude Tag).

### Claude Code

```bash
claude mcp add --transport http rad-security https://api.rad.security/mcp/ \
  --header "Authorization: Bearer <access_key_id>:<secret_key>:<account_id>"
```

### OpenAI Codex CLI

`~/.codex/config.toml`:

```toml
[mcp_servers.rad-security]
url = "https://api.rad.security/mcp/"
http_headers = { "Authorization" = "Bearer <access_key_id>:<secret_key>:<account_id>" }
```

Or via the CLI, keeping the secret in an env var (`export RAD_MCP_TOKEN=<access_key_id>:<secret_key>:<account_id>`):

```bash
codex mcp add rad-security --url https://api.rad.security/mcp/ --bearer-token-env-var RAD_MCP_TOKEN
```

### Cursor

`.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "rad-security": {
      "type": "http",
      "url": "https://api.rad.security/mcp/",
      "headers": {
        "Authorization": "Bearer <access_key_id>:<secret_key>:<account_id>"
      }
    }
  }
}
```

### VS Code (GitHub Copilot)

`.vscode/mcp.json` — note the wrapper key is `servers`, not `mcpServers`:

```json
{
  "servers": {
    "rad-security": {
      "type": "http",
      "url": "https://api.rad.security/mcp/",
      "headers": {
        "Authorization": "Bearer <access_key_id>:<secret_key>:<account_id>"
      }
    }
  }
}
```

### Gemini CLI

`~/.gemini/settings.json` — note the URL field is `httpUrl` (not `url`):

```json
{
  "mcpServers": {
    "rad-security": {
      "httpUrl": "https://api.rad.security/mcp/",
      "headers": {
        "Authorization": "Bearer <access_key_id>:<secret_key>:<account_id>"
      }
    }
  }
}
```

### Cline

`cline_mcp_settings.json` — note `type` must be exactly `streamableHttp` (camelCase):

```json
{
  "mcpServers": {
    "rad-security": {
      "type": "streamableHttp",
      "url": "https://api.rad.security/mcp/",
      "headers": {
        "Authorization": "Bearer <access_key_id>:<secret_key>:<account_id>"
      }
    }
  }
}
```

### Windsurf

`~/.codeium/windsurf/mcp_config.json` — note the URL field is `serverUrl`:

```json
{
  "mcpServers": {
    "rad-security": {
      "serverUrl": "https://api.rad.security/mcp/",
      "headers": {
        "Authorization": "Bearer <access_key_id>:<secret_key>:<account_id>"
      }
    }
  }
}
```

### Other clients

Most MCP clients accept a remote Streamable HTTP server with a URL and an `Authorization` header — only the field names differ. Keep the **trailing slash** on the URL in every case.

| Client | Config location | URL field | Transport marker | Header field |
| --- | --- | --- | --- | --- |
| Claude Code | `claude mcp add` | positional arg | `--transport http` | `--header` |
| OpenAI Codex CLI | `~/.codex/config.toml` | `url` | inferred | `http_headers` / `bearer_token_env_var` |
| Cursor | `.cursor/mcp.json` | `url` | `type: "http"` | `headers` |
| VS Code | `.vscode/mcp.json` (`servers`) | `url` | `type: "http"` | `headers` |
| Gemini CLI | `~/.gemini/settings.json` | `httpUrl` | inferred | `headers` |
| Cline | `cline_mcp_settings.json` | `url` | `type: "streamableHttp"` | `headers` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | `serverUrl` | inferred | `headers` |

### Claude.ai / Claude Desktop / Claude Tag (Slack)

These surfaces add remote MCP servers as **connectors**, which use their own credential settings rather than a raw request header. Add `https://api.rad.security/mcp/` as a custom connector, then supply the bearer credential through the connector's settings:

- **Claude Tag (Slack):** attach the server as a plugin whose `.mcp.json` points at the endpoint, and add the bearer credential on the Access bundle's **Credentials** tab. See [Claude Tag — connect a custom MCP server](https://claude.com/docs/claude-tag/admins/connections/custom).
- **Claude.ai / Desktop:** add it under Settings → Connectors; see [custom connectors](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp).

### Test it (MCP Inspector or curl)

```bash
npx @modelcontextprotocol/inspector
# Transport:      Streamable HTTP
# URL:            https://api.rad.security/mcp/   (trailing slash)
# Custom headers: { "Authorization": "Bearer <access_key_id>:<secret_key>:<account_id>" }
```

```bash
curl -H "authorization: Bearer <access_key_id>:<secret_key>:<account_id>" \
  -H "content-type: application/json" \
  -H "accept: application/json, text/event-stream" \
  -X POST https://api.rad.security/mcp/ \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
```

## Features

All tools require authentication and an account in RAD Security. The hosted endpoint exposes every toolkit below except `custom_workflows` (workflow authoring), which is off by default.

- Account Inventory
  - List clusters and their details

- Containers Inventory
  - List containers and their details

- Security Findings
  - List and analyze security findings
  - Update the status of a security finding

- Runtime Security
  - Get process trees of running containers
  - Get runtime baselines of running containers
  - Analyze process behavior of running containers

- Audit
  - List who shelled into a pod

- Images and Vulnerabilities
  - Get SBOMs
  - List images and their vulnerabilities
  - Get top vulnerable images
  - Ignore / unignore CVEs and list active CVE dispositions

- Kubernetes Objects
  - Get details of a specific Kubernetes resource
  - List Kubernetes resources

- Inbox
  - List inbox items and their details
  - Mark an inbox item as a false positive

- Workflows
  - List workflows, runs and schedules
  - Get workflow and workflow run details
  - Run a workflow
  - Create and update custom workflows and schedules (via `custom_workflows`, disabled by default)

- Knowledge Base
  - Search the knowledge base
  - List collections and documents
  - Run structured queries against a document

- Dashboards
  - List dashboards and get their details
  - List and get dashboard and widget templates

- Integrations
  - List external integrations

- RadQL (Advanced Querying)
  - List available data types for querying (containers, findings, kubernetes_resources, etc.)
  - Get schema/metadata for specific data types
  - List possible values for filter fields
  - Execute RadQL queries with filtering, searching, and aggregations
  - Build queries programmatically from structured conditions
  - Execute multiple queries in parallel

## Self-hosting

Prefer to run the server yourself — for example an air-gapped environment, data-residency requirements, or if you don't want to route through the hosted gateway? It's published to npm and as a container image.

### Prerequisites

- Node.js 20.x or higher

### Credentials

Provide your RAD Security credentials via environment variables:

```bash
RAD_SECURITY_ACCESS_KEY_ID="your_access_key"
RAD_SECURITY_SECRET_KEY="your_secret_key"
RAD_SECURITY_ACCOUNT_ID="your_account_id"

# Optional: fetched automatically from the account if not set
RAD_SECURITY_TENANT_ID="your_tenant_id"
```

### npx (stdio) — e.g. Claude Desktop

```json
{
  "mcpServers": {
    "rad-security": {
      "command": "npx",
      "args": ["-y", "@rad-security/mcp-server"],
      "env": {
        "RAD_SECURITY_ACCESS_KEY_ID": "<your-access-key-id>",
        "RAD_SECURITY_SECRET_KEY": "<your-secret-key>",
        "RAD_SECURITY_ACCOUNT_ID": "<your-account-id>"
      }
    }
  }
}
```

### Docker (Streamable HTTP)

```bash
docker build -t rad-security/mcp-server .
docker run \
  -e TRANSPORT_TYPE=streamable \
  -e RAD_SECURITY_ACCESS_KEY_ID=your_access_key \
  -e RAD_SECURITY_SECRET_KEY=your_secret_key \
  -e RAD_SECURITY_ACCOUNT_ID=your_account_id \
  -p 3000:3000 \
  rad-security/mcp-server
```

### Toolkit filtering

Control which toolkits a self-hosted server exposes:

- `INCLUDE_TOOLKITS`: comma-separated list of toolkits to include (only these are enabled).
- `EXCLUDE_TOOLKITS`: comma-separated list of toolkits to exclude (all others are enabled). Ignored if `INCLUDE_TOOLKITS` is set.

Available toolkits: `containers`, `clusters`, `audit`, `images`, `kubeobject`, `runtime`, `findings`, `inbox`, `workflows`, `custom_workflows` (disabled by default), `knowledge_base`, `radql`, `dashboards`, `integrations`.

```bash
# Only the workflows toolkit
INCLUDE_TOOLKITS="workflows"

# Everything except runtime
EXCLUDE_TOOLKITS="runtime"
```

### Multi-tenant (per-request auth)

`MCP_AUTH_MODE` controls how a streamable HTTP deployment authenticates inbound requests — this is what the hosted endpoint uses:

- `MCP_AUTH_MODE=env` (default) — every session uses the `RAD_SECURITY_*` environment credentials. Single-tenant, and **unauthenticated at the HTTP layer**, so it must not be reachable from untrusted networks.
- `MCP_AUTH_MODE=header` — every request must carry its own credential in the `Authorization` header (the `Bearer <access_key_id>:<secret_key>:<account_id>` form above); a missing or malformed header is rejected with `401`. Only supported with `TRANSPORT_TYPE=streamable`. `RAD_SECURITY_API_URL` is taken from server config, not the caller.

```bash
docker run \
  -e TRANSPORT_TYPE=streamable \
  -e MCP_AUTH_MODE=header \
  -e RAD_SECURITY_API_URL=https://api.rad.security \
  -p 3000:3000 \
  rad-security/mcp-server
```

> The SSE transport (`TRANSPORT_TYPE=sse`) is deprecated in favor of Streamable HTTP and uses env credentials only.

## Development

```bash
# Install dependencies
npm install

# Run type checking
npm run type-check

# Run linter
npm run lint

# Build
npm run build
```

## License

MIT License - see the [LICENSE](LICENSE) file for details
