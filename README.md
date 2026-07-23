# RAD Security MCP Server

[![npm version](https://img.shields.io/npm/v/@rad-security/mcp-server)](https://npmjs.com/package/@rad-security/mcp-server)

A Model Context Protocol (MCP) server for RAD Security, providing AI-powered security insights for Kubernetes and cloud environments.

<a href="https://glama.ai/mcp/servers/@rad-security/mcp-server">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/@rad-security/mcp-server/badge" alt="RAD Security MCP server" />
</a>

## Installation

```bash
npm install @rad-security/mcp-server
```

## Usage

### Prerequisites

- Node.js 20.x or higher

### Environment Variables

The following environment variables are required to use the MCP server with Rad Security:

```bash
RAD_SECURITY_ACCESS_KEY_ID="your_access_key"
RAD_SECURITY_SECRET_KEY="your_secret_key"
RAD_SECURITY_ACCOUNT_ID="your_account_id"
```

Optional environment variables:

```bash
RAD_SECURITY_TENANT_ID="your_tenant_id"  # Optional: If not provided, will be fetched automatically from the account
```

#### Optional: Filter Toolkits

You can control which toolkits are exposed by the MCP server using these environment variables:

- `INCLUDE_TOOLKITS`: Comma-separated list of toolkits to include (only these will be enabled)
- `EXCLUDE_TOOLKITS`: Comma-separated list of toolkits to exclude (all except these will be enabled)

Available toolkits:
- `containers` - Container inventory operations
- `clusters` - Kubernetes cluster operations
- `audit` - Audit log operations
- `images` - Container image, vulnerability and CVE disposition operations
- `kubeobject` - Kubernetes resource operations
- `runtime` - Runtime analysis operations
- `findings` - Security findings operations
- `inbox` - Inbox item operations
- `workflows` - Workflow execution operations
- `custom_workflows` - Workflow authoring operations (disabled by default)
- `knowledge_base` - Knowledge base search operations
- `radql` - Query interface for rad data platform
- `dashboards` - Dashboard and widget template operations
- `integrations` - External integration operations

Note: `custom_workflows` is disabled by default and must be enabled explicitly via `INCLUDE_TOOLKITS`.

#### Inbound authentication (`MCP_AUTH_MODE`)

When running over the streamable HTTP transport, the server can authenticate each
inbound request instead of using a single set of process-env credentials. This is
what makes a single deployment safe to serve multiple accounts (for example, when
hosting the server as a remote connector).

- `MCP_AUTH_MODE=env` (default) — every session uses the `RAD_SECURITY_*`
  environment credentials. Single-tenant; unauthenticated at the HTTP layer.
  This preserves the existing local / self-hosted / per-account-pod behavior.
- `MCP_AUTH_MODE=header` — every session must present its own credential in the
  `Authorization` header. A missing or malformed header is rejected with
  `401 Unauthorized`. Only supported with `TRANSPORT_TYPE=streamable`
  (the server refuses to start otherwise).

In `header` mode the bearer credential encodes the account, in one of two forms:

```
Authorization: Bearer <access_key_id>:<secret_key>:<account_id>
Authorization: Bearer ory_st_<session_token>:<account_id>
```

`RAD_SECURITY_API_URL` is still taken from server configuration (not the caller).
The credential shape is validated on connect; whether it actually authenticates
against the Rad API surfaces on the first tool call.

> **Note:** exposing the server publicly requires `MCP_AUTH_MODE=header` (or an
> authenticating proxy in front). The default `env` mode does **not** authenticate
> inbound HTTP requests and must not be reachable from untrusted networks.

Examples:

```bash
# Only enable workflow toolkit
INCLUDE_TOOLKITS="workflows"

# Enable only containers and images toolkits
INCLUDE_TOOLKITS="containers,images"

# Exclude workflow toolkit (enable all others)
EXCLUDE_TOOLKITS="workflows"

# Exclude runtime toolkit
EXCLUDE_TOOLKITS="runtime"
```

Note: If `INCLUDE_TOOLKITS` is set, `EXCLUDE_TOOLKITS` is ignored.

### In cursor IDE

It's quite problematic to set ENV variables in cursor IDE.

So, you can use the following start.sh script to start the server.

```bash
./start.sh
```

Please set the ENV variables in the start.sh script first!

### In Claude Desktop

You can use the following config to start the server in Claude Desktop.

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

To filter toolkits, add `INCLUDE_TOOLKITS` or `EXCLUDE_TOOLKITS` to the env:

```json
{
  "mcpServers": {
    "rad-security": {
      "command": "npx",
      "args": ["-y", "@rad-security/mcp-server"],
      "env": {
        "RAD_SECURITY_ACCESS_KEY_ID": "<your-access-key-id>",
        "RAD_SECURITY_SECRET_KEY": "<your-secret-key>",
        "RAD_SECURITY_ACCOUNT_ID": "<your-account-id>",
        "EXCLUDE_TOOLKITS": "workflows"
      }
    }
  }
```

### As a Docker Container - with Streamable HTTP

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

With toolkit filters:

```bash
docker run \
  -e TRANSPORT_TYPE=streamable \
  -e RAD_SECURITY_ACCESS_KEY_ID=your_access_key \
  -e RAD_SECURITY_SECRET_KEY=your_secret_key \
  -e RAD_SECURITY_ACCOUNT_ID=your_account_id \
  -e INCLUDE_TOOLKITS=workflows,containers \
  -p 3000:3000 \
  rad-security/mcp-server
```

### As a Docker Container - multi-tenant (per-request auth)

Serve multiple accounts from one deployment by requiring each request to carry its
own credential. Note there are no `RAD_SECURITY_ACCESS_KEY_ID` / `_SECRET_KEY` /
`_ACCOUNT_ID` env vars here — those arrive per request in the `Authorization` header.

```bash
docker run \
  -e TRANSPORT_TYPE=streamable \
  -e MCP_AUTH_MODE=header \
  -e RAD_SECURITY_API_URL=https://api.rad.security \
  -p 3000:3000 \
  rad-security/mcp-server
```

Callers then authenticate per request:

```bash
curl -H "authorization: Bearer <access_key_id>:<secret_key>:<account_id>" \
  -H "content-type: application/json" \
  -H "accept: application/json, text/event-stream" \
  -X POST http://localhost:3000/mcp -d '{...}'
```

### As a Docker Container - with SSE (deprecated)

*Note:* The SSE transport is now deprecated in favor of Streamable HTTP. It's still supported for backward compatibility, but it's recommended to use Streamable HTTP instead.

```bash
docker build -t rad-security/mcp-server .
docker run \
  -e TRANSPORT_TYPE=sse \
  -e RAD_SECURITY_ACCESS_KEY_ID=your_access_key \
  -e RAD_SECURITY_SECRET_KEY=your_secret_key \
  -e RAD_SECURITY_ACCOUNT_ID=your_account_id \
  -p 3000:3000 \
  rad-security/mcp-server
```

## Features

All tools require authentication and an account in Rad Security.

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
