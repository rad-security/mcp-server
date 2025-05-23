# RAD Security MCP Server

A Model Context Protocol (MCP) server for RAD Security, providing AI-powered security insights for Kubernetes and cloud environments.

## Installation

```bash
npm install @rad-security/mcp-server
```

## Usage

### Prerequisites

- Node.js 20.x or higher

### Environment Variables

The following environment are required required to use the MCP server with Rad Security:

```bash
RAD_SECURITY_ACCESS_KEY_ID="your_access_key"
RAD_SECURITY_SECRET_KEY="your_secret_key"
RAD_SECURITY_ACCOUNT_ID="your_account_id"
```

but you can also use few operations without authentication:

- List CVEs
- Get details of a specific CVE
- Get latest 30 CVEs
- List Kubernetes resource misconfiguration policies

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

- Account Inventory
  - List clusters and their details*

- Containers Inventory
  - List containers and their details*

- Security Findings
  - List and analyze security findings*

- Runtime Security
  - Get process trees of running containers*
  - Get runtime baselines of running containers*
  - Analyze process behavior of running containers*

- Network Security
  - Monitor HTTP requests*
  - Track network connections*
  - Analyze network patterns*

- Identity and Access
  - List identities*
  - Get identity details*

- Audit
  - List who shelled into a pod*

- Cloud Security
  - List and monitor cloud resources*
  - Get resource details and compliance status*

- Images
  - Get SBOMs*
  - List images and their vulnerabilities*
  - Get top vulnerable images*

- Kubernetes Objects
  - Get details of a specific Kubernetes resource*
  - List Kubernetes resources*
  - List Kubernetes resource misconfiguration policies*

- Threat Vector
  - List threat vectors*
  - Get details of a specific threat vector*

- CVEs
  - List CVEs
  - Get details of a specific CVE
  - Get latest 30 CVEs

`*` - requires authentication and account in Rad Security.

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
