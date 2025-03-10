# RAD Security MCP Server

A Model Context Protocol (MCP) server that provides tools for interacting with the RAD Security platform.

## Features

### Container Tools

- `rad_security_list_containers`: List containers with optional filtering
  - **filters** (optional): Filter string (e.g., 'image_name:nginx' or 'image_digest:sha256:...' or 'owner_namespace:namespace' or 'cluster_id:cluster_id')
  - **offset** (optional): Pagination offset
  - **limit** (optional): Maximum number of results to return (default: 20)
  - **q** (optional): Free text search query

- `rad_security_get_container_details`: Get detailed information about a container
  - **container_id** (required): ID of the container to get details for

### Cluster Tools

- `rad_security_list_clusters`: List Kubernetes clusters
  - **page_size** (optional): Number of results per page
  - **page** (optional): Page number

- `rad_security_get_cluster_details`: Get detailed information about a cluster
  - **cluster_id** (required): ID of the cluster to get details for

### Misconfig Tools

- `rad_security_get_manifest_misconfigs`: Get misconfigurations in Kubernetes manifests
  - **resource_uid** (required): UID of the resource to get misconfigs for

- `rad_security_get_misconfig_details`: Get detailed information about a misconfiguration
  - **misconfig_id** (required): ID of the misconfig to get details for

### Runtime Tools

- `rad_security_get_containers_process_trees`: Get process trees for containers
  - **container_ids** (required): Array of container IDs to get process trees for

- `rad_security_get_containers_baselines`: Get runtime baselines for containers
  - **container_ids** (required): Array of container IDs to get baselines for

- `rad_security_get_container_llm_analysis`: Get LLM analysis of a container
  - **container_id** (required): ID of the container to get LLM analysis for

- `rad_security_get_runtime_findings`: Get runtime security findings for a container
  - **container_id** (required): ID of the container to get runtime findings for

### Cloud Inventory Tools

- `rad_security_list_resources`: List cloud resources
  - **provider** (required): Cloud provider name
  - **filters** (optional): Filter string
  - **offset** (optional): Pagination offset
  - **limit** (optional): Maximum number of results to return
  - **q** (optional): Free text search query

- `rad_security_get_resource_details`: Get detailed information about a cloud resource
  - **provider** (required): Cloud provider name
  - **resource_type** (required): Type of the resource
  - **resource_id** (required): ID of the resource

- `rad_security_get_facets`: Get available facets for filtering cloud resources
  - **provider** (required): Cloud provider name

- `rad_security_get_facet_values`: Get possible values for a facet
  - **provider** (required): Cloud provider name
  - **facet_id** (required): ID of the facet to get values for

### Runtime Network Tools

- `rad_security_list_http_requests`: List HTTP requests observed in containers
  - **filters** (optional): Filter string
  - **offset** (optional): Pagination offset
  - **limit** (optional): Maximum number of results to return
  - **q** (optional): Free text search query

- `rad_security_list_network_connections`: List network connections from containers
  - **filters** (optional): Filter string
  - **offset** (optional): Pagination offset
  - **limit** (optional): Maximum number of results to return
  - **q** (optional): Free text search query

- `rad_security_list_network_connection_sources`: List network connection sources
  - **filters** (optional): Filter string
  - **offset** (optional): Pagination offset
  - **limit** (optional): Maximum number of results to return
  - **q** (optional): Free text search query

### Image Tools

- `rad_security_list_images`: List container images
  - **page** (optional): Page number
  - **page_size** (optional): Number of results per page
  - **sort** (optional): Sort order
  - **search** (optional): Search query

- `rad_security_list_image_vulnerabilities`: List vulnerabilities in a container image
  - **digest** (required): Image digest
  - **severities** (optional): Array of severity levels to filter by
  - **page** (optional): Page number
  - **page_size** (optional): Number of results per page

- `rad_security_get_top_vulnerable_images`: Get the most vulnerable images
  - No parameters required

## Prerequisites

- Node.js >= 16.0.0
- npm

## Installation

```bash
# Clone the repository
git clone https://github.com/rad-security/mcp-server.git
cd mcp-server

# Install dependencies
npm install
```

## Configuration

Set the following environment variables:

```bash
export RAD_SECURITY_ACCESS_KEY_ID="your_access_key_id"
export RAD_SECURITY_SECRET_KEY="your_secret_key"
export RAD_SECURITY_API_URL="https://api.rad.security"
export RAD_SECURITY_ACCOUNT_ID="your_account_id"
```

You can also create a `.env` file in the project root with these variables.

## Running the Server

### On macOS/Linux

```bash
# Option 2: Use npm
npm start
```

## Using with Claude Desktop

To enable the RAD Security MCP server in Claude Desktop:

1. Install the package globally:

   ```bash
   npm install -g @rad-security/mcp-server
   ```

2. Create or edit the Claude Desktop configuration file:
   - On macOS: `~/Library/Application Support/Claude Desktop/claude_desktop_config.json`
   - On Windows: `%APPDATA%\Claude Desktop\claude_desktop_config.json`
   - On Linux: `~/.config/Claude Desktop/claude_desktop_config.json`

3. Add the RAD Security MCP server configuration:

   ```json
   {
     "mcpServers": {
       "rad-security": {
         "command": "npx",
         "args": [
           "security-mcp"
         ],
         "env": {
           "RAD_SECURITY_API_URL": "https://api.rad.security",
           "RAD_SECURITY_ACCESS_KEY_ID": "<your-access-key-id>",
           "RAD_SECURITY_SECRET_KEY": "<your-secret-key>",
           "RAD_SECURITY_ACCOUNT_ID": "<your-account-id>"
         }
       }
     }
   }
   ```

4. Replace the placeholder values with your actual credentials.

5. Restart Claude Desktop to apply the changes.

6. In Claude Desktop, you can now use RAD Security tools by typing `/tool` and selecting the desired tool from the list.

## Development

```bash
# Watch for changes and rebuild automatically
npm run watch
```

## License

MIT
