import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { RadSecurityAuth } from "./auth.js";

// Type definitions for tool arguments
export interface ListHttpRequestsArgs {
  filters?: string;
  offset?: number;
  limit?: number;
  q?: string;
}

export interface ListNetworkConnectionsArgs {
  filters?: string;
  offset?: number;
  limit?: number;
  q?: string;
}

export interface ListNetworkConnectionSourcesArgs {
  filters?: string;
  offset?: number;
  limit?: number;
  q?: string;
}

// Tool definitions
export const listHttpRequestsTool: Tool = {
  name: "rad_security_list_http_requests",
  description: "List HTTP requests insights with optional filtering",
  inputSchema: {
    type: "object",
    properties: {
      filters: {
        type: "string",
        description: `Filter string for filtering results.
        Filter options: method, path, scheme, source_workload_name, source_workload_namespace, destination_workload_name, destination_workload_namespace, has_pii
        Example: "method:GET,path:/api/v1/users,scheme:https,source_workload_name:my-workload"`,
      },
      offset: {
        type: "number",
        description: "Pagination offset",
      },
      limit: {
        type: "number",
        description: "Maximum number of results to return (default: 20)",
        default: 20,
      },
      q: {
        type: "string",
        description: "Free text search query",
      },
    },
  },
};

export const listNetworkConnectionsTool: Tool = {
  name: "rad_security_list_network_connections",
  description: "List network connections with optional filtering",
  inputSchema: {
    type: "object",
    properties: {
      filters: {
        type: "string",
        description: "Filter string for filtering network connections",
      },
      offset: {
        type: "number",
        description: "Pagination offset",
      },
      limit: {
        type: "number",
        description: "Maximum number of results to return (default: 20)",
        default: 20,
      },
      q: {
        type: "string",
        description: "Free text search query",
      },
    },
  },
};

export const listNetworkConnectionSourcesTool: Tool = {
  name: "rad_security_list_network_connection_sources",
  description: "List network connection sources with optional filtering",
  inputSchema: {
    type: "object",
    properties: {
      filters: {
        type: "string",
        description: `Filter string for filtering results.
        Filter options: source_workload_name, source_workload_namespace, destination_workload_name, destination_workload_namespace
        Example: "source_workload_name:my-workload,destination_workload_name:my-workload"`,
      },
      offset: {
        type: "number",
        description: "Pagination offset",
      },
      limit: {
        type: "number",
        description: "Maximum number of results to return (default: 20)",
        default: 20,
      },
      q: {
        type: "string",
        description: "Free text search query",
      },
    },
  },
};

export class RuntimeNetworkAPIClient {
  private baseUrl: string;
  private accountId: string;
  private auth: RadSecurityAuth;

  constructor(accountId: string, baseUrl: string, auth: RadSecurityAuth) {
    this.baseUrl = baseUrl;
    this.accountId = accountId;
    this.auth = auth;
  }

  private async makeRequest(
    method: string,
    endpoint: string,
    params?: Record<string, any>
  ): Promise<any> {
    const url = new URL(`${this.baseUrl}${endpoint}`);
    
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          url.searchParams.append(key, String(value));
        }
      });
    }

    const token = await this.auth.getToken();
    
    const response = await fetch(url.toString(), {
      method,
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return response.json();
  }

  async listHttpRequests(
    filters?: string,
    offset?: number,
    limit: number = 20,
    q?: string
  ): Promise<any> {
    const params: Record<string, any> = { limit };

    if (filters) {
      params.filters = filters;
    }
    if (offset !== undefined) {
      params.offset = offset;
    }
    if (q) {
      params.q = q;
    }

    return this.makeRequest(
      "GET",
      `/accounts/${this.accountId}/container_runtime_insights/http_requests`,
      params
    );
  }

  async listNetworkConnections(
    filters?: string,
    offset?: number,
    limit: number = 20,
    q?: string
  ): Promise<any> {
    const params: Record<string, any> = { limit };

    if (filters) {
      params.filters = filters;
    }
    if (offset !== undefined) {
      params.offset = offset;
    }
    if (q) {
      params.q = q;
    }

    return this.makeRequest(
      "GET",
      `/accounts/${this.accountId}/container_runtime_insights/network_connections`,
      params
    );
  }

  async listNetworkConnectionSources(
    filters?: string,
    offset?: number,
    limit: number = 20,
    q?: string
  ): Promise<any> {
    const params: Record<string, any> = { limit };

    if (filters) {
      params.filters = filters;
    }
    if (offset !== undefined) {
      params.offset = offset;
    }
    if (q) {
      params.q = q;
    }

    return this.makeRequest(
      "GET",
      `/accounts/${this.accountId}/container_runtime_insights/network_connection_sources`,
      params
    );
  }
} 