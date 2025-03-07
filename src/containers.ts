import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { RadSecurityAuth } from "./auth.js";

// Type definitions for tool arguments
export interface ListContainersArgs {
  filters?: string;
  offset?: number;
  limit?: number;
  q?: string;
}

export interface GetContainerDetailsArgs {
  container_id: string;
}

// Tool definitions
export const listContainersTool: Tool = {
  name: "rad_security_list_containers",
  description: "List containers with optional filtering by image name, image digest, namespace, cluster_id, or free text search",
  inputSchema: {
    type: "object",
    properties: {
      filters: {
        type: "string",
        description: "Filter string (e.g., 'image_name:nginx' or 'image_digest:sha256:...' or 'owner_namespace:namespace' or 'cluster_id:cluster_id'). Multiple filters can be combined with commas.",
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

export const getContainerDetailsTool: Tool = {
  name: "rad_security_get_container_details",
  description: "Get detailed information about a container including metadata, image information, and runtime configuration",
  inputSchema: {
    type: "object",
    properties: {
      container_id: {
        type: "string",
        description: "ID of the container to get details for",
      },
    },
    required: ["container_id"],
  },
};

export class ContainersAPIClient {
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

  async getContainerDetails(containerId: string): Promise<any> {
    const response = await this.makeRequest(
      "GET",
      `/accounts/${this.accountId}/inventory_containers`,
      { filters: `container_id:${containerId}` }
    );

    if (!response || !response.entries || response.entries.length === 0) {
      throw new Error(`No container found with ID: ${containerId}`);
    }

    if (response.entries.length > 1) {
      throw new Error(
        `Found multiple containers with ID: ${containerId}. Please provide a more specific container ID.`
      );
    }

    // Remove "id" from the response to avoid confusion
    const result = response.entries[0];
    delete result.id;

    return result;
  }

  async listContainers(
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

    const response = await this.makeRequest(
      "GET",
      `/accounts/${this.accountId}/inventory_containers`,
      params
    );

    // Remove "id" from each container to avoid confusion
    response.entries.forEach((container: any) => {
      delete container.id;
    });

    return response;
  }
} 