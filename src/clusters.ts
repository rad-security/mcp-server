import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { RadSecurityAuth } from "./auth.js";

// Type definitions for tool arguments
export interface ListClustersArgs {
  page_size?: number;
  page?: number;
}

export interface GetClusterDetailsArgs {
  cluster_id: string;
}

// Tool definitions
export const listClustersTool: Tool = {
  name: "rad_security_list_clusters",
  description: "List Kubernetes clusters with optional pagination",
  inputSchema: {
    type: "object",
    properties: {
      page_size: {
        type: "number",
        description: "Number of clusters per page (default: 50)",
        default: 50,
      },
      page: {
        type: "number",
        description: "Page number to retrieve (default: 1)",
        default: 1,
      },
    },
  },
};

export const getClusterDetailsTool: Tool = {
  name: "rad_security_get_cluster_details",
  description: "Get detailed information about a specific Kubernetes cluster",
  inputSchema: {
    type: "object",
    properties: {
      cluster_id: {
        type: "string",
        description: "ID of the cluster to get details for",
      },
    },
    required: ["cluster_id"],
  },
};

export class ClustersAPIClient {
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
      if (response.status === 401) {
        throw new Error("Authentication failed. Please check your credentials.");
      }
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return response.json();
  }

  async listClusters(pageSize: number = 50, page: number = 1): Promise<any> {
    const params: Record<string, any> = {
      page_size: pageSize,
      page: page,
    };

    return this.makeRequest(
      "GET",
      `/accounts/${this.accountId}/clusters`,
      params
    );
  }

  async getClusterDetails(clusterId: string): Promise<any> {
    const response = await this.makeRequest(
      "GET",
      `/accounts/${this.accountId}/clusters/${clusterId}`
    );

    if (!response) {
      throw new Error(`No cluster found with ID: ${clusterId}`);
    }

    return response;
  }
} 