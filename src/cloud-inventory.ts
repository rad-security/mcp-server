import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { RadSecurityAuth } from "./auth.js";

// Type definitions
export type ProviderType = "aws" | "gcp" | "azure";

// Type definitions for tool arguments
export interface ListResourcesArgs {
  provider: ProviderType;
  filters?: string;
  offset?: number;
  limit?: number;
  q?: string;
}

export interface GetResourceDetailsArgs {
  provider: ProviderType;
  resource_type: string;
  resource_id: string;
}

export interface GetFacetsArgs {
  provider: ProviderType;
}

export interface GetFacetValuesArgs {
  provider: ProviderType;
  facet_id: string;
}

// Tool definitions
export const listResourcesTool: Tool = {
  name: "rad_security_list_resources",
  description: "List cloud resources for a specific provider with optional filtering",
  inputSchema: {
    type: "object",
    properties: {
      provider: {
        type: "string",
        enum: ["aws", "gcp", "azure"],
        description: "Cloud provider (aws, gcp, azure)",
      },
      filters: {
        type: "string",
        description: "Filter string (e.g., 'resource_type:EC2NetworkInterface,aws_account:123456789012')",
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
    required: ["provider"],
  },
};

export const getResourceDetailsTool: Tool = {
  name: "rad_security_get_resource_details",
  description: "Get detailed information about a specific cloud resource",
  inputSchema: {
    type: "object",
    properties: {
      provider: {
        type: "string",
        enum: ["aws", "gcp", "azure"],
        description: "Cloud provider (aws, gcp, azure)",
      },
      resource_type: {
        type: "string",
        description: "Type of resource (to be fetched from get_facet_values or from list_resources)",
      },
      resource_id: {
        type: "string",
        description: "ID of the resource",
      },
    },
    required: ["provider", "resource_type", "resource_id"],
  },
};

export const getFacetsTool: Tool = {
  name: "rad_security_get_facets",
  description: "Get available facets for filtering cloud resources",
  inputSchema: {
    type: "object",
    properties: {
      provider: {
        type: "string",
        enum: ["aws", "gcp", "azure"],
        description: "Cloud provider (aws, gcp, azure)",
      },
    },
    required: ["provider"],
  },
};

export const getFacetValuesTool: Tool = {
  name: "rad_security_get_facet_values",
  description: "Get values for a specific facet",
  inputSchema: {
    type: "object",
    properties: {
      provider: {
        type: "string",
        enum: ["aws", "gcp", "azure"],
        description: "Cloud provider (aws, gcp, azure)",
      },
      facet_id: {
        type: "string",
        description: "ID of the facet",
      },
    },
    required: ["provider", "facet_id"],
  },
};

export class CloudInventoryAPIClient {
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

  async listResources(
    provider: ProviderType,
    filters?: string,
    offset?: number,
    limit: number = 20,
    q?: string
  ): Promise<any> {
    const params: Record<string, any> = { limit };

    if (filters) {
      params.filter = filters;
    }
    if (offset !== undefined) {
      params.offset = offset;
    }
    if (q) {
      params.q = q;
    }

    return this.makeRequest(
      "GET",
      `/accounts/${this.accountId}/cloud-inventory/v1/${provider}`,
      params
    );
  }

  async getResourceDetails(
    provider: ProviderType,
    resourceType: string,
    resourceId: string
  ): Promise<any> {
    return this.makeRequest(
      "GET",
      `/accounts/${this.accountId}/cloud-inventory/v1/${provider}/${resourceType}/${resourceId}`
    );
  }

  async getFacets(provider: ProviderType): Promise<any> {
    return this.makeRequest(
      "GET",
      `/accounts/${this.accountId}/cloud-inventory/v1/${provider}/facets`
    );
  }

  async getFacetValues(provider: ProviderType, facetId: string): Promise<any> {
    return this.makeRequest(
      "GET",
      `/accounts/${this.accountId}/cloud-inventory/v1/${provider}/facets/${facetId}`
    );
  }
}
