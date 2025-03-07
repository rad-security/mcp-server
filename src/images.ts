import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { RadSecurityAuth } from "./auth.js";

// Type definitions for tool arguments
export interface ListImagesArgs {
  page?: number;
  page_size?: number;
  sort?: string;
  search?: string;
}

export interface ListImageVulnerabilitiesArgs {
  digest: string;
  severities?: string[];
  page?: number;
  page_size?: number;
}

export interface GetTopVulnerableImagesArgs {
  // No additional arguments needed
}

// Tool definitions
export const listImagesTool: Tool = {
  name: "rad_security_list_images",
  description: "List images with optional filtering and pagination",
  inputSchema: {
    type: "object",
    properties: {
      page: {
        type: "number",
        description: "Page number for pagination",
        default: 1,
      },
      page_size: {
        type: "number",
        description: "Number of items per page",
        default: 100,
      },
      sort: {
        type: "string",
        description: "Sort order (e.g., 'name:asc')",
        default: "name:asc",
      },
      search: {
        type: "string",
        description: "Search query",
      },
    },
  },
};

export const listImageVulnerabilitiesTool: Tool = {
  name: "rad_security_list_image_vulnerabilities",
  description: "List vulnerabilities for a specific image",
  inputSchema: {
    type: "object",
    properties: {
      digest: {
        type: "string",
        description: "Image digest",
      },
      severities: {
        type: "array",
        items: {
          type: "string",
        },
        description: "List of severity levels to filter",
      },
      page: {
        type: "number",
        description: "Page number for pagination",
        default: 1,
      },
      page_size: {
        type: "number",
        description: "Number of items per page",
        default: 1000,
      },
    },
    required: ["digest"],
  },
};

export const getTopVulnerableImagesTool: Tool = {
  name: "rad_security_get_top_vulnerable_images",
  description: "Get list of most vulnerable images",
  inputSchema: {
    type: "object",
    properties: {},
  },
};

export class ImagesAPIClient {
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

  async listImages(
    page: number = 1,
    pageSize: number = 100,
    sort: string = "name:asc",
    search?: string
  ): Promise<any> {
    const params: Record<string, any> = {
      page,
      page_size: pageSize,
      sort
    };

    if (search) {
      params.q = search;
    }

    return this.makeRequest(
      "GET",
      `/accounts/${this.accountId}/images`,
      params
    );
  }

  async listImageScans(
    digest: string,
    page: number = 1,
    pageSize: number = 3
  ): Promise<any> {
    const params: Record<string, any> = {
      page,
      page_size: pageSize
    };

    return this.makeRequest(
      "GET",
      `/accounts/${this.accountId}/images/${digest}/scans`,
      params
    );
  }

  async listImageVulnerabilities(
    digest: string,
    severities?: string[],
    page: number = 1,
    pageSize: number = 1000
  ): Promise<any> {
    const params: Record<string, any> = {
      page,
      page_size: pageSize,
      sort: "severity:desc"
    };

    if (severities && severities.length > 0) {
      params.severities = severities.join(",");
    }

    // Get the latest scan first
    const scans = await this.listImageScans(digest);

    if (!scans || !scans.entries || scans.entries.length === 0) {
      throw new Error(`Image with digest: ${digest} hasn't been scanned yet`);
    }

    // Get the latest scan
    const scanId = scans.entries[0].id;

    const vulns = await this.makeRequest(
      "GET",
      `/accounts/${this.accountId}/images/${digest}/scans/${scanId}/vulnerabilities`,
      params
    );

    // Remove CPEs to reduce context window size
    if (vulns.entries) {
      vulns.entries.forEach((vuln: any) => {
        if (vuln.cpes) {
          delete vuln.cpes;
        }
      });
    }

    return vulns;
  }

  async getTopVulnerableImages(): Promise<any> {
    return this.makeRequest(
      "GET",
      `/accounts/${this.accountId}/reports/top_vulnerable_images`
    );
  }
} 