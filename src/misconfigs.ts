import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { RadSecurityAuth } from "./auth.js";

// Type definitions for tool arguments
export interface GetManifestMisconfigsArgs {
  resource_uid: string;
}

export interface GetMisconfigDetailsArgs {
  misconfig_id: string;
}

// Tool definitions
export const getManifestMisconfigsTool: Tool = {
  name: "rad_security_get_manifest_misconfigs",
  description: "Get manifest misconfigurations for a Kubernetes resource",
  inputSchema: {
    type: "object",
    properties: {
      resource_uid: {
        type: "string",
        description: "Kubernetes resource UID to get misconfigurations for",
      },
    },
    required: ["resource_uid"],
  },
};

export const getMisconfigDetailsTool: Tool = {
  name: "rad_security_get_misconfig_details",
  description: "Get detailed information about a specific misconfiguration",
  inputSchema: {
    type: "object",
    properties: {
      misconfig_id: {
        type: "string",
        description: "ID of the misconfiguration to get details for",
      },
    },
    required: ["misconfig_id"],
  },
};

export class MisconfigsAPIClient {
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

  async getManifestMisconfigs(resourceUid: string): Promise<any> {
    const params: Record<string, any> = {
      kubeobject_uids: resourceUid,
      page_size: 30,
    };

    const misconfigs = await this.makeRequest(
      "GET",
      `/accounts/${this.accountId}/misconfig`,
      params
    );

    // Deduplicate the list based on field "guard_policy.human_id"
    const seenIds = new Set<string>();
    const toReturn = [];

    for (const misconfig of misconfigs.entries) {
      const humanId = misconfig.guard_policy.human_id;
      if (!seenIds.has(humanId)) {
        seenIds.add(humanId);
        toReturn.push({
          id: misconfig.id,
          title: misconfig.guard_policy.title,
          human_id: misconfig.guard_policy.human_id,
        });
      }
    }

    misconfigs.entries = toReturn;
    return misconfigs;
  }

  async getMisconfigDetails(misconfigId: string): Promise<any> {
    const response = await this.makeRequest(
      "GET",
      `/accounts/${this.accountId}/misconfig/${misconfigId}`
    );

    if (!response) {
      throw new Error(`No misconfiguration found with ID: ${misconfigId}`);
    }

    return response;
  }
}
