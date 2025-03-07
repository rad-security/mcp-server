import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { RadSecurityAuth } from "./auth.js";

// Type definitions for tool arguments
export interface GetContainersProcessTreesArgs {
  container_ids: string[];
}

export interface GetContainersBaselinesArgs {
  container_ids: string[];
}

export interface GetContainerLLMAnalysisArgs {
  container_id: string;
}

export interface GetRuntimeFindingsArgs {
  container_id: string;
}

// Tool definitions
export const getContainersProcessTreesTool: Tool = {
  name: "rad_security_get_containers_process_trees",
  description: "Get process trees for multiple containers",
  inputSchema: {
    type: "object",
    properties: {
      container_ids: {
        type: "array",
        items: {
          type: "string"
        },
        description: "List of container IDs to get process trees for",
      },
    },
    required: ["container_ids"],
  },
};

export const getContainersBaselinesTool: Tool = {
  name: "rad_security_get_containers_baselines",
  description: "Get baselines for multiple containers",
  inputSchema: {
    type: "object",
    properties: {
      container_ids: {
        type: "array",
        items: {
          type: "string"
        },
        description: "List of container IDs to get baselines for",
      },
    },
    required: ["container_ids"],
  },
};

export const getContainerLLMAnalysisTool: Tool = {
  name: "rad_security_get_container_llm_analysis",
  description: "Get the last 3 LLM analyses for a container",
  inputSchema: {
    type: "object",
    properties: {
      container_id: {
        type: "string",
        description: "Container ID to get LLM analysis for",
      },
    },
    required: ["container_id"],
  },
};

export const getRuntimeFindingsTool: Tool = {
  name: "rad_security_get_runtime_findings",
  description: "Get runtime alerts and findings for a container",
  inputSchema: {
    type: "object",
    properties: {
      container_id: {
        type: "string",
        description: "Container ID to get runtime findings for",
      },
    },
    required: ["container_id"],
  },
};

export class RuntimeAPIClient {
  private findingsBaseUrl: string;
  private runtimeBaseUrl: string;
  private accountId: string;
  private auth: RadSecurityAuth;

  constructor(accountId: string, baseUrl: string, auth: RadSecurityAuth) {
    this.findingsBaseUrl = baseUrl;
    this.runtimeBaseUrl = baseUrl;
    this.accountId = accountId;
    this.auth = auth;
  }

  private async makeRequest(
    baseUrl: string,
    method: string,
    endpoint: string,
    params?: Record<string, any>
  ): Promise<any> {
    const url = new URL(`${baseUrl}${endpoint}`);
    
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          if (Array.isArray(value)) {
            url.searchParams.append(key, value.join(','));
          } else {
            url.searchParams.append(key, String(value));
          }
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

  async getContainersBaselines(containerIds: string[]): Promise<any> {
    // Convert array to comma-separated string for API request
    const containerIdsParam = containerIds.join(',');

    // Get container runtime insights for all containers
    const cris = await this.makeRequest(
      this.runtimeBaseUrl,
      "GET",
      `/accounts/${this.accountId}/container_runtime_insights`,
      { container_ids: containerIdsParam }
    );

    if (!cris.entries || cris.entries.length === 0) {
      throw new Error(`No process trees found for container_ids: ${containerIds}`);
    }

    // Map to store results
    const baselines: Record<string, any> = {};

    // Process each container runtime insight
    for (const entry of cris.entries) {
      const criId = entry.id;
      const containerMeta = entry.summary?.container_meta || {};
      const containerId = containerMeta.container_id;

      if (!containerId || !containerIds.includes(containerId)) {
        continue;
      }

      // Get detailed data for this container
      const data = await this.makeRequest(
        this.runtimeBaseUrl,
        "GET",
        `/accounts/${this.accountId}/container_runtime_insights/${criId}`
      );

      if (data.baseline) {
        baselines[containerId] = data.baseline;
      } else {
        console.warn(`No baseline found for container_id: ${containerId}`);
      }
    }

    if (Object.keys(baselines).length === 0) {
      throw new Error(`No baselines found for any of the container_ids: ${containerIds}`);
    }

    return baselines;
  }

  async getContainersProcessTrees(containerIds: string[]): Promise<any> {
    const cris = await this.makeRequest(
      this.runtimeBaseUrl,
      "GET",
      `/accounts/${this.accountId}/container_runtime_insights`,
      { container_ids: containerIds.join(',') }
    );

    const containersProcessTrees: Record<string, any> = {};
    
    for (const cri of cris.entries) {
      const criId = cri.id;
      const data = await this.makeRequest(
        this.runtimeBaseUrl,
        "GET",
        `/accounts/${this.accountId}/container_runtime_insights/${criId}`
      );

      if (!data.ongoing || !data.ongoing.containers || data.ongoing.containers.length === 0) {
        containersProcessTrees[criId] = {};
      } else {
        containersProcessTrees[criId] = data.ongoing.containers[0];
      }
    }

    return containersProcessTrees;
  }

  async getContainerLLMAnalysis(containerId: string): Promise<any> {
    const cris = await this.makeRequest(
      this.runtimeBaseUrl,
      "GET",
      `/accounts/${this.accountId}/container_runtime_insights`,
      { container_id: containerId }
    );

    if (!cris.entries || cris.entries.length === 0) {
      throw new Error(`No container runtime insights found for container_id: ${containerId}`);
    }

    return cris.entries[0].analysis;
  }

  async getRuntimeFindings(containerId: string): Promise<any> {
    const findings = await this.makeRequest(
      this.findingsBaseUrl,
      "GET",
      `/accounts/${this.accountId}/findings`,
      {
        types: "runtime_alert",
        source_ids: containerId,
        page_size: 10,
      }
    );

    // Use only second message from "messages" field
    const toReturn = [];
    for (const finding of findings.entries) {
      if (finding.messages && finding.messages.length > 1) {
        toReturn.push(finding.messages[1]);
      }
    }

    findings.entries = toReturn;
    return findings;
  }

  private extractProcesses(processList: any[]): any[] {
    const processes: any[] = [];

    for (const proc of processList) {
      // Extract programs from the current process
      for (const program of proc.programs || []) {
        processes.push({
          comm: program.comm || "",
          args: program.args || [],
          drift: program.drift || false,
        });
      }

      // Recursively process children
      if (proc.children) {
        processes.push(...this.extractProcesses(proc.children));
      }
    }

    return processes;
  }
} 