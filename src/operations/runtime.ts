import { z } from "zod";
import { RadSecurityClient } from "../client.js";

export const GetContainersProcessTreesSchema = z.object({
  container_ids: z.array(z.string()).describe("List of container IDs to get process trees for"),
  processes_limit: z.number().default(1000).describe("Limit the number of processes to get"),
});

export const GetContainersBaselinesSchema = z.object({
  container_ids: z.array(z.string()).describe("List of container IDs to get baselines for"),
});

export const GetContainerLLMAnalysisSchema = z.object({
  container_id: z.string().describe("Container ID to get LLM analysis for"),
});

export async function getContainersBaselines(
  client: RadSecurityClient,
  containerIds: string[]
): Promise<any> {
  if (containerIds.length === 0) {
    throw new Error("No container IDs provided");
  }

  // Convert list to comma-separated string for API request
  const containerIdsParam = containerIds.join(',');

  // Get container runtime insights for all containers
  const cris = await client.makeRequest(
    `/accounts/${client.getAccountId()}/container_runtime_insights`,
    { container_ids: containerIdsParam }
  );

  if (!cris.entries) {
    throw new Error(`No process trees found for container_ids: ${containerIds}`);
  }

  // Map to store results
  const baselines: Record<string, any> = {};

  // Process each container runtime insight
  for (const entry of cris.entries) {
    const criId = entry.id;
    const containerId = entry.summary?.container_meta?.container_id;

    if (!containerId || !containerIds.includes(containerId)) {
      continue;
    }

    // Get detailed data for this container
    const data = await client.makeRequest(
      `/accounts/${client.getAccountId()}/container_runtime_insights/${criId}`
    );

    if (data.baseline) {
      baselines[containerId] = data.baseline;
    } else {
      // Just log a warning instead of raising an error to allow partial results
      console.warn(`No baseline found for container_id: ${containerId}`);
    }
  }

  if (Object.keys(baselines).length === 0) {
    throw new Error(`No baselines found for any of the container_ids: ${containerIds}`);
  }

  return baselines;
}

export async function getContainersProcessTrees(
  client: RadSecurityClient,
  containerIds: string[],
  processesLimit: number = 1000
): Promise<any> {
  if (containerIds.length === 0) {
    throw new Error("No container IDs provided");
  }

  const cris = await client.makeRequest(
    `/accounts/${client.getAccountId()}/container_runtime_insights`,
    { container_ids: containerIds.join(',') }
  );

  const containersProcessTrees: Record<string, any> = {};
  for (const cri of cris.entries) {
    const criId = cri.id;
    const data = await client.makeRequest(
      `/accounts/${client.getAccountId()}/container_runtime_insights/${criId}`
    );

    if (!data.ongoing || !data.ongoing.containers || data.ongoing.containers.length === 0) {
      containersProcessTrees[criId] = {};
    } else {
      containersProcessTrees[criId] = data.ongoing.containers[0];
      containersProcessTrees[criId].processes = reduceProcesses(data.ongoing.containers[0].processes, processesLimit);
    }
  }

  return containersProcessTrees;
}

function reduceProcesses(processes: any[], limit: number): any[] {
  if (processes.length === 0 || limit <= 0) {
    return [];
  }

  const countProcesses = (procs: any[]): number => {
    let total = 0;
    for (const proc of procs) {
      total += 1;
      if (proc.children) {
        total += countProcesses(proc.children);
      }
    }
    return total;
  };

  const extractProcessTree = (procs: any[], indent: string = "", remainingLimit: number): string[] => {
    const result: string[] = [];

    for (const process of procs) {
      if (result.length >= remainingLimit) {
        break;
      }

      const timestamp = process.timestamp || "";

      // Print process info
      if (process.programs) {
        for (const program of process.programs) {
          const comm = program.comm || "unknown";
          const args = (program.args || []).join(" ");
          result.push(`${indent}├─ [${timestamp}] ${comm}: ${args}`);
        }
      }

      // Print connections if any
      if (process.connections) {
        for (const conn of process.connections) {
          const addr = conn.hostname || conn.address || "unknown";
          const port = conn.port || "unknown";
          const connTime = conn.timestamp || "";
          result.push(`${indent}│  └─ Connection to ${addr}:${port} at ${connTime}`);
        }
      }

      // Recursively print children with increased indentation
      if (process.children) {
        result.push(...extractProcessTree(process.children, indent + "│  ", remainingLimit - result.length));
      }
    }

    return result;
  };

  // Extract the process tree
  const tree = extractProcessTree(processes, "", limit);

  // Add a note if we hit the limit
  if (tree.length >= limit) {
    const totalCount = countProcesses(processes);
    tree.push(`Processes limit(${limit}) reached. Some processes were not included in the output. Total processes: ${totalCount}`);
  }

  return tree;
}

export async function getContainerLLMAnalysis(
  client: RadSecurityClient,
  containerId: string
): Promise<any> {
  const cris = await client.makeRequest(
    `/accounts/${client.getAccountId()}/container_runtime_insights`,
    { container_id: containerId }
  );

  return cris.entries[0].analysis;
}
