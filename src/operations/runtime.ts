import { z } from "zod";
import { RadSecurityClient } from "../client.js";

export const GetContainersProcessTreesSchema = z.object({
  container_ids: z.array(z.string()).describe("List of container IDs to get process trees for"),
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
  containerIds: string[]
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
    }
  }

  return containersProcessTrees;
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
