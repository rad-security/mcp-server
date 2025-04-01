import { z } from "zod";
import { RadSecurityClient } from "../client.js";

export const ListContainersSchema = z.object({
  filters: z.string().optional().describe("Filter string (e.g., 'image_name:nginx' or 'image_digest:sha256:...' or 'owner_namespace:namespace' or 'cluster_id:cluster_id'). Multiple filters can be combined with commas."),
  offset: z.number().optional().describe("Pagination offset. Default: 0"),
  limit: z.number().optional().describe("Maximum number of results to return. Default: 20"),
  q: z.string().optional().describe("Free text search query"),
});

export const GetContainerDetailsSchema = z.object({
  container_id: z.string().describe("ID of the container to get details for"),
});

export async function listContainers(
  client: RadSecurityClient,
  offset: number = 0,
  limit: number = 20,
  filters?: string,
  q?: string
): Promise<any> {
  const params: Record<string, any> = { limit, offset, filters, q };
  const response = await client.makeRequest(`/accounts/${client.getAccountId()}/inventory_containers`, params);

  // Remove "id" from each container to avoid confusion
  response.entries.forEach((container: any) => {
    delete container.id;
  });

  return response;
}

export async function getContainerDetails(
  client: RadSecurityClient,
  containerId: string
): Promise<any> {
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/inventory_containers`,
  { filters: `container_id:${containerId}` },
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
