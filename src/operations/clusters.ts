import { z } from "zod";
import { RadSecurityClient } from "../client.js";

export const ListClustersSchema = z.object({
  page_size: z.number().optional().default(50).describe("Number of clusters per page for list_clusters (default: 50)"),
  page: z.number().optional().default(1).describe("Page number to retrieve for list_clusters (default: 1)"),
});

export const GetClusterDetailsSchema = z.object({
  cluster_id: z.string().describe("ID of the cluster to get details for"),
});

export async function listClusters(
  client: RadSecurityClient,
  page_size: number = 50,
  page: number = 1,
): Promise<any> {
  const params: Record<string, any> = { page_size, page };
  return client.makeRequest(
    `/accounts/${client.getAccountId()}/clusters`,
    params
  );
}

export async function getClusterDetails(
  client: RadSecurityClient,
  clusterId: string
): Promise<any> {
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/clusters/${clusterId}`
  );

  if (!response) {
    throw new Error(`No cluster found with ID: ${clusterId}`);
  }

  return response;
}
