import { z } from "zod";
import { RadSecurityClient } from "../client.js";

// Input schemas
export const listThreatVectorsSchema = z.object({
  clustersIds: z.array(z.string()).optional().describe("Cluster ids to check for threat vectors"),
  namespaces: z.array(z.string()).optional().describe("Namespaces to check for threat vectors"),
  resource_uid: z.string().optional().describe("Threat vector associated with this resource"),
  page: z.number().optional().default(1).describe("Page number to retrieve"),
  page_size: z.number().optional().default(20).describe("Number of items per page"),
});

// Main functions
export async function listThreatVectors(
  client: RadSecurityClient,
  clustersIds: string[] | undefined,
  namespaces: string[] | undefined,
  resourceUid: string | undefined,
  page: number = 1,
  pageSize: number = 20
): Promise<any> {
  const params = {
    associated_with_resource_uid: resourceUid,
    clusters: clustersIds,
    namespaces: namespaces,
    statuses: "Open",
    page_size: pageSize,
    page: page,
  };
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/threat_vector_instances/v2`,
    params
  );

  // Return the transformed response
  return response;
}
