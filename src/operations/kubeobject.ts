import { z } from "zod";
import { RadSecurityClient } from "../client.js";

export const GetKubernetesResourceDetailsSchema = z.object({
  cluster_id: z.string().describe("ID of the Kubernetes cluster"),
  resource_uid: z.string().describe("Resource UID to get the details for"),
});

export const ListKubernetesResourcesSchema = z.object({
  namespace: z.string().optional().describe("Namespace to filter resources"),
  kinds: z.array(z.string()).optional().describe("List of kinds to filter. Example: ['Deployment', 'ServiceAccount', 'Pod']"),
  cluster_id: z.string().optional().describe("Cluster ID to filter resources"),
  page: z.number().optional().default(1).describe("Page number for pagination"),
  page_size: z.number().optional().default(20).describe("Number of items per page"),
});

export async function getKubernetesResourceDetails(
  client: RadSecurityClient,
  clusterId: string,
  resourceUid: string
): Promise<any> {
  const details = await client.makeRequest(
    `/clusters/${clusterId}/resources/${resourceUid}/latest`
  );

  if (!details) {
    throw new Error(`No details found for resource_uid: ${resourceUid} in cluster: ${clusterId}`);
  }

  // Decode the base64 raw manifest
  if (details.raw) {
    details.raw = Buffer.from(details.raw, 'base64').toString('utf-8');
  }

  return details;
}

export async function listKubernetesResources(
  client: RadSecurityClient,
  kinds: string[] | undefined,
  namespace?: string,
  clusterId?: string,
  page: number = 1,
  pageSize: number = 20
): Promise<any> {
  const params: Record<string, any> = {
    page,
    page_size: pageSize,
    resource_types: kinds?.join(',')
  };

  if (namespace) {
    params.namespace = namespace;
  }

  if (clusterId) {
    params.cluster_id = clusterId;
  }

  return client.makeRequest(
    `/accounts/${client.getAccountId()}/resources`,
    params
  );
}
