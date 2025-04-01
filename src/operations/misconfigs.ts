import { z } from "zod";
import { RadSecurityClient } from "../client.js";

export const ListKubernetesResourceMisconfigurationsSchema = z.object({
  resource_uid: z.string().describe("Kubernetes resource UID to get misconfigurations for"),
});

export const GetKubernetesResourceMisconfigurationDetailsSchema = z.object({
  cluster_id: z.string().describe("ID of the cluster to get misconfiguration for"),
  misconfig_id: z.string().describe("ID of the misconfiguration to get details for"),
});

export async function listKubernetesResourceMisconfigurations(
  client: RadSecurityClient,
  resourceUid: string
): Promise<any> {
  const misconfigs = await client.makeRequest(
    `/accounts/${client.getAccountId()}/misconfig`,
    { kubeobject_uids: resourceUid, page_size: 50 }
  );

  // deduplicate the list based on field "guard_policy.human_id"
  const seenIds = new Set<string>();
  const toReturn = [];

  for (const misconfig of misconfigs.entries) {
    const humanId = misconfig.guard_policy.human_id;
    if (!seenIds.has(humanId)) {
      seenIds.add(humanId);
      toReturn.push({
        id: misconfig.id,
        cluster_id: misconfig.cluster_id,
        title: misconfig.guard_policy.title,
        human_id: misconfig.guard_policy.human_id,
      });
    }
  }

  misconfigs.entries = toReturn;
  return misconfigs;
}

export async function getKubernetesResourceMisconfigurationDetails(
  client: RadSecurityClient,
  clusterId: string,
  misconfigId: string
): Promise<any> {
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/clusters/${clusterId}/misconfig/${misconfigId}`
  );

  if (!response) {
    throw new Error(`No misconfiguration found with ID: ${misconfigId}`);
  }

  return response;
}
