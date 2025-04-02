import { z } from "zod";
import { RadSecurityClient } from "../client.js";

const IdentityTypeEnum = z.enum(["k8s_service_account", "k8s_user", "k8s_group"]);
type IdentityType = z.infer<typeof IdentityTypeEnum>;

export const ListIdentitiesSchema = z.object({
  identity_types: z.array(IdentityTypeEnum).optional().describe("Identity types to get"),
  cluster_ids: z.array(z.string()).optional().describe("Cluster IDs to get identities for"),
  page: z.number().optional().describe("Page number to get. Default: 1"),
  page_size: z.number().optional().describe("Page size to get. Default: 10"),
  q: z.string().optional().describe("Query to filter identities"),
});

export const GetIdentityDetailsSchema = z.object({
  identity_id: z.string().describe("Identity ID to get details for"),
});

export async function listIdentities(
  client: RadSecurityClient,
  identityTypes: IdentityType[] = [],
  clusterIds: string[] = [],
  page: number = 1,
  page_size: number = 10,
  q: string = "",
): Promise<any> {
  const identities = await client.makeRequest(
    `/accounts/${client.getAccountId()}/identities`,
    {
      identity_types: identityTypes.join(","),
      identity_sources: clusterIds.join(","),
      page,
      page_size,
      q,
    }
  );

  return identities;
}

export async function getIdentityDetails(
    client: RadSecurityClient,
    identityId: string
  ): Promise<any> {
    const identity = await client.makeRequest(
      `/accounts/${client.getAccountId()}/identities/${identityId}`
    );

    if (!identity) {
      throw new Error(`No identity found with ID: ${identityId}`);
    }

    return identity;
  }
