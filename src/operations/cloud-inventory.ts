import { z } from "zod";
import { RadSecurityClient } from "../client.js";

// Define provider type using Zod enum
const ProviderTypeEnum = z.enum(["aws", "gcp", "azure"]);
type ProviderType = z.infer<typeof ProviderTypeEnum>;

// Schema for list_cloud_resources
export const ListCloudResourcesSchema = z.object({
  provider: ProviderTypeEnum.describe("Cloud provider (aws, gcp, azure)"),
  filters: z.string().optional().describe("Filter string (e.g., 'resource_type:EC2NetworkInterface,resource_type:SQSQueue,aws_account:123456789012,compliance:not_compliant')"),
  offset: z.number().optional().describe("Pagination offset. Default: 0"),
  limit: z.number().optional().default(20).describe("Maximum number of results to return"),
  q: z.string().optional().describe("Free text search query"),
});

// Schema for get_resource_details
export const GetCloudResourceDetailsSchema = z.object({
  provider: ProviderTypeEnum.describe("Cloud provider (aws, gcp, azure)"),
  resource_type: z.string().describe("Type of cloud resource (to be fetched from get_cloud_resource_facet_values or from list_cloud_resources)"),
  resource_id: z.string().describe("ID of the cloud resource"),
});

// Schema for get_facets
export const GetCloudResourceFacetsSchema = z.object({
  provider: ProviderTypeEnum.describe("Cloud provider (aws, gcp, azure)"),
});

// Schema for get_cloud_resource_facet_values
export const GetCloudResourceFacetValuesSchema = z.object({
  provider: ProviderTypeEnum.describe("Cloud provider (aws, gcp, azure)"),
  facet_id: z.string().describe("ID of the facet"),
});

/**
 * List cloud resources for a specific provider.
 */
export async function listCloudResources(
  client: RadSecurityClient,
  provider: ProviderType,
  filters?: string,
  offset?: number,
  limit: number = 20,
  q?: string
): Promise<any> {
  const params: Record<string, any> = { limit };

  if (filters) {
    params.filter = filters;
  }
  if (offset !== undefined) {
    params.offset = offset;
  }
  if (q) {
    params.q = q;
  }

  return client.makeRequest(
    `/accounts/${client.getAccountId()}/cloud-inventory/v1/${provider}`,
    params
  );
}

/**
 * Get details for a specific cloud resource.
 */
export async function getCloudResourceDetails(
  client: RadSecurityClient,
  provider: ProviderType,
  resource_type: string,
  resource_id: string
): Promise<any> {
  return client.makeRequest(
    `/accounts/${client.getAccountId()}/cloud-inventory/v1/${provider}/${resource_type}/${resource_id}`
  );
}

/**
 * Get available facets for a provider.
 */
export async function getCloudResourceFacets(
  client: RadSecurityClient,
  provider: ProviderType
): Promise<any> {
  return client.makeRequest(
    `/accounts/${client.getAccountId()}/cloud-inventory/v1/${provider}/facets`
  );
}

/**
 * Get values for a specific facet.
 */
export async function getCloudResourceFacetValues(
  client: RadSecurityClient,
  provider: ProviderType,
  facet_id: string
): Promise<any> {
  return client.makeRequest(
    `/accounts/${client.getAccountId()}/cloud-inventory/v1/${provider}/facets/${facet_id}`
  );
}
