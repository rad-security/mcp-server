import { z } from "zod";
import { RadSecurityClient } from "../client.js";

// Schema for listing external integrations
export const ListExternalIntegrationsSchema = z.object({
  offset: z
    .number()
    .optional()
    .describe("Pagination offset for the results (default: 0)"),
  limit: z
    .number()
    .optional()
    .describe("Maximum number of integrations to return (default: 20)"),
});

/**
 * List external integrations configured for the tenant
 */
export async function listExternalIntegrations(
  client: RadSecurityClient,
  offset: number = 0,
  limit: number = 20
): Promise<any> {
  const tenantId = await client.getTenantId();
  const params: Record<string, any> = { offset, limit };

  const response = await client.makeRequest(
    `/tenants/${tenantId}/integrations/external`,
    params
  );

  return response;
}
