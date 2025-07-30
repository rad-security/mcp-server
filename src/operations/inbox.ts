import { z } from "zod";
import { RadSecurityClient } from "../client.js";

export const MarkInboxItemAsFalsePositiveSchema = z.object({
  inbox_item_id: z.string().describe("ID of the inbox item to mark as false positive"),
  value: z.boolean().default(true).describe("Whether to mark the item as false positive (true) or not (false)"),
  reason: z.string().describe("Reason for marking the item as false positive"),
});

export const ListInboxItemsSchema = z.object({
  limit: z.number().optional().default(10).describe("Number of inbox items per page (default: 10)"),
  offset: z.number().optional().default(0).describe("Offset to retrieve (default: 0)"),
  filters_query: z.string().optional().describe("Filter query string (e.g. full text search: 'search:<query>', severity: 'severity:low', type 'type:workflow_output' any other field). Multiple filters can be combined eg. 'search:cve-2024-12345 and severity:high'"),
});

export const GetInboxItemDetailsSchema = z.object({
  inbox_item_id: z.string().describe("ID of the inbox item to get details for"),
});

export async function markInboxItemAsFalsePositive(
  client: RadSecurityClient,
  inboxItemId: string,
  value: boolean = true,
  reason: string
): Promise<any> {
  const payload: Record<string, any> = { value, reason };

  return client.makeRequest(
    `/accounts/${client.getAccountId()}/inbox_items/${inboxItemId}/mark_false_positive`,
    {},
    { method: "PUT", body: payload }
  );
}

export async function listInboxItems(
  client: RadSecurityClient,
  limit: number = 10,
  offset: number = 0,
  filters_query?: string,
): Promise<any> {
  const params: Record<string, any> = { limit, offset };

  if (filters_query) {
    // encode the filters_query to avoid URL encoding issues
    filters_query = encodeURIComponent(filters_query);
    params.filters_query = filters_query;
  }

  return client.makeRequest(
    `/accounts/${client.getAccountId()}/data/inbox_items`,
    params
  );
}

export async function getInboxItemDetails(
  client: RadSecurityClient,
  inboxItemId: string
): Promise<any> {
  return client.makeRequest(
    `/accounts/${client.getAccountId()}/data/inbox_items/${inboxItemId}`
  );
}
