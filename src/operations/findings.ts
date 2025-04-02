import { z } from "zod";
import { RadSecurityClient } from "../client.js";

// enum statuses
export const statuses = ["open", "closed", "ignored"] as const;
export const types = ["k8s_misconfiguration", "threat_vector", "runtime_alert", "k8s_audit_logs_anomaly"] as const;
export const source_types = ["kubeobject", "k8s_audit_log", "container"] as const;
export const severities = ["negligible", "low", "medium", "high", "critical"] as const;

// Input schemas
export const listFindingsSchema = z.object({
  limit: z.number().optional().default(20).describe("Number of findings to return"),
  types: z.array(z.enum(types)).optional().describe("List of finding types to filter by"),
  severities: z.array(z.enum(severities)).optional().describe("List of severity levels to filter by"),
  source_kinds: z.array(z.string()).optional().describe("List of source kinds to filter by. i.e. Deployment,Pod,Container,Node,etc."),
  source_types: z.array(z.enum(source_types)).optional().describe("List of source types to filter by"),
  source_names: z.array(z.string()).optional().describe("List of source names to filter by"),
  source_namespaces: z.array(z.string()).optional().describe("List of source namespaces to filter by"),
  status: z.enum(statuses).optional().default("open").describe("Status of the findings to filter by"),
  from_time: z.string().optional().default("now-7d").describe("From time in RFC3339 or relative format, i.e. now-7d"),
  to_time: z.string().optional().describe("To time in RFC3339 or relative format, i.e. now-7d"),
});

export const updateFindingStatusSchema = z.object({
  id: z.string().describe("Finding ID to update"),
  status: z.enum(statuses).describe("New status for the finding"),
});

// Helper function to create filter params from multiple arrays
function makeFilter(filterObj: Record<string, string | string[] | undefined>): string {
  const filters: string[] = [];

  for (const [key, value] of Object.entries(filterObj)) {
    if (!value) continue;

    if (Array.isArray(value)) {
      for (const item of value) {
        if (item) {
          filters.push(`${key}:${item}`);
        }
      }
    } else {
      filters.push(`${key}:${value}`);
    }
  }

  return filters.join(",");
}

// Main functions
export async function listFindings(
  client: RadSecurityClient,
  limit: number = 20,
  types?: string[],
  severities?: string[],
  source_types?: string[],
  source_kinds?: string[],
  source_names?: string[],
  source_namespaces?: string[],
  status: string = "open",
  from_time: string = "now-7d",
  to_time?: string
): Promise<any> {
  const filterParam = makeFilter({
    type: types,
    severity: severities,
    source_type: source_types,
    source_kind: source_kinds,
    source_name: source_names,
    source_namespace: source_namespaces,
    status: status,
  });

  const params: Record<string, any> = {
    limit,
    filters: filterParam,
    from: from_time,
  };

  if (to_time) {
    params.to = to_time;
  }

  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/unified_findings/groups`,
    params
  );

  return {
    size: response.length,
    entries: response,
    has_more: response.length === limit,
  };
}

export async function updateFindingGroupStatus(
  client: RadSecurityClient,
  id: string,
  status: string
): Promise<void> {
  const data = { status };
  await client.makeRequest(
    `/accounts/${client.getAccountId()}/unified_findings/groups/${id}/status`,
    {},
    {
      method: "PUT",
      body: data,
    }
  );
}
