import { z } from "zod";
import { RadSecurityClient } from "../client.js";

export const WhoShelledIntoPodSchema = z.object({
  name: z.string().optional().describe("Optional Pod name"),
  namespace: z.string().optional().describe("Optional Pod namespace"),
  cluster_id: z.string().optional().describe("Optional Cluster ID"),
  from_time: z.string().optional().describe("Start time of the time range to search for audit events. Example: 2024-01-01T00:00:00Z. Default: 7 days ago"),
  to_time: z.string().optional().describe("End time of the time range to search for audit events. Example: 2024-01-03T00:00:00Z"),
  limit: z.number().optional().default(20).describe("Maximum number of results to return"),
  page: z.number().optional().default(1).describe("Page number to return"),
});

/**
 * Get users who shelled into a pod with the given name and namespace around the given time.
 */
export async function whoShelledIntoPod(
  client: RadSecurityClient,
  name?: string,
  namespace?: string,
  cluster_id?: string,
  from_time: string = "now-7d",
  to_time: string = "",
  limit: number = 20,
  page: number = 1
): Promise<any> {
  const params: Record<string, any> = {
    types: "k8s_audit_logs_anomaly",
    rule_ids: "A001",
    from: from_time ,
    to: to_time,
    page: page,
    page_size: limit,
  };

  if (cluster_id) {
    params.cluster_ids = cluster_id;
  }

  const violations = await client.makeRequest(
    `/accounts/${client.getAccountId()}/findings`,
    params
  );

  const toReturn = [];
  for (const violation of violations.entries) {
    const auditLog = violation.source;
    if (!auditLog) {
      continue;
    }

    let match = true;
    if (name) {
      if (auditLog.objectRef && auditLog.objectRef.name !== name) {
        match = false;
      }
    }
    if (namespace) {
      if (auditLog.objectRef && auditLog.objectRef.namespace !== namespace) {
        match = false;
      }
    }
    if (match) {
      toReturn.push({
        who: auditLog.user,
        time: auditLog.stageTimestamp,
        where: auditLog.objectRef,
      });
    }
  }

  violations.entries = toReturn;
  return violations;
}
