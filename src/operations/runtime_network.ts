import { z } from "zod";
import { RadSecurityClient } from "../client.js";

// Input schemas
export const listHttpRequestsSchema = z.object({
  filters: z.string().optional().describe("Filter string for filtering results. Filter options: method, path," +
    "scheme, source_workload_name, source_workload_namespace, destination_workload_name, destination_workload_namespace," +
    "has_pii. Example: 'method:GET,path:/api/v1/users,scheme:https,source_workload_name:my-workload,source_workload_namespace:my-namespace,destination_workload_name:my-workload,destination_workload_namespace:my-namespace,has_pii:true'"),
  offset: z.number().optional().describe("Offset to start the list from"),
  limit: z.number().optional().default(20).describe("Limit the number of items in the list"),
  q: z.string().optional().describe("Query to filter the list of HTTP requests"),
});

export const listNetworkConnectionsSchema = z.object({
  filters: z.string().optional().describe("Filter string for filtering results." +
        "Example: 'resource_type:EC2NetworkInterface,resource_type:SQSQueue,aws_account:123456789012,compliance:not_compliant'"),
  offset: z.number().optional().describe("Offset to start the list from"),
  limit: z.number().optional().default(20).describe("Limit the number of items in the list"),
  q: z.string().optional().describe("Query to filter the list of network connections"),
});

export const listNetworkConnectionSourcesSchema = z.object({
  filters: z.string().optional().describe("Filter string for filtering results." +
    "Filter options: source_workload_name, source_workload_namespace, destination_workload_name, destination_workload_namespace" +
    "Example: 'source_workload_name:my-workload,destination_workload_name:my-workload'"),
  offset: z.number().optional().describe("Offset to start the list from"),
  limit: z.number().optional().default(20).describe("Limit the number of items in the list"),
  q: z.string().optional().describe("Query to filter the list of network connection sources"),
});

export async function listHttpRequests(
  client: RadSecurityClient,
  params: z.infer<typeof listHttpRequestsSchema>
): Promise<any> {
  const validatedParams = listHttpRequestsSchema.parse(params);
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/container_runtime_insights/http_requests`,
    validatedParams
  );
  return response;
}

export async function listNetworkConnections(
  client: RadSecurityClient,
  params: z.infer<typeof listNetworkConnectionsSchema>
): Promise<any> {
  const validatedParams = listNetworkConnectionsSchema.parse(params);
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/container_runtime_insights/network_connections`,
    validatedParams
  );
  return response;
}

export async function listNetworkConnectionSources(
  client: RadSecurityClient,
  params: z.infer<typeof listNetworkConnectionSourcesSchema>
): Promise<any> {
  const validatedParams = listNetworkConnectionSourcesSchema.parse(params);
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/container_runtime_insights/network_connection_sources`,
    validatedParams
  );
  return response;
}
