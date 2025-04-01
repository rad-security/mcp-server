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

// Response types
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  offset: number;
  limit: number;
}

export interface HttpRequest {
  method: string;
  path: string;
  scheme: string;
  source_workload_name: string;
  source_workload_namespace: string;
  destination_workload_name: string;
  destination_workload_namespace: string;
  has_pii: boolean;
  // Add other fields as needed
}

export interface NetworkConnection {
  resource_type: string;
  aws_account: string;
  compliance: string;
  // Add other fields as needed
}

export interface NetworkConnectionSource {
  source_workload_name: string;
  source_workload_namespace: string;
  destination_workload_name: string;
  destination_workload_namespace: string;
  // Add other fields as needed
}

// Main functions
export async function listHttpRequests(
  client: RadSecurityClient,
  params: z.infer<typeof listHttpRequestsSchema>
): Promise<PaginatedResponse<HttpRequest>> {
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
): Promise<PaginatedResponse<NetworkConnection>> {
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
): Promise<PaginatedResponse<NetworkConnectionSource>> {
  const validatedParams = listNetworkConnectionSourcesSchema.parse(params);
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/container_runtime_insights/network_connection_sources`,
    validatedParams
  );
  return response;
}
