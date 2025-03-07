#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequest,
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { RadSecurityAuth } from "./auth.js";
import {
  ContainersAPIClient,
  listContainersTool,
  getContainerDetailsTool,
  ListContainersArgs,
  GetContainerDetailsArgs
} from "./containers.js";
import {
  ClustersAPIClient,
  listClustersTool,
  getClusterDetailsTool,
  ListClustersArgs,
  GetClusterDetailsArgs
} from "./clusters.js";
import {
  MisconfigsAPIClient,
  getManifestMisconfigsTool,
  getMisconfigDetailsTool,
  GetManifestMisconfigsArgs,
  GetMisconfigDetailsArgs
} from "./misconfigs.js";
import {
  RuntimeAPIClient,
  getContainersProcessTreesTool,
  getContainersBaselinesTool,
  getContainerLLMAnalysisTool,
  getRuntimeFindingsTool,
  GetContainersProcessTreesArgs,
  GetContainersBaselinesArgs,
  GetContainerLLMAnalysisArgs,
  GetRuntimeFindingsArgs
} from "./runtime.js";
import {
  CloudInventoryAPIClient,
  listResourcesTool,
  getResourceDetailsTool,
  getFacetsTool,
  getFacetValuesTool,
  ListResourcesArgs,
  GetResourceDetailsArgs,
  GetFacetsArgs,
  GetFacetValuesArgs
} from "./cloud-inventory.js";
import {
  RuntimeNetworkAPIClient,
  listHttpRequestsTool,
  listNetworkConnectionsTool,
  listNetworkConnectionSourcesTool,
  ListHttpRequestsArgs,
  ListNetworkConnectionsArgs,
  ListNetworkConnectionSourcesArgs
} from "./runtime-network.js";
import {
  ImagesAPIClient,
  listImagesTool,
  listImageVulnerabilitiesTool,
  getTopVulnerableImagesTool,
  ListImagesArgs,
  ListImageVulnerabilitiesArgs,
  GetTopVulnerableImagesArgs
} from "./images.js";

async function main() {
  try {
    // Initialize authentication
    const auth = RadSecurityAuth.fromEnv();
    
    // Get account ID from environment
    const accountId = process.env.RAD_SECURITY_ACCOUNT_ID;
    if (!accountId) {
      throw new Error("RAD_SECURITY_ACCOUNT_ID must be set");
    }
    
    // Get base URL from environment
    const baseUrl = process.env.RAD_SECURITY_API_URL;
    if (!baseUrl) {
      throw new Error("RAD_SECURITY_API_URL must be set");
    }
    
    // Initialize API clients
    const containersClient = new ContainersAPIClient(accountId, baseUrl, auth);
    const clustersClient = new ClustersAPIClient(accountId, baseUrl, auth);
    const misconfigsClient = new MisconfigsAPIClient(accountId, baseUrl, auth);
    const runtimeClient = new RuntimeAPIClient(accountId, baseUrl, auth);
    const cloudInventoryClient = new CloudInventoryAPIClient(accountId, baseUrl, auth);
    const runtimeNetworkClient = new RuntimeNetworkAPIClient(accountId, baseUrl, auth);
    const imagesClient = new ImagesAPIClient(accountId, baseUrl, auth);

    // Initialize MCP server
    const server = new Server(
      {
        name: "RAD Security MCP Server",
        version: "1.0.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    // Set up request handlers
    server.setRequestHandler(
      ListToolsRequestSchema,
      async () => {
        return {
          tools: [
            listContainersTool, 
            getContainerDetailsTool,
            listClustersTool,
            getClusterDetailsTool,
            getManifestMisconfigsTool,
            getMisconfigDetailsTool,
            getContainersProcessTreesTool,
            getContainersBaselinesTool,
            getContainerLLMAnalysisTool,
            getRuntimeFindingsTool,
            listResourcesTool,
            getResourceDetailsTool,
            getFacetsTool,
            getFacetValuesTool,
            listHttpRequestsTool,
            listNetworkConnectionsTool,
            listNetworkConnectionSourcesTool,
            listImagesTool,
            listImageVulnerabilitiesTool,
            getTopVulnerableImagesTool
          ],
        };
      }
    );

    server.setRequestHandler(
      CallToolRequestSchema,
      async (request: CallToolRequest) => {
        try {
          const toolName = request.params.name;
          const toolArgs = request.params.arguments || {};

          switch (toolName) {
            case "rad_security_list_containers": {
              const args = toolArgs as unknown as ListContainersArgs;
              const result = await containersClient.listContainers(
                args.filters,
                args.offset,
                args.limit,
                args.q
              );
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            case "rad_security_get_container_details": {
              const args = toolArgs as unknown as GetContainerDetailsArgs;
              if (!args.container_id) {
                throw new Error("Missing required argument: container_id");
              }
              const result = await containersClient.getContainerDetails(args.container_id);
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            case "rad_security_list_clusters": {
              const args = toolArgs as unknown as ListClustersArgs;
              const result = await clustersClient.listClusters(
                args.page_size,
                args.page
              );
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            case "rad_security_get_cluster_details": {
              const args = toolArgs as unknown as GetClusterDetailsArgs;
              if (!args.cluster_id) {
                throw new Error("Missing required argument: cluster_id");
              }
              const result = await clustersClient.getClusterDetails(args.cluster_id);
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            case "rad_security_get_manifest_misconfigs": {
              const args = toolArgs as unknown as GetManifestMisconfigsArgs;
              if (!args.resource_uid) {
                throw new Error("Missing required argument: resource_uid");
              }
              const result = await misconfigsClient.getManifestMisconfigs(args.resource_uid);
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            case "rad_security_get_misconfig_details": {
              const args = toolArgs as unknown as GetMisconfigDetailsArgs;
              if (!args.misconfig_id) {
                throw new Error("Missing required argument: misconfig_id");
              }
              const result = await misconfigsClient.getMisconfigDetails(args.misconfig_id);
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            case "rad_security_get_containers_process_trees": {
              const args = toolArgs as unknown as GetContainersProcessTreesArgs;
              if (!args.container_ids || args.container_ids.length === 0) {
                throw new Error("Missing required argument: container_ids");
              }
              const result = await runtimeClient.getContainersProcessTrees(args.container_ids);
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            case "rad_security_get_containers_baselines": {
              const args = toolArgs as unknown as GetContainersBaselinesArgs;
              if (!args.container_ids || args.container_ids.length === 0) {
                throw new Error("Missing required argument: container_ids");
              }
              const result = await runtimeClient.getContainersBaselines(args.container_ids);
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            case "rad_security_get_container_llm_analysis": {
              const args = toolArgs as unknown as GetContainerLLMAnalysisArgs;
              if (!args.container_id) {
                throw new Error("Missing required argument: container_id");
              }
              const result = await runtimeClient.getContainerLLMAnalysis(args.container_id);
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            case "rad_security_get_runtime_findings": {
              const args = toolArgs as unknown as GetRuntimeFindingsArgs;
              if (!args.container_id) {
                throw new Error("Missing required argument: container_id");
              }
              const result = await runtimeClient.getRuntimeFindings(args.container_id);
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            case "rad_security_list_resources": {
              const args = toolArgs as unknown as ListResourcesArgs;
              if (!args.provider) {
                throw new Error("Missing required argument: provider");
              }
              const result = await cloudInventoryClient.listResources(
                args.provider,
                args.filters,
                args.offset,
                args.limit,
                args.q
              );
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            case "rad_security_get_resource_details": {
              const args = toolArgs as unknown as GetResourceDetailsArgs;
              if (!args.provider) {
                throw new Error("Missing required argument: provider");
              }
              if (!args.resource_type) {
                throw new Error("Missing required argument: resource_type");
              }
              if (!args.resource_id) {
                throw new Error("Missing required argument: resource_id");
              }
              const result = await cloudInventoryClient.getResourceDetails(
                args.provider,
                args.resource_type,
                args.resource_id
              );
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            case "rad_security_get_facets": {
              const args = toolArgs as unknown as GetFacetsArgs;
              if (!args.provider) {
                throw new Error("Missing required argument: provider");
              }
              const result = await cloudInventoryClient.getFacets(args.provider);
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            case "rad_security_get_facet_values": {
              const args = toolArgs as unknown as GetFacetValuesArgs;
              if (!args.provider) {
                throw new Error("Missing required argument: provider");
              }
              if (!args.facet_id) {
                throw new Error("Missing required argument: facet_id");
              }
              const result = await cloudInventoryClient.getFacetValues(
                args.provider,
                args.facet_id
              );
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            case "rad_security_list_http_requests": {
              const args = toolArgs as unknown as ListHttpRequestsArgs;
              const result = await runtimeNetworkClient.listHttpRequests(
                args.filters,
                args.offset,
                args.limit,
                args.q
              );
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            case "rad_security_list_network_connections": {
              const args = toolArgs as unknown as ListNetworkConnectionsArgs;
              const result = await runtimeNetworkClient.listNetworkConnections(
                args.filters,
                args.offset,
                args.limit,
                args.q
              );
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            case "rad_security_list_network_connection_sources": {
              const args = toolArgs as unknown as ListNetworkConnectionSourcesArgs;
              const result = await runtimeNetworkClient.listNetworkConnectionSources(
                args.filters,
                args.offset,
                args.limit,
                args.q
              );
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            case "rad_security_list_images": {
              const args = toolArgs as unknown as ListImagesArgs;
              const result = await imagesClient.listImages(
                args.page,
                args.page_size,
                args.sort,
                args.search
              );
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            case "rad_security_list_image_vulnerabilities": {
              const args = toolArgs as unknown as ListImageVulnerabilitiesArgs;
              if (!args.digest) {
                throw new Error("Missing required argument: digest");
              }
              const result = await imagesClient.listImageVulnerabilities(
                args.digest,
                args.severities,
                args.page,
                args.page_size
              );
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            case "rad_security_get_top_vulnerable_images": {
              const result = await imagesClient.getTopVulnerableImages();
              return {
                content: [{ type: "text", text: JSON.stringify(result) }],
              };
            }
            default:
              throw new Error(`Unknown tool: ${toolName}`);
          }
        } catch (error) {
          console.error("Error calling tool:", error);
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  error: error instanceof Error ? error.message : String(error),
                }),
              },
            ],
          };
        }
      }
    );

    // Start the server with stdio transport
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("RAD Security MCP server started with stdio transport");
  } catch (error) {
    console.error("Error starting server:", error);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Unhandled error:", error);
  process.exit(1);
});