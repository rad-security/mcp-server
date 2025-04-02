#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import cors from 'cors';
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { zodToJsonSchema } from 'zod-to-json-schema';
import { z } from "zod";
import {
  CallToolRequest,
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import express from "express";

import { RadSecurityClient } from "./client.js";
import * as containers from "./operations/containers.js";
import * as audit from "./operations/audit.js";
import * as cloudInventory from "./operations/cloud-inventory.js";
import * as clusters from "./operations/clusters.js";
import * as identities from "./operations/identities.js";
import * as images from "./operations/images.js";
import * as kubeobject from "./operations/kubeobject.js";
import * as misconfigs from "./operations/misconfigs.js";
import * as runtime from "./operations/runtime.js";
import * as runtimeNetwork from "./operations/runtime_network.js";
import * as threats from "./operations/threats.js";
import * as findings from "./operations/findings.js";
import { VERSION } from "./version.js";

async function newServer(): Promise<Server> {
  // Initialize authentication
  const client = RadSecurityClient.fromEnv();

  // Initialize MCP server
  const server = new Server(
    {
      name: "RAD Security MCP Server",
      version: VERSION,
    },
    {
      capabilities: {
        prompts: {},
        resources: {},
        tools: {},
        logging: {},
      },
    }
  );

  server.setRequestHandler(
    ListToolsRequestSchema,
    async () => {
      return {
        tools: [
          // Container tools
          {
            name: "list_containers",
            description: "List containers secured by RAD Security with optional filtering by image name, image digest, namespace, cluster_id, or free text search",
            inputSchema: zodToJsonSchema(containers.ListContainersSchema),
          },
          {
            name: "get_container_details",
            description: "Get detailed information about a container secured by RAD Security",
            inputSchema: zodToJsonSchema(containers.GetContainerDetailsSchema),
          },
          // Cluster tools
          {
            name: "list_clusters",
            description: "List Kubernetes clusters managed by RAD Security",
            inputSchema: zodToJsonSchema(clusters.ListClustersSchema),
          },
          {
            name: "get_cluster_details",
            description: "Get detailed information about a specific Kubernetes cluster managed by RAD Security",
            inputSchema: zodToJsonSchema(clusters.GetClusterDetailsSchema),
          },
          // Identity tools
          {
            name: "list_identities",
            description: "Get list of identities for a specific Kubernetes cluster",
            inputSchema: zodToJsonSchema(identities.ListIdentitiesSchema),
          },
          {
            name: "get_identity_details",
            description: "Get detailed information about a specific identity in a Kubernetes cluster",
            inputSchema: zodToJsonSchema(identities.GetIdentityDetailsSchema),
          },
          // Audit tools
          {
            name: "who_shelled_into_pod",
            description: "Get users who shelled into a pod with the given name and namespace around the given time",
            inputSchema: zodToJsonSchema(audit.WhoShelledIntoPodSchema),
          },
          // Cloud Inventory tools
          {
            name: "list_cloud_resources",
            description: "List cloud resources for a specific provider with optional filtering",
            inputSchema: zodToJsonSchema(cloudInventory.ListCloudResourcesSchema),
          },
          {
            name: "get_cloud_resource_details",
            description: "Get detailed information about a specific cloud resource",
            inputSchema: zodToJsonSchema(cloudInventory.GetCloudResourceDetailsSchema),
          },
          {
            name: "get_cloud_resource_facets",
            description: "Get available facets for filtering cloud resources from a provider",
            inputSchema: zodToJsonSchema(cloudInventory.GetCloudResourceFacetsSchema),
          },
          {
            name: "get_cloud_resource_facet_values",
            description: "Get values for a specific facet from a cloud provider",
            inputSchema: zodToJsonSchema(cloudInventory.GetCloudResourceFacetValuesSchema),
          },
          // Image tools
          {
            name: "list_images",
            description: "List container images with optional filtering by page, page size, sort, and search query",
            inputSchema: zodToJsonSchema(images.ListImagesSchema),
          },
          {
            name: "list_image_vulnerabilities",
            description: "List vulnerabilities in a container image with optional filtering by severity",
            inputSchema: zodToJsonSchema(images.ListImageVulnerabilitiesSchema),
          },
          {
            name: "get_top_vulnerable_images",
            description: "Get the most vulnerable images from your account",
            inputSchema: zodToJsonSchema(z.object({})),
          },
          {
            name: "get_image_sbom",
            description: "Get the SBOM of a container image",
            inputSchema: zodToJsonSchema(images.GetImageSBOMSchema),
          },
          // Kubernetes Object tools
          {
            name: "get_kubernetes_resource_details",
            description: "Get the latest manifest of a Kubernetes resource",
            inputSchema: zodToJsonSchema(kubeobject.GetKubernetesResourceDetailsSchema),
          },
          {
            name: "list_kubernetes_resources",
            description: "List Kubernetes resources with optional filtering by namespace, resource types, and cluster",
            inputSchema: zodToJsonSchema(kubeobject.ListKubernetesResourcesSchema),
          },
          // Manifest Misconfigurations tools
          {
            name: "list_kubernetes_resource_misconfigurations",
            description: "Get manifest misconfigurations for a Kubernetes resource",
            inputSchema: zodToJsonSchema(misconfigs.ListKubernetesResourceMisconfigurationsSchema),
          },
          {
            name: "get_kubernetes_resource_misconfiguration_details",
            description: "Get detailed information about a specific Kubernetes resource misconfiguration",
            inputSchema: zodToJsonSchema(misconfigs.GetKubernetesResourceMisconfigurationDetailsSchema),
          },
          // Runtime tools
          {
            name: "get_containers_process_trees",
            description: "Get process trees for multiple containers",
            inputSchema: zodToJsonSchema(runtime.GetContainersProcessTreesSchema),
          },
          {
            name: "get_containers_baselines",
            description: "Get runtime baselines for multiple containers",
            inputSchema: zodToJsonSchema(runtime.GetContainersBaselinesSchema),
          },
          {
            name: "get_container_llm_analysis",
            description: "Get LLM analysis of a container's process tree",
            inputSchema: zodToJsonSchema(runtime.GetContainerLLMAnalysisSchema),
          },
          // Runtime Network tools
          {
            name: "list_http_requests",
            description: "List HTTP requests insights with optional filtering by method, path, source and destination workloads, and PII detection",
            inputSchema: zodToJsonSchema(runtimeNetwork.listHttpRequestsSchema),
          },
          {
            name: "list_network_connections",
            description: "List network connections with optional filtering",
            inputSchema: zodToJsonSchema(runtimeNetwork.listNetworkConnectionsSchema),
          },
          {
            name: "list_network_connection_sources",
            description: "List network connection sources with optional filtering by source and destination workloads",
            inputSchema: zodToJsonSchema(runtimeNetwork.listNetworkConnectionSourcesSchema),
          },
          // Threat Vectors tools
          {
            name: "list_threat_vectors",
            description: "List threat vectors",
            inputSchema: zodToJsonSchema(threats.listThreatVectorsSchema),
          },
          // Findings tools
          {
            name: "list_security_findings",
            description: "List security findings with optional filtering by types, severities, sources, and status",
            inputSchema: zodToJsonSchema(findings.listFindingsSchema),
          },
          {
            name: "update_security_finding_status",
            description: "Update the status of a security finding",
            inputSchema: zodToJsonSchema(findings.updateFindingStatusSchema),
          },
        ],
      };
    }
  );

  server.setRequestHandler(
    CallToolRequestSchema,
    async (request: CallToolRequest) => {
      try {
        if (!request.params.arguments) {
          throw new Error("Arguments are required");
        }

        const toolName = request.params.name;
        switch (toolName) {
          // Container tools
          case "list_containers": {
            const args = containers.ListContainersSchema.parse(request.params.arguments);
            const response = await containers.listContainers(client, args.offset, args.limit, args.filters, args.q);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "get_container_details": {
            const args = containers.GetContainerDetailsSchema.parse(request.params.arguments);
            const response = await containers.getContainerDetails(client, args.container_id);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          // Cluster tools
          case "list_clusters": {
            const args = clusters.ListClustersSchema.parse(request.params.arguments);
            const response = await clusters.listClusters(client, args.page_size, args.page);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "get_cluster_details": {
            const args = clusters.GetClusterDetailsSchema.parse(request.params.arguments);
            const response = await clusters.getClusterDetails(client, args.cluster_id);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          // Identity tools
          case "list_identities": {
            const args = identities.ListIdentitiesSchema.parse(request.params.arguments);
            const response = await identities.listIdentities(client, args.identity_types, args.cluster_ids, args.page, args.page_size, args.q);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "get_identity_details": {
            const args = identities.GetIdentityDetailsSchema.parse(request.params.arguments);
            const response = await identities.getIdentityDetails(client, args.identity_id);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          // Audit tools
          case "who_shelled_into_pod": {
            const args = audit.WhoShelledIntoPodSchema.parse(request.params.arguments);
            const response = await audit.whoShelledIntoPod(
              client,
              args.name,
              args.namespace,
              args.cluster_id,
              args.from_time,
              args.to_time,
              args.limit,
              args.page
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          // Cloud Inventory tools
          case "list_cloud_resources": {
            const args = cloudInventory.ListCloudResourcesSchema.parse(request.params.arguments);
            const response = await cloudInventory.listCloudResources(
              client,
              args.provider,
              args.filters,
              args.offset,
              args.limit,
              args.q
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "get_cloud_resource_details": {
            const args = cloudInventory.GetCloudResourceDetailsSchema.parse(request.params.arguments);
            const response = await cloudInventory.getCloudResourceDetails(
              client,
              args.provider,
              args.resource_type,
              args.resource_id
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "get_cloud_resource_facets": {
            const args = cloudInventory.GetCloudResourceFacetsSchema.parse(request.params.arguments);
            const response = await cloudInventory.getCloudResourceFacets(
              client,
              args.provider
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "get_cloud_resource_facet_values": {
            const args = cloudInventory.GetCloudResourceFacetValuesSchema.parse(request.params.arguments);
            const response = await cloudInventory.getCloudResourceFacetValues(
              client,
              args.provider,
              args.facet_id
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          // Image tools
          case "list_images": {
            const args = images.ListImagesSchema.parse(request.params.arguments);
            const response = await images.listImages(
              client,
              args.page,
              args.page_size,
              args.sort,
              args.search
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "list_image_vulnerabilities": {
            const args = images.ListImageVulnerabilitiesSchema.parse(request.params.arguments);
            const response = await images.listImageVulnerabilities(
              client,
              args.digest,
              args.severities,
              args.page,
              args.page_size
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "get_top_vulnerable_images": {
            const response = await images.getTopVulnerableImages(client);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "get_image_sbom": {
            const args = images.GetImageSBOMSchema.parse(request.params.arguments);
            const response = await images.getImageSBOM(client, args.digest);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          // Kubernetes Objects tools
          case "get_kubernetes_resource_details": {
            const args = kubeobject.GetKubernetesResourceDetailsSchema.parse(request.params.arguments);
            const response = await kubeobject.getKubernetesResourceDetails(
              client,
              args.cluster_id,
              args.resource_uid
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "list_kubernetes_resources": {
            const args = kubeobject.ListKubernetesResourcesSchema.parse(request.params.arguments);
            const response = await kubeobject.listKubernetesResources(
              client,
              args.kinds,
              args.namespace,
              args.cluster_id,
              args.page,
              args.page_size
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          // Kubernetes Resource Misconfigurations tools
          case "list_kubernetes_resource_misconfigurations": {
            const args = misconfigs.ListKubernetesResourceMisconfigurationsSchema.parse(request.params.arguments);
            const response = await misconfigs.listKubernetesResourceMisconfigurations(
              client,
              args.resource_uid
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "get_kubernetes_resource_misconfiguration_details": {
            const args = misconfigs.GetKubernetesResourceMisconfigurationDetailsSchema.parse(request.params.arguments);
            const response = await misconfigs.getKubernetesResourceMisconfigurationDetails(
              client,
              args.cluster_id,
              args.misconfig_id
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          // Runtime tools
          case "get_containers_process_trees": {
            const args = runtime.GetContainersProcessTreesSchema.parse(request.params.arguments);
            const response = await runtime.getContainersProcessTrees(
              client,
              args.container_ids
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "get_containers_baselines": {
            const args = runtime.GetContainersBaselinesSchema.parse(request.params.arguments);
            const response = await runtime.getContainersBaselines(
              client,
              args.container_ids
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "get_container_llm_analysis": {
            const args = runtime.GetContainerLLMAnalysisSchema.parse(request.params.arguments);
            const response = await runtime.getContainerLLMAnalysis(
              client,
              args.container_id
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          // Runtime Network tools
          case "list_http_requests": {
            const args = runtimeNetwork.listHttpRequestsSchema.parse(request.params.arguments);
            const response = await runtimeNetwork.listHttpRequests(client, args);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "list_network_connections": {
            const args = runtimeNetwork.listNetworkConnectionsSchema.parse(request.params.arguments);
            const response = await runtimeNetwork.listNetworkConnections(client, args);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "list_network_connection_sources": {
            const args = runtimeNetwork.listNetworkConnectionSourcesSchema.parse(request.params.arguments);
            const response = await runtimeNetwork.listNetworkConnectionSources(client, args);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          // Threat Vectors tools
          case "list_threat_vectors": {
            const args = threats.listThreatVectorsSchema.parse(request.params.arguments);
            const response = await threats.listThreatVectors(client, args.clustersIds, args.namespaces, args.resource_uid, args.page, args.page_size);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          // Findings tools
          case "list_security_findings": {
            const args = findings.listFindingsSchema.parse(request.params.arguments);
            const response = await findings.listFindings(
              client,
              args.limit,
              args.types,
              args.severities,
              args.source_types,
              args.source_kinds,
              args.source_names,
              args.source_namespaces,
              args.status,
              args.from_time,
              args.to_time
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "update_security_finding_status": {
            const args = findings.updateFindingStatusSchema.parse(request.params.arguments);
            await findings.updateFindingGroupStatus(client, args.id, args.status);
            return {
              content: [{ type: "text", text: JSON.stringify({ success: true, message: `Finding ${args.id} status updated to ${args.status}` }, null, 2) }],
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

  return server;
}


async function main() {
  try {
    const transportType = process.env.TRANSPORT_TYPE || 'stdio';
    if (!['stdio', 'sse'].includes(transportType)) {
      throw new Error("Transport type must be either 'stdio' or 'sse'");
    }

    if (transportType === 'stdio') {
      const transport = new StdioServerTransport();
      const server = await newServer();
      await server.connect(transport);
      console.info("RAD Security MCP server started with stdio transport");
    } else {
      const app = express();
      app.use(cors({
        origin: '*',
        methods: ['GET', 'POST', 'OPTIONS', 'HEAD'],
        allowedHeaders: ['Content-Type'],
      }));

      const server = await newServer();
      let transport: SSEServerTransport;
      app.head("/sse", async (req, res) => {
        res.sendStatus(200);
      });
      app.head("/messages", async (req, res) => {
        res.sendStatus(200);
      });

      app.get("/sse", async (req, res) => {
        transport = new SSEServerTransport("/messages", res);

        await server.connect(transport);
      });

      app.post("/messages", async (req, res) => {
        await transport.handlePostMessage(req, res);
      });

      const port = process.env.PORT || 3000;
      app.listen(port, () => {
        console.info(`Server running on http://localhost:${port}/sse`);
      });
    }
  } catch (error) {
    console.error("Error starting server:", error);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Unhandled error:", error);
  process.exit(1);
});
