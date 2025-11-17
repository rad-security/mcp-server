#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import cors from 'cors';
import { randomUUID } from "node:crypto";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js"
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
import * as cves from "./operations/cves.js";
import * as inbox from "./operations/inbox.js";
import * as workflows from "./operations/workflows.js";
import * as knowledgeBase from "./operations/knowledge-base.js";
import { VERSION } from "./version.js";

// Toolkit type definitions
type ToolkitType =
  | "containers"
  | "clusters"
  | "identities"
  | "audit"
  | "cloud_inventory"
  | "images"
  | "kubeobject"
  | "misconfigs"
  | "runtime"
  | "runtime_network"
  | "threats"
  | "findings"
  | "cves"
  | "inbox"
  | "workflows"
  | "knowledge_base";

// Parse toolkit filters from environment variables
function parseToolkitFilters(): { include?: ToolkitType[], exclude?: ToolkitType[] } {
  const includeEnv = process.env.INCLUDE_TOOLKITS;
  const excludeEnv = process.env.EXCLUDE_TOOLKITS;

  const result: { include?: ToolkitType[], exclude?: ToolkitType[] } = {};

  if (includeEnv) {
    result.include = includeEnv.split(',').map(s => s.trim()) as ToolkitType[];
  }

  if (excludeEnv) {
    result.exclude = excludeEnv.split(',').map(s => s.trim()) as ToolkitType[];
  }

  return result;
}

// Check if a toolkit type should be enabled
function isToolkitEnabled(toolkitType: ToolkitType, filters: { include?: ToolkitType[], exclude?: ToolkitType[] }): boolean {
  // If include list is specified, only those toolkits are enabled
  if (filters.include && filters.include.length > 0) {
    return filters.include.includes(toolkitType);
  }

  // If exclude list is specified, all except those are enabled
  if (filters.exclude && filters.exclude.length > 0) {
    return !filters.exclude.includes(toolkitType);
  }

  // By default, all toolkits are enabled
  return true;
}

async function newServer(): Promise<Server> {
  const client = RadSecurityClient.fromEnv();
  const toolkitFilters = parseToolkitFilters();

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
      const allTools = [
        // Container tools
        ...(isToolkitEnabled("containers", toolkitFilters) ? [
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
        ] : []),
        // Cluster tools
        ...(isToolkitEnabled("clusters", toolkitFilters) ? [
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
        ] : []),
        // Identity tools
        ...(isToolkitEnabled("identities", toolkitFilters) ? [
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
        ] : []),
        // Audit tools
        ...(isToolkitEnabled("audit", toolkitFilters) ? [
          {
            name: "who_shelled_into_pod",
            description: "Get k8s audit logs with information about users who shelled into a pod",
            inputSchema: zodToJsonSchema(audit.WhoShelledIntoPodSchema),
          },
        ] : []),
        // Cloud Inventory tools
        ...(isToolkitEnabled("cloud_inventory", toolkitFilters) ? [
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
            name: "get_cloud_resource_facet_value",
            description: "Get values for a specific facet from a cloud provider",
            inputSchema: zodToJsonSchema(cloudInventory.GetCloudResourceFacetValuesSchema),
          },
        ] : []),
        // Image tools
        ...(isToolkitEnabled("images", toolkitFilters) ? [
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
        ] : []),
        // Kubernetes Object tools
        ...(isToolkitEnabled("kubeobject", toolkitFilters) ? [
          {
            name: "get_k8s_resource_details",
            description: "Get the latest manifest of a Kubernetes resource",
            inputSchema: zodToJsonSchema(kubeobject.GetKubernetesResourceDetailsSchema),
          },
          {
            name: "list_k8s_resources",
            description: "List Kubernetes resources with optional filtering by namespace, resource types, and cluster",
            inputSchema: zodToJsonSchema(kubeobject.ListKubernetesResourcesSchema),
          },
        ] : []),
        // Manifest Misconfigurations tools
        ...(isToolkitEnabled("misconfigs", toolkitFilters) ? [
          {
            name: "list_k8s_resource_misconfigs",
            description: "Get manifest misconfigurations for a Kubernetes resource",
            inputSchema: zodToJsonSchema(misconfigs.ListKubernetesResourceMisconfigurationsSchema),
          },
          {
            name: "get_k8s_resource_misconfig",
            description: "Get detailed information about a specific Kubernetes resource misconfiguration",
            inputSchema: zodToJsonSchema(misconfigs.GetKubernetesResourceMisconfigurationDetailsSchema),
          },
          {
            name: "list_k8s_resource_misconfig_policies",
            description: "List available misconfiguration policies used by RAD Security to detect Kubernetes resource misconfigurations",
            inputSchema: zodToJsonSchema(misconfigs.ListKubernetesResourceMisconfigurationPoliciesSchema),
          },
        ] : []),
        // Runtime tools
        ...(isToolkitEnabled("runtime", toolkitFilters) ? [
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
        ] : []),
        // Runtime Network tools
        ...(isToolkitEnabled("runtime_network", toolkitFilters) ? [
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
            name: "list_network_connection_srcs",
            description: "List network connection sources with optional filtering by source and destination workloads",
            inputSchema: zodToJsonSchema(runtimeNetwork.listNetworkConnectionSourcesSchema),
          },
        ] : []),
        // Threat Vectors tools
        ...(isToolkitEnabled("threats", toolkitFilters) ? [
          {
            name: "list_threat_vectors",
            description: "List threat vectors",
            inputSchema: zodToJsonSchema(threats.listThreatVectorsSchema),
          },
        ] : []),
        // Findings tools
        ...(isToolkitEnabled("findings", toolkitFilters) ? [
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
        ] : []),
        // CVE tools
        ...(isToolkitEnabled("cves", toolkitFilters) ? [
          {
            name: "list_cve_vendors",
            description: "Get a list of all vendors in the CVE database. Source: cve-search.org",
            inputSchema: zodToJsonSchema(z.object({})),
          },
          {
            name: "list_cve_products",
            description: "Get a list of all products associated with a vendor in the CVE database. Source: cve-search.org",
            inputSchema: zodToJsonSchema(z.object({
              vendor: z.string().describe("Vendor name to list products for")
            })),
          },
          {
            name: "search_cves",
            description: "Search CVEs by vendor and optionally product. Source: cve-search.org",
            inputSchema: zodToJsonSchema(cves.searchCvesSchema),
          },
          {
            name: "get_cve",
            description: "Get details for a specific CVE ID. Source: cve-search.org",
            inputSchema: zodToJsonSchema(cves.getCveSchema),
          },
          {
            name: "get_latest_30_cves",
            description: "Get the latest/newest 30 CVEs including CAPEC, CWE and CPE expansions. Source: cve-search.org",
            inputSchema: zodToJsonSchema(z.object({})),
          },
        ] : []),
        // Inbox tools
        ...(isToolkitEnabled("inbox", toolkitFilters) ? [
          {
            name: "mark_inbox_item_as_false_positive",
            description: "Mark an inbox item as a false positive with a reason",
            inputSchema: zodToJsonSchema(inbox.MarkInboxItemAsFalsePositiveSchema),
          },
          {
            name: "list_inbox_items",
            description: "List inbox items with optional filtering by any field. Multiple filters can be combined eg. 'search:cve-2024-12345 and severity:high'",
            inputSchema: zodToJsonSchema(inbox.ListInboxItemsSchema),
          },
          {
            name: "get_inbox_item_details",
            description: "Get detailed information about a specific inbox item",
            inputSchema: zodToJsonSchema(inbox.GetInboxItemDetailsSchema),
          },
        ] : []),
        // Workflows tools
        ...(isToolkitEnabled("workflows", toolkitFilters) ? [
          {
            name: "list_workflow_runs",
            description: "List workflow runs with optional filtering by workflow ID",
            inputSchema: zodToJsonSchema(workflows.ListWorkflowRunsSchema),
          },
          {
            name: "get_workflow_run",
            description: "Get detailed information about a specific workflow run",
            inputSchema: zodToJsonSchema(workflows.GetWorkflowRunSchema),
          },
          {
            name: "run_workflow",
            description: "Run a workflow",
            inputSchema: zodToJsonSchema(workflows.RunWorkflowSchema),
          },
          {
            name: "list_workflow_schedules",
            description: "List workflow schedules with optional filtering by workflow ID",
            inputSchema: zodToJsonSchema(workflows.ListWorkflowSchedulesSchema),
          },
        ] : []),
        // Knowledge Base tools
        ...(isToolkitEnabled("knowledge_base", toolkitFilters) ? [
          {
            name: "search_knowledge_base",
            description: "Search your organization's knowledge base to find relevant uploaded documents, procedures, reports, and other content using natural language queries",
            inputSchema: zodToJsonSchema(knowledgeBase.SearchKnowledgeBaseSchema),
          },
        ] : []),
      ];

      return {
        tools: allTools,
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
          case "get_cloud_resource_facet_value": {
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
              args.limit,
              args.offset,
              args.sort,
              args.filters,
              args.q
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
          case "get_k8s_resource_details": {
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
          case "list_k8s_resources": {
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
          case "list_k8s_resource_misconfigs": {
            const args = misconfigs.ListKubernetesResourceMisconfigurationsSchema.parse(request.params.arguments);
            const response = await misconfigs.listKubernetesResourceMisconfigurations(
              client,
              args.resource_uid
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "get_k8s_resource_misconfig": {
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
          case "list_k8s_resource_misconfig_policies": {
            const response = await misconfigs.listKubernetesResourceMisconfigurationPolicies();
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          // Runtime tools
          case "get_containers_process_trees": {
            const args = runtime.GetContainersProcessTreesSchema.parse(request.params.arguments);
            const response = await runtime.getContainersProcessTrees(
              client,
              args.container_ids,
              args.processes_limit
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
          case "list_network_connection_srcs": {
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
          // CVE tools
          case "list_cve_vendors": {
            const response = await cves.listCveVendors();
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "list_cve_products": {
            const args = z.object({
              vendor: z.string()
            }).parse(request.params.arguments);
            const response = await cves.listCveProducts(args.vendor);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "search_cves": {
            const args = cves.searchCvesSchema.parse(request.params.arguments);
            const response = await cves.searchCves(args.vendor, args.product);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "get_cve": {
            const args = cves.getCveSchema.parse(request.params.arguments);
            const response = await cves.getCve(args.cveId);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "get_latest_30_cves": {
            const response = await cves.getLatest30Cves();
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          // Inbox tools
          case "mark_inbox_item_as_false_positive": {
            const args = inbox.MarkInboxItemAsFalsePositiveSchema.parse(request.params.arguments);
            const response = await inbox.markInboxItemAsFalsePositive(
              client,
              args.inbox_item_id,
              args.value,
              args.reason
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "list_inbox_items": {
            const args = inbox.ListInboxItemsSchema.parse(request.params.arguments);
            const response = await inbox.listInboxItems(
              client,
              args.limit,
              args.offset,
              args.filters_query,
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "get_inbox_item_details": {
            const args = inbox.GetInboxItemDetailsSchema.parse(request.params.arguments);
            const response = await inbox.getInboxItemDetails(
              client,
              args.inbox_item_id
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          // Workflows tools
          case "list_workflow_runs": {
            const args = workflows.ListWorkflowRunsSchema.parse(request.params.arguments);
            const response = await workflows.listWorkflowRuns(client, args.workflow_id);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "get_workflow_run": {
            const args = workflows.GetWorkflowRunSchema.parse(request.params.arguments);
            const response = await workflows.getWorkflowRun(client, args.workflow_id, args.run_id);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "run_workflow": {
            const args = workflows.RunWorkflowSchema.parse(request.params.arguments);
            const response = await workflows.runWorkflow(client, args.workflow_id, args.async);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "list_workflow_schedules": {
            const args = workflows.ListWorkflowSchedulesSchema.parse(request.params.arguments);
            const response = await workflows.listWorkflowSchedules(client, args.workflow_id);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          // Knowledge Base tools
          case "search_knowledge_base": {
            const args = knowledgeBase.SearchKnowledgeBaseSchema.parse(request.params.arguments);
            const response = await knowledgeBase.searchKnowledgeBase(
              client,
              args.query,
              args.top_k,
              args.min_score,
              args.thread_id
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
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
    if (!['stdio', 'sse', 'streamable'].includes(transportType)) {
      throw new Error("Transport type must be either 'stdio', 'sse' or 'streamable'");
    }

    console.error(`RAD Security MCP server version: ${VERSION}`);
    console.error(`Node version: ${process.version}`);

    // Log toolkit filters if set
    const filters = parseToolkitFilters();
    if (filters.include && filters.include.length > 0) {
      console.error(`Toolkit filter: INCLUDE ONLY [${filters.include.join(', ')}]`);
    } else if (filters.exclude && filters.exclude.length > 0) {
      console.error(`Toolkit filter: EXCLUDE [${filters.exclude.join(', ')}]`);
    } else {
      console.error(`Toolkit filter: ALL toolkits enabled`);
    }

    console.error(`Starting MCP server with transport type: ${transportType}...`);

    if (transportType === 'stdio') {
      const transport = new StdioServerTransport();
      const server = await newServer();
      await server.connect(transport);
      console.error(`RAD Security MCP server started.`);
    } else if (transportType === 'sse') {
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
        console.error(`RAD Security MCP Server started on http://localhost:${port}/sse`);
      });
    } else if (transportType === 'streamable') {
      const app = express();
      app.use(express.json());
      app.use(cors({
        origin: '*',
        methods: ['GET', 'POST', 'OPTIONS', 'HEAD'],
        allowedHeaders: ['Content-Type'],
      }));

      // Map to store transports by session ID
      const transports: { [sessionId: string]: StreamableHTTPServerTransport } = {};

      // Handle POST requests for client-to-server communication
      app.post('/mcp', async (req, res) => {
        // Check for existing session ID
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        let transport: StreamableHTTPServerTransport;

        if (sessionId && transports[sessionId]) {
          // Reuse existing transport
          transport = transports[sessionId];
        } else if (!sessionId && isInitializeRequest(req.body)) {
          // New initialization request
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: (sessionId) => {
              // Store the transport by session ID
              transports[sessionId] = transport;
            }
          });

          // Clean up transport when closed
          transport.onclose = () => {
            if (transport.sessionId) {
              delete transports[transport.sessionId];
            }
          };
          const server = await newServer();

          // Connect to the MCP server
          await server.connect(transport);
        } else {
          // Invalid request
          res.status(400).json({
            jsonrpc: '2.0',
            error: {
              code: -32000,
              message: 'Bad Request: No valid session ID provided',
            },
            id: null,
          });
          return;
        }

        // Handle the request
        await transport.handleRequest(req, res, req.body);
      });

      // Reusable handler for GET and DELETE requests
      const handleSessionRequest = async (req: express.Request, res: express.Response) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        if (!sessionId || !transports[sessionId]) {
          res.status(400).send('Invalid or missing session ID');
          return;
        }

        const transport = transports[sessionId];
        await transport.handleRequest(req, res);
      };

      // Handle GET requests for server-to-client notifications via SSE
      app.get('/mcp', handleSessionRequest);

      // Handle DELETE requests for session termination
      app.delete('/mcp', handleSessionRequest);

      const port = process.env.PORT || 3000;
      app.listen(port, () => {
        console.error(`MCP Stateless Streamable HTTP Server listening on port ${port}`);
      });
    }
    console.error(`RAD Security MCP server started.`);
  } catch (error) {
    console.error("Error starting server:", error);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Unhandled error:", error);
  process.exit(1);
});
