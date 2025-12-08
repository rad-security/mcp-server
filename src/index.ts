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
  SetLevelRequestSchema,
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
import * as radql from "./operations/radql.js";
import * as cloudCompliance from "./operations/cloud-compliance.js";
import { VERSION } from "./version.js";
import { logger, LogLevel, LogFormat } from "./logger.js";

// Toolkit type definitions
type ToolkitType =
  | "containers"
  | "clusters"
  | "identities"
  | "audit"
  | "cloud_inventory"
  | "cloud_compliance"
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
  | "knowledge_base"
  | "radql";

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

  // Attach logger to server for MCP notifications
  logger.setServer(server);

  // Handle logging level changes
  server.setRequestHandler(
    SetLevelRequestSchema,
    async (request) => {
      const level = request.params.level as LogLevel;
      logger.setLevel(level);
      logger.configChange("log_level", level);
      return {};
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
        // Cloud Compliance tools
        ...(isToolkitEnabled("cloud_compliance", toolkitFilters) ? [
          {
            name: "list_compliance_frameworks",
            description: "List all compliance frameworks available for cloud resources (e.g., CIS, SOC2, PCI-DSS)",
            inputSchema: zodToJsonSchema(cloudCompliance.ListComplianceFrameworksSchema),
          },
          {
            name: "list_framework_requirements",
            description: "List all requirements for a specific compliance framework",
            inputSchema: zodToJsonSchema(cloudCompliance.ListFrameworkRequirementsSchema),
          },
          {
            name: "list_requirement_controls",
            description: "List controls associated with a specific requirement within a compliance framework",
            inputSchema: zodToJsonSchema(cloudCompliance.ListRequirementControlsSchema),
          },
          {
            name: "list_compliance_controls",
            description: "List all compliance control summaries for the account",
            inputSchema: zodToJsonSchema(cloudCompliance.ListComplianceControlsSchema),
          },
          {
            name: "get_compliance_control",
            description: "Get detailed information about a specific compliance control",
            inputSchema: zodToJsonSchema(cloudCompliance.GetComplianceControlSchema),
          },
          {
            name: "list_control_resources",
            description: "List cloud resources associated with a specific compliance control",
            inputSchema: zodToJsonSchema(cloudCompliance.ListControlResourcesSchema),
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
            name: "list_workflows",
            description: "List all workflows",
            inputSchema: zodToJsonSchema(workflows.ListWorkflowsSchema),
          },
          {
            name: "get_workflow",
            description: "Get detailed information about a specific workflow by ID. It contains the workflow definition, default arguments, and schema how to run the workflow",
            inputSchema: zodToJsonSchema(workflows.GetWorkflowSchema),
          },
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
            description: "Run a workflow with optional argument overrides",
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
          {
            name: "list_knowledge_base_collections",
            description: "List all collections in your organization's knowledge base. Collections are used to organize and categorize documents",
            inputSchema: zodToJsonSchema(knowledgeBase.ListCollectionsSchema),
          },
          {
            name: "list_knowledge_base_documents",
            description: "List documents in your organization's knowledge base with optional filtering by collections, file type, or status",
            inputSchema: zodToJsonSchema(knowledgeBase.ListDocumentsSchema),
          },
            {
                name: "query_knowledge_base_document",
                description: "Query a CSV document from the knowledge base using natural language. IMPORTANT: This tool ONLY works with CSV documents. Use list_knowledge_base_documents with filters='file_type:csv' to find CSV document IDs (search_knowledge_base results also contain document IDs). Results are returned as a markdown table",
                inputSchema: zodToJsonSchema(knowledgeBase.StructuredQueryDocumentSchema),
            },
        ] : []),
        // RadQL tools
        ...(isToolkitEnabled("radql", toolkitFilters) ? [
          {
            name: "radql_list_data_types",
            description: "List all available RadQL data types (discovery). ALWAYS call this FIRST before using other RadQL tools to discover what data is available to query. Returns data types like 'containers', 'kubernetes_resources', 'inbox_items', 'vulnerabilities', etc. with descriptions.",
            inputSchema: zodToJsonSchema(radql.RadQLListDataTypesSchema),
          },
          {
            name: "radql_get_type_metadata",
            description: "Get schema/metadata for a specific RadQL data type. Shows available fields, data types, which fields can be filtered/searched, and provides query examples. Call this AFTER radql_list_data_types to understand how to query a specific data type.",
            inputSchema: zodToJsonSchema(radql.RadQLGetTypeMetadataSchema),
          },
          {
            name: "radql_list_filter_values",
            description: "List possible values for a filter field (e.g., namespace list, cluster list, severity values). Useful for building dynamic filters when you need to know available enum-like values. Call this when constructing filters that need specific values.",
            inputSchema: zodToJsonSchema(radql.RadQLListFilterValuesSchema),
          },
          {
            name: "radql_query",
            description: `Execute RadQL queries for security investigations. Supports: list (filter/search), get_by_id (single item), stats (aggregations).

WORKFLOW: radql_list_data_types -> radql_get_type_metadata -> radql_query

COMMON FIELDS BY DATA TYPE:
containers: name, image_name, image_repo, owner_kind, cluster_id, created_at
  Example: image_name:*nginx* AND owner_kind:Pod

finding_groups: type, source_kind, source_name, rule_title, severity, event_timestamp
  Types: k8s_misconfiguration, k8s_audit_logs_anomaly, threat_vector
  Example: type:k8s_misconfiguration AND severity:critical

inbox_items: severity (High|Medium|Low), type, title, archived, false_positive, created_at
  Example: severity:High AND archived:false

kubernetes_resources: kind, name, namespace, cluster_id, owner_kind, created_at
  Example: kind:Deployment AND namespace:production

CRITICAL QUOTING RULES:
MUST quote when value contains:
  - Dates/timestamps: created_at>"2024-01-01" (NOT created_at>2024-01-01)
  - Hyphens: cluster_id:"abc-123-def", name:"kube-system"
  - UUIDs: id:"550e8400-e29b-41d4-a716-446655440000"
  - Spaces: title:"my alert"
  - Special chars: :, =, <, >, !, (, )
  - Wildcards with hyphens: name:"kube-*"

OK to leave unquoted:
  - Simple strings: status:active, kind:Pod
  - Numbers: count:123
  - Booleans: archived:true
  - Simple wildcards: name:nginx*

For complete schema: call radql_get_type_metadata with target data_type`,
            inputSchema: zodToJsonSchema(radql.RadQLQuerySchema),
          },
          {
            name: "radql_query_builder",
            description: "Helper tool to build RadQL queries programmatically from structured conditions. Useful when you need to construct complex filter or stats queries from structured inputs.",
            inputSchema: zodToJsonSchema(radql.RadQLQueryBuilderSchema),
          },
          {
            name: "radql_batch_query",
            description: "Execute multiple RadQL queries in parallel for efficiency. Useful for fetching related data from different data types simultaneously (e.g., container details + vulnerabilities + network connections).",
            inputSchema: zodToJsonSchema(radql.RadQLBatchQuerySchema),
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
      const startTime = Date.now();
      const toolName = request.params.name;

      try {
        if (!request.params.arguments) {
          throw new Error("Arguments are required");
        }

        logger.toolInvocation(toolName, request.params.arguments);

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
          // Cloud Compliance tools
          case "list_compliance_frameworks": {
            const args = cloudCompliance.ListComplianceFrameworksSchema.parse(request.params.arguments);
            const response = await cloudCompliance.listComplianceFrameworks(
              client,
              args.datasource_ids,
              args.page,
              args.page_size
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "list_framework_requirements": {
            const args = cloudCompliance.ListFrameworkRequirementsSchema.parse(request.params.arguments);
            const response = await cloudCompliance.listFrameworkRequirements(
              client,
              args.framework_name,
              args.datasource_ids,
              args.page,
              args.page_size
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "list_requirement_controls": {
            const args = cloudCompliance.ListRequirementControlsSchema.parse(request.params.arguments);
            const response = await cloudCompliance.listRequirementControls(
              client,
              args.framework_name,
              args.requirement_id,
              args.datasource_ids,
              args.page,
              args.page_size
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "list_compliance_controls": {
            const args = cloudCompliance.ListComplianceControlsSchema.parse(request.params.arguments);
            const response = await cloudCompliance.listComplianceControls(
              client,
              args.status,
              args.providers,
              args.page,
              args.page_size
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "get_compliance_control": {
            const args = cloudCompliance.GetComplianceControlSchema.parse(request.params.arguments);
            const response = await cloudCompliance.getComplianceControl(
              client,
              args.control_name,
              args.datasource_ids
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "list_control_resources": {
            const args = cloudCompliance.ListControlResourcesSchema.parse(request.params.arguments);
            const response = await cloudCompliance.listControlResources(
              client,
              args.control_name,
              args.datasource_ids,
              args.page,
              args.page_size
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
          case "list_workflows": {
            workflows.ListWorkflowsSchema.parse(request.params.arguments);
            const response = await workflows.listWorkflows(client);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "get_workflow": {
            const args = workflows.GetWorkflowSchema.parse(request.params.arguments);
            const response = await workflows.getWorkflow(client, args.workflow_id);
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
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
            const response = await workflows.runWorkflow(client, args.workflow_id, args.async, args.args);
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
              args.thread_id,
              args.collections,
              args.document_ids
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "list_knowledge_base_collections": {
            const args = knowledgeBase.ListCollectionsSchema.parse(request.params.arguments);
            const response = await knowledgeBase.listCollections(
              client,
              args.limit,
              args.offset
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "list_knowledge_base_documents": {
            const args = knowledgeBase.ListDocumentsSchema.parse(request.params.arguments);
            const response = await knowledgeBase.listDocuments(
              client,
              args.limit,
              args.offset,
              args.filters
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
          case "query_knowledge_base_document": {
            const args = knowledgeBase.StructuredQueryDocumentSchema.parse(request.params.arguments);
            const response = await knowledgeBase.structuredQueryDocument(
              client,
              args.document_id,
              args.query
            );
            return {
              content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
            };
          }
            // RadQL tools
            case "radql_list_data_types": {
                const response = await radql.executeListDataTypes(client);
                return {
                    content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
                };
            }
            case "radql_get_type_metadata": {
                const args = radql.RadQLGetTypeMetadataSchema.parse(request.params.arguments);
                const response = await radql.executeGetTypeMetadata(client, args);
                return {
                    content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
                };
            }
            case "radql_list_filter_values": {
                const args = radql.RadQLListFilterValuesSchema.parse(request.params.arguments);
                const response = await radql.executeListFilterValues(client, args);
                return {
                    content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
                };
            }
            case "radql_query": {
                const args = radql.RadQLQuerySchema.parse(request.params.arguments);
                const response = await radql.executeRadQLQuery(client, args);
                return {
                    content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
                };
            }
            case "radql_query_builder": {
                const args = radql.RadQLQueryBuilderSchema.parse(request.params.arguments);
                const response = radql.buildRadQLQuery(args);
                return {
                    content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
                };
            }
            case "radql_batch_query": {
                const args = radql.RadQLBatchQuerySchema.parse(request.params.arguments);
                const response = await radql.executeBatchQueries(client, args);
                return {
                    content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
                };
            }
          default:
            throw new Error(`Unknown tool: ${toolName}`);
        }

        const duration = Date.now() - startTime;
        logger.toolSuccess(toolName, duration);
      } catch (error) {
        const duration = Date.now() - startTime;
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.toolError(toolName, errorMessage, duration);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: errorMessage,
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

    // Configure logger from environment variables
    const logLevel = (process.env.LOG_LEVEL || 'info') as LogLevel;
    const enableStderr = process.env.LOG_STDERR !== 'false'; // Default: true
    const enableMcpNotifications = process.env.LOG_MCP !== 'false'; // Default: true
    const stderrFormat = (process.env.LOG_FORMAT || 'human') as LogFormat; // 'human' or 'json'

    logger.configure({
      minLevel: logLevel,
      enableStderr,
      enableMcpNotifications,
      stderrFormat,
    });

    logger.serverStartup(VERSION, transportType);

    // Log toolkit filters if set
    const filters = parseToolkitFilters();
    if (filters.include && filters.include.length > 0) {
      logger.configChange("toolkit_filter", { mode: "include", toolkits: filters.include });
    } else if (filters.exclude && filters.exclude.length > 0) {
      logger.configChange("toolkit_filter", { mode: "exclude", toolkits: filters.exclude });
    } else {
      logger.configChange("toolkit_filter", { mode: "all" });
    }

    if (transportType === 'stdio') {
      const transport = new StdioServerTransport();
      const server = await newServer();
      await server.connect(transport);
      logger.serverReady('stdio');
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
        logger.serverReady('sse', { url: `http://localhost:${port}/sse` });
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
        logger.serverReady('streamable', { url: `http://localhost:${port}/mcp` });
      });
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.emergency("server", {
      message: "Server startup failed",
      error: errorMessage,
    });
    process.exit(1);
  }
}

main().catch((error) => {
  const errorMessage = error instanceof Error ? error.message : String(error);
  logger.emergency("server", {
    message: "Unhandled error in main",
    error: errorMessage,
  });
  process.exit(1);
});
