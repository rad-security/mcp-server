#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import cors from "cors";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { zodToJsonSchema } from "zod-to-json-schema";
import { z } from "zod";
import {
  CallToolRequest,
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import express from "express";

import { RadSecurityClient, CredentialError } from "./client.js";
import * as containers from "./operations/containers.js";
import * as audit from "./operations/audit.js";
import * as clusters from "./operations/clusters.js";
import * as images from "./operations/images.js";
import * as cveDispositions from "./operations/cve-dispositions.js";
import * as kubeobject from "./operations/kubeobject.js";
import * as runtime from "./operations/runtime.js";
import * as findings from "./operations/findings.js";
import * as inbox from "./operations/inbox.js";
import * as workflows from "./operations/workflows.js";
import * as customWorkflows from "./operations/custom-workflows.js";
import * as knowledgeBase from "./operations/knowledge-base.js";
import * as radql from "./operations/radql.js";
import * as dashboards from "./operations/dashboards.js";
import * as integrations from "./operations/integrations.js";
import { VERSION } from "./version.js";
import { logger } from "./logger.js";

// Toolkit type definitions
type ToolkitType =
  | "containers"
  | "clusters"
  | "audit"
  | "images"
  | "kubeobject"
  | "runtime"
  | "findings"
  | "inbox"
  | "workflows"
  | "knowledge_base"
  | "radql"
  | "dashboards"
  | "integrations";

type ToolkitFilters = {
  include?: ToolkitType[];
  exclude?: ToolkitType[];
  readonly?: boolean;
};

// Parse toolkit filters from environment variables
function parseToolkitFilters(): ToolkitFilters {
  const includeEnv = process.env.INCLUDE_TOOLKITS;
  const excludeEnv = process.env.EXCLUDE_TOOLKITS;

  const result: ToolkitFilters = {};

  if (includeEnv) {
    result.include = includeEnv
      .split(",")
      .map((s) => s.trim()) as ToolkitType[];
  }

  if (excludeEnv) {
    result.exclude = excludeEnv
      .split(",")
      .map((s) => s.trim()) as ToolkitType[];
  }

  return result;
}

// Per-request toolkit selection via headers, so a single hosted endpoint can
// serve different agents a scoped subset. Falls back to the env filters when no
// toolkit header is present.
//   X-Rad-Toolkits:         comma-separated include list (only these enabled)
//   X-Rad-Exclude-Toolkits: comma-separated exclude list (all others enabled)
//   X-Rad-Readonly: true    expose/allow only read-only tools (drops writes)
function toolkitFiltersForRequest(req: express.Request): ToolkitFilters {
  const header = (name: string): string | undefined => {
    const v = req.headers[name];
    return Array.isArray(v) ? v[0] : v;
  };
  const parseList = (v?: string): ToolkitType[] | undefined => {
    const items = (v || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    return items.length ? (items as ToolkitType[]) : undefined;
  };

  const readonly = /^(1|true|yes)$/i.test((header("x-rad-readonly") || "").trim());
  const include = parseList(header("x-rad-toolkits"));
  const exclude = parseList(header("x-rad-exclude-toolkits"));

  // A toolkit header, when present, overrides the env filters.
  if (include || exclude) {
    return { include, exclude, readonly };
  }
  return { ...parseToolkitFilters(), readonly };
}

// Check if a toolkit type should be enabled.
//
// Every toolkit is enabled by default; narrowing is opt-in through the include/exclude filters
// (INCLUDE_TOOLKITS / EXCLUDE_TOOLKITS, or the X-Rad-Toolkits / X-Rad-Exclude-Toolkits headers).
// Write safety is `readonly`'s job, not the toolkit list's: it is enforced per tool, so a caller
// that wants read-only access gets it no matter which toolkits are loaded.
function isToolkitEnabled(
  toolkitType: ToolkitType,
  filters: { include?: ToolkitType[]; exclude?: ToolkitType[] }
): boolean {
  // If include list is specified, only those toolkits are enabled
  if (filters.include && filters.include.length > 0) {
    return filters.include.includes(toolkitType);
  }

  // If exclude list is specified, all except those are enabled
  if (filters.exclude && filters.exclude.length > 0) {
    return !filters.exclude.includes(toolkitType);
  }

  // By default, every toolkit is enabled
  return true;
}

async function newServer(
  client: RadSecurityClient,
  toolkitFilters: ToolkitFilters
): Promise<Server> {
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
      },
    }
  );

  const allTools = [
      // Container tools
      ...(isToolkitEnabled("containers", toolkitFilters)
        ? [
            {
              name: "list_containers",
              annotations: { title: "List Containers", readOnlyHint: true },
              description:
                "List containers secured by RAD Security with optional filtering by image name, image digest, namespace, cluster_id, or free text search",
              inputSchema: zodToJsonSchema(containers.ListContainersSchema),
            },
            {
              name: "get_container_details",
              annotations: { title: "Get Container Details", readOnlyHint: true },
              description:
                "Get detailed information about a container secured by RAD Security",
              inputSchema: zodToJsonSchema(
                containers.GetContainerDetailsSchema
              ),
            },
          ]
        : []),
      // Cluster tools
      ...(isToolkitEnabled("clusters", toolkitFilters)
        ? [
            {
              name: "list_clusters",
              annotations: { title: "List Clusters", readOnlyHint: true },
              description: "List Kubernetes clusters managed by RAD Security",
              inputSchema: zodToJsonSchema(clusters.ListClustersSchema),
            },
            {
              name: "get_cluster_details",
              annotations: { title: "Get Cluster Details", readOnlyHint: true },
              description:
                "Get detailed information about a specific Kubernetes cluster managed by RAD Security",
              inputSchema: zodToJsonSchema(clusters.GetClusterDetailsSchema),
            },
          ]
        : []),
      // Audit tools
      ...(isToolkitEnabled("audit", toolkitFilters)
        ? [
            {
              name: "who_shelled_into_pod",
              annotations: { title: "Who Shelled Into Pod", readOnlyHint: true },
              description:
                "Get k8s audit logs with information about users who shelled into a pod",
              inputSchema: zodToJsonSchema(audit.WhoShelledIntoPodSchema),
            },
          ]
        : []),
      // Image tools
      ...(isToolkitEnabled("images", toolkitFilters)
        ? [
            {
              name: "list_images",
              annotations: { title: "List Images", readOnlyHint: true },
              description:
                "List container images with optional filtering by page, page size, sort, and search query",
              inputSchema: zodToJsonSchema(images.ListImagesSchema),
            },
            {
              name: "list_image_vulnerabilities",
              annotations: { title: "List Image Vulnerabilities", readOnlyHint: true },
              description:
                "List vulnerabilities in a container image with optional filtering by severity",
              inputSchema: zodToJsonSchema(
                images.ListImageVulnerabilitiesSchema
              ),
            },
            {
              name: "get_top_vulnerable_images",
              annotations: { title: "Get Top Vulnerable Images", readOnlyHint: true },
              description: "Get the most vulnerable images from your account",
              inputSchema: zodToJsonSchema(z.object({})),
            },
            {
              name: "get_image_sbom",
              annotations: { title: "Get Image SBOM", readOnlyHint: true },
              description: "Get the SBOM of a container image",
              inputSchema: zodToJsonSchema(images.GetImageSBOMSchema),
            },
            {
              name: "ignore_cve",
              annotations: { title: "Ignore CVE", readOnlyHint: false, destructiveHint: false },
              description:
                "Ignore a CVE for this account so it no longer appears in vulnerability reporting. Use for confirmed false positives, accepted risks, or won't-fix decisions. Do NOT use for remediated CVEs — those drop off automatically on the next scan.",
              inputSchema: zodToJsonSchema(cveDispositions.ignoreCveSchema),
            },
            {
              name: "unignore_cve",
              annotations: { title: "Unignore CVE", readOnlyHint: false, destructiveHint: true },
              description:
                "Remove an account-wide CVE disposition, restoring the CVE to vulnerability reporting.",
              inputSchema: zodToJsonSchema(cveDispositions.unignoreCveSchema),
            },
            {
              name: "list_cve_dispositions",
              annotations: { title: "List CVE Dispositions", readOnlyHint: true },
              description:
                "List active CVE dispositions (ignored / false positive) for this account, with reason and author.",
              inputSchema: zodToJsonSchema(
                cveDispositions.listCveDispositionsSchema
              ),
            },
          ]
        : []),
      // Kubernetes Object tools
      ...(isToolkitEnabled("kubeobject", toolkitFilters)
        ? [
            {
              name: "get_k8s_resource_details",
              annotations: { title: "Get Kubernetes Resource Details", readOnlyHint: true },
              description: "Get the latest manifest of a Kubernetes resource",
              inputSchema: zodToJsonSchema(
                kubeobject.GetKubernetesResourceDetailsSchema
              ),
            },
            {
              name: "list_k8s_resources",
              annotations: { title: "List Kubernetes Resources", readOnlyHint: true },
              description:
                "List Kubernetes resources with optional filtering by namespace, resource types, and cluster",
              inputSchema: zodToJsonSchema(
                kubeobject.ListKubernetesResourcesSchema
              ),
            },
          ]
        : []),
      // Runtime tools
      ...(isToolkitEnabled("runtime", toolkitFilters)
        ? [
            {
              name: "get_containers_process_trees",
              annotations: { title: "Get Container Process Trees", readOnlyHint: true },
              description: "Get process trees for multiple containers",
              inputSchema: zodToJsonSchema(
                runtime.GetContainersProcessTreesSchema
              ),
            },
            {
              name: "get_containers_baselines",
              annotations: { title: "Get Container Baselines", readOnlyHint: true },
              description: "Get runtime baselines for multiple containers",
              inputSchema: zodToJsonSchema(
                runtime.GetContainersBaselinesSchema
              ),
            },
            {
              name: "get_container_llm_analysis",
              annotations: { title: "Get Container LLM Analysis", readOnlyHint: true },
              description: "Get LLM analysis of a container's process tree",
              inputSchema: zodToJsonSchema(
                runtime.GetContainerLLMAnalysisSchema
              ),
            },
          ]
        : []),
      // Findings tools
      ...(isToolkitEnabled("findings", toolkitFilters)
        ? [
            {
              name: "list_security_findings",
              annotations: { title: "List Security Findings", readOnlyHint: true },
              description:
                "List security findings with optional filtering by types, severities, sources, and status",
              inputSchema: zodToJsonSchema(findings.listFindingsSchema),
            },
            {
              name: "update_security_finding_status",
              annotations: { title: "Update Security Finding Status", readOnlyHint: false, destructiveHint: false },
              description: "Update the status of a security finding",
              inputSchema: zodToJsonSchema(findings.updateFindingStatusSchema),
            },
          ]
        : []),
      // Inbox tools
      ...(isToolkitEnabled("inbox", toolkitFilters)
        ? [
            {
              name: "mark_inbox_item_as_false_positive",
              annotations: { title: "Mark Inbox Item as False Positive", readOnlyHint: false, destructiveHint: false },
              description:
                "Mark an inbox item as a false positive with a reason",
              inputSchema: zodToJsonSchema(
                inbox.MarkInboxItemAsFalsePositiveSchema
              ),
            },
            {
              name: "list_inbox_items",
              annotations: { title: "List Inbox Items", readOnlyHint: true },
              description:
                "List inbox items with optional filtering by any field. Multiple filters can be combined eg. 'search:cve-2024-12345 and severity:high'",
              inputSchema: zodToJsonSchema(inbox.ListInboxItemsSchema),
            },
            {
              name: "get_inbox_item_details",
              annotations: { title: "Get Inbox Item Details", readOnlyHint: true },
              description:
                "Get detailed information about a specific inbox item",
              inputSchema: zodToJsonSchema(inbox.GetInboxItemDetailsSchema),
            },
          ]
        : []),
      // Workflows tools
      ...(isToolkitEnabled("workflows", toolkitFilters)
        ? [
            {
              name: "list_workflows",
              annotations: { title: "List Workflows", readOnlyHint: true },
              description: "List all workflows",
              inputSchema: zodToJsonSchema(workflows.ListWorkflowsSchema),
            },
            {
              name: "get_workflow",
              annotations: { title: "Get Workflow", readOnlyHint: true },
              description:
                "Get detailed information about a specific workflow by ID. It contains the workflow definition, default arguments, and schema how to run the workflow",
              inputSchema: zodToJsonSchema(workflows.GetWorkflowSchema),
            },
            {
              name: "list_workflow_runs",
              annotations: { title: "List Workflow Runs", readOnlyHint: true },
              description:
                "List workflow runs with optional filtering by workflow ID",
              inputSchema: zodToJsonSchema(workflows.ListWorkflowRunsSchema),
            },
            {
              name: "get_workflow_run",
              annotations: { title: "Get Workflow Run", readOnlyHint: true },
              description:
                "Get detailed information about a specific workflow run",
              inputSchema: zodToJsonSchema(workflows.GetWorkflowRunSchema),
            },
            {
              name: "run_workflow",
              annotations: { title: "Run Workflow", readOnlyHint: false, destructiveHint: true },
              description: "Run a workflow with optional argument overrides",
              inputSchema: zodToJsonSchema(workflows.RunWorkflowSchema),
            },
            {
              name: "list_workflow_schedules",
              annotations: { title: "List Workflow Schedules", readOnlyHint: true },
              description:
                "List workflow schedules with optional filtering by workflow ID",
              inputSchema: zodToJsonSchema(
                workflows.ListWorkflowSchedulesSchema
              ),
            },
          ]
        : []),
      // Automation authoring tools. These live in the `workflows` toolkit alongside the read
      // tools above — an agent that can inspect automations can also build them.
      //
      // The tool NAMES are a public contract: the web-app's automations builder watches for
      // `create_custom_workflow` / `update_custom_workflow` by name to know a workflow was
      // written, and onboarding provisioning does the same. Do not rename them.
      ...(isToolkitEnabled("workflows", toolkitFilters)
        ? [
            {
              name: "create_custom_workflow",
              annotations: { title: "Create Automation", readOnlyHint: false, destructiveHint: false },
              description:
                "Create a new automation (a Windmill workflow) from a YAML definition. Pass the YAML document itself as a string, not a file path. It is validated server-side before deployment; on failure nothing is deployed and the errors are returned. Returns the new automation WITHOUT echoing the definition back — use `id` from the result when referring to it, and `get_workflow` if you need to read the definition.",
              inputSchema: zodToJsonSchema(
                customWorkflows.CreateCustomWorkflowSchema
              ),
            },
            {
              name: "update_custom_workflow",
              annotations: { title: "Update Automation", readOnlyHint: false, destructiveHint: false },
              description:
                "Update an existing automation with new YAML. Only automations created via create_custom_workflow can be updated. Returns the updated automation without echoing the definition back.",
              inputSchema: zodToJsonSchema(
                customWorkflows.UpdateCustomWorkflowSchema
              ),
            },
            {
              name: "add_workflow_schedule",
              annotations: { title: "Add Automation Schedule", readOnlyHint: false, destructiveHint: false },
              description:
                "Add a cron-based schedule to an automation so it runs automatically at the specified times.",
              inputSchema: zodToJsonSchema(
                customWorkflows.AddWorkflowScheduleSchema
              ),
            },
          ]
        : []),
      // Knowledge Base tools
      ...(isToolkitEnabled("knowledge_base", toolkitFilters)
        ? [
            {
              name: "search_knowledge_base",
              annotations: { title: "Search Knowledge Base", readOnlyHint: true },
              description:
                "Search your organization's knowledge base to find relevant uploaded documents, procedures, reports, and other content using natural language queries",
              inputSchema: zodToJsonSchema(
                knowledgeBase.SearchKnowledgeBaseSchema
              ),
            },
            {
              name: "list_knowledge_base_collections",
              annotations: { title: "List Knowledge Base Collections", readOnlyHint: true },
              description:
                "List all collections in your organization's knowledge base. Collections are used to organize and categorize documents",
              inputSchema: zodToJsonSchema(knowledgeBase.ListCollectionsSchema),
            },
            {
              name: "list_knowledge_base_documents",
              annotations: { title: "List Knowledge Base Documents", readOnlyHint: true },
              description:
                "List documents in your organization's knowledge base with optional filtering by collections, file type, or status",
              inputSchema: zodToJsonSchema(knowledgeBase.ListDocumentsSchema),
            },
            {
              name: "query_knowledge_base_document",
              annotations: { title: "Query Knowledge Base Document", readOnlyHint: true },
              description:
                "Query a CSV document from the knowledge base using natural language. IMPORTANT: This tool ONLY works with CSV documents. Use list_knowledge_base_documents with filters='file_type:csv' to find CSV document IDs (search_knowledge_base results also contain document IDs). Results are returned as a markdown table",
              inputSchema: zodToJsonSchema(
                knowledgeBase.StructuredQueryDocumentSchema
              ),
            },
            {
              name: "get_knowledge_base_document_content",
              annotations: { title: "Get Knowledge Base Document Content", readOnlyHint: true },
              description:
                "Get the FULL text content of a knowledge base document (extracted text for PDF/DOCX, the raw file for markdown/plaintext/CSV). Use this to read or analyze a whole document rather than the excerpts search_knowledge_base returns. Find document IDs via list_knowledge_base_documents or search_knowledge_base results",
              inputSchema: zodToJsonSchema(
                knowledgeBase.GetDocumentContentSchema
              ),
            },
            {
              name: "get_knowledge_base_document_download_url",
              annotations: { title: "Get Knowledge Base Document Download URL", readOnlyHint: true },
              description:
                "Get a time-limited download URL for the ORIGINAL document file (any format, including PDF/DOCX binaries). Use when you need the original file itself — e.g. to fetch it into a sandbox for structural parsing (tables, layout), or when get_knowledge_base_document_content reports no text available. For reading text, prefer get_knowledge_base_document_content",
              inputSchema: zodToJsonSchema(
                knowledgeBase.GetDocumentDownloadUrlSchema
              ),
            },
          ]
        : []),
      // RadQL tools
      ...(isToolkitEnabled("radql", toolkitFilters)
        ? [
            {
              name: "radql_list_data_types",
              annotations: { title: "RadQL: List Data Types", readOnlyHint: true },
              description:
                "List all available RadQL data types (discovery). ALWAYS call this FIRST before using other RadQL tools to discover what data is available to query. Returns data types like 'containers', 'kubernetes_resources', 'inbox_items', 'cloud_resources', 'cloud_benchmarks', 'cloud_benchmark_summaries', etc. with descriptions.",
              inputSchema: zodToJsonSchema(radql.RadQLListDataTypesSchema),
            },
            {
              name: "radql_get_type_metadata",
              annotations: { title: "RadQL: Get Type Metadata", readOnlyHint: true },
              description:
                "Get schema/metadata for a specific RadQL data type. Shows available fields, data types, which fields can be filtered/searched, and provides query examples. Call this AFTER radql_list_data_types to understand how to query a specific data type.",
              inputSchema: zodToJsonSchema(radql.RadQLGetTypeMetadataSchema),
            },
            {
              name: "radql_list_filter_values",
              annotations: { title: "RadQL: List Filter Values", readOnlyHint: true },
              description:
                "List possible values for a filter field (e.g., namespace list, cluster list, severity values). Useful for building dynamic filters when you need to know available enum-like values. Call this when constructing filters that need specific values.",
              inputSchema: zodToJsonSchema(radql.RadQLListFilterValuesSchema),
            },
            {
              name: "radql_query",
              annotations: { title: "RadQL: Query", readOnlyHint: true },
              description: `Execute RadQL queries for security investigations. Supports: list (filter/search), get_by_id (single item), stats (aggregations).

WORKFLOW: radql_list_data_types -> radql_get_type_metadata -> radql_query

COMMON FIELDS BY DATA TYPE:
containers: name, image_name, image_repo, owner_kind, cluster_id, created_at
  Example: image_name:*nginx* AND owner_kind:Pod

finding_groups: type, source_kind, source_name, rule_title, severity, event_timestamp
  Types: k8s_misconfiguration, k8s_audit_logs_anomaly
  Example: type:k8s_misconfiguration AND severity:critical

inbox_items: severity (High|Medium|Low), type, title, archived, false_positive, created_at
  Example: severity:High AND archived:false

kubernetes_resources: kind, name, namespace, cluster_id, owner_kind, created_at
  Example: kind:Deployment AND namespace:production

CLOUD RESOURCES & COMPLIANCE (use these RadQL data types instead of dedicated cloud tools):
cloud_resources: cloud_provider, cloud_account_id, resource_type, resource_name, resource_id, resource_json, last_seen_at
  Example: cloud_provider:aws AND resource_type:aws_iam_policy

cloud_benchmark_summaries: cloud_provider, cloud_account_id, benchmark_id, title, description, fail_count, pass_count, total_count, last_seen_at
  Example: cloud_provider:aws AND fail_count>0

cloud_benchmarks: cloud_provider, cloud_account_id, benchmark_id, control_id, control_title, severity, status, reason, resource_id, last_seen_at
  Example: status:fail AND benchmark_id:*cis*

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
              annotations: { title: "RadQL: Query Builder", readOnlyHint: true },
              description:
                "Helper tool to build RadQL queries programmatically from structured conditions. Useful when you need to construct complex filter or stats queries from structured inputs.",
              inputSchema: zodToJsonSchema(radql.RadQLQueryBuilderSchema),
            },
            {
              name: "radql_batch_query",
              annotations: { title: "RadQL: Batch Query", readOnlyHint: true },
              description:
                "Execute multiple RadQL queries in parallel for efficiency. Useful for fetching related data from different data types simultaneously (e.g., container details + vulnerabilities + network connections).",
              inputSchema: zodToJsonSchema(radql.RadQLBatchQuerySchema),
            },
          ]
        : []),
      // Dashboards tools
      ...(isToolkitEnabled("dashboards", toolkitFilters)
        ? [
            {
              name: "list_widget_templates",
              annotations: { title: "List Widget Templates", readOnlyHint: true },
              description:
                "List widget templates with optional filtering by visualization type and category",
              inputSchema: zodToJsonSchema(
                dashboards.ListWidgetTemplatesSchema
              ),
            },
            {
              name: "get_widget_template",
              annotations: { title: "Get Widget Template", readOnlyHint: true },
              description:
                "Get detailed information about a specific widget template",
              inputSchema: zodToJsonSchema(dashboards.GetWidgetTemplateSchema),
            },
            {
              name: "list_dashboard_templates",
              annotations: { title: "List Dashboard Templates", readOnlyHint: true },
              description:
                "List dashboard templates with optional filtering by category",
              inputSchema: zodToJsonSchema(
                dashboards.ListDashboardTemplatesSchema
              ),
            },
            {
              name: "get_dashboard_template",
              annotations: { title: "Get Dashboard Template", readOnlyHint: true },
              description:
                "Get detailed information about a specific dashboard template",
              inputSchema: zodToJsonSchema(
                dashboards.GetDashboardTemplateSchema
              ),
            },
            {
              name: "list_dashboards",
              annotations: { title: "List Dashboards", readOnlyHint: true },
              description: "List dashboards for the account",
              inputSchema: zodToJsonSchema(dashboards.ListDashboardsSchema),
            },
            {
              name: "get_dashboard",
              annotations: { title: "Get Dashboard", readOnlyHint: true },
              description:
                "Get detailed information about a specific dashboard",
              inputSchema: zodToJsonSchema(dashboards.GetDashboardSchema),
            },
            {
              name: "create_dashboard",
              annotations: { title: "Create Dashboard", readOnlyHint: false, destructiveHint: false },
              description:
                "Create a dashboard for the account. Build `rows` from the widget templates (list_widget_templates / get_widget_template) so the visualization and query shapes are valid.",
              inputSchema: zodToJsonSchema(dashboards.CreateDashboardSchema),
            },
            {
              name: "update_dashboard",
              annotations: { title: "Update Dashboard", readOnlyHint: false, destructiveHint: false },
              description:
                "Update an existing dashboard. Omitted fields are left unchanged, so a small edit (a title, one row) does not require resending the whole dashboard.",
              inputSchema: zodToJsonSchema(dashboards.UpdateDashboardSchema),
            },
          ]
        : []),
      // Integrations tools
      ...(isToolkitEnabled("integrations", toolkitFilters)
        ? [
            {
              name: "list_external_integrations",
              annotations: { title: "List External Integrations", readOnlyHint: true },
              description:
                "List external integrations configured for the tenant (e.g., Slack, AWS CloudTrail, Okta). Returns integration details including capabilities, configuration, mcp support and sync status.",
              inputSchema: zodToJsonSchema(
                integrations.ListExternalIntegrationsSchema
              ),
            },
          ]
        : []),
    ];

  // In read-only mode, expose only tools whose readOnlyHint is true.
  const tools = toolkitFilters.readonly
    ? allTools.filter(
        (t) =>
          (t as { annotations?: { readOnlyHint?: boolean } }).annotations
            ?.readOnlyHint === true
      )
    : allTools;
  // The advertised set is also the allowed set — CallTool enforces it below.
  const enabledToolNames = new Set(
    tools.map((t) => (t as { name: string }).name)
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

  server.setRequestHandler(
    CallToolRequestSchema,
    async (request: CallToolRequest) => {
      const startTime = Date.now();
      const toolName = request.params.name;

      try {
        if (!enabledToolNames.has(toolName)) {
          throw new Error(
            `Tool "${toolName}" is not enabled for this session`
          );
        }
        if (!request.params.arguments) {
          throw new Error("Arguments are required");
        }

        logger.info(
          {
            tool: toolName,
            account_id: client.getAccountId(),
            arguments: request.params.arguments,
          },
          "tool_invoked"
        );

        switch (toolName) {
          // Container tools
          case "list_containers": {
            const args = containers.ListContainersSchema.parse(
              request.params.arguments
            );
            const response = await containers.listContainers(
              client,
              args.offset,
              args.limit,
              args.filters,
              args.q
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "get_container_details": {
            const args = containers.GetContainerDetailsSchema.parse(
              request.params.arguments
            );
            const response = await containers.getContainerDetails(
              client,
              args.container_id
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          // Cluster tools
          case "list_clusters": {
            const args = clusters.ListClustersSchema.parse(
              request.params.arguments
            );
            const response = await clusters.listClusters(
              client,
              args.page_size,
              args.page
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "get_cluster_details": {
            const args = clusters.GetClusterDetailsSchema.parse(
              request.params.arguments
            );
            const response = await clusters.getClusterDetails(
              client,
              args.cluster_id
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          // Audit tools
          case "who_shelled_into_pod": {
            const args = audit.WhoShelledIntoPodSchema.parse(
              request.params.arguments
            );
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
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          // Image tools
          case "list_images": {
            const args = images.ListImagesSchema.parse(
              request.params.arguments
            );
            const response = await images.listImages(
              client,
              args.limit,
              args.offset,
              args.sort,
              args.filters,
              args.q
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "list_image_vulnerabilities": {
            const args = images.ListImageVulnerabilitiesSchema.parse(
              request.params.arguments
            );
            const response = await images.listImageVulnerabilities(
              client,
              args.digest,
              args.severities,
              args.page,
              args.page_size
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "get_top_vulnerable_images": {
            const response = await images.getTopVulnerableImages(client);
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "get_image_sbom": {
            const args = images.GetImageSBOMSchema.parse(
              request.params.arguments
            );
            const response = await images.getImageSBOM(client, args.digest);
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "ignore_cve": {
            const args = cveDispositions.ignoreCveSchema.parse(
              request.params.arguments
            );
            const response = await cveDispositions.ignoreCve(client, args);
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "unignore_cve": {
            const args = cveDispositions.unignoreCveSchema.parse(
              request.params.arguments
            );
            const response = await cveDispositions.unignoreCve(
              client,
              args.cve_name
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "list_cve_dispositions": {
            cveDispositions.listCveDispositionsSchema.parse(
              request.params.arguments
            );
            const response = await cveDispositions.listCveDispositions(client);
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          // Kubernetes Objects tools
          case "get_k8s_resource_details": {
            const args = kubeobject.GetKubernetesResourceDetailsSchema.parse(
              request.params.arguments
            );
            const response = await kubeobject.getKubernetesResourceDetails(
              client,
              args.cluster_id,
              args.resource_uid
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "list_k8s_resources": {
            const args = kubeobject.ListKubernetesResourcesSchema.parse(
              request.params.arguments
            );
            const response = await kubeobject.listKubernetesResources(
              client,
              args.kinds,
              args.namespace,
              args.cluster_id,
              args.page,
              args.page_size
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          // Runtime tools
          case "get_containers_process_trees": {
            const args = runtime.GetContainersProcessTreesSchema.parse(
              request.params.arguments
            );
            const response = await runtime.getContainersProcessTrees(
              client,
              args.container_ids,
              args.processes_limit
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "get_containers_baselines": {
            const args = runtime.GetContainersBaselinesSchema.parse(
              request.params.arguments
            );
            const response = await runtime.getContainersBaselines(
              client,
              args.container_ids
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "get_container_llm_analysis": {
            const args = runtime.GetContainerLLMAnalysisSchema.parse(
              request.params.arguments
            );
            const response = await runtime.getContainerLLMAnalysis(
              client,
              args.container_id
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          // Findings tools
          case "list_security_findings": {
            const args = findings.listFindingsSchema.parse(
              request.params.arguments
            );
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
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "update_security_finding_status": {
            const args = findings.updateFindingStatusSchema.parse(
              request.params.arguments
            );
            await findings.updateFindingGroupStatus(
              client,
              args.id,
              args.status
            );
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(
                    {
                      success: true,
                      message: `Finding ${args.id} status updated to ${args.status}`,
                    },
                    null,
                    2
                  ),
                },
              ],
            };
          }
          // Inbox tools
          case "mark_inbox_item_as_false_positive": {
            const args = inbox.MarkInboxItemAsFalsePositiveSchema.parse(
              request.params.arguments
            );
            const response = await inbox.markInboxItemAsFalsePositive(
              client,
              args.inbox_item_id,
              args.value,
              args.reason
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "list_inbox_items": {
            const args = inbox.ListInboxItemsSchema.parse(
              request.params.arguments
            );
            const response = await inbox.listInboxItems(
              client,
              args.limit,
              args.offset,
              args.filters_query
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "get_inbox_item_details": {
            const args = inbox.GetInboxItemDetailsSchema.parse(
              request.params.arguments
            );
            const response = await inbox.getInboxItemDetails(
              client,
              args.inbox_item_id
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          // Workflows tools
          case "list_workflows": {
            workflows.ListWorkflowsSchema.parse(request.params.arguments);
            const response = await workflows.listWorkflows(client);
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "get_workflow": {
            const args = workflows.GetWorkflowSchema.parse(
              request.params.arguments
            );
            const response = await workflows.getWorkflow(
              client,
              args.workflow_id
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "list_workflow_runs": {
            const args = workflows.ListWorkflowRunsSchema.parse(
              request.params.arguments
            );
            const response = await workflows.listWorkflowRuns(
              client,
              args.workflow_id
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "get_workflow_run": {
            const args = workflows.GetWorkflowRunSchema.parse(
              request.params.arguments
            );
            const response = await workflows.getWorkflowRun(
              client,
              args.workflow_id,
              args.run_id
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "run_workflow": {
            const args = workflows.RunWorkflowSchema.parse(
              request.params.arguments
            );
            const response = await workflows.runWorkflow(
              client,
              args.workflow_id,
              args.async,
              args.args
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "list_workflow_schedules": {
            const args = workflows.ListWorkflowSchedulesSchema.parse(
              request.params.arguments
            );
            const response = await workflows.listWorkflowSchedules(
              client,
              args.workflow_id
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          // Custom Workflows tools
          case "create_custom_workflow": {
            const args = customWorkflows.CreateCustomWorkflowSchema.parse(
              request.params.arguments
            );
            const response = await customWorkflows.createCustomWorkflow(client, args);
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "update_custom_workflow": {
            const args = customWorkflows.UpdateCustomWorkflowSchema.parse(
              request.params.arguments
            );
            const response = await customWorkflows.updateCustomWorkflow(
              client,
              args.workflow_id,
              args
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "add_workflow_schedule": {
            const args = customWorkflows.AddWorkflowScheduleSchema.parse(
              request.params.arguments
            );
            const response = await customWorkflows.addWorkflowSchedule(
              client,
              args.workflow_id,
              args.schedule,
              args.timezone
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          // Knowledge Base tools
          case "search_knowledge_base": {
            const args = knowledgeBase.SearchKnowledgeBaseSchema.parse(
              request.params.arguments
            );
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
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "list_knowledge_base_collections": {
            const args = knowledgeBase.ListCollectionsSchema.parse(
              request.params.arguments
            );
            const response = await knowledgeBase.listCollections(
              client,
              args.limit,
              args.offset
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "list_knowledge_base_documents": {
            const args = knowledgeBase.ListDocumentsSchema.parse(
              request.params.arguments
            );
            const response = await knowledgeBase.listDocuments(
              client,
              args.limit,
              args.offset,
              args.filters
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "query_knowledge_base_document": {
            const args = knowledgeBase.StructuredQueryDocumentSchema.parse(
              request.params.arguments
            );
            const response = await knowledgeBase.structuredQueryDocument(
              client,
              args.document_id,
              args.query
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "get_knowledge_base_document_content": {
            const args = knowledgeBase.GetDocumentContentSchema.parse(
              request.params.arguments
            );
            const response = await knowledgeBase.getDocumentContent(
              client,
              args.document_id
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "get_knowledge_base_document_download_url": {
            const args = knowledgeBase.GetDocumentDownloadUrlSchema.parse(
              request.params.arguments
            );
            const response = await knowledgeBase.getDocumentDownloadUrl(
              client,
              args.document_id
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          // RadQL tools
          case "radql_list_data_types": {
            const response = await radql.executeListDataTypes(client);
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "radql_get_type_metadata": {
            const args = radql.RadQLGetTypeMetadataSchema.parse(
              request.params.arguments
            );
            const response = await radql.executeGetTypeMetadata(client, args);
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "radql_list_filter_values": {
            const args = radql.RadQLListFilterValuesSchema.parse(
              request.params.arguments
            );
            const response = await radql.executeListFilterValues(client, args);
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "radql_query": {
            const args = radql.RadQLQuerySchema.parse(request.params.arguments);
            const response = await radql.executeRadQLQuery(client, args);
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "radql_query_builder": {
            const args = radql.RadQLQueryBuilderSchema.parse(
              request.params.arguments
            );
            const response = radql.buildRadQLQuery(args);
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "radql_batch_query": {
            const args = radql.RadQLBatchQuerySchema.parse(
              request.params.arguments
            );
            const response = await radql.executeBatchQueries(client, args);
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          // Dashboards tools
          case "list_widget_templates": {
            const args = dashboards.ListWidgetTemplatesSchema.parse(
              request.params.arguments
            );
            const response = await dashboards.listWidgetTemplates(
              client,
              args.limit,
              args.offset,
              args.visualization_type,
              args.category
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "get_widget_template": {
            const args = dashboards.GetWidgetTemplateSchema.parse(
              request.params.arguments
            );
            const response = await dashboards.getWidgetTemplate(
              client,
              args.widget_template_id
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "list_dashboard_templates": {
            const args = dashboards.ListDashboardTemplatesSchema.parse(
              request.params.arguments
            );
            const response = await dashboards.listDashboardTemplates(
              client,
              args.limit,
              args.offset,
              args.category
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "get_dashboard_template": {
            const args = dashboards.GetDashboardTemplateSchema.parse(
              request.params.arguments
            );
            const response = await dashboards.getDashboardTemplate(
              client,
              args.dashboard_template_id
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "list_dashboards": {
            const args = dashboards.ListDashboardsSchema.parse(
              request.params.arguments
            );
            const response = await dashboards.listDashboards(
              client,
              args.limit,
              args.offset
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "get_dashboard": {
            const args = dashboards.GetDashboardSchema.parse(
              request.params.arguments
            );
            const response = await dashboards.getDashboard(
              client,
              args.dashboard_id
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "create_dashboard": {
            const args = dashboards.CreateDashboardSchema.parse(
              request.params.arguments
            );
            const response = await dashboards.createDashboard(client, args);
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          case "update_dashboard": {
            const { dashboard_id, ...changes } =
              dashboards.UpdateDashboardSchema.parse(request.params.arguments);
            const response = await dashboards.updateDashboard(
              client,
              dashboard_id,
              changes
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          // Integrations tools
          case "list_external_integrations": {
            const args = integrations.ListExternalIntegrationsSchema.parse(
              request.params.arguments
            );
            const response = await integrations.listExternalIntegrations(
              client,
              args.offset,
              args.limit
            );
            return {
              content: [
                { type: "text", text: JSON.stringify(response, null, 2) },
              ],
            };
          }
          default:
            throw new Error(`Unknown tool: ${toolName}`);
        }

        const duration = Date.now() - startTime;
        logger.info(
          {
            tool: toolName,
            account_id: client.getAccountId(),
            duration_ms: duration,
          },
          "tool_execution_completed"
        );
      } catch (error) {
        const duration = Date.now() - startTime;
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        logger.error(
          {
            tool: toolName,
            account_id: client.getAccountId(),
            error: errorMessage,
            duration_ms: duration,
          },
          "tool_execution_failed"
        );

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

/**
 * Resolve the Rad Security client for an inbound HTTP request.
 *  - "header" mode: credentials come from the request's Authorization header
 *    (multi-tenant). A missing/malformed header throws CredentialError → 401.
 *  - "env" mode (default): process-env credentials, single-tenant. Backwards
 *    compatible with existing self-hosted and per-account-pod deployments.
 */
function clientForRequest(
  req: express.Request,
  authMode: string
): RadSecurityClient {
  if (authMode === "header") {
    return RadSecurityClient.fromAuthHeader(req.headers["authorization"]);
  }
  return RadSecurityClient.fromEnv();
}

async function main() {
  try {
    const transportType = process.env.TRANSPORT_TYPE || "stdio";
    if (!["stdio", "sse", "streamable"].includes(transportType)) {
      throw new Error(
        "Transport type must be either 'stdio', 'sse' or 'streamable'"
      );
    }

    // Inbound authentication mode for the HTTP transports.
    //  - "env":    single set of process-env credentials (default, backwards compatible)
    //  - "header": per-request credentials from the Authorization header (multi-tenant)
    const authMode = (process.env.MCP_AUTH_MODE || "env").toLowerCase();
    if (!["env", "header"].includes(authMode)) {
      throw new Error("MCP_AUTH_MODE must be either 'env' or 'header'");
    }

    // Log server startup
    logger.info(
      {
        version: VERSION,
        transport: transportType,
        auth_mode: authMode,
        node_version: process.version,
      },
      "server_starting"
    );

    // Header auth is only enforced on the streamable transport. Fail loud rather
    // than silently serving unauthenticated traffic in a mode the operator
    // believes is protected.
    if (authMode === "header" && transportType !== "streamable") {
      throw new Error(
        "MCP_AUTH_MODE=header is only supported with TRANSPORT_TYPE=streamable"
      );
    }

    // Log toolkit filters if set
    const filters = parseToolkitFilters();
    if (filters.include && filters.include.length > 0) {
      logger.info(
        { mode: "include", toolkits: filters.include },
        "toolkit_filter_configured"
      );
    } else if (filters.exclude && filters.exclude.length > 0) {
      logger.info(
        { mode: "exclude", toolkits: filters.exclude },
        "toolkit_filter_configured"
      );
    } else {
      logger.info("toolkit_all_enabled");
    }

    if (transportType === "stdio") {
      const transport = new StdioServerTransport();
      const server = await newServer(
        RadSecurityClient.fromEnv(),
        parseToolkitFilters()
      );
      await server.connect(transport);
      logger.info({ transport: "stdio" }, "server_ready");
    } else if (transportType === "sse") {
      // SSE is deprecated in favour of the streamable transport, and does not
      // support per-request (header) authentication — it always uses process-env
      // credentials. Use TRANSPORT_TYPE=streamable for multi-tenant deployments.
      logger.warn(
        { transport: "sse" },
        "sse_transport_deprecated_use_streamable"
      );

      const app = express();
      app.use(
        cors({
          origin: "*",
          methods: ["GET", "POST", "OPTIONS", "HEAD"],
          allowedHeaders: ["Content-Type"],
        })
      );

      // Liveness/readiness probe — always 200, no auth (used by Kubernetes
      // probes; the backend-v2 chart's startupProbe hits GET /healthz).
      app.get("/healthz", (_req, res) => {
        res.status(200).json({ status: "ok" });
      });

      // Map to store transports by session ID so concurrent SSE clients don't
      // clobber each other (each connection gets its own transport + server).
      const transports: { [sessionId: string]: SSEServerTransport } = {};

      app.head("/sse", async (req, res) => {
        res.sendStatus(200);
      });
      app.head("/messages", async (req, res) => {
        res.sendStatus(200);
      });

      app.get("/sse", async (req, res) => {
        const transport = new SSEServerTransport("/messages", res);
        transports[transport.sessionId] = transport;

        // Clean up when the client disconnects
        transport.onclose = () => {
          delete transports[transport.sessionId];
        };

        const server = await newServer(
          RadSecurityClient.fromEnv(),
          parseToolkitFilters()
        );
        await server.connect(transport);
      });

      app.post("/messages", async (req, res) => {
        const sessionId = req.query.sessionId as string | undefined;
        const transport = sessionId ? transports[sessionId] : undefined;
        if (!transport) {
          res.status(400).send("No transport found for the provided sessionId");
          return;
        }
        await transport.handlePostMessage(req, res);
      });

      const port = process.env.PORT || 3000;
      app.listen(port, () => {
        logger.info(
          { transport: "sse", url: `http://localhost:${port}/sse` },
          "server_ready"
        );
      });
    } else if (transportType === "streamable") {
      const app = express();
      app.use(express.json());
      app.use(
        cors({
          origin: "*",
          methods: ["GET", "POST", "OPTIONS", "HEAD", "DELETE"],
          allowedHeaders: [
            "Content-Type",
            "Authorization",
            "mcp-session-id",
            "mcp-protocol-version",
            "X-Rad-Toolkits",
            "X-Rad-Exclude-Toolkits",
            "X-Rad-Readonly",
          ],
          exposedHeaders: ["mcp-session-id"],
        })
      );

      // Liveness/readiness probe — always 200, no auth (used by Kubernetes
      // probes; the backend-v2 chart's startupProbe hits GET /healthz).
      app.get("/healthz", (_req, res) => {
        res.status(200).json({ status: "ok" });
      });

      // Stateless: a transport and server are built per request and torn down with it.
      //
      // The previous shape kept `transports[sessionId]` in process memory, so a follow-up request
      // that landed on another replica found nothing and failed. That pinned this deployment to a
      // single pod, which means a node drain takes the hosted MCP server down for every agent
      // using it. Nothing here is worth keeping between requests: credentials arrive per request
      // (MCP_AUTH_MODE=header) and so do the toolkit filters, so every call already describes
      // itself. Statelessness lets any request land on any replica behind a plain round-robin
      // service, with no sticky sessions and no shared store.
      //
      // This is the SDK's documented stateless mode (`sessionIdGenerator: undefined`), and it is
      // also the shape the 2026-07-28 MCP spec assumes now that protocol-level sessions are gone.
      app.post("/mcp", async (req, res) => {
        // Resolve credentials first so an unauthenticated caller gets a 401 rather than a
        // half-built server.
        let client: RadSecurityClient;
        try {
          client = clientForRequest(req, authMode);
        } catch (err) {
          if (err instanceof CredentialError) {
            res
              .status(401)
              .set(
                "WWW-Authenticate",
                `Bearer error="invalid_token", error_description="${err.message}"`
              )
              .json({
                jsonrpc: "2.0",
                error: { code: -32001, message: err.message },
                id: null,
              });
            return;
          }
          throw err;
        }

        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: undefined,
        });
        const server = await newServer(client, toolkitFiltersForRequest(req));

        // Tear both down when the response ends, however it ends. Without this every request
        // leaks a Server and its transport — which matters far more now that one is built per
        // call rather than per session.
        res.on("close", () => {
          void transport.close();
          void server.close();
        });

        await server.connect(transport);
        await transport.handleRequest(req, res, req.body);
      });

      // GET opens a server-to-client SSE stream and DELETE terminates a session. Both are session
      // concepts and there are no sessions here, so answer with 405 and a reason rather than a
      // 400 about a missing session id that can never be satisfied.
      const noSessionEndpoint = (_req: express.Request, res: express.Response) => {
        res
          .status(405)
          .set("Allow", "POST")
          .json({
            jsonrpc: "2.0",
            error: {
              code: -32000,
              message:
                "This server is stateless: no sessions and no server-initiated stream. Send requests as POST /mcp.",
            },
            id: null,
          });
      };

      app.get("/mcp", noSessionEndpoint);
      app.delete("/mcp", noSessionEndpoint);

      const port = process.env.PORT || 3000;
      app.listen(port, () => {
        logger.info(
          { transport: "streamable", url: `http://localhost:${port}/mcp` },
          "server_ready"
        );
      });
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.fatal({ error: errorMessage }, "server_startup_failed");
    process.exit(1);
  }
}

main().catch((error) => {
  const errorMessage = error instanceof Error ? error.message : String(error);
  logger.fatal({ error: errorMessage }, "server_error_unhandled");
  process.exit(1);
});
