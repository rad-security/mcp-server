import { z } from "zod";
import { RadSecurityClient } from "../client.js";

// ============================================================================
// Schema Definitions
// ============================================================================

/**
 * Schema for listing available data types (discovery)
 */
export const RadQLListDataTypesSchema = z.object({}).describe(
  "List all available RadQL data types. Returns data types with descriptions. ALWAYS call this FIRST to discover what data is available."
);

/**
 * Schema for getting metadata about a specific data type (schema discovery)
 */
export const RadQLGetTypeMetadataSchema = z.object({
  data_type: z.string()
    .describe("The data type to get metadata for (e.g., 'containers', 'kubernetes_resources', 'inbox_items'). Call radql_list_data_types first to see available types.")
}).describe(
  "Get schema/metadata for a specific RadQL data type. Returns available fields, types, and query examples. Call this AFTER radql_list_data_types to understand how to query a data type."
);

/**
 * Schema for listing filter values for a field (enum discovery)
 */
export const RadQLListFilterValuesSchema = z.object({
  data_type: z.string()
    .describe("The data type (e.g., 'containers', 'kubernetes_resources')"),

  filter_name: z.string()
    .describe("The filter field name to get possible values for (e.g., 'namespace', 'cluster_id', 'severity')")
}).describe(
  "List possible values for a filter field. Useful for discovering available namespaces, clusters, severities, etc. Call this when building dynamic filters."
);

/**
 * Main RadQL query schema for executing queries against the Data API
 */
export const RadQLQuerySchema = z.object({
  data_type: z.string()
    .describe("The data type to query (e.g., 'containers', 'kubernetes_resources', 'inbox_items'). Use radql_list_data_types to discover available types."),

  operation: z.enum([
    "list",
    "get_by_id",
    "stats"
  ]).describe("The operation to perform: 'list' for filtering/searching, 'get_by_id' for single item, 'stats' for aggregations"),

  filters_query: z.string().optional()
    .describe("RadQL filter query (e.g., 'severity:High AND type:misconfiguration'). Used for filtering results."),

  stats_query: z.string().optional()
    .describe("RadQL analytics query (e.g., 'count() by severity'). Used for aggregations and grouping."),

  id: z.string().optional()
    .describe("The ID of a specific item to retrieve (for get_by_id operation)"),

  limit: z.number().optional().default(20)
    .describe("Maximum number of results to return"),

  offset: z.number().optional().default(0)
    .describe("Pagination offset"),

  include_relations: z.array(z.string()).optional()
    .describe("Relations to include (e.g., ['owner'] for containers to include Kubernetes owner resource)")
});

/**
 * Helper schema for building RadQL queries programmatically
 */
export const RadQLQueryBuilderSchema = z.object({
  data_type: z.string()
    .describe("The data type to build a query for"),

  conditions: z.array(z.object({
    field: z.string(),
    operator: z.enum([":", "=", "!=", "!:", "<>", ">", ">=", "<", "<=", "contains", "starts_with", "ends_with"]),
    value: z.union([z.string(), z.number(), z.boolean()]),
    negate: z.boolean().optional()
  })).optional()
    .describe("Filter conditions to combine into a RadQL query"),

  logic: z.enum(["AND", "OR"]).optional().default("AND")
    .describe("Logical operator to combine conditions"),

  aggregation: z.enum(["count", "sum", "avg", "min", "max", "median"]).optional()
    .describe("Aggregation function to apply"),

  aggregate_field: z.string().optional()
    .describe("Field to aggregate (omit for count(*))"),

  group_by: z.array(z.string()).optional()
    .describe("Fields to group by"),

  time_group: z.enum(["second", "minute", "hour", "day", "month", "year"]).optional()
    .describe("Time-based grouping interval for datetime fields")
});

/**
 * Batch query schema for executing multiple queries in parallel
 */
export const RadQLBatchQuerySchema = z.object({
  queries: z.array(RadQLQuerySchema).max(10)
    .describe("Array of queries to execute in parallel (max 10)")
});

// ============================================================================
// Core Functions
// ============================================================================

/**
 * List all available data types that can be queried
 */
export async function listDataTypes(
  client: RadSecurityClient
): Promise<any> {
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/data/types`
  );

  return {
    available_types: Array.isArray(response) ? response : response.available_types || [],
    hint: "Use radql_get_type_metadata with a specific data_type to see available fields and filtering options"
  };
}

/**
 * Get metadata for a specific data type including available fields
 */
export async function getDataTypeMetadata(
  client: RadSecurityClient,
  dataType: string
): Promise<any> {
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/data/${dataType}/meta`
  );

  return {
    ...response,
    radql_examples: generateRadQLExamples(dataType, response.fields || [])
  };
}

/**
 * List data items with optional filtering
 */
async function listDataItems(
  client: RadSecurityClient,
  dataType: string,
  params: any
): Promise<any> {
  const queryParams: Record<string, any> = {
    limit: params.limit,
    offset: params.offset
  };

  if (params.filters_query) queryParams.filters_query = params.filters_query;

  if (params.include_relations && params.include_relations.length > 0) {
    queryParams.include_relations = params.include_relations.join(",");
  }

  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/data/${dataType}`,
    queryParams
  );

  return {
    query_explanation: explainRadQLQuery(params.filters_query),
    total_count: response.total_count || 0,
    returned_count: response.items?.length || 0,
    data: response.items || [],
    fields: response.fields || [],
    applied_filters: params.filters_query || "none",
    pagination: {
      limit: params.limit,
      offset: params.offset,
      has_more: response.has_more || false
    }
  };
}

/**
 * Get a single data item by ID
 */
async function getDataItemById(
  client: RadSecurityClient,
  dataType: string,
  id: string
): Promise<any> {
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/data/${dataType}/${id}`
  );

  return {
    data: response.data,
    fields: response.fields || [],
    data_type: dataType,
    id: id
  };
}

/**
 * Get aggregated statistics for a data type
 */
async function getDataStats(
  client: RadSecurityClient,
  dataType: string,
  params: any
): Promise<any> {
  const queryParams: Record<string, any> = {
    stats_query: params.stats_query
  };

  if (params.filters_query) queryParams.filters_query = params.filters_query;
  if (params.limit) queryParams.limit = params.limit;
  if (params.offset) queryParams.offset = params.offset;

  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/data/stats/${dataType}`,
    queryParams
  );

  return {
    query_explanation: explainStatsQuery(params.stats_query),
    stats_query: params.stats_query,
    applied_filters: params.filters_query || "none",
    results: response.items || [],
    fields: response.fields || [],
    total_count: response.total_count || 0,
    returned_count: response.items?.length || 0,
    has_more: response.has_more || false
  };
}

/**
 * List available values for a specific filter field
 */
async function listFilterValues(
  client: RadSecurityClient,
  dataType: string,
  filterName: string
): Promise<any> {
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/data/${dataType}/filters/${filterName}/values`
  );

  // Extract values from nested API response structure
  // API returns: { values: { items: [{data: {value, count}}] } }
  const items = response.values?.items || [];
  const values = items.map((item: any) => ({
    value: item.data?.value,
    count: item.data?.count
  }));

  return {
    data_type: dataType,
    filter_name: filterName,
    values: values,
    total_count: response.values?.total_count || 0,
    has_more: response.values?.has_more || false,
    hint: `Use these values in your filters_query like: ${filterName}:value`
  };
}

/**
 * Main function to execute RadQL queries (list, get_by_id, stats)
 */
export async function executeRadQLQuery(
  client: RadSecurityClient,
  args: z.infer<typeof RadQLQuerySchema>
): Promise<any> {
  const { operation, data_type, ...params } = args;

  try {
    switch (operation) {
      case "list":
        return await listDataItems(client, data_type, params);

      case "get_by_id":
        if (!params.id) {
          throw new Error("id is required for get_by_id operation");
        }
        return await getDataItemById(client, data_type, params.id);

      case "stats":
        if (!params.stats_query) {
          throw new Error("stats_query is required for stats operation");
        }
        return await getDataStats(client, data_type, params);

      default:
        throw new Error(`Unknown operation: ${operation}`);
    }
  } catch (error: any) {
    throw handleRadQLError(error, data_type);
  }
}

/**
 * Wrapper for listing data types (discovery tool)
 */
export async function executeListDataTypes(
  client: RadSecurityClient
): Promise<any> {
  return await listDataTypes(client);
}

/**
 * Wrapper for getting type metadata (schema discovery tool)
 */
export async function executeGetTypeMetadata(
  client: RadSecurityClient,
  args: z.infer<typeof RadQLGetTypeMetadataSchema>
): Promise<any> {
  return await getDataTypeMetadata(client, args.data_type);
}

/**
 * Wrapper for listing filter values (enum discovery tool)
 */
export async function executeListFilterValues(
  client: RadSecurityClient,
  args: z.infer<typeof RadQLListFilterValuesSchema>
): Promise<any> {
  return await listFilterValues(client, args.data_type, args.filter_name);
}

/**
 * Build RadQL queries programmatically from structured conditions
 */
export function buildRadQLQuery(
  args: z.infer<typeof RadQLQueryBuilderSchema>
): { filters_query?: string; stats_query?: string } {
  const result: { filters_query?: string; stats_query?: string } = {};

  if (args.conditions && args.conditions.length > 0) {
    const conditions = args.conditions.map(cond => {
      let query = "";

      if (cond.negate) {
        query += "NOT ";
      }

      query += cond.field;

      // Map operator to RadQL syntax
      if (cond.operator === "contains") {
        // Quote wildcard values if they contain special characters
        const needsQuoting = typeof cond.value === "string" && (
          cond.value.includes("-") || cond.value.includes(" ") || cond.value.includes(":")
        );
        const valueStr = needsQuoting ? `"*${cond.value}*"` : `*${cond.value}*`;
        query += `:${valueStr}`;
      } else if (cond.operator === "starts_with") {
        const needsQuoting = typeof cond.value === "string" && (
          cond.value.includes("-") || cond.value.includes(" ") || cond.value.includes(":")
        );
        const valueStr = needsQuoting ? `"${cond.value}*"` : `${cond.value}*`;
        query += `:${valueStr}`;
      } else if (cond.operator === "ends_with") {
        const needsQuoting = typeof cond.value === "string" && (
          cond.value.includes("-") || cond.value.includes(" ") || cond.value.includes(":")
        );
        const valueStr = needsQuoting ? `"*${cond.value}"` : `*${cond.value}`;
        query += `:${valueStr}`;
      } else {
        // Quote string values to handle dates, hyphens, and special characters
        // The RadQL parser requires quoting for:
        // - Dates/timestamps (contain hyphens): "2024-01-01"
        // - UUIDs (contain hyphens): "550e8400-e29b-41d4-a716-446655440000"
        // - Strings with special characters: colons, spaces, etc.
        // - Any value that's not a simple alphanumeric string
        const value = cond.value;
        let valueStr: string;

        if (typeof value === "string") {
          // Check if the string needs quoting
          // Quote if it contains: spaces, hyphens, colons, or other special chars
          // Or if it looks like a date/timestamp
          const needsQuoting =
            value.includes(" ") ||
            value.includes("-") ||
            value.includes(":") ||
            value.includes("(") ||
            value.includes(")") ||
            /^\d{4}-\d{2}-\d{2}/.test(value) ||
            /[<>=!]/.test(value);

          valueStr = needsQuoting ? `"${value}"` : value;
        } else {
          valueStr = String(value);
        }

        query += `${cond.operator}${valueStr}`;
      }

      return query;
    });

    result.filters_query = conditions.join(` ${args.logic} `);
  }

  if (args.aggregation) {
    let statsQuery = "";

    if (args.aggregation === "count") {
      statsQuery = args.aggregate_field ? `count(${args.aggregate_field})` : "count()";
    } else {
      if (!args.aggregate_field) {
        throw new Error(`${args.aggregation} requires an aggregate_field`);
      }
      statsQuery = `${args.aggregation}(${args.aggregate_field})`;
    }

    if (args.group_by && args.group_by.length > 0) {
      const groupByFields = args.group_by.map(field => {
        if (args.time_group && (field.includes("_at") || field.includes("timestamp") || field.includes("time"))) {
          return `${args.time_group}(${field})`;
        }
        return field;
      });
      statsQuery += ` by ${groupByFields.join(", ")}`;
    }

    result.stats_query = statsQuery;
  }

  return result;
}

/**
 * Execute multiple RadQL queries in parallel
 */
export async function executeBatchQueries(
  client: RadSecurityClient,
  args: z.infer<typeof RadQLBatchQuerySchema>
): Promise<any[]> {
  const promises = args.queries.map(query =>
    executeRadQLQuery(client, query).catch(err => ({
      error: err.message,
      query: query
    }))
  );

  return await Promise.all(promises);
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Generate example RadQL queries for a data type
 */
function generateRadQLExamples(dataType: string, fields: any[]): any {
  const examples: any = {
    filter_examples: [],
    stats_examples: []
  };

  // Find fields by type
  const stringFields = fields.filter((f: any) => f.type === "string" && f.is_filter);
  const numberFields = fields.filter((f: any) => f.type === "number" && f.is_filter);
  const booleanFields = fields.filter((f: any) => f.type === "boolean" && f.is_filter);
  const dateFields = fields.filter((f: any) => f.type === "datetime" && f.is_filter);

  if (stringFields.length > 0) {
    examples.filter_examples.push({
      description: "Find items with specific text value",
      query: `${stringFields[0].name}:example_value`
    });
    examples.filter_examples.push({
      description: "Find items containing text (wildcard search)",
      query: `${stringFields[0].name}:*partial*`
    });
  }

  if (numberFields.length > 0) {
    examples.filter_examples.push({
      description: "Find items with number comparison",
      query: `${numberFields[0].name}>100`
    });
  }

  if (booleanFields.length > 0) {
    examples.filter_examples.push({
      description: "Find items by boolean value",
      query: `${booleanFields[0].name}:true`
    });
  }

  if (dateFields.length > 0) {
    examples.filter_examples.push({
      description: "Find items after a specific date",
      query: `${dateFields[0].name}>"2024-01-01"`
    });
  }

  if (stringFields.length >= 2) {
    examples.filter_examples.push({
      description: "Combine multiple conditions",
      query: `${stringFields[0].name}:value1 AND ${stringFields[1].name}:value2`
    });
  }

  examples.stats_examples.push({
    description: "Count all items",
    query: "count()"
  });

  if (stringFields.length > 0) {
    examples.stats_examples.push({
      description: `Count items grouped by ${stringFields[0].name}`,
      query: `count() by ${stringFields[0].name}`
    });
  }

  if (numberFields.length > 0) {
    examples.stats_examples.push({
      description: `Average ${numberFields[0].name}`,
      query: `avg(${numberFields[0].name})`
    });

    if (stringFields.length > 0) {
      examples.stats_examples.push({
        description: `Sum ${numberFields[0].name} grouped by ${stringFields[0].name}`,
        query: `sum(${numberFields[0].name}) by ${stringFields[0].name}`
      });
    }
  }

  if (dateFields.length > 0) {
    examples.stats_examples.push({
      description: "Count items by day",
      query: `count() by day(${dateFields[0].name})`
    });
    examples.stats_examples.push({
      description: "Count items by month",
      query: `count() by month(${dateFields[0].name})`
    });
  }

  // Data type specific examples
  if (dataType === "containers") {
    examples.filter_examples.push({
      description: "Find nginx containers in production",
      query: 'image_name:*nginx* AND cluster_id:prod*'
    });
    examples.stats_examples.push({
      description: "Count containers by image",
      query: "count() by image_name"
    });
  }

  if (dataType === "inbox_items") {
    examples.filter_examples.push({
      description: "Find high-severity unresolved items",
      query: 'severity:High AND NOT archived:true'
    });
    examples.stats_examples.push({
      description: "Count items by severity and type",
      query: "count() by severity, type"
    });
  }

  if (dataType === "kubernetes_resources") {
    examples.filter_examples.push({
      description: "Find Pods or Services",
      query: 'kind:Pod OR kind:Service'
    });
    examples.stats_examples.push({
      description: "Count resources by kind",
      query: "count() by kind"
    });
  }

  return examples;
}

/**
 * Explain a RadQL filter query in natural language
 */
function explainRadQLQuery(query: string | undefined): string {
  if (!query) return "No filters applied - returning all items";

  const explanations: string[] = [];

  // Parse common patterns
  if (query.includes(" AND ")) {
    explanations.push("All conditions must be true");
  }
  if (query.includes(" OR ")) {
    explanations.push("Any condition can be true");
  }
  if (query.includes("NOT ")) {
    explanations.push("Excluding items matching certain conditions");
  }
  if (query.includes(":")) {
    explanations.push("Filtering by exact field values");
  }
  if (query.includes("*")) {
    explanations.push("Using wildcard pattern matching");
  }
  if (query.includes(">") || query.includes("<")) {
    explanations.push("Comparing numeric or date values");
  }
  if (query.includes("(") && query.includes(")")) {
    explanations.push("Using grouped conditions");
  }

  return explanations.length > 0
    ? explanations.join("; ")
    : "Applying custom filter conditions";
}

/**
 * Explain a RadQL stats query in natural language
 */
function explainStatsQuery(query: string | undefined): string {
  if (!query) return "No aggregation specified";

  const explanations: string[] = [];

  // Parse aggregation functions
  if (query.includes("count(")) {
    explanations.push("Counting items");
  }
  if (query.includes("sum(")) {
    explanations.push("Summing numeric values");
  }
  if (query.includes("avg(")) {
    explanations.push("Calculating average values");
  }
  if (query.includes("min(")) {
    explanations.push("Finding minimum values");
  }
  if (query.includes("max(")) {
    explanations.push("Finding maximum values");
  }
  if (query.includes("median(")) {
    explanations.push("Calculating median values");
  }

  // Parse grouping
  if (query.includes(" by ")) {
    explanations.push("Grouping results by specified fields");
  }

  // Parse time grouping
  const timeGroups = ["second(", "minute(", "hour(", "day(", "month(", "year("];
  for (const timeGroup of timeGroups) {
    if (query.includes(timeGroup)) {
      explanations.push(`Grouping by ${timeGroup.replace("(", "")} intervals`);
      break;
    }
  }

  return explanations.length > 0
    ? explanations.join("; ")
    : "Applying aggregation functions";
}

/**
 * Enhanced error handling for RadQL queries
 */
function handleRadQLError(error: any, dataType?: string): Error {
  const originalMsg = error.message || error.response?.data?.message || String(error);

  // Parse API error responses
  if (error.response?.status === 400) {
    // Detect parser errors (e.g., "unexpected token")
    if (originalMsg.includes("unexpected token") || originalMsg.includes("invalid query")) {
      let helpfulMsg = "RadQL Parser Error\n\n";

      // Specific error patterns with solutions
      if (originalMsg.match(/unexpected token.*"-\d+"/)) {
        helpfulMsg += "ISSUE: Unquoted date or hyphenated value detected\n";
        helpfulMsg += "SOLUTION: Dates and values with hyphens MUST be quoted\n\n";
        helpfulMsg += "Examples:\n";
        helpfulMsg += '  INCORRECT: created_at>2024-01-01\n';
        helpfulMsg += '  CORRECT:   created_at>"2024-01-01"\n\n';
        helpfulMsg += '  INCORRECT: id:abc-123-def\n';
        helpfulMsg += '  CORRECT:   id:"abc-123-def"\n\n';
      } else if (originalMsg.includes("unknown field") || originalMsg.includes("not found")) {
        helpfulMsg += "ISSUE: Unknown or misspelled field name\n";
        helpfulMsg += `SOLUTION: Call radql_get_type_metadata with data_type="${dataType || "your_type"}" to see all available fields\n\n`;

        // Add common fields based on data type
        if (dataType === "containers") {
          helpfulMsg += "Common container fields:\n";
          helpfulMsg += "  Filterable: name, image_name, image_repo, owner_kind\n";
          helpfulMsg += "  All: id, cluster_id, image_tag, created_at\n\n";
        } else if (dataType === "finding_groups") {
          helpfulMsg += "Common finding_groups fields:\n";
          helpfulMsg += "  Filterable: type, severity, source_kind, source_name, rule_title\n";
          helpfulMsg += "  All: group_id, severity, rule_id, event_timestamp\n\n";
        } else if (dataType === "inbox_items") {
          helpfulMsg += "Common inbox_items fields:\n";
          helpfulMsg += "  severity (High|Medium|Low), type, title, archived, false_positive, created_at\n\n";
        }
      } else {
        helpfulMsg += "ISSUE: Invalid query syntax\n";
        helpfulMsg += "COMMON SOLUTIONS:\n";
        helpfulMsg += '  1. Quote dates: created_at>"2024-01-01"\n';
        helpfulMsg += '  2. Quote UUIDs: id:"abc-123-def"\n';
        helpfulMsg += '  3. Quote special chars: title:"my value"\n';
        helpfulMsg += `  4. Verify fields: radql_get_type_metadata (data_type="${dataType}")\n\n`;
      }

      helpfulMsg += `Original error: ${originalMsg}`;
      return new Error(helpfulMsg);
    }

    // Unknown field error
    if (originalMsg.includes("unknown field") || originalMsg.includes("field") && originalMsg.includes("not found")) {
      let helpfulMsg = "Unknown Field Error\n\n";
      helpfulMsg += `NEXT STEP: Call radql_get_type_metadata with data_type="${dataType}" for complete field list\n\n`;

      // Add field suggestions based on data type
      if (dataType === "containers") {
        helpfulMsg += "Common container fields (quick reference):\n";
        helpfulMsg += "  Filterable: name, image_name, image_repo, owner_kind\n";
        helpfulMsg += "  All: id, cluster_id, image_tag, created_at\n\n";
      } else if (dataType === "finding_groups") {
        helpfulMsg += "Common finding_groups fields (quick reference):\n";
        helpfulMsg += "  Filterable: type, source_kind, source_name, source_namespace, rule_title\n";
        helpfulMsg += "  All: group_id, severity, rule_id, event_timestamp\n\n";
      } else if (dataType === "inbox_items") {
        helpfulMsg += "Common inbox_items fields (quick reference):\n";
        helpfulMsg += "  severity (High|Medium|Low), type, title, archived, false_positive, created_at\n\n";
      }

      helpfulMsg += `Original error: ${originalMsg}`;
      return new Error(helpfulMsg);
    }

    const message = "Invalid RadQL query syntax";
    const details = {
      original_error: originalMsg,
      next_step: `Call radql_get_type_metadata with data_type="${dataType}" for field list and examples`,
      data_type: dataType
    };

    return new Error(`${message}\n\n${JSON.stringify(details, null, 2)}`);
  }

  if (error.response?.status === 404) {
    return new Error(
      `Data type '${dataType}' not found\n\nNEXT STEP: Call radql_list_data_types to see all available types\n\nCommon types: containers, finding_groups, inbox_items, kubernetes_resources`
    );
  }

  if (error.response?.status === 401) {
    return new Error(
      "Authentication failed\n\nVERIFY: RAD Security API credentials are set (BASE_URL and BEARER_TOKEN)"
    );
  }

  if (error.response?.status === 403) {
    return new Error(
      `Access denied to data type '${dataType}'\n\nVERIFY: Account permissions or call radql_list_data_types to confirm type exists`
    );
  }

  return error;
}