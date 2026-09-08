import { z } from "zod";
import { RadSecurityClient } from "../client.js";

// Schema for list_widget_templates
export const ListWidgetTemplatesSchema = z.object({
  limit: z.number().optional().default(10).describe("Maximum number of results to return (default: 10, min: 1)"),
  offset: z.number().optional().default(0).describe("Pagination offset (default: 0, min: 0)"),
  visualization_type: z.string().optional().describe("Filter by visualization type"),
  category: z.string().optional().describe("Filter by category"),
});

// Schema for get_widget_template
export const GetWidgetTemplateSchema = z.object({
  widget_template_id: z.string().describe("ID of the widget template"),
});

// Schema for list_dashboard_templates
export const ListDashboardTemplatesSchema = z.object({
  limit: z.number().optional().default(10).describe("Maximum number of results to return (default: 10, min: 1)"),
  offset: z.number().optional().default(0).describe("Pagination offset (default: 0, min: 0)"),
  category: z.string().optional().describe("Filter by category"),
});

// Schema for get_dashboard_template
export const GetDashboardTemplateSchema = z.object({
  dashboard_template_id: z.string().describe("ID of the dashboard template"),
});

// Schema for list_dashboards
export const ListDashboardsSchema = z.object({
  limit: z.number().optional().default(10).describe("Maximum number of results to return (default: 10, min: 1)"),
  offset: z.number().optional().default(0).describe("Pagination offset (default: 0, min: 0)"),
});

// Schema for get_dashboard
export const GetDashboardSchema = z.object({
  dashboard_id: z.string().describe("ID of the dashboard"),
});

/**
 * List widget templates with optional filtering.
 */
export async function listWidgetTemplates(
  client: RadSecurityClient,
  limit: number = 50,
  offset: number = 0,
  visualization_type?: string,
  category?: string
): Promise<any> {
  const params: Record<string, any> = { limit, offset };

  if (visualization_type) {
    params.visualization_type = visualization_type;
  }
  if (category) {
    params.category = category;
  }

  return client.makeRequest(
    `/accounts/${client.getAccountId()}/dashboards/widget_templates`,
    params
  );
}

/**
 * Get details for a specific widget template.
 */
export async function getWidgetTemplate(
  client: RadSecurityClient,
  widget_template_id: string
): Promise<any> {
  return client.makeRequest(
    `/accounts/${client.getAccountId()}/dashboards/widget_templates/${widget_template_id}`
  );
}

/**
 * Drop each template's `rows` from a listing.
 *
 * A dashboard template carries its whole definition — every row, widget, and query. Seventeen of
 * them come to ~116KB (~29k tokens), which is more than an agent can afford to spend on browsing a
 * catalogue. Without the rows the same listing is ~7KB, and the id, title, description and category
 * that survive are everything needed to choose one.
 *
 * Read the definition back with `get_dashboard_template` once a choice is made.
 *
 * Widget templates are deliberately NOT trimmed: their query and config are the payload, so
 * removing them would leave nothing worth listing.
 */
function withoutRowDefinitions<T>(response: T): T {
  if (!response || typeof response !== "object") return response;

  const stripRows = (entry: unknown) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return entry;
    const rest = { ...(entry as Record<string, unknown>) };
    delete rest.rows;
    return rest;
  };

  if (Array.isArray(response)) {
    return response.map(stripRows) as T;
  }

  const body = response as Record<string, unknown>;
  if (!Array.isArray(body.entries)) return response;

  return { ...body, entries: body.entries.map(stripRows) } as T;
}

/**
 * List dashboard templates with optional filtering.
 *
 * Returns each template WITHOUT its rows — see `withoutRowDefinitions`.
 */
export async function listDashboardTemplates(
  client: RadSecurityClient,
  limit: number = 50,
  offset: number = 0,
  category?: string
): Promise<any> {
  const params: Record<string, any> = { limit, offset };

  if (category) {
    params.category = category;
  }

  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/dashboards/templates`,
    params
  );

  return withoutRowDefinitions(response);
}

/**
 * Get details for a specific dashboard template.
 */
export async function getDashboardTemplate(
  client: RadSecurityClient,
  dashboard_template_id: string
): Promise<any> {
  return client.makeRequest(
    `/accounts/${client.getAccountId()}/dashboards/templates/${dashboard_template_id}`
  );
}

/**
 * List dashboards.
 */
export async function listDashboards(
  client: RadSecurityClient,
  limit: number = 50,
  offset: number = 0
): Promise<any> {
  const params: Record<string, any> = { limit, offset };

  return client.makeRequest(
    `/accounts/${client.getAccountId()}/dashboards`,
    params
  );
}

/**
 * Get details for a specific dashboard.
 */
export async function getDashboard(
  client: RadSecurityClient,
  dashboard_id: string
): Promise<any> {
  return client.makeRequest(
    `/accounts/${client.getAccountId()}/dashboards/${dashboard_id}`
  );
}

// Schema for create_dashboard
export const CreateDashboardSchema = z.object({
  title: z.string().describe("Dashboard title shown in the UI"),
  rows: z
    .array(z.record(z.any()))
    .describe(
      "Dashboard layout: an ordered list of rows, each holding widgets. Build widgets from list_widget_templates / get_widget_template so the visualization and query shapes are valid."
    ),
  description: z.string().optional().describe("What the dashboard shows, and who it is for"),
  visibility: z
    .string()
    .optional()
    .describe("Dashboard visibility, e.g. 'private' or 'public'. Defaults to the account's default."),
});

// No `tags` parameter, deliberately. The dashboards API returns a `tags` field, but it drops the
// value on both POST and PATCH — verified against sbx: creating with ["alpha","beta"] and then
// patching ["gamma"] both read back as []. Advertising a parameter that silently does nothing is
// worse than not having it: the model spends tokens choosing tags and believes it applied them.
// Re-add on both schemas if the API starts honouring it.

// Schema for update_dashboard
export const UpdateDashboardSchema = z.object({
  dashboard_id: z.string().describe("ID of the dashboard to update"),
  title: z.string().optional().describe("New title"),
  rows: z
    .array(z.record(z.any()))
    .optional()
    .describe(
      "Replacement layout. `rows` is replaced wholesale, so when you change it send the full intended layout, not just the changed row. Omit it entirely to leave the layout untouched."
    ),
  description: z.string().optional().describe("New description"),
  visibility: z.string().optional().describe("New visibility"),
});

/**
 * Create a dashboard.
 */
export async function createDashboard(
  client: RadSecurityClient,
  args: {
    title: string;
    rows: Record<string, any>[];
    description?: string;
    visibility?: string;
  }
): Promise<any> {
  return client.makeRequest(
    `/accounts/${client.getAccountId()}/dashboards`,
    {},
    { method: "POST", body: args }
  );
}

/**
 * Update a dashboard. PATCH semantics: omitted fields are left untouched, so a small edit does
 * not require resending the whole dashboard.
 */
export async function updateDashboard(
  client: RadSecurityClient,
  dashboard_id: string,
  changes: {
    title?: string;
    rows?: Record<string, any>[];
    description?: string;
    visibility?: string;
  }
): Promise<any> {
  return client.makeRequest(
    `/accounts/${client.getAccountId()}/dashboards/${dashboard_id}`,
    {},
    { method: "PATCH", body: changes }
  );
}
