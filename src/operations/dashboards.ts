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
 * List dashboard templates with optional filtering.
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

  return client.makeRequest(
    `/accounts/${client.getAccountId()}/dashboards/templates`,
    params
  );
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
