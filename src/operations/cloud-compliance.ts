import { z } from "zod";
import { RadSecurityClient } from "../client.js";

// Schema for list_compliance_frameworks
export const ListComplianceFrameworksSchema = z.object({
  datasource_ids: z.string().optional().describe("Comma-separated datasource IDs (e.g. AWS Account IDs)"),
  page: z.number().optional().describe("Page number starting from 1"),
  page_size: z.number().optional().describe("Page size"),
});

// Schema for list_framework_requirements
export const ListFrameworkRequirementsSchema = z.object({
  framework_name: z.string().describe("Name of the compliance framework"),
  datasource_ids: z.string().describe("Comma-separated datasource IDs (e.g. AWS Account IDs)"),
  page: z.number().optional().describe("Page number starting from 1"),
  page_size: z.number().optional().describe("Page size"),
});

// Schema for list_requirement_controls
export const ListRequirementControlsSchema = z.object({
  framework_name: z.string().describe("Name of the compliance framework"),
  requirement_id: z.string().describe("ID of the requirement within the framework"),
  datasource_ids: z.string().describe("Comma-separated datasource IDs (e.g. AWS Account IDs)"),
  page: z.number().optional().default(1).describe("Page number starting from 1"),
  page_size: z.number().optional().default(10).describe("Page size"),
});

// Schema for list_compliance_controls
export const ListComplianceControlsSchema = z.object({
  status: z.enum(["failing", "passing"]).optional().describe("Filter by failure status: failing or passing"),
  providers: z.string().optional().describe("Comma-separated list of cloud providers (aws, azure, gcp, linode)"),
  page: z.number().optional().describe("Page number starting from 1"),
  page_size: z.number().optional().describe("Page size"),
});

// Schema for get_compliance_control
export const GetComplianceControlSchema = z.object({
  control_name: z.string().describe("Name of the compliance control"),
  datasource_ids: z.string().describe("Comma-separated datasource IDs (e.g. AWS Account IDs)"),
});

// Schema for list_control_resources
export const ListControlResourcesSchema = z.object({
  control_name: z.string().describe("Name of the compliance control"),
  datasource_ids: z.string().describe("Comma-separated datasource IDs (e.g. AWS Account IDs)"),
  page: z.number().optional().describe("Page number starting from 1"),
  page_size: z.number().optional().describe("Page size"),
});

/**
 * List all compliance frameworks available for cloud resources.
 */
export async function listComplianceFrameworks(
  client: RadSecurityClient,
  datasourceIds?: string,
  page?: number,
  pageSize?: number
): Promise<any> {
  const params: Record<string, any> = {};

  if (datasourceIds) {
    params.datasource_ids = datasourceIds;
  }
  if (page !== undefined) {
    params.page = page;
  }
  if (pageSize !== undefined) {
    params.page_size = pageSize;
  }

  return client.makeRequest(
    `/accounts/${client.getAccountId()}/compliance/cloud/frameworks`,
    params
  );
}

/**
 * List all requirements for a specific compliance framework.
 */
export async function listFrameworkRequirements(
  client: RadSecurityClient,
  frameworkName: string,
  datasourceIds: string,
  page?: number,
  pageSize?: number
): Promise<any> {
  const params: Record<string, any> = { datasource_ids: datasourceIds };

  if (page !== undefined) {
    params.page = page;
  }
  if (pageSize !== undefined) {
    params.page_size = pageSize;
  }

  return client.makeRequest(
    `/accounts/${client.getAccountId()}/compliance/cloud/frameworks/${encodeURIComponent(frameworkName)}/requirements`,
    params
  );
}

/**
 * List controls associated with a specific requirement within a compliance framework.
 */
export async function listRequirementControls(
  client: RadSecurityClient,
  frameworkName: string,
  requirementId: string,
  datasourceIds: string,
  page?: number,
  pageSize?: number
): Promise<any> {
  const params: Record<string, any> = { datasource_ids: datasourceIds };

  if (page !== undefined) {
    params.page = page;
  }
  if (pageSize !== undefined) {
    params.page_size = pageSize;
  }

  return client.makeRequest(
    `/accounts/${client.getAccountId()}/compliance/cloud/frameworks/${encodeURIComponent(frameworkName)}/requirements/${encodeURIComponent(requirementId)}/controls`,
    params
  );
}

/**
 * List all compliance control summaries for the account.
 */
export async function listComplianceControls(
  client: RadSecurityClient,
  status?: string,
  providers?: string,
  page?: number,
  pageSize?: number
): Promise<any> {
  const params: Record<string, any> = {};

  if (status) {
    params.status = status;
  }
  if (providers) {
    params.providers = providers;
  }
  if (page !== undefined) {
    params.page = page;
  }
  if (pageSize !== undefined) {
    params.page_size = pageSize;
  }

  return client.makeRequest(
    `/accounts/${client.getAccountId()}/compliance/cloud/controls`,
    params
  );
}

/**
 * Get details for a specific compliance control.
 */
export async function getComplianceControl(
  client: RadSecurityClient,
  controlName: string,
  datasourceIds: string
): Promise<any> {
  const params: Record<string, any> = { datasource_ids: datasourceIds };
  return client.makeRequest(
    `/accounts/${client.getAccountId()}/compliance/cloud/controls/${encodeURIComponent(controlName)}`,
    params
  );
}

/**
 * List resources associated with a specific compliance control.
 */
export async function listControlResources(
  client: RadSecurityClient,
  controlName: string,
  datasourceIds: string,
  page?: number,
  pageSize?: number
): Promise<any> {
  const params: Record<string, any> = { datasource_ids: datasourceIds };

  if (page !== undefined) {
    params.page = page;
  }
  if (pageSize !== undefined) {
    params.page_size = pageSize;
  }

  return client.makeRequest(
    `/accounts/${client.getAccountId()}/compliance/cloud/controls/${encodeURIComponent(controlName)}/resources`,
    params
  );
}
