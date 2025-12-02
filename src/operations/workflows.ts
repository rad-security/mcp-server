import { z } from "zod";
import { RadSecurityClient } from "../client.js";

export const ListWorkflowRunsSchema = z.object({
  workflow_id: z.string().describe("ID of the workflow to list runs for"),
});

export const GetWorkflowRunSchema = z.object({
  workflow_id: z.string().describe("ID of the workflow"),
  run_id: z.string().describe("ID of the workflow run"),
});

export const RunWorkflowSchema = z.object({
  workflow_id: z.string().describe("ID of the workflow to run"),
  async: z.boolean().default(true).describe("If true, run asynchronously and return immediately. If false, wait for the workflow to finish."),
});

export const ListWorkflowSchedulesSchema = z.object({
  workflow_id: z.string().describe("ID of the workflow to list schedules for"),
});

export const ListWorkflowsSchema = z.object({});

/**
 * Fetch tenant_id from the accounts API using parent_id
 */
async function getTenantId(
  client: RadSecurityClient
): Promise<string> {
  const accountData = await client.makeRequest(`/accounts/${client.getAccountId()}`);

  if (!accountData || !accountData.parent_id) {
    throw new Error(`No parent_id found for account: ${client.getAccountId()}`);
  }

  return accountData.parent_id;
}

/**
 * List workflow runs
 */
export async function listWorkflowRuns(
  client: RadSecurityClient,
  workflowId: string
): Promise<any> {
  const tenantId = await getTenantId(client);

  const response = await client.makeRequest(
    `/tenants/${tenantId}/workflows/${workflowId}/runs`
  );

  return response;
}

/**
 * Get a specific workflow run
 */
export async function getWorkflowRun(
  client: RadSecurityClient,
  workflowId: string,
  runId: string
): Promise<any> {
  const tenantId = await getTenantId(client);

  const response = await client.makeRequest(
    `/tenants/${tenantId}/workflows/${workflowId}/runs/${runId}`
  );

  return response;
}

/**
 * Extract default values from a JSON schema
 */
function extractDefaultValues(schema: any): Record<string, any> {
  const defaults: Record<string, any> = {};

  if (!schema || !schema.properties) {
    return defaults;
  }

  for (const [key, value] of Object.entries(schema.properties)) {
    const prop = value as any;
    if (prop.default !== undefined) {
      defaults[key] = prop.default;
    }
  }

  return defaults;
}

/**
 * Run a workflow
 * If async is false, wait for the workflow to finish
 */
export async function runWorkflow(
  client: RadSecurityClient,
  workflowId: string,
  async: boolean = true
): Promise<any> {
  const tenantId = await getTenantId(client);

  // Get the workflow definition to extract input schema
  const workflow = await client.makeRequest(
    `/tenants/${tenantId}/workflows/${workflowId}`
  );

  if (!workflow || !workflow.flow || !workflow.flow.schema) {
    throw new Error(`Failed to get workflow schema for workflow ${workflowId}`);
  }

  // Build the workflow input from the default values in the schema
  const workflowInput = extractDefaultValues(workflow.flow.schema);

  const response = await client.makeRequest(
    `/tenants/${tenantId}/workflows/${workflowId}/runs`,
    {},
    { method: "POST", body: workflowInput }
  );

  if (!response || !response.id) {
    throw new Error(`Failed to run workflow ${workflowId}: no id in response`);
  }

  const runId = response.id;

  // If async, return immediately with the run_id
  if (async) {
    return { run_id: runId, status: "running", message: "Workflow started asynchronously" };
  }

  // Otherwise, poll until the workflow is finished
  const pollInterval = 2000; // 2 seconds
  const maxWaitTime = 300000; // 5 minutes
  const startTime = Date.now();

  while (true) {
    const runDetails = await getWorkflowRun(client, workflowId, runId);

    // Check if the workflow has finished
    const status = runDetails.status;
    if (status === "completed" || status === "failed" || status === "cancelled") {
      return runDetails;
    }

    // Check if we've exceeded the max wait time
    if (Date.now() - startTime > maxWaitTime) {
      throw new Error(
        `Workflow ${workflowId} run ${runId} did not finish within ${maxWaitTime / 1000} seconds. Last status: ${status}`
      );
    }

    // Wait before polling again
    await new Promise(resolve => setTimeout(resolve, pollInterval));
  }
}

/**
 * List workflow schedules
 */
export async function listWorkflowSchedules(
  client: RadSecurityClient,
  workflowId: string
): Promise<any> {
  const tenantId = await getTenantId(client);

  const response = await client.makeRequest(
    `/tenants/${tenantId}/workflows/${workflowId}/schedules`
  );

  return response;
}

/**
 * List all workflows
 */
export async function listWorkflows(
  client: RadSecurityClient
): Promise<any> {
  const tenantId = await getTenantId(client);

  const response = await client.makeRequest(
    `/tenants/${tenantId}/workflows`
  );

  return response;
}
