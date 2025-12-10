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
  args: z.record(z.any()).optional().describe("Optional arguments to override when running the workflow"),
});

export const GetWorkflowSchema = z.object({
  workflow_id: z.string().describe("ID of the workflow to get"),
});

export const ListWorkflowSchedulesSchema = z.object({
  workflow_id: z.string().describe("ID of the workflow to list schedules for"),
});

export const ListWorkflowsSchema = z.object({});

/**
 * List workflow runs
 */
export async function listWorkflowRuns(
  client: RadSecurityClient,
  workflowId: string
): Promise<any> {
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/workflows/${workflowId}/runs`
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
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/workflows/${workflowId}/runs/${runId}`
  );

  return response;
}

/**
 * Get a specific workflow by ID
 */
export async function getWorkflow(
  client: RadSecurityClient,
  workflowId: string
): Promise<any> {
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/workflows/${workflowId}`
  );

  return response;
}

/**
 * Run a workflow
 * If async is false, wait for the workflow to finish
 */
export async function runWorkflow(
  client: RadSecurityClient,
  workflowId: string,
  async: boolean = true,
  args?: Record<string, any>
): Promise<any> {
  const body: Record<string, any> = {};
  if (args) {
    body.args = args;
  }

  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/workflows/${workflowId}/runs`,
    {},
    { method: "POST", body: args??{} }
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
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/workflows/${workflowId}/schedules`
  );

  return response;
}

/**
 * List all workflows
 */
export async function listWorkflows(
  client: RadSecurityClient
): Promise<any> {
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/workflows`
  );

  return response;
}
