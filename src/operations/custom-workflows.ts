import { z } from "zod";
import { RadSecurityClient } from "../client.js";

export const CreateCustomWorkflowSchema = z.object({
  name: z.string().describe("Name of the custom workflow"),
  description: z.string().describe("Description of the workflow"),
  summary: z.string().describe("Summary of what the workflow does"),
  yaml: z.string().describe("The workflow YAML definition (required)"),
  agent_id: z.string().optional().describe("ID of the agent that created this workflow"),
  thread_id: z.string().optional().describe("ID of the conversation thread"),
});

export const UpdateCustomWorkflowSchema = z.object({
  workflow_id: z.string().describe("ID of the custom workflow to update"),
  name: z.string().optional().describe("New name for the workflow"),
  description: z.string().optional().describe("New description"),
  summary: z.string().optional().describe("New summary"),
  yaml: z.string().describe("The updated workflow YAML definition (required)"),
  agent_id: z.string().optional().describe("ID of the agent making the update"),
  thread_id: z.string().optional().describe("ID of the conversation thread"),
});

export const AddWorkflowScheduleSchema = z.object({
  workflow_id: z.string().describe("ID of the workflow to add a schedule to"),
  schedule: z.string().describe("Cron-based schedule expression (e.g., '0 0 12 * * *' for daily at noon)"),
  timezone: z.string().describe("Timezone for the schedule (e.g., 'UTC', 'America/New_York')"),
});

/**
 * Strip the echoed workflow definition from a create/update response.
 *
 * The API returns the whole stored workflow, and `flow` — the definition the caller just sent —
 * is 94% of it (11,382 of 12,091 bytes on a measured deploy). Handing that back to an LLM costs
 * ~3k tokens to tell it what it just wrote, and it is the only reason the result is large enough
 * for the agent runtime to offload it to a file and replace it with a 500-char preview. That
 * preview is what the web-app's automations builder then regexes for `"id"` — so today the
 * workflow id survives purely because `id` happens to sort first in the response.
 *
 * Everything except `flow` is kept: the remaining fields total a few hundred bytes, and dropping
 * only the echo keeps this a safe change for any other consumer.
 *
 * Read the definition back with `get_workflow` when it is actually needed.
 */
function withoutFlowDefinition<T>(response: T): T {
  if (!response || typeof response !== "object" || Array.isArray(response)) return response;
  const rest = { ...(response as Record<string, unknown>) };
  delete rest.flow;
  return rest as T;
}

/**
 * Create a custom workflow from YAML
 */
export async function createCustomWorkflow(
  client: RadSecurityClient,
  params: z.infer<typeof CreateCustomWorkflowSchema>
): Promise<any> {
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/workflows/custom`,
    {},
    {
      method: "POST",
      body: {
        name: params.name,
        description: params.description,
        summary: params.summary,
        yaml: params.yaml,
        agent_id: params.agent_id,
        thread_id: params.thread_id,
      },
    }
  );

  return withoutFlowDefinition(response);
}

/**
 * Update an existing custom workflow with new YAML
 */
export async function updateCustomWorkflow(
  client: RadSecurityClient,
  workflowId: string,
  params: Omit<z.infer<typeof UpdateCustomWorkflowSchema>, "workflow_id">
): Promise<any> {
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/workflows/custom/${workflowId}`,
    {},
    {
      method: "PUT",
      body: {
        name: params.name,
        description: params.description,
        summary: params.summary,
        yaml: params.yaml,
        agent_id: params.agent_id,
        thread_id: params.thread_id,
      },
    }
  );

  return withoutFlowDefinition(response);
}

/**
 * Add a schedule to a workflow
 */
export async function addWorkflowSchedule(
  client: RadSecurityClient,
  workflowId: string,
  schedule: string,
  timezone: string
): Promise<any> {
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/workflows/${workflowId}/schedules`,
    {},
    {
      method: "POST",
      body: {
        schedule: {
          schedule,
          timezone,
        },
      },
    }
  );

  return response;
}
