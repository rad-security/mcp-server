import { z } from "zod";
import { RadSecurityClient } from "../client.js";

export const CreateCustomWorkflowSchema = z.object({
  name: z.string().describe("Name of the custom workflow"),
  description: z.string().optional().describe("Description of the workflow"),
  summary: z.string().optional().describe("Summary of what the workflow does"),
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

  return response;
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

  return response;
}
