import { z } from "zod";
import { RadSecurityClient } from "../client.js";

export const SearchKnowledgeBaseSchema = z.object({
  query: z.string().describe("Natural language question or keywords to search for across your uploaded knowledge base content. Can be a full question, technical terms, or key phrases."),
  top_k: z.number().optional().describe("Maximum number of most relevant document excerpts to return. Use higher values (10-20) for comprehensive research, lower values (3-5) for focused answers. Default: 5"),
  min_score: z.number().optional().describe("Minimum semantic similarity score threshold (0.0 to 1.0). Higher values (0.8-1.0) return only highly relevant matches, lower values (0.5-0.7) include broader context. Default: 0.7"),
  thread_id: z.string().optional().describe("Thread identifier for the current conversation or session. IMPORTANT: If a thread_id is available in your context, you MUST provide it to include thread-specific documents alongside general knowledge base content. Only omit if no thread context exists."),
});

export async function searchKnowledgeBase(
  client: RadSecurityClient,
  query: string,
  topK?: number,
  minScore?: number,
  threadId?: string,
): Promise<any> {
  const tenantId = await client.getTenantId();

  const body: Record<string, any> = { query };

  if (topK !== undefined) {
    body.top_k = topK;
  }

  if (minScore !== undefined) {
    body.min_score = minScore;
  }

  if (threadId !== undefined) {
    body.thread_id = threadId;
  }

  return client.makeRequest(
    `/tenants/${tenantId}/accounts/${client.getAccountId()}/knowledge_base/search`,
    {},
    {
      method: "POST",
      body: body,
    }
  );
}
