import { z } from "zod";
import { RadSecurityClient } from "../client.js";

export const SearchKnowledgeBaseSchema = z.object({
  query: z.string().describe("Natural language question or keywords to search for across your uploaded knowledge base content. Can be a full question, technical terms, or key phrases."),
  top_k: z.number().optional().describe("Maximum number of most relevant document excerpts to return. Use higher values (10-20) for comprehensive research, lower values (3-5) for focused answers. Default: 5"),
  min_score: z.number().optional().describe("Minimum semantic similarity score threshold (0.0 to 1.0). Higher values (0.8-1.0) return only highly relevant matches, lower values (0.5-0.7) include broader context. Default: 0.5"),
  thread_id: z.string().optional().describe("Thread identifier for the current conversation or session. IMPORTANT: If a thread_id is available in your context, you MUST provide it to include thread-specific documents alongside general knowledge base content. Only omit if no thread context exists."),
  collections: z.array(z.string()).optional().describe("Optional list of collection names to filter search results. Only documents tagged with these collections will be searched. Cannot be used with document_ids."),
  document_ids: z.array(z.string()).optional().describe("Optional list of specific document IDs to search within. Use this to restrict search to known documents. Cannot be used with collections."),
});

export const ListCollectionsSchema = z.object({
  limit: z.number().optional().describe("Maximum number of collections to return. Default: 100"),
  offset: z.number().optional().describe("Number of collections to skip for pagination. Default: 0"),
});

export const ListDocumentsSchema = z.object({
  limit: z.number().optional().describe("Maximum number of documents to return. Default: 100"),
  offset: z.number().optional().describe("Number of documents to skip for pagination. Default: 0"),
  filters: z.string().optional().describe("Filter documents by collections, file_type (pdf, markdown, plaintext, csv), or status (ready, processing, error) (e.g., 'collections:vuln;security,file_type:pdf,status:ready'). Multiple filters can be combined with commas."),
});

export const StructuredQueryDocumentSchema = z.object({
  document_id: z.string().describe("The ID of the CSV document to query. Use list_knowledge_base_documents with filters='file_type:csv' to find CSV document IDs. Document IDs are also available in search_knowledge_base results. This will fail if the document is not a CSV file."),
  query: z.string().describe("Natural language question to execute against the CSV document. The system will analyze the CSV structure and generate the appropriate query (e.g., 'Show me all rows where severity is critical', 'Count the number of vulnerabilities by type', 'Show me the owner of asset IKM99832')."),
});

export async function searchKnowledgeBase(
  client: RadSecurityClient,
  query: string,
  topK?: number,
  minScore?: number,
  threadId?: string,
  collections?: string[],
  documentIds?: string[],
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

  if (collections !== undefined) {
    body.collections = collections;
  }

  if (documentIds !== undefined) {
    body.document_ids = documentIds;
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

export async function listCollections(
  client: RadSecurityClient,
  limit?: number,
  offset?: number,
): Promise<any> {
  const tenantId = await client.getTenantId();

  const params: Record<string, any> = {};

  if (limit !== undefined) {
    params.limit = limit;
  }

  if (offset !== undefined) {
    params.offset = offset;
  }

  return client.makeRequest(
    `/tenants/${tenantId}/accounts/${client.getAccountId()}/knowledge_base/collections`,
    params,
    {
      method: "GET",
    }
  );
}

export async function listDocuments(
  client: RadSecurityClient,
  limit?: number,
  offset?: number,
  filters?: string,
): Promise<any> {
  const tenantId = await client.getTenantId();

  const params: Record<string, any> = {};

  if (limit !== undefined) {
    params.limit = limit;
  }

  if (offset !== undefined) {
    params.offset = offset;
  }

  if (filters !== undefined) {
    params.filters = filters;
  }

  return client.makeRequest(
    `/tenants/${tenantId}/accounts/${client.getAccountId()}/knowledge_base/documents`,
    params,
    {
      method: "GET",
    }
  );
}

export async function structuredQueryDocument(
  client: RadSecurityClient,
  documentId: string,
  query: string,
): Promise<any> {
  const tenantId = await client.getTenantId();

  const body = { query };

  return client.makeRequest(
    `/tenants/${tenantId}/accounts/${client.getAccountId()}/knowledge_base/documents/${documentId}/query`,
    {},
    {
      method: "POST",
      body: body,
    }
  );
}
