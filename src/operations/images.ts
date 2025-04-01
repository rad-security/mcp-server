import { z } from "zod";
import { RadSecurityClient } from "../client.js";

export const ListImagesSchema = z.object({
  page: z.number().optional().default(1).describe("Page number for pagination"),
  page_size: z.number().optional().default(20).describe("Number of items per page"),
  sort: z.string().optional().default("name:asc").describe("Sort order"),
  search: z.string().optional().describe("Search query"),
});

export const ListImageVulnerabilitiesSchema = z.object({
  digest: z.string().describe("Image digest (required for vulnerabilities)"),
  severities: z.array(z.string()).optional().describe("List of severity levels to filter"),
  page: z.number().optional().default(1).describe("Page number for pagination"),
  page_size: z.number().optional().default(100).describe("Number of items per page"),
});

export async function listImages(
  client: RadSecurityClient,
  page: number = 1,
  page_size: number = 20,
  sort: string = "name:asc",
  search?: string
): Promise<any> {
  const params: Record<string, any> = { page, page_size, sort };
  if (search) {
    params.q = search;
  }

  return client.makeRequest(`/accounts/${client.getAccountId()}/images`, params);
}

export async function listImageScans(
  client: RadSecurityClient,
  digest: string,
  page: number = 1,
  page_size: number = 3
): Promise<any> {
  const params: Record<string, any> = { page, page_size };

  return client.makeRequest(
    `/accounts/${client.getAccountId()}/images/${digest}/scans`,
    params
  );
}

export async function listImageVulnerabilities(
  client: RadSecurityClient,
  digest: string,
  severities?: string[],
  page: number = 1,
  page_size: number = 20
): Promise<any> {
  const params: Record<string, any> = { page, page_size, sort: "severity:desc" };
  if (severities && severities.length > 0) {
    params.severities = severities.join(",");
  }

  const scans = await listImageScans(client, digest);

  if (!scans || !scans.entries || scans.entries.length === 0) {
    throw new Error(`Image with digest: ${digest} hasn't been scanned yet`);
  }

  // Get the latest scan
  const scanId = scans.entries[0].id;

  const vulns = await client.makeRequest(
    `/accounts/${client.getAccountId()}/images/${digest}/scans/${scanId}/vulnerabilities`,
    params
  );

  // Remove CPEs to reduce context window size when used with LLMs
  vulns.entries.forEach((vuln: any) => {
    if (vuln.cpes) {
      delete vuln.cpes;
    }
  });

  return vulns;
}

export async function getTopVulnerableImages(
  client: RadSecurityClient
): Promise<any> {
  return client.makeRequest(
    `/accounts/${client.getAccountId()}/reports/top_vulnerable_images`,
    {},
    {
      headers: {
        "Accept": "application/json",
      },
    }
  );
}
