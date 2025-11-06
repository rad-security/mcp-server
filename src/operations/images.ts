import { z } from "zod";
import { RadSecurityClient } from "../client.js";

export const ListImagesSchema = z.object({
  limit: z.number().optional().default(20).describe("Number of items per page"),
  offset: z.number().optional().default(0).describe("Offset to start the list from"),
  sort: z.string().optional().default("name:asc").describe("Sort order"),
  filters: z.string().optional().describe("Filter string (e.g., 'eol:ok', 'eol:reached', 'name:nginx', 'tag:1.26.0'), where eol is end of life status of the base image"),
  q: z.string().optional().describe("Free text search query"),
});

export const ListImageVulnerabilitiesSchema = z.object({
  digest: z.string().describe("Image digest (required for vulnerabilities)"),
  severities: z.array(z.string()).optional().describe("List of severity levels to filter"),
  page: z.number().optional().default(1).describe("Page number for pagination"),
  page_size: z.number().optional().default(100).describe("Number of items per page"),
});

export const GetImageSBOMSchema = z.object({
  digest: z.string().describe("Image digest (required for SBOM)"),
});

export async function listImages(
  client: RadSecurityClient,
  limit: number = 20,
  offset: number = 0,
  sort: string = "name:asc",
  filters?: string,
  q?: string
): Promise<any> {
  const params: Record<string, any> = { limit, offset, sort };
  if (q) {
    params.q = q;
  }
  if (filters) {
    params.filters = filters;
  }

  let images = await client.makeRequest(`/accounts/${client.getAccountId()}/inventory_images`, params);
  let toReturn = [];
  for (let image of images.entries) {
    // leave only first element in the array: upgrade_opportunities
    if (image.upgrade_opportunities && image.upgrade_opportunities.length > 0) {
      image.upgrade_opportunities = [image.upgrade_opportunities[0]];
    }

    toReturn.push(image);
  }
  images.entries = toReturn;
  return images;
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

export async function getImageSBOM(
  client: RadSecurityClient,
  digest: string
): Promise<any> {
  return client.makeRequest(
    `/accounts/${client.getAccountId()}/sboms/${digest}/download`,
  );
}
