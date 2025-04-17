import { z } from "zod";

// Base URL for the CVE Search API
const BASE_URL = "https://cve.circl.lu/api";

// Input schemas
export const getCveSchema = z.object({
  cveId: z.string().describe("CVE ID to retrieve information for"),
});

export const searchCvesSchema = z.object({
  vendor: z.string().describe("Vendor name to search for"),
  product: z.string().optional().describe("Product name to search for"),
});

// Main functions
export async function listCveVendors(): Promise<any> {
  const response = await fetch(`${BASE_URL}/browse`);
  if (!response.ok) {
    throw new Error(`Failed to list vendors: ${response.statusText}`);
  }
  return response.json();
}

export async function listCveProducts(vendor: string): Promise<any> {
  const response = await fetch(`${BASE_URL}/browse/${encodeURIComponent(vendor)}`);
  if (!response.ok) {
    throw new Error(`Failed to list products for vendor ${vendor}: ${response.statusText}`);
  }
  return response.json();
}

export async function searchCves(vendor: string, product?: string): Promise<any> {
  const url = product
    ? `${BASE_URL}/search/${encodeURIComponent(vendor)}/${encodeURIComponent(product)}`
    : `${BASE_URL}/search/${encodeURIComponent(vendor)}`;

  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to search CVEs: ${response.statusText}`);
  }
  return response.json();
}

export async function getCve(cveId: string): Promise<any> {
  const response = await fetch(`${BASE_URL}/cve/${encodeURIComponent(cveId)}`);
  if (!response.ok) {
    throw new Error(`Failed to get CVE ${cveId}: ${response.statusText}`);
  }
  return response.json();
}

export async function getLatest30Cves(): Promise<any> {
  const response = await fetch(`${BASE_URL}/last`);
  if (!response.ok) {
    throw new Error(`Failed to get last CVEs: ${response.statusText}`);
  }
  return response.json();
}
