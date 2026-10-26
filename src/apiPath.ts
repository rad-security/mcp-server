/**
 * Request-path construction for the RAD Security API.
 *
 * Tool arguments and the configured account id are interpolated into request paths. Interpolated
 * raw, a value does not necessarily stay one path segment: `/`, `..`, `?` and `#` all have meaning
 * in a URL, and `new URL()` resolves them before the request is sent. An argument could therefore
 * move a call to an endpoint the operation never intended — carrying the server's own credentials.
 *
 * These helpers make that structurally impossible: segments are encoded as they are interpolated,
 * and the single place every request passes through refuses a path that still looks dangerous.
 */

/**
 * Build an API path, percent-encoding every interpolated value as one path segment.
 *
 * Used as a tagged template:
 *
 *     apiPath`/accounts/${accountId}/images/${digest}/scans`
 *
 * `encodeURIComponent` leaves ordinary identifiers (letters, digits, `-`, `_`, `.`, `~`) untouched,
 * so the bytes on the wire change only for values that were never a valid single segment.
 */
export function apiPath(strings: TemplateStringsArray, ...values: unknown[]): string {
  let path = strings[0] ?? "";

  for (let i = 0; i < values.length; i++) {
    path += encodeSegment(values[i]) + (strings[i + 1] ?? "");
  }

  return path;
}

/**
 * Encode one path segment. A missing or empty value is a caller bug — unencoded it would produce
 * `/accounts//images` or a literal `undefined` in the path — so it fails here, where the message
 * names the problem, rather than as a puzzling 404 from the API.
 */
function encodeSegment(value: unknown): string {
  if (value === undefined || value === null || String(value) === "") {
    throw new Error("Cannot build an API path: a required path segment is missing");
  }

  return encodeURIComponent(String(value));
}

/**
 * Reject a request path that can still leave the endpoint the caller asked for.
 *
 * The backstop to `apiPath`: operations are expected to build paths with it, but this is the one
 * place every request passes through, so a site that forgets — or one added later — cannot quietly
 * reintroduce the problem. Query parameters belong in `makeRequest`'s `params` argument, which is
 * why a `?` here is treated as injection rather than as a legitimate query string.
 */
export function assertSafeEndpoint(endpoint: string): void {
  const unsafe =
    !endpoint.startsWith("/") ||
    endpoint.includes("?") ||
    endpoint.includes("#") ||
    endpoint.includes("\\") ||
    endpoint.split("/").includes("..");

  if (unsafe) {
    throw new Error(`Refusing to request a malformed API path: ${JSON.stringify(endpoint)}`);
  }
}
