import { logger } from "./logger.js";

const USER_AGENT = `rad-security/mcp-server`;

/**
 * Thrown when a per-request credential (e.g. an inbound Authorization header)
 * is missing or malformed. Transports translate this into an HTTP 401.
 */
export class CredentialError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CredentialError";
  }
}

type RequestOptions = {
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
};

export class RadSecurityClient {
  private sessionToken: string;
  private accessKeyId: string;
  private secretKey: string;
  private baseUrl: string;
  private accountId: string;
  private tenantId: string;
  private tokenCache: { token: string; expiry: Date } | null = null;

  constructor(
    sessionToken: string,
    accessKeyId: string,
    secretKey: string,
    baseUrl: string,
    accountId: string,
    tenantId: string
  ) {
    this.sessionToken = sessionToken;
    this.accessKeyId = accessKeyId;
    this.secretKey = secretKey;
    this.baseUrl = baseUrl;
    this.accountId = accountId;
    this.tenantId = tenantId;
  }

  static fromEnv(): RadSecurityClient {
    const sessionToken = process.env.RAD_SECURITY_SESSION_TOKEN || "";
    const accessKeyId = process.env.RAD_SECURITY_ACCESS_KEY_ID || "";
    const secretKey = process.env.RAD_SECURITY_SECRET_KEY || "";
    const accountId = process.env.RAD_SECURITY_ACCOUNT_ID || "";
    const tenantId = process.env.RAD_SECURITY_TENANT_ID || "";
    const baseUrl =
      process.env.RAD_SECURITY_API_URL || "https://api.rad.security";

    return new RadSecurityClient(sessionToken, accessKeyId, secretKey, baseUrl, accountId, tenantId);
  }

  /**
   * Build a client from an inbound HTTP `Authorization` header, for multi-tenant
   * deployments where each request carries its own Rad Security credential
   * (MCP_AUTH_MODE=header). The base URL is still taken from server config
   * (RAD_SECURITY_API_URL), not the caller.
   *
   * Accepted credential formats (after the `Bearer ` prefix):
   *   - `<access_key_id>:<secret_key>:<account_id>`  (long-lived access key)
   *   - `ory_st_<session_token>:<account_id>`         (pre-minted session token)
   *
   * Only the shape is validated here; whether the credential actually
   * authenticates against the Rad API is determined on the first API call.
   */
  static fromAuthHeader(authHeader: string | undefined): RadSecurityClient {
    if (!authHeader) {
      throw new CredentialError("Missing Authorization header");
    }

    const match = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
    if (!match) {
      throw new CredentialError(
        "Authorization header must be in the form 'Bearer <credential>'"
      );
    }

    const parts = match[1].split(":");
    const baseUrl =
      process.env.RAD_SECURITY_API_URL || "https://api.rad.security";

    // Session-token form: ory_st_<token>:<account_id>
    if (parts.length === 2 && parts[0].startsWith("ory_st_")) {
      const [sessionToken, accountId] = parts;
      if (!accountId) {
        throw new CredentialError(
          "Session-token credential must be 'ory_st_<session_token>:<account_id>'"
        );
      }
      return new RadSecurityClient(sessionToken, "", "", baseUrl, accountId, "");
    }

    // Access-key form: <access_key_id>:<secret_key>:<account_id>
    if (parts.length === 3) {
      const [accessKeyId, secretKey, accountId] = parts;
      if (!accessKeyId || !secretKey || !accountId) {
        throw new CredentialError(
          "Access-key credential must be '<access_key_id>:<secret_key>:<account_id>'"
        );
      }
      return new RadSecurityClient("", accessKeyId, secretKey, baseUrl, accountId, "");
    }

    throw new CredentialError(
      "Bearer credential must be '<access_key_id>:<secret_key>:<account_id>' " +
        "or 'ory_st_<session_token>:<account_id>'"
    );
  }

  private isTokenValid(): boolean {
    if (!this.tokenCache) {
      return false;
    }

    return new Date() < this.tokenCache.expiry;
  }

  getBaseUrl(): string {
    return this.baseUrl;
  }

  getAccountId(): string {
    return this.accountId;
  }

  async getTenantId(): Promise<string> {
    if (this.tenantId) {
      return this.tenantId;
    }

    if (!this.accountId) {
      throw new Error(
        "Cannot fetch tenant ID without an account ID. Set RAD_SECURITY_ACCOUNT_ID or RAD_SECURITY_TENANT_ID."
      );
    }

    const accountData = await this.makeRequest(`/accounts/${this.accountId}`);

    if (!accountData || !accountData.parent_id) {
      throw new Error(`No parent_id found for account: ${this.accountId}`);
    }

    this.tenantId = accountData.parent_id;
    return this.tenantId;
  }

  private async getToken(): Promise<string> {
    if (!this.accountId) {
      throw new Error(
        "You can't access the Rad Security API without setting the RAD_SECURITY_ACCOUNT_ID environment variable."
      );
    }

    if (!this.sessionToken && (!this.accessKeyId || !this.secretKey)) {
      throw new Error(
        "You can't access the Rad Security API without setting the RAD_SECURITY_SESSION_TOKEN or RAD_SECURITY_ACCESS_KEY_ID and RAD_SECURITY_SECRET_KEY." +
        "Only few operations are available without authentication."
      );
    }

    if (this.sessionToken) {
      return this.sessionToken;
    }

    if (this.isTokenValid()) {
      return this.tokenCache!.token;
    }

    try {
      const response = await fetch(
        `${this.baseUrl}/authentication/authenticate`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            access_key_id: this.accessKeyId,
            secret_key: this.secretKey,
          }),
        }
      );

      if (!response.ok) {
        const error = `HTTP error! status: ${response.status}`;
        logger.error({ auth_method: 'access_key', error }, 'auth_attempt_failed');
        throw new Error(error);
      }

      const tokenData = await response.json() as { token: string };

      // Cache token with 5 min buffer before expiry (assuming 4 hour token validity)
      const expiry = new Date();
      expiry.setMinutes(expiry.getMinutes() + 235); // 3h 55m

      this.tokenCache = {
        token: tokenData.token,
        expiry,
      };

      logger.info({ auth_method: 'access_key' }, 'auth_attempt_succeeded');
      return this.tokenCache.token;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error({ auth_method: 'access_key', error: errorMessage }, 'auth_attempt_failed');
      throw new Error(`Error getting authentication token: ${error}`);
    }
  }

  async makeRequest(
    endpoint: string,
    params: Record<string, any> = {},
    options: RequestOptions = {}
  ): Promise<any> {
    const startTime = Date.now();
    const method = options.method || "GET";

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "User-Agent": USER_AGENT,
      ...options.headers,
    };
    const token = await this.getToken();
    if (token && token.startsWith("ory_st_")) {
      headers["Authorization"] = `Bearer ${token}`;
    } else {
      headers["Cookie"] = `ory_kratos_session=${token}`;
    }

    const url = new URL(`${this.getBaseUrl()}${endpoint}`);

    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          url.searchParams.append(key, String(value));
        }
      });
    }

    logger.debug({ endpoint, method, params }, 'api_request_started');

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: options.body ? JSON.stringify(options.body) : undefined,
      });

      const responseBody = await this.parseResponseBody(response);
      const duration = Date.now() - startTime;

      const logLevel = response.status >= 500 ? 'error' : response.status >= 400 ? 'warn' : 'debug';
      logger[logLevel]({ endpoint, status: response.status, duration_ms: duration }, 'api_response_received');

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status} error: ${JSON.stringify(responseBody, null, 2)}`);
      }

      return responseBody;
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error({ endpoint, duration_ms: duration }, 'api_request_failed');
      throw error;
    }
  }

  private async parseResponseBody(response: Response): Promise<unknown> {
    const contentType = response.headers.get("content-type");
    if (contentType?.includes("application/json")) {
      return response.json();
    }
    return response.text();
  }
}
