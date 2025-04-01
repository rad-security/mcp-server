const USER_AGENT = `rad-security/mcp-server`;

type RequestOptions = {
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
};

export class RadSecurityClient {
  private accessKeyId: string;
  private secretKey: string;
  private baseUrl: string;
  private accountId: string;
  private tokenCache: { token: string; expiry: Date } | null = null;

  constructor(
    accessKeyId: string,
    secretKey: string,
    baseUrl: string,
    accountId: string
  ) {
    this.accessKeyId = accessKeyId;
    this.secretKey = secretKey;
    this.baseUrl = baseUrl;
    this.accountId = accountId;
  }

  static fromEnv(): RadSecurityClient {
    const accessKeyId = process.env.RAD_SECURITY_ACCESS_KEY_ID;
    const secretKey = process.env.RAD_SECURITY_SECRET_KEY;
    const accountId = process.env.RAD_SECURITY_ACCOUNT_ID;
    const baseUrl =
      process.env.RAD_SECURITY_API_URL || "https://api.rad.security";

    if (!accessKeyId || !secretKey || !accountId) {
      throw new Error(
        "RAD_SECURITY_ACCESS_KEY_ID, RAD_SECURITY_SECRET_KEY, and RAD_SECURITY_ACCOUNT_ID must be set"
      );
    }

    return new RadSecurityClient(accessKeyId, secretKey, baseUrl, accountId);
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

  private async getToken(): Promise<string> {
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
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const tokenData = await response.json();

      // Cache token with 5 min buffer before expiry (assuming 4 hour token validity)
      const expiry = new Date();
      expiry.setMinutes(expiry.getMinutes() + 235); // 3h 55m

      this.tokenCache = {
        token: tokenData.token,
        expiry,
      };

      return this.tokenCache.token;
    } catch (error) {
      throw new Error(`Error getting authentication token: ${error}`);
    }
  }

  async makeRequest(
    endpoint: string,
    params: Record<string, any> = {},
    options: RequestOptions = {}
  ): Promise<any> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "User-Agent": USER_AGENT,
      Authorization: `Bearer ${await this.getToken()}`,
      ...options.headers,
    };

    const url = new URL(`${this.getBaseUrl()}${endpoint}`);

    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          url.searchParams.append(key, String(value));
        }
      });
    }

    const response = await fetch(url, {
      method: options.method || "GET",
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });

    const responseBody = await this.parseResponseBody(response);

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status} error: ${JSON.stringify(responseBody, null, 2)}`);
    }

    return responseBody;
  }

  private async parseResponseBody(response: Response): Promise<unknown> {
    const contentType = response.headers.get("content-type");
    if (contentType?.includes("application/json")) {
      return response.json();
    }
    return response.text();
  }
}
