export class RadSecurityAuth {
  private accessKeyId: string;
  private secretKey: string;
  private baseUrl: string;
  private tokenCache: { token: string; expiry: Date } | null = null;

  constructor(accessKeyId: string, secretKey: string, baseUrl: string) {
    this.accessKeyId = accessKeyId;
    this.secretKey = secretKey;
    this.baseUrl = baseUrl;
  }

  static fromEnv(): RadSecurityAuth {
    const accessKeyId = process.env.RAD_SECURITY_ACCESS_KEY_ID;
    const secretKey = process.env.RAD_SECURITY_SECRET_KEY;
    const baseUrl = process.env.RAD_SECURITY_API_URL;

    if (!accessKeyId || !secretKey || !baseUrl) {
      throw new Error(
        "RAD_SECURITY_ACCESS_KEY_ID, RAD_SECURITY_SECRET_KEY, and RAD_SECURITY_API_URL must be set"
      );
    }

    return new RadSecurityAuth(accessKeyId, secretKey, baseUrl);
  }

  private isTokenValid(): boolean {
    if (!this.tokenCache) {
      return false;
    }

    return new Date() < this.tokenCache.expiry;
  }

  async getToken(): Promise<string> {
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
} 