import { Server } from "@modelcontextprotocol/sdk/server/index.js";

export type LogLevel = "debug" | "info" | "notice" | "warning" | "error" | "critical" | "alert" | "emergency";

const LOG_LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  notice: 2,
  warning: 3,
  error: 4,
  critical: 5,
  alert: 6,
  emergency: 7,
};

export type LogFormat = "human" | "json";

export interface LoggerConfig {
  minLevel?: LogLevel;
  enableStderr?: boolean;
  enableMcpNotifications?: boolean;
  stderrFormat?: LogFormat;
}

export class Logger {
  private server: Server | null = null;
  private minLevel: LogLevel = "info";
  private enableStderr: boolean = true;
  private enableMcpNotifications: boolean = true;
  private stderrFormat: LogFormat = "human";

  constructor(config: LoggerConfig = {}) {
    this.minLevel = config.minLevel || "info";
    this.enableStderr = config.enableStderr ?? true;
    this.enableMcpNotifications = config.enableMcpNotifications ?? true;
    this.stderrFormat = config.stderrFormat || "human";
  }

  configure(config: Partial<LoggerConfig>): void {
    if (config.minLevel !== undefined) {
      this.minLevel = config.minLevel;
    }
    if (config.enableStderr !== undefined) {
      this.enableStderr = config.enableStderr;
    }
    if (config.enableMcpNotifications !== undefined) {
      this.enableMcpNotifications = config.enableMcpNotifications;
    }
    if (config.stderrFormat !== undefined) {
      this.stderrFormat = config.stderrFormat;
    }
  }

  setServer(server: Server): void {
    this.server = server;
  }

  setLevel(level: LogLevel): void {
    this.minLevel = level;
  }

  getLevel(): LogLevel {
    return this.minLevel;
  }

  private shouldLog(level: LogLevel): boolean {
    return LOG_LEVEL_PRIORITY[level] >= LOG_LEVEL_PRIORITY[this.minLevel];
  }

  private sanitizeData(data: any): any {
    if (typeof data !== 'object' || data === null) {
      return data;
    }

    const sanitized = Array.isArray(data) ? [...data] : { ...data };

    const sensitiveKeys = [
      'token',
      'sessionToken',
      'session_token',
      'accessKeyId',
      'access_key_id',
      'secretKey',
      'secret_key',
      'password',
      'authorization',
      'cookie',
      'api_key',
      'apiKey',
    ];

    for (const key in sanitized) {
      const lowerKey = key.toLowerCase();
      if (sensitiveKeys.some(sk => lowerKey.includes(sk.toLowerCase()))) {
        sanitized[key] = '[REDACTED]';
      } else if (typeof sanitized[key] === 'object' && sanitized[key] !== null) {
        sanitized[key] = this.sanitizeData(sanitized[key]);
      }
    }

    return sanitized;
  }

  private async sendLog(level: LogLevel, logger: string, data: any): Promise<void> {
    // Send MCP notification - only if server is attached
    if (!this.server) {
      return;
    }

    try {
      await this.server.sendLoggingMessage({
        level,
        logger,
        data
      });
    } catch (error) {
      // If notification fails (e.g., not connected yet), silently skip
      // The stderr log already happened, so the log isn't lost
      if (error instanceof Error && error.message !== "Not connected") {
        console.error('Failed to send log notification:', error);
      }
    }
  }

  private formatTimestamp(): string {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const seconds = String(now.getSeconds()).padStart(2, '0');
    const ms = String(now.getMilliseconds()).padStart(3, '0');
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}.${ms}`;
  }

  private formatForHuman(data: any): string {
    if (typeof data === 'string') {
      return data;
    }

    if (typeof data !== 'object' || data === null) {
      return String(data);
    }

    const parts: string[] = [];

    // Extract message first if it exists
    if (data.message) {
      parts.push(data.message);
    }

    // Add other fields as key=value pairs
    for (const [key, value] of Object.entries(data)) {
      if (key === 'message') continue; // Already handled

      let formattedValue: string;
      if (typeof value === 'object' && value !== null) {
        formattedValue = JSON.stringify(value);
      } else {
        formattedValue = String(value);
      }

      parts.push(`${key}=${formattedValue}`);
    }

    return parts.join(' ');
  }

  private log(level: LogLevel, logger: string, data: any): void {
    if (!this.shouldLog(level)) {
      return;
    }

    const sanitizedData = this.sanitizeData(data);

    // HYBRID APPROACH (configurable):
    // 1. stderr: Human-readable or JSON format (controlled by enableStderr + stderrFormat)
    // 2. MCP notification: Structured JSON (controlled by enableMcpNotifications)

    // Output to stderr if enabled
    if (this.enableStderr) {
      const consoleLevel = level === 'debug' ? 'debug' :
                          level === 'info' || level === 'notice' ? 'log' :
                          level === 'warning' ? 'warn' : 'error';

      if (this.stderrFormat === 'json') {
        // JSON format for machine parsing
        const jsonLog = {
          timestamp: new Date().toISOString(),
          level,
          logger,
          ...sanitizedData
        };
        console[consoleLevel](JSON.stringify(jsonLog));
      } else {
        // Human-readable format
        const timestamp = this.formatTimestamp();
        const humanReadable = this.formatForHuman(sanitizedData);
        const stderrMessage = `${timestamp} [${level.toUpperCase()}] ${logger}: ${humanReadable}`;
        console[consoleLevel](stderrMessage);
      }
    }

    // Send structured JSON via MCP notification if enabled and server is connected
    if (this.enableMcpNotifications && this.server) {
      // Don't await - fire and forget to avoid blocking
      void this.sendLog(level, logger, sanitizedData);
    }
  }

  debug(logger: string, data: any): void {
    this.log("debug", logger, data);
  }

  info(logger: string, data: any): void {
    this.log("info", logger, data);
  }

  notice(logger: string, data: any): void {
    this.log("notice", logger, data);
  }

  warning(logger: string, data: any): void {
    this.log("warning", logger, data);
  }

  error(logger: string, data: any): void {
    this.log("error", logger, data);
  }

  critical(logger: string, data: any): void {
    this.log("critical", logger, data);
  }

  alert(logger: string, data: any): void {
    this.log("alert", logger, data);
  }

  emergency(logger: string, data: any): void {
    this.log("emergency", logger, data);
  }

  // Convenience methods for common logging patterns
  apiRequest(endpoint: string, method: string, params?: Record<string, any>): void {
    this.debug("api", {
      message: "Making API request",
      endpoint,
      method,
      params,
    });
  }

  apiResponse(endpoint: string, status: number, duration: number): void {
    const level = status >= 500 ? "error" : status >= 400 ? "warning" : "debug";
    this.log(level, "api", {
      message: "API response received",
      endpoint,
      status,
      duration_ms: duration,
    });
  }

  toolInvocation(toolName: string, args: any): void {
    this.info("tools", {
      message: "Tool invoked",
      tool: toolName,
      arguments: args,
    });
  }

  toolSuccess(toolName: string, duration: number): void {
    this.info("tools", {
      message: "Tool execution completed",
      tool: toolName,
      duration_ms: duration,
    });
  }

  toolError(toolName: string, error: Error | string, duration: number): void {
    this.error("tools", {
      message: "Tool execution failed",
      tool: toolName,
      error: error instanceof Error ? error.message : error,
      duration_ms: duration,
    });
  }

  authAttempt(method: string): void {
    this.debug("auth", {
      message: "Authentication attempt",
      method,
    });
  }

  authSuccess(method: string): void {
    this.info("auth", {
      message: "Authentication successful",
      method,
    });
  }

  authFailure(method: string, error: string): void {
    this.error("auth", {
      message: "Authentication failed",
      method,
      error,
    });
  }

  serverStartup(version: string, transport: string): void {
    this.notice("server", {
      message: "Server starting",
      version,
      transport,
      node_version: process.version,
    });
  }

  serverReady(transport: string, details?: any): void {
    this.notice("server", {
      message: "Server ready",
      transport,
      ...details,
    });
  }

  configChange(setting: string, value: any): void {
    this.notice("config", {
      message: "Configuration changed",
      setting,
      value: this.sanitizeData(value),
    });
  }
}

// Global logger instance
export const logger = new Logger();
