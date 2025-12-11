import pino from 'pino';

/**
 * Configuration via environment variables:
 * - LOG_LEVEL: Minimum log level (trace|debug|info|warn|error|fatal) [default: info]
 * - LOG_FORMAT: Output format [default: json]
 * - RAD_SECURITY_ACCOUNT_ID: Account ID to include in all logs
 * - RAD_SECURITY_TENANT_ID: Tenant ID to include in all logs
 */

const logLevel = process.env.LOG_LEVEL || 'info';
const logFormat = process.env.LOG_FORMAT || 'json';
const accountId = process.env.RAD_SECURITY_ACCOUNT_ID || '';
const tenantId = process.env.RAD_SECURITY_TENANT_ID || '';

// Determine if we should use pretty printing
const usePretty = logFormat != 'json';

// Build base context to include in all logs
const baseContext: Record<string, string> = {
  langgraph_node: 'mcp-server'
};
if (accountId) baseContext.account_id = accountId;
if (tenantId) baseContext.tenant_id = tenantId;

export const logger = pino({
  level: logLevel,

  // Use ISO 8601 timestamp format with custom field name
  timestamp: () => `,"timestamp":"${new Date().toISOString()}"`,

  // Add langgraph_node, account_id, and tenant_id to all logs
  base: baseContext,

  formatters: {
    level: (label) => {
      return { level: label };
    }
  },

  messageKey: 'event',

  // Redact sensitive fields automatically
  redact: {
    paths: [
      '*.token',
      '*.sessionToken',
      '*.session_token',
      '*.accessKeyId',
      '*.access_key_id',
      '*.secretKey',
      '*.secret_key',
      '*.password',
      '*.authorization',
      '*.cookie',
      '*.api_key',
      '*.apiKey',
    ],
    remove: true
  },

  transport: usePretty ? {
    target: 'pino-pretty',
    options: {
      colorize: true,
      translateTime: 'yyyy-mm-dd HH:MM:ss.l',
      ignore: 'pid,hostname',
      levelFirst: false,
      messageFormat: '{msg}'
    }
  } : undefined

}, pino.destination(2)); // Write to stderr (fd 2)

// Log startup info
if (process.env.NODE_ENV !== 'test') {
  logger.info({
    log_level: logLevel,
    log_format: logFormat,
    node_version: process.version
  }, 'logger_initialized');
}
