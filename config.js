'use strict';

module.exports = {
  PORT: parseInt(process.env.PORT || '3020', 10),

  // Enterprise Cloud Agent — used for DID resolution and revocation checking
  ENTERPRISE_CLOUD_AGENT_URL:     process.env.ENTERPRISE_CLOUD_AGENT_URL || 'http://91.99.4.54:8300',
  ENTERPRISE_CLOUD_AGENT_API_KEY: process.env.ENTERPRISE_CLOUD_AGENT_API_KEY || '',

  // Iagon decentralized storage
  IAGON_ACCESS_TOKEN:    process.env.IAGON_ACCESS_TOKEN || '',
  IAGON_NODE_ID:         process.env.IAGON_NODE_ID || '',
  IAGON_DOWNLOAD_BASE_URL: process.env.IAGON_DOWNLOAD_BASE_URL || 'https://gw.iagon.com/api/v2',

  // Optional fallback audit webhook when the DID document has no AuditLog endpoint
  AUDIT_FALLBACK_URL: process.env.AUDIT_FALLBACK_URL || '',

  // Request timeout for outbound HTTP calls (ms)
  REQUEST_TIMEOUT_MS: parseInt(process.env.REQUEST_TIMEOUT_MS || '15000', 10),
};
