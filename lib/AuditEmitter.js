/**
 * AuditEmitter.js
 *
 * Fire-and-forget POST of a structured audit event to the webhook URL
 * stored in the document DID's AuditLog service endpoint.
 *
 * Errors are logged but never thrown — audit failures must never block access.
 */

'use strict';

const fetch = require('node-fetch');

/**
 * Emit an audit event to the given URL.
 * Returns immediately; the HTTP call runs in the background.
 *
 * @param {string|null} auditEndpointUrl
 * @param {object} event
 */
function emitAuditEvent(auditEndpointUrl, event) {
  if (!auditEndpointUrl) return;

  const payload = {
    ...event,
    emittedAt: new Date().toISOString()
  };

  fetch(auditEndpointUrl, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(payload),
    timeout: 10000
  }).then(res => {
    if (!res.ok) {
      console.warn(`[AuditEmitter] Audit POST returned ${res.status} for ${auditEndpointUrl}`);
    }
  }).catch(err => {
    console.warn('[AuditEmitter] Audit POST failed:', err.message);
  });
}

module.exports = { emitAuditEvent };
