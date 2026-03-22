/**
 * DIDDocumentResolver.js
 *
 * Resolves a PRISM DID via the Enterprise Cloud Agent REST API and extracts
 * the document service endpoint metadata embedded at DID creation time.
 *
 * Expected DID document services:
 *   #metadata  (DocumentMetadata)   — iagonFileId, clearanceLevel, releasableTo, …
 *   #access    (DocumentAccessGate) — URL of this service's /access endpoint
 *   #audit     (AuditLog)           — webhook URL for audit events
 */

'use strict';

const fetch  = require('node-fetch');
const config = require('../config');

/**
 * Resolve a document DID and return structured metadata.
 *
 * @param {string} documentDID
 * @returns {Promise<{
 *   iagonFileId: string,
 *   clearanceLevel: string,
 *   releasableTo: string[],
 *   title: string|null,
 *   contentHash: string|null,
 *   encryptionInfo: object|null,
 *   filename: string|null,
 *   mimeType: string|null,
 *   accessEndpoint: string|null,
 *   auditEndpoint: string|null,
 *   verificationMethods: object[]
 * }>}
 */
async function resolveDocumentDID(documentDID) {
  const url = `${config.ENTERPRISE_CLOUD_AGENT_URL}/dids/${encodeURIComponent(documentDID)}`;

  const headers = { 'Content-Type': 'application/json' };
  if (config.ENTERPRISE_CLOUD_AGENT_API_KEY) {
    headers['apikey'] = config.ENTERPRISE_CLOUD_AGENT_API_KEY;
  }

  const response = await fetch(url, {
    method:  'GET',
    headers,
    timeout: config.REQUEST_TIMEOUT_MS
  });

  if (!response.ok) {
    throw new Error(`DID resolution failed (${response.status}) for: ${documentDID}`);
  }

  const data = await response.json();

  // Identus Cloud Agent wraps the DID document under { did: { ... } }
  const didDoc = data.did || data.document || data;

  const services = didDoc.services || didDoc.service || [];
  const verificationMethods = didDoc.verificationMethods || didDoc.authentication || [];

  // ---- DocumentMetadata -------------------------------------------------
  const metadataService = services.find(s => s.type === 'DocumentMetadata');
  if (!metadataService) {
    throw new Error(`No DocumentMetadata service endpoint in DID document: ${documentDID}`);
  }

  let metadata = metadataService.serviceEndpoint;

  // The Cloud Agent may return a single-element array
  if (Array.isArray(metadata)) {
    metadata = metadata[0];
  }

  // May be stored as a JSON string inside a plain string serviceEndpoint
  if (typeof metadata === 'string') {
    try { metadata = JSON.parse(metadata); } catch (_) {}
  }

  if (!metadata || typeof metadata !== 'object') {
    throw new Error(`Malformed DocumentMetadata service endpoint in DID: ${documentDID}`);
  }

  if (!metadata.iagonFileId) {
    throw new Error(`DocumentMetadata missing iagonFileId in DID: ${documentDID}`);
  }

  // ---- DocumentAccessGate -----------------------------------------------
  const accessService  = services.find(s => s.type === 'DocumentAccessGate');
  const accessEndpoint = accessService
    ? _unwrapEndpoint(accessService.serviceEndpoint)
    : null;

  // ---- AuditLog ---------------------------------------------------------
  const auditService  = services.find(s => s.type === 'AuditLog');
  const auditEndpoint = auditService
    ? _unwrapEndpoint(auditService.serviceEndpoint)
    : (config.AUDIT_FALLBACK_URL || null);

  return {
    iagonFileId:      metadata.iagonFileId,
    clearanceLevel:   metadata.clearanceLevel   || 'INTERNAL',
    releasableTo:     Array.isArray(metadata.releasableTo) ? metadata.releasableTo : [],
    title:            metadata.title            || null,
    contentHash:      metadata.contentHash      || null,
    encryptionInfo:   metadata.encryptionInfo   || null,
    filename:         metadata.filename         || null,
    mimeType:         metadata.mimeType         || null,
    accessEndpoint,
    auditEndpoint,
    verificationMethods
  };
}

/** Extract a plain URL string from whatever shape the serviceEndpoint arrives in. */
function _unwrapEndpoint(ep) {
  if (!ep) return null;
  if (typeof ep === 'string') return ep;
  if (Array.isArray(ep))     return ep[0] || null;
  if (typeof ep === 'object' && ep.uri) return ep.uri;
  return null;
}

module.exports = { resolveDocumentDID };
