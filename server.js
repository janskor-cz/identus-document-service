/**
 * identus-document-service — Stateless Document Access Microservice
 *
 * Endpoints:
 *   POST /access              — VP-gated document access (re-encrypts for client)
 *   GET  /health              — Liveness probe
 *   GET  /resolve/:documentDID — Public DID metadata lookup (no encryptionInfo)
 *
 * All document state lives in:
 *   - The document's PRISM DID document (service endpoints)
 *   - Iagon decentralized storage (encrypted file)
 * No local database or file system writes.
 */

'use strict';

require('dotenv').config();

const express = require('express');
const crypto  = require('crypto');

const config                  = require('./config');
const { resolveDocumentDID }  = require('./lib/DIDDocumentResolver');
const { emitAuditEvent }      = require('./lib/AuditEmitter');
const { verifyVPAndExtractClaims } = require('./lib/VPVerificationService');
const { processAccessRequest, getLevelNumber, getLevelLabel } = require('./lib/ReEncryptionService');
const { IagonStorageClient }  = require('./lib/IagonStorageClient');

const app = express();
app.use(express.json({ limit: '10mb' }));

// ---------------------------------------------------------------------------
// GET /health
// ---------------------------------------------------------------------------
app.get('/health', async (req, res) => {
  const iagon = new IagonStorageClient({
    accessToken:     config.IAGON_ACCESS_TOKEN,
    nodeId:          config.IAGON_NODE_ID,
    downloadBaseUrl: config.IAGON_DOWNLOAD_BASE_URL
  });

  const iagonStatus = await iagon.testConnection().catch(() => ({ connected: false }));

  res.json({
    status:    'ok',
    timestamp: new Date().toISOString(),
    config: {
      cloudAgentUrl: config.ENTERPRISE_CLOUD_AGENT_URL,
      iagonConfigured: iagon.isConfigured(),
      iagonConnected:  iagonStatus.connected ?? false
    }
  });
});

// ---------------------------------------------------------------------------
// GET /resolve/:documentDID
// Public metadata lookup — strips encryptionInfo before responding
// ---------------------------------------------------------------------------
app.get('/resolve/:documentDID', async (req, res) => {
  const { documentDID } = req.params;

  if (!documentDID || !documentDID.startsWith('did:')) {
    return res.status(400).json({ error: 'Invalid DID format' });
  }

  try {
    const meta = await resolveDocumentDID(documentDID);

    // Never expose the AES encryption key in a public endpoint
    const { encryptionInfo: _stripped, ...publicMeta } = meta;

    return res.json({
      documentDID,
      ...publicMeta,
      resolvedAt: new Date().toISOString()
    });

  } catch (err) {
    console.error('[/resolve] Error:', err.message);

    if (err.message.includes('resolution failed')) {
      return res.status(404).json({ error: 'DID not found', documentDID });
    }

    return res.status(500).json({ error: 'DID resolution error', details: err.message });
  }
});

// ---------------------------------------------------------------------------
// POST /access
// Main document access gate — VP → clearance check → re-encrypt → return
// ---------------------------------------------------------------------------
app.post('/access', async (req, res) => {
  const startTime = Date.now();
  const clientIp  = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  const {
    documentDID,
    ephemeralPublicKey,
    vp,
    // Optional explicit signature fields (for wallet clients that sign separately)
    signature,
    ephemeralDID,
    timestamp,
    nonce: reqNonce
  } = req.body;

  // ── Basic validation ────────────────────────────────────────────────────
  if (!documentDID || !ephemeralPublicKey || !vp) {
    return res.status(400).json({
      error:   'MISSING_FIELDS',
      message: 'documentDID, ephemeralPublicKey, and vp are required'
    });
  }

  if (!documentDID.startsWith('did:')) {
    return res.status(400).json({ error: 'INVALID_DID', message: 'documentDID must be a valid DID' });
  }

  try {
    // ── Step 1: Resolve document DID → get metadata ────────────────────────
    let docMeta;
    try {
      docMeta = await resolveDocumentDID(documentDID);
    } catch (resolveErr) {
      console.error('[/access] DID resolution error:', resolveErr.message);
      return res.status(404).json({
        error:   'DOCUMENT_NOT_FOUND',
        message: 'Could not resolve document DID'
      });
    }

    // ── Step 2: Verify VP + extract issuerDID and clearanceLevel ───────────
    // releasableTo is the accepted issuer DID list embedded in the DID document
    const vpResult = verifyVPAndExtractClaims(vp, docMeta.releasableTo);

    if (!vpResult.success) {
      console.warn('[/access] VP verification failed:', vpResult.error);

      _fireAudit(docMeta.auditEndpoint, {
        event:       'ACCESS_DENIED',
        documentDID,
        denialReason: vpResult.error,
        clientIp,
        processingMs: Date.now() - startTime
      });

      return res.status(403).json({
        error:   vpResult.error,
        message: vpResult.message
      });
    }

    const { issuerDID, clearanceLevel: clearanceLevelStr, viewerName } = vpResult;
    const clearanceLevelNum = getLevelNumber(clearanceLevelStr || 'UNCLASSIFIED');

    // ── Step 3–8: Delegate to stateless ReEncryptionService ───────────────
    const result = await processAccessRequest({
      documentDID,
      requestorDID:      vpResult.companyDID || issuerDID,
      issuerDID,
      clearanceLevelNum,
      clearanceLevelStr: clearanceLevelStr || getLevelLabel(clearanceLevelNum),
      ephemeralPublicKey,
      signature:         signature  || _generateNullSig(),
      ephemeralDID:      ephemeralDID || `did:key:${crypto.randomUUID()}`,
      timestamp:         timestamp  || new Date().toISOString(),
      nonce:             reqNonce   || crypto.randomUUID(),
      docMeta,
      clientIp
    });

    // ── Emit audit event ──────────────────────────────────────────────────
    _fireAudit(docMeta.auditEndpoint, {
      event:          result.success ? 'ACCESS_GRANTED' : 'ACCESS_DENIED',
      documentDID,
      issuerDID,
      clearanceLevel: clearanceLevelStr,
      copyId:         result.copyId || null,
      denialReason:   result.error  || null,
      viewerName:     viewerName    || null,
      clientIp,
      processingMs:   Date.now() - startTime
    });

    if (!result.success) {
      return res.status(403).json({
        error:   result.error,
        message: result.message
      });
    }

    return res.json({
      success:         true,
      copyId:          result.copyId,
      copyHash:        result.copyHash,
      filename:        result.filename,
      mimeType:        result.mimeType,
      clearanceLevel:  result.clearanceLevel,
      encryptedDocument: {
        ciphertext:      result.ciphertext,
        nonce:           result.nonce,
        senderPublicKey: result.serverPublicKey
      },
      accessedAt: result.accessedAt
    });

  } catch (err) {
    console.error('[/access] Unhandled error:', err);
    return res.status(500).json({
      error:   'INTERNAL_ERROR',
      message: 'An internal error occurred'
    });
  }
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function _fireAudit(url, event) {
  emitAuditEvent(url, event);
}

/** Produces a 64-byte zero signature used when the client doesn't provide one.
 *  verifySignature will fall back to format-only validation in this case. */
function _generateNullSig() {
  return Buffer.alloc(64).toString('base64');
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
app.listen(config.PORT, () => {
  console.log(`[identus-document-service] Listening on port ${config.PORT}`);
  console.log(`[identus-document-service] Cloud Agent: ${config.ENTERPRISE_CLOUD_AGENT_URL}`);
  console.log(`[identus-document-service] Iagon configured: ${!!(config.IAGON_ACCESS_TOKEN && config.IAGON_NODE_ID)}`);
});

module.exports = app; // for testing
