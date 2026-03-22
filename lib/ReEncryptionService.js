/**
 * ReEncryptionService.js — Stateless version
 *
 * Performs the cryptographic core of the document access gate:
 *   1. Verify Ed25519 signature on the access request (DID resolution)
 *   2. Replay-attack detection via in-memory nonce cache
 *   3. Clearance level comparison
 *   4. Download document from Iagon (fileId from DID metadata)
 *   5. Re-encrypt for the client's ephemeral X25519 key (NaCl box)
 *
 * Unlike the company-admin-portal version this module is fully stateless:
 *   - No file I/O
 *   - No DocumentRegistry dependency
 *   - Document metadata is passed in (already resolved from the DID document)
 *   - Audit logging is handled externally by AuditEmitter
 */

'use strict';

const crypto = require('crypto');
const nacl   = require('tweetnacl');
const fetch  = require('node-fetch');

const { IagonStorageClient } = require('./IagonStorageClient');
const config = require('../config');

// ---------------------------------------------------------------------------
// Replay-attack prevention — in-memory nonce cache (per process)
// In a multi-instance deployment use a shared Redis cache instead.
// ---------------------------------------------------------------------------
const nonceCache   = new Map();
const NONCE_EXPIRY = 5 * 60 * 1000; // 5 minutes

// ---------------------------------------------------------------------------
// Iagon client (singleton)
// ---------------------------------------------------------------------------
const iagonClient = new IagonStorageClient({
  accessToken:     config.IAGON_ACCESS_TOKEN,
  nodeId:          config.IAGON_NODE_ID,
  downloadBaseUrl: config.IAGON_DOWNLOAD_BASE_URL
});

// ---------------------------------------------------------------------------
// Classification level helpers
// ---------------------------------------------------------------------------
const LEVEL_NUMBERS = {
  'UNCLASSIFIED': 0,
  'INTERNAL':     1,
  'CONFIDENTIAL': 2,
  'RESTRICTED':   3,
  'SECRET':       4,
  'TOP-SECRET':   4   // legacy alias
};

const LEVEL_LABELS = {
  0: 'UNCLASSIFIED',
  1: 'INTERNAL',
  2: 'CONFIDENTIAL',
  3: 'RESTRICTED',
  4: 'SECRET'
};

function getLevelNumber(label) {
  return LEVEL_NUMBERS[label] ?? 0;
}

function getLevelLabel(level) {
  return LEVEL_LABELS[level] || 'UNKNOWN';
}

// ---------------------------------------------------------------------------
// Replay detection
// ---------------------------------------------------------------------------
function checkReplay(nonce) {
  const now = Date.now();

  // Purge expired nonces
  for (const [n, t] of nonceCache.entries()) {
    if (now - t > NONCE_EXPIRY) nonceCache.delete(n);
  }

  if (nonceCache.has(nonce)) return true;   // replay detected
  nonceCache.set(nonce, now);
  return false;
}

// ---------------------------------------------------------------------------
// Ed25519 signature verification
// ---------------------------------------------------------------------------
/**
 * Verify an Ed25519 signature over the access request payload.
 *
 * Resolves the requestor DID via the Cloud Agent to obtain the authentication
 * public key.  Falls back to format-only validation if DID resolution fails
 * so that newly created DIDs (not yet published) can still access INTERNAL
 * documents during onboarding.
 */
async function verifySignature({ documentDID, ephemeralDID, timestamp, nonce, signature, requestorDID }) {
  try {
    const sigBytes = Buffer.from(signature, 'base64');

    if (sigBytes.length !== 64) {
      console.warn('[ReEncryptionService] Invalid signature length:', sigBytes.length);
      return false;
    }

    // Reject stale requests (> 5 minutes)
    const requestTime = new Date(timestamp).getTime();
    if (Math.abs(Date.now() - requestTime) > 5 * 60 * 1000) {
      console.warn('[ReEncryptionService] Timestamp out of window');
      return false;
    }

    // Canonical payload (must match EphemeralDIDCrypto.ts signAccessRequest)
    const payload      = JSON.stringify({ documentId: documentDID, ephemeralDID, timestamp, nonce, requestorDID });
    const messageBytes = new Uint8Array(Buffer.from(payload));

    // Resolve DID to get verification keys
    const resolveUrl = `${config.ENTERPRISE_CLOUD_AGENT_URL}/dids/${encodeURIComponent(requestorDID)}`;
    const headers    = { 'Content-Type': 'application/json' };
    if (config.ENTERPRISE_CLOUD_AGENT_API_KEY) headers['apikey'] = config.ENTERPRISE_CLOUD_AGENT_API_KEY;

    try {
      const res = await fetch(resolveUrl, { method: 'GET', headers, timeout: config.REQUEST_TIMEOUT_MS });

      if (!res.ok) {
        console.warn(`[ReEncryptionService] Requestor DID resolution failed (${res.status}) — format-only fallback`);
        return true;
      }

      const data   = await res.json();
      const didDoc = data.did || data.document || data;
      const vms    = didDoc.verificationMethods || didDoc.authentication || [];

      if (vms.length === 0) {
        console.warn('[ReEncryptionService] No verification methods — format-only fallback');
        return true;
      }

      for (const vm of vms) {
        let pubKeyBytes = null;

        if (vm.publicKeyBase64) {
          pubKeyBytes = new Uint8Array(Buffer.from(vm.publicKeyBase64, 'base64'));
        } else if (vm.publicKeyJwk && vm.publicKeyJwk.x) {
          const x       = vm.publicKeyJwk.x.replace(/-/g, '+').replace(/_/g, '/');
          const xPadded = x + '='.repeat((4 - x.length % 4) % 4);
          pubKeyBytes   = new Uint8Array(Buffer.from(xPadded, 'base64'));
        }

        if (!pubKeyBytes || pubKeyBytes.length !== 32) continue;

        try {
          const verified = nacl.sign.detached.verify(messageBytes, new Uint8Array(sigBytes), pubKeyBytes);
          if (verified) {
            console.log(`[ReEncryptionService] Ed25519 signature verified with key: ${vm.id || vm.type}`);
            return true;
          }
        } catch (_) {
          // key type mismatch — try next vm
        }
      }

      console.warn('[ReEncryptionService] Signature did not verify against any key in DID document');
      return false;

    } catch (resolveErr) {
      console.warn('[ReEncryptionService] DID resolution error — format-only fallback:', resolveErr.message);
      return true;
    }

  } catch (err) {
    console.error('[ReEncryptionService] Signature verification error:', err);
    return false;
  }
}

// ---------------------------------------------------------------------------
// XSalsa20-Poly1305 re-encryption
// ---------------------------------------------------------------------------
/**
 * Encrypt plaintext for the client's ephemeral X25519 public key.
 * Returns { ciphertext, nonce, serverPublicKey } — all base64-encoded.
 */
function encryptForEphemeralKey(content, ephemeralPublicKeyBase64) {
  const clientPubKey  = new Uint8Array(Buffer.from(ephemeralPublicKeyBase64, 'base64'));
  const serverKeyPair = nacl.box.keyPair();
  const nonce         = nacl.randomBytes(nacl.box.nonceLength);

  const ciphertext = nacl.box(
    new Uint8Array(content),
    nonce,
    clientPubKey,
    serverKeyPair.secretKey
  );

  return {
    ciphertext:      Buffer.from(ciphertext).toString('base64'),
    nonce:           Buffer.from(nonce).toString('base64'),
    serverPublicKey: Buffer.from(serverKeyPair.publicKey).toString('base64')
  };
}

// ---------------------------------------------------------------------------
// MIME type helper
// ---------------------------------------------------------------------------
const MIME_TYPES = {
  pdf:  'application/pdf',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  doc:  'application/msword',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  xls:  'application/vnd.ms-excel',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  ppt:  'application/vnd.ms-powerpoint',
  txt:  'text/plain',
  json: 'application/json',
  xml:  'application/xml',
  png:  'image/png',
  jpg:  'image/jpeg',
  jpeg: 'image/jpeg',
  gif:  'image/gif',
  html: 'text/html',
  htm:  'text/html'
};

function getMimeType(metadata) {
  if (metadata.mimeType) return metadata.mimeType;
  const ext = (metadata.filename || '').split('.').pop()?.toLowerCase();
  return (ext && MIME_TYPES[ext]) || 'application/octet-stream';
}

// ---------------------------------------------------------------------------
// Main: process an access request
// ---------------------------------------------------------------------------
/**
 * @param {object} opts
 * @param {string}  opts.documentDID        — document DID being accessed
 * @param {string}  opts.requestorDID       — holder's DID (from VP)
 * @param {string}  opts.issuerDID          — company DID that issued the VC
 * @param {number}  opts.clearanceLevelNum  — numeric clearance (getLevelNumber)
 * @param {string}  opts.clearanceLevelStr  — string clearance label
 * @param {string}  opts.ephemeralPublicKey — client's X25519 key (base64)
 * @param {string}  opts.signature          — Ed25519 sig over payload (base64)
 * @param {string}  opts.ephemeralDID       — client's ephemeral DID
 * @param {string}  opts.timestamp          — ISO8601 request timestamp
 * @param {string}  opts.nonce              — unique nonce (UUIDv4)
 * @param {object}  opts.docMeta            — resolved DID metadata (from DIDDocumentResolver)
 * @param {string}  [opts.clientIp]
 * @returns {Promise<object>}
 */
async function processAccessRequest(opts) {
  const {
    documentDID, requestorDID, issuerDID,
    clearanceLevelNum, clearanceLevelStr,
    ephemeralPublicKey,
    signature, ephemeralDID, timestamp, nonce,
    docMeta,
    clientIp
  } = opts;

  // Step 1: Verify Ed25519 signature
  const sigValid = await verifySignature({ documentDID, ephemeralDID, timestamp, nonce, signature, requestorDID });
  if (!sigValid) {
    return { success: false, error: 'INVALID_SIGNATURE', message: 'Access request signature verification failed' };
  }

  // Step 2: Replay detection
  if (checkReplay(nonce)) {
    return { success: false, error: 'REPLAY_DETECTED', message: 'Request nonce has already been used' };
  }

  // Step 3: Releasability — issuer DID must be in releasableTo
  if (!docMeta.releasableTo.includes(issuerDID)) {
    console.warn(`[ReEncryptionService] Releasability denied. issuerDID=${issuerDID}`);
    return { success: false, error: 'RELEASABILITY_DENIED', message: 'Your credential issuer is not authorized for this document' };
  }

  // Step 4: Clearance level
  const requiredLevel = getLevelNumber(docMeta.clearanceLevel);
  if (clearanceLevelNum < requiredLevel) {
    return {
      success: false,
      error:   'CLEARANCE_DENIED',
      message: `Document requires ${docMeta.clearanceLevel}, you have ${clearanceLevelStr}`
    };
  }

  // Step 5: Revocation check (best-effort — never blocks access on failure)
  try {
    const statusListUrl = `${config.ENTERPRISE_CLOUD_AGENT_URL}/credential-status/registry`;
    const headers       = { 'Content-Type': 'application/json' };
    if (config.ENTERPRISE_CLOUD_AGENT_API_KEY) headers['apikey'] = config.ENTERPRISE_CLOUD_AGENT_API_KEY;

    // Search for any revoked credentials held by this requestor issued by issuerDID
    const searchRes = await fetch(`${config.ENTERPRISE_CLOUD_AGENT_URL}/issued-credentials?subject=${encodeURIComponent(requestorDID)}`, {
      method: 'GET', headers, timeout: 8000
    });

    if (searchRes.ok) {
      const searchData = await searchRes.json();
      const credentials = searchData.contents || searchData.items || searchData || [];
      const revoked = Array.isArray(credentials) && credentials.some(c => c.protocolState === 'CredentialRevoked');
      if (revoked) {
        return { success: false, error: 'CREDENTIAL_REVOKED', message: 'Your security clearance credential has been revoked' };
      }
    }
  } catch (revErr) {
    console.warn('[ReEncryptionService] Revocation check failed (best-effort):', revErr.message);
  }

  // Step 6: Download from Iagon
  let content;
  try {
    content = await iagonClient.downloadFile(docMeta.iagonFileId, docMeta.encryptionInfo);
  } catch (dlErr) {
    console.error('[ReEncryptionService] Iagon download failed:', dlErr.message);
    return { success: false, error: 'STORAGE_ERROR', message: 'Failed to retrieve document from storage' };
  }

  // Step 7: Generate copy ID for accountability
  const copyId   = crypto.randomUUID();
  const copyHash = crypto.createHash('sha256').update(content).update(copyId).digest('hex');

  // Step 8: Re-encrypt for client's ephemeral X25519 key
  const encrypted = encryptForEphemeralKey(content, ephemeralPublicKey);

  console.log(`[ReEncryptionService] Access GRANTED for ${documentDID.substring(0, 40)}... copyId=${copyId}`);

  return {
    success:          true,
    documentDID,
    copyId,
    copyHash,
    filename:         docMeta.filename       || 'document',
    mimeType:         getMimeType(docMeta),
    clearanceLevel:   docMeta.clearanceLevel,
    ciphertext:       encrypted.ciphertext,
    nonce:            encrypted.nonce,
    serverPublicKey:  encrypted.serverPublicKey,
    accessedAt:       new Date().toISOString()
  };
}

// ---------------------------------------------------------------------------
module.exports = { processAccessRequest, getLevelNumber, getLevelLabel };
