/**
 * IagonStorageClient - Iagon Decentralized Storage API Client
 *
 * Handles file uploads/downloads to Iagon decentralized storage
 * with clearance-based encryption support.
 *
 * @see https://api.docs.iagon.com/
 */

const crypto = require('crypto');
const axios = require('axios');
const FormData = require('form-data');

class IagonStorageClient {
  constructor(options = {}) {
    this.accessToken = options.accessToken || process.env.IAGON_ACCESS_TOKEN;
    this.nodeId = options.nodeId || process.env.IAGON_NODE_ID;
    this.tunnelingUrl = options.tunnelingUrl || process.env.IAGON_TUNNELING_URL;
    this.downloadBaseUrl = options.downloadBaseUrl || process.env.IAGON_DOWNLOAD_BASE_URL || 'https://gw.iagon.com/api/v2';

    // Validate required config
    if (!this.accessToken) {
      console.warn('[IagonStorageClient] Warning: IAGON_ACCESS_TOKEN not configured');
    }
    if (!this.nodeId) {
      console.warn('[IagonStorageClient] Warning: IAGON_NODE_ID not configured');
    }

    // Retry configuration
    this.maxRetries = options.maxRetries || 3;
    this.retryDelay = options.retryDelay || 1000; // 1 second initial delay

    // File size limits
    this.maxFileSize = options.maxFileSize || 40 * 1024 * 1024; // 40MB (Iagon limit)
  }

  /**
   * Check if Iagon is properly configured
   */
  isConfigured() {
    return !!(this.accessToken && this.nodeId);
  }

  /**
   * Generate a unique filename for Iagon storage
   * Format: {shortDID}_{contentHash8}_{version}.{extension}
   */
  generateFilename(documentDID, contentHash, version = 1, extension = 'dat') {
    // Extract short DID (last 12 chars of the DID UUID part)
    const didParts = documentDID.split(':');
    const shortDID = didParts[2] ? didParts[2].substring(0, 12) : 'unknown';

    // Get first 8 chars of content hash
    const shortHash = contentHash.substring(0, 8);

    return `${shortDID}_${shortHash}_v${version}.${extension}`;
  }

  /**
   * Calculate SHA-256 hash of content
   */
  calculateContentHash(content) {
    const hash = crypto.createHash('sha256').update(content).digest('hex');
    return `sha256:${hash}`;
  }

  /**
   * Encrypt content using AES-256-GCM
   * Returns encrypted buffer and encryption metadata
   */
  encryptContent(content, classificationLevel) {
    // UNCLASSIFIED documents don't need pre-encryption
    if (classificationLevel === 'UNCLASSIFIED') {
      return {
        content: content,
        encryptionInfo: {
          algorithm: 'none',
          keyId: null,
          iv: null,
          authTag: null
        }
      };
    }

    // Generate encryption key and IV
    const key = crypto.randomBytes(32); // 256 bits
    const iv = crypto.randomBytes(12);  // 96 bits for GCM

    // Create cipher
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    // Encrypt content
    const encrypted = Buffer.concat([
      cipher.update(content),
      cipher.final()
    ]);

    // Get auth tag
    const authTag = cipher.getAuthTag();

    // Generate key ID (hash of key for reference)
    const keyId = crypto.createHash('sha256').update(key).digest('hex').substring(0, 16);

    return {
      content: encrypted,
      encryptionInfo: {
        algorithm: 'AES-256-GCM',
        keyId: keyId,
        key: key.toString('base64'),  // Store for later decryption
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64')
      }
    };
  }

  /**
   * Decrypt content using AES-256-GCM
   */
  decryptContent(encryptedContent, encryptionInfo) {
    if (encryptionInfo.algorithm === 'none') {
      return encryptedContent;
    }

    const key = Buffer.from(encryptionInfo.key, 'base64');
    const iv = Buffer.from(encryptionInfo.iv, 'base64');
    const authTag = Buffer.from(encryptionInfo.authTag, 'base64');

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
      decipher.update(encryptedContent),
      decipher.final()
    ]);

    return decrypted;
  }

  /**
   * Upload file to Iagon storage
   * @param {Buffer} fileContent - File content as Buffer
   * @param {string} filename - Filename to use on Iagon
   * @param {Object} options - Upload options
   * @returns {Object} Upload result with URL and metadata
   */
  async uploadFile(fileContent, filename, options = {}) {
    if (!this.isConfigured()) {
      throw new Error('Iagon storage not configured. Set IAGON_ACCESS_TOKEN and IAGON_NODE_ID.');
    }

    const { classificationLevel = 'UNCLASSIFIED' } = options;

    // Check file size
    if (fileContent.length > this.maxFileSize) {
      throw new Error(`File size ${fileContent.length} exceeds maximum ${this.maxFileSize} bytes`);
    }

    // Calculate content hash before encryption
    const contentHash = this.calculateContentHash(fileContent);

    // Encrypt content if needed
    const { content: encryptedContent, encryptionInfo } = this.encryptContent(
      fileContent,
      classificationLevel
    );

    // Retry logic
    let lastError;
    for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
      try {
        console.log(`[IagonStorageClient] Upload attempt ${attempt}/${this.maxRetries} for ${filename}`);

        const result = await this._uploadToIagon(encryptedContent, filename);

        console.log(`[IagonStorageClient] Upload successful: ${filename}`);

        return {
          success: true,
          filename: filename,
          nodeId: this.nodeId,
          fileId: result.fileId,  // File ID from Iagon for downloads
          contentHash: contentHash,
          encryptionInfo: {
            algorithm: encryptionInfo.algorithm,
            keyId: encryptionInfo.keyId,
            key: encryptionInfo.key,
            iv: encryptionInfo.iv,
            authTag: encryptionInfo.authTag
          },
          iagonUrl: this.getFileUrl(result.fileId, filename),
          uploadedAt: new Date().toISOString(),
          fileSize: encryptedContent.length,
          originalSize: fileContent.length
        };
      } catch (error) {
        lastError = error;
        console.error(`[IagonStorageClient] Upload attempt ${attempt} failed:`, error.message);

        if (attempt < this.maxRetries) {
          const delay = this.retryDelay * Math.pow(2, attempt - 1); // Exponential backoff
          console.log(`[IagonStorageClient] Retrying in ${delay}ms...`);
          await this._sleep(delay);
        }
      }
    }

    throw new Error(`Upload failed after ${this.maxRetries} attempts: ${lastError.message}`);
  }

  /**
   * Internal method to upload to Iagon API
   * Uses public gateway (tunneling URL returns 404)
   */
  async _uploadToIagon(content, filename) {
    // Use public gateway - verified working (Dec 6, 2025)
    const uploadUrl = `${this.downloadBaseUrl}/storage/upload`;

    const formData = new FormData();
    formData.append('file', content, {
      filename: filename,
      contentType: 'application/octet-stream'
    });
    formData.append('node_id', this.nodeId);

    const response = await axios.post(uploadUrl, formData, {
      headers: {
        ...formData.getHeaders(),
        'x-api-key': this.accessToken
      },
      timeout: 120000, // 2 minute timeout for large files
      maxContentLength: this.maxFileSize,
      maxBodyLength: this.maxFileSize
    });

    if (response.status !== 200 && response.status !== 201) {
      throw new Error(`Iagon upload failed with status ${response.status}: ${response.data}`);
    }

    // Extract file ID from response for downloads
    // Response format: { success: true, data: { _id: "...", name: "...", ... } }
    return {
      ...response.data,
      fileId: response.data.data?._id
    };
  }

  /**
   * Download file from Iagon storage
   * @param {string} fileId - File ID from upload response (data._id)
   * @param {Object} encryptionInfo - Encryption metadata for decryption
   * @returns {Buffer} Decrypted file content
   */
  async downloadFile(fileId, encryptionInfo = null) {
    if (!this.accessToken) {
      throw new Error('Iagon access token not configured');
    }

    let lastError;
    for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
      try {
        console.log(`[IagonStorageClient] Download attempt ${attempt}/${this.maxRetries} for file ${fileId}`);

        // Iagon download requires POST with JSON body (verified Dec 6, 2025)
        const downloadUrl = `${this.downloadBaseUrl}/storage/download`;

        const response = await axios.post(downloadUrl, {
          id: fileId,
          files: [fileId]
        }, {
          headers: {
            'x-api-key': this.accessToken,
            'Content-Type': 'application/json'
          },
          responseType: 'arraybuffer',
          timeout: 120000
        });

        const encryptedContent = Buffer.from(response.data);

        // Decrypt if encryption info provided
        if (encryptionInfo && encryptionInfo.algorithm !== 'none') {
          const decryptedContent = this.decryptContent(encryptedContent, encryptionInfo);
          console.log(`[IagonStorageClient] Download and decryption successful: ${fileId}`);
          return decryptedContent;
        }

        console.log(`[IagonStorageClient] Download successful: ${fileId}`);
        return encryptedContent;

      } catch (error) {
        lastError = error;
        console.error(`[IagonStorageClient] Download attempt ${attempt} failed:`, error.message);

        if (attempt < this.maxRetries) {
          const delay = this.retryDelay * Math.pow(2, attempt - 1);
          console.log(`[IagonStorageClient] Retrying in ${delay}ms...`);
          await this._sleep(delay);
        }
      }
    }

    throw new Error(`Download failed after ${this.maxRetries} attempts: ${lastError.message}`);
  }

  /**
   * Delete file from Iagon storage
   * @param {string} nodeId - Node ID where file is stored
   * @param {string} filename - Filename to delete
   */
  async deleteFile(nodeId, filename) {
    if (!this.isConfigured()) {
      throw new Error('Iagon storage not configured');
    }

    const deleteUrl = this.tunnelingUrl
      ? `${this.tunnelingUrl}/delete`
      : `${this.downloadBaseUrl}/files/delete`;

    try {
      const response = await axios.delete(deleteUrl, {
        headers: {
          'x-api-key': this.accessToken
        },
        data: {
          nodeId: nodeId,
          filename: filename
        },
        timeout: 30000
      });

      console.log(`[IagonStorageClient] Delete successful: ${filename}`);
      return { success: true, filename, nodeId };
    } catch (error) {
      console.error(`[IagonStorageClient] Delete failed:`, error.message);
      throw new Error(`Delete failed: ${error.message}`);
    }
  }

  /**
   * Get the download URL for a file
   * @param {string} fileId - File ID from upload response (data._id)
   * @param {string} filename - Filename (for reference)
   * @returns {string} Download URL
   */
  getFileUrl(fileId, filename) {
    // URL encode the filename to handle special characters
    const encodedFilename = encodeURIComponent(filename);
    // Include fileId as the primary identifier for downloads
    // The fileId is what Iagon's download API needs (not nodeId)
    return `${this.downloadBaseUrl}/download?fileId=${fileId}&filename=${encodedFilename}`;
  }

  /**
   * Check if a file exists on Iagon
   * @param {string} nodeId - Node ID
   * @param {string} filename - Filename
   * @returns {boolean} Whether file exists
   */
  async fileExists(nodeId, filename) {
    try {
      const url = this.getFileUrl(nodeId, filename);
      const response = await axios.head(url, {
        headers: {
          'x-api-key': this.accessToken
        },
        timeout: 10000
      });
      return response.status === 200;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get file extension from filename or content type
   */
  static getExtension(filename, contentType = null) {
    if (filename && filename.includes('.')) {
      return filename.split('.').pop().toLowerCase();
    }

    // Map content types to extensions
    const contentTypeMap = {
      'application/pdf': 'pdf',
      'application/msword': 'doc',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
      'text/plain': 'txt',
      'application/json': 'json',
      'image/jpeg': 'jpg',
      'image/png': 'png',
      'application/octet-stream': 'dat'
    };

    return contentTypeMap[contentType] || 'dat';
  }

  /**
   * Sleep utility for retry delays
   */
  _sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Validate Iagon configuration and connectivity
   *
   * Note: Iagon API may not have a public /health endpoint.
   * This test validates DNS resolution and basic connectivity.
   */
  async testConnection() {
    if (!this.isConfigured()) {
      return {
        configured: false,
        error: 'Missing IAGON_ACCESS_TOKEN or IAGON_NODE_ID'
      };
    }

    try {
      // Try to access the API base - even a 404 indicates the server is reachable
      const testUrl = `${this.downloadBaseUrl}/`;
      const response = await axios.get(testUrl, {
        headers: {
          'x-api-key': this.accessToken
        },
        timeout: 10000,
        validateStatus: (status) => status < 500 // Accept 2xx, 3xx, 4xx as "connected"
      });

      // Even 404 means the server is reachable
      return {
        configured: true,
        connected: true,
        nodeId: this.nodeId,
        downloadBaseUrl: this.downloadBaseUrl,
        note: 'Iagon gateway reachable (actual upload/download may require specific endpoints)'
      };
    } catch (error) {
      // Check if it's a DNS or network error vs API error
      const isDnsError = error.message.includes('ENOTFOUND') || error.message.includes('getaddrinfo');
      const isNetworkError = error.message.includes('ECONNREFUSED') || error.message.includes('ETIMEDOUT');

      return {
        configured: true,
        connected: false,
        error: error.message,
        errorType: isDnsError ? 'DNS_RESOLUTION' : (isNetworkError ? 'NETWORK' : 'API'),
        nodeId: this.nodeId,
        downloadBaseUrl: this.downloadBaseUrl
      };
    }
  }
}

// Singleton instance for convenience
let defaultClient = null;

function getIagonClient(options = {}) {
  if (!defaultClient) {
    defaultClient = new IagonStorageClient(options);
  }
  return defaultClient;
}

module.exports = {
  IagonStorageClient,
  getIagonClient
};
