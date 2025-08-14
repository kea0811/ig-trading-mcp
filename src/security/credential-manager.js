import crypto from 'crypto';
import CryptoJS from 'crypto-js';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { logger } from '../config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Secure credential management with encryption at rest
 */
export class CredentialManager {
  constructor() {
    this.masterKey = null;
    this.encryptedCredentials = new Map();
    this.sessionKeys = new Map();
    this.saltRounds = 12;
    this.keyDerivationIterations = 100000;
    this.initializeMasterKey();
  }

  /**
   * Initialize or derive master encryption key
   */
  async initializeMasterKey() {
    try {
      // In production, this should use a hardware security module (HSM) or key management service
      const envKey = process.env.MASTER_ENCRYPTION_KEY;
      
      if (envKey) {
        // Derive key from environment variable using PBKDF2
        const salt = this.getOrCreateSalt();
        this.masterKey = crypto.pbkdf2Sync(
          envKey,
          salt,
          this.keyDerivationIterations,
          32,
          'sha256'
        );
      } else {
        // Generate a new key for this session (less secure, for development only)
        this.masterKey = crypto.randomBytes(32);
        logger.warn('Using session-only encryption key. Set MASTER_ENCRYPTION_KEY for production.');
      }
    } catch (error) {
      logger.error('Failed to initialize master key:', error);
      throw new Error('Security initialization failed');
    }
  }

  /**
   * Get or create a persistent salt for key derivation
   */
  getOrCreateSalt() {
    try {
      const saltFile = path.join(__dirname, '../../.salt');
      
      if (fs.existsSync(saltFile)) {
        return fs.readFileSync(saltFile);
      }
      
      const salt = crypto.randomBytes(32);
      // Store salt securely (in production, use secure storage)
      if (process.env.NODE_ENV !== 'production') {
        fs.writeFileSync(saltFile, salt);
      }
      
      return salt;
    } catch (error) {
      // Fallback to deterministic salt (less secure)
      return Buffer.from('default-salt-change-in-production', 'utf8');
    }
  }

  /**
   * Encrypt sensitive data using AES-256-GCM
   */
  encrypt(data, additionalData = '') {
    try {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-gcm', this.masterKey, iv);
      
      if (additionalData) {
        cipher.setAAD(Buffer.from(additionalData, 'utf8'));
      }
      
      let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      const authTag = cipher.getAuthTag();
      
      return {
        encrypted,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        algorithm: 'aes-256-gcm'
      };
    } catch (error) {
      logger.error('Encryption failed:', error);
      throw new Error('Failed to encrypt data');
    }
  }

  /**
   * Decrypt data using AES-256-GCM
   */
  decrypt(encryptedData, additionalData = '') {
    try {
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        this.masterKey,
        Buffer.from(encryptedData.iv, 'hex')
      );
      
      decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
      
      if (additionalData) {
        decipher.setAAD(Buffer.from(additionalData, 'utf8'));
      }
      
      let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return JSON.parse(decrypted);
    } catch (error) {
      logger.error('Decryption failed:', error);
      throw new Error('Failed to decrypt data');
    }
  }

  /**
   * Store credentials securely
   */
  async storeCredentials(identifier, credentials) {
    try {
      // Validate credentials
      this.validateCredentials(credentials);
      
      // Hash the identifier for storage
      const hashedId = await bcrypt.hash(identifier, this.saltRounds);
      
      // Encrypt credentials with additional authenticated data
      const encryptedCreds = this.encrypt(credentials, identifier);
      
      // Store with timestamp and version
      this.encryptedCredentials.set(hashedId, {
        data: encryptedCreds,
        timestamp: Date.now(),
        version: '1.0',
        checksum: this.calculateChecksum(credentials)
      });
      
      logger.info(`Credentials stored securely for user: ${identifier.substring(0, 3)}***`);
      
      return true;
    } catch (error) {
      logger.error('Failed to store credentials:', error);
      throw error;
    }
  }

  /**
   * Retrieve credentials securely
   */
  async retrieveCredentials(identifier) {
    try {
      // Find matching hashed identifier
      for (const [hashedId, encData] of this.encryptedCredentials.entries()) {
        const matches = await bcrypt.compare(identifier, hashedId);
        
        if (matches) {
          // Check credential age (expire after 24 hours)
          const age = Date.now() - encData.timestamp;
          if (age > 24 * 60 * 60 * 1000) {
            this.encryptedCredentials.delete(hashedId);
            throw new Error('Credentials expired');
          }
          
          // Decrypt credentials
          const credentials = this.decrypt(encData.data, identifier);
          
          // Verify integrity
          const checksum = this.calculateChecksum(credentials);
          if (checksum !== encData.checksum) {
            throw new Error('Credential integrity check failed');
          }
          
          logger.info('Credentials retrieved securely');
          return credentials;
        }
      }
      
      throw new Error('Credentials not found');
    } catch (error) {
      logger.error('Failed to retrieve credentials:', error);
      throw error;
    }
  }

  /**
   * Validate credential format and strength
   */
  validateCredentials(credentials) {
    if (!credentials.apiKey || credentials.apiKey.length < 20) {
      throw new Error('Invalid API key format');
    }
    
    if (!credentials.identifier || credentials.identifier.length < 3) {
      throw new Error('Invalid identifier format');
    }
    
    if (!credentials.password || credentials.password.length < 8) {
      throw new Error('Password too weak');
    }
    
    // Check for common weak passwords
    const weakPasswords = ['password', '12345678', 'qwerty123', 'admin123'];
    if (weakPasswords.includes(credentials.password.toLowerCase())) {
      throw new Error('Password is too common');
    }
    
    return true;
  }

  /**
   * Calculate checksum for integrity verification
   */
  calculateChecksum(data) {
    const hash = crypto.createHash('sha256');
    hash.update(JSON.stringify(data));
    return hash.digest('hex');
  }

  /**
   * Generate secure session token
   */
  generateSessionToken(userId) {
    const token = {
      id: uuidv4(),
      userId,
      created: Date.now(),
      expires: Date.now() + (12 * 60 * 60 * 1000), // 12 hours
      fingerprint: this.generateFingerprint()
    };
    
    const signature = this.signToken(token);
    token.signature = signature;
    
    this.sessionKeys.set(token.id, token);
    
    return token;
  }

  /**
   * Validate session token
   */
  validateSessionToken(tokenId, fingerprint) {
    const token = this.sessionKeys.get(tokenId);
    
    if (!token) {
      return { valid: false, reason: 'Token not found' };
    }
    
    if (Date.now() > token.expires) {
      this.sessionKeys.delete(tokenId);
      return { valid: false, reason: 'Token expired' };
    }
    
    if (token.fingerprint !== fingerprint) {
      return { valid: false, reason: 'Fingerprint mismatch' };
    }
    
    const expectedSignature = this.signToken({
      id: token.id,
      userId: token.userId,
      created: token.created,
      expires: token.expires,
      fingerprint: token.fingerprint
    });
    
    if (token.signature !== expectedSignature) {
      return { valid: false, reason: 'Invalid signature' };
    }
    
    return { valid: true, token };
  }

  /**
   * Sign token for integrity
   */
  signToken(token) {
    const hmac = crypto.createHmac('sha256', this.masterKey);
    hmac.update(JSON.stringify({
      id: token.id,
      userId: token.userId,
      created: token.created,
      expires: token.expires,
      fingerprint: token.fingerprint
    }));
    return hmac.digest('hex');
  }

  /**
   * Generate device/session fingerprint
   */
  generateFingerprint() {
    const data = {
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version,
      timestamp: Date.now(),
      random: crypto.randomBytes(8).toString('hex')
    };
    
    const hash = crypto.createHash('sha256');
    hash.update(JSON.stringify(data));
    return hash.digest('hex');
  }

  /**
   * Rotate encryption keys
   */
  async rotateKeys() {
    try {
      logger.info('Starting key rotation...');
      
      // Generate new master key
      const newMasterKey = crypto.randomBytes(32);
      
      // Re-encrypt all stored credentials with new key
      const reencrypted = new Map();
      
      for (const [id, encData] of this.encryptedCredentials.entries()) {
        // Decrypt with old key
        const decrypted = this.decrypt(encData.data);
        
        // Update master key temporarily
        const oldKey = this.masterKey;
        this.masterKey = newMasterKey;
        
        // Encrypt with new key
        const newEncrypted = this.encrypt(decrypted);
        
        reencrypted.set(id, {
          ...encData,
          data: newEncrypted,
          rotated: Date.now()
        });
        
        this.masterKey = oldKey;
      }
      
      // Commit the rotation
      this.masterKey = newMasterKey;
      this.encryptedCredentials = reencrypted;
      
      logger.info('Key rotation completed successfully');
      
      return true;
    } catch (error) {
      logger.error('Key rotation failed:', error);
      throw error;
    }
  }

  /**
   * Clear all sensitive data from memory
   */
  clearSensitiveData() {
    this.encryptedCredentials.clear();
    this.sessionKeys.clear();
    
    // Overwrite master key in memory
    if (this.masterKey) {
      crypto.randomFillSync(this.masterKey);
      this.masterKey = null;
    }
    
    logger.info('Sensitive data cleared from memory');
  }
}

export const credentialManager = new CredentialManager();