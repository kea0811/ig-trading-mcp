import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import speakeasy from 'speakeasy';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../config.js';
import { auditLogger } from './audit-logger.js';

/**
 * Secure session management with JWT and 2FA support
 */
export class SessionManager {
  constructor() {
    this.sessions = new Map();
    this.refreshTokens = new Map();
    this.mfaSecrets = new Map();
    this.sessionConfig = {
      accessTokenExpiry: 15 * 60 * 1000, // 15 minutes
      refreshTokenExpiry: 7 * 24 * 60 * 60 * 1000, // 7 days
      maxConcurrentSessions: 3,
      requireMFA: false,
      jwtSecret: this.getOrCreateJWTSecret(),
      sessionTimeout: 30 * 60 * 1000, // 30 minutes of inactivity
      absoluteTimeout: 12 * 60 * 60 * 1000 // 12 hours absolute
    };
    
    // Session security features
    this.sessionFingerprints = new Map();
    this.sessionActivity = new Map();
    this.suspiciousSessions = new Set();
    
    // Start session cleanup
    this.startSessionCleanup();
  }

  /**
   * Get or create JWT secret
   */
  getOrCreateJWTSecret() {
    // In production, this should be stored in a secure vault
    return process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
  }

  /**
   * Create a new session
   */
  async createSession(userId, credentials, context = {}) {
    try {
      // Check concurrent sessions
      const activeSessions = this.getActiveSessionsForUser(userId);
      if (activeSessions.length >= this.sessionConfig.maxConcurrentSessions) {
        // Revoke oldest session
        const oldestSession = activeSessions.sort((a, b) => a.created - b.created)[0];
        await this.revokeSession(oldestSession.id, 'Max concurrent sessions reached');
      }

      // Generate session ID and tokens
      const sessionId = uuidv4();
      const fingerprint = this.generateFingerprint(context);
      
      // Create session object
      const session = {
        id: sessionId,
        userId,
        created: Date.now(),
        lastActivity: Date.now(),
        expires: Date.now() + this.sessionConfig.absoluteTimeout,
        fingerprint,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        permissions: await this.getUserPermissions(userId),
        mfaVerified: false,
        flags: new Set()
      };

      // Generate tokens
      const accessToken = this.generateAccessToken(session);
      const refreshToken = this.generateRefreshToken(session);
      
      // Store session
      this.sessions.set(sessionId, session);
      this.refreshTokens.set(refreshToken, sessionId);
      this.sessionFingerprints.set(sessionId, fingerprint);
      
      // Log session creation
      auditLogger.logAuthentication({
        action: 'SESSION_CREATED',
        userId,
        sessionId,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        success: true
      });

      return {
        sessionId,
        accessToken,
        refreshToken,
        expiresIn: this.sessionConfig.accessTokenExpiry / 1000,
        requiresMFA: this.sessionConfig.requireMFA && !session.mfaVerified
      };
    } catch (error) {
      logger.error('Failed to create session:', error);
      throw new Error('Session creation failed');
    }
  }

  /**
   * Validate session
   */
  async validateSession(accessToken, context = {}) {
    try {
      // Verify JWT
      const decoded = jwt.verify(accessToken, this.sessionConfig.jwtSecret);
      const session = this.sessions.get(decoded.sessionId);
      
      if (!session) {
        throw new Error('Session not found');
      }

      // Check session expiry
      if (Date.now() > session.expires) {
        await this.revokeSession(session.id, 'Session expired');
        throw new Error('Session expired');
      }

      // Check inactivity timeout
      if (Date.now() - session.lastActivity > this.sessionConfig.sessionTimeout) {
        await this.revokeSession(session.id, 'Inactivity timeout');
        throw new Error('Session timeout');
      }

      // Validate fingerprint
      if (context.fingerprint && !this.validateFingerprint(session.id, context)) {
        this.flagSuspiciousSession(session.id, 'Fingerprint mismatch');
        throw new Error('Session validation failed');
      }

      // Check for suspicious activity
      if (this.suspiciousSessions.has(session.id)) {
        throw new Error('Session flagged as suspicious');
      }

      // Update last activity
      session.lastActivity = Date.now();
      this.trackSessionActivity(session.id, context);

      return {
        valid: true,
        session,
        permissions: session.permissions
      };
    } catch (error) {
      logger.warn('Session validation failed:', error.message);
      
      auditLogger.logSecurity({
        severity: 'MEDIUM',
        category: 'AUTHENTICATION',
        description: 'Session validation failed',
        details: { error: error.message, context }
      });

      throw error;
    }
  }

  /**
   * Refresh access token
   */
  async refreshAccessToken(refreshToken, context = {}) {
    try {
      const sessionId = this.refreshTokens.get(refreshToken);
      
      if (!sessionId) {
        throw new Error('Invalid refresh token');
      }

      const session = this.sessions.get(sessionId);
      
      if (!session) {
        this.refreshTokens.delete(refreshToken);
        throw new Error('Session not found');
      }

      // Validate session state
      if (Date.now() > session.expires) {
        await this.revokeSession(session.id, 'Session expired');
        throw new Error('Session expired');
      }

      // Generate new access token
      const newAccessToken = this.generateAccessToken(session);
      
      // Rotate refresh token for security
      const newRefreshToken = this.generateRefreshToken(session);
      this.refreshTokens.delete(refreshToken);
      this.refreshTokens.set(newRefreshToken, sessionId);

      // Update session
      session.lastActivity = Date.now();

      auditLogger.logAuthentication({
        action: 'TOKEN_REFRESHED',
        userId: session.userId,
        sessionId,
        success: true
      });

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresIn: this.sessionConfig.accessTokenExpiry / 1000
      };
    } catch (error) {
      logger.error('Token refresh failed:', error);
      
      auditLogger.logSecurity({
        severity: 'MEDIUM',
        category: 'AUTHENTICATION',
        description: 'Token refresh failed',
        details: { error: error.message }
      });

      throw error;
    }
  }

  /**
   * Setup MFA for user
   */
  setupMFA(userId) {
    const secret = speakeasy.generateSecret({
      name: `IG Trading (${userId})`,
      length: 32
    });

    this.mfaSecrets.set(userId, secret.base32);

    return {
      secret: secret.base32,
      qrCode: secret.otpauth_url,
      backupCodes: this.generateBackupCodes()
    };
  }

  /**
   * Verify MFA token
   */
  verifyMFA(sessionId, token) {
    const session = this.sessions.get(sessionId);
    
    if (!session) {
      throw new Error('Session not found');
    }

    const secret = this.mfaSecrets.get(session.userId);
    
    if (!secret) {
      throw new Error('MFA not configured');
    }

    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 2 // Allow 2 time steps for clock skew
    });

    if (verified) {
      session.mfaVerified = true;
      
      auditLogger.logAuthentication({
        action: 'MFA_VERIFIED',
        userId: session.userId,
        sessionId,
        success: true
      });

      return true;
    }

    auditLogger.logSecurity({
      severity: 'MEDIUM',
      category: 'AUTHENTICATION',
      description: 'MFA verification failed',
      userId: session.userId
    });

    return false;
  }

  /**
   * Revoke session
   */
  async revokeSession(sessionId, reason = 'Manual revocation') {
    const session = this.sessions.get(sessionId);
    
    if (session) {
      // Remove session
      this.sessions.delete(sessionId);
      this.sessionFingerprints.delete(sessionId);
      this.sessionActivity.delete(sessionId);
      this.suspiciousSessions.delete(sessionId);

      // Remove associated refresh tokens
      for (const [token, sid] of this.refreshTokens.entries()) {
        if (sid === sessionId) {
          this.refreshTokens.delete(token);
        }
      }

      auditLogger.logAuthentication({
        action: 'SESSION_REVOKED',
        userId: session.userId,
        sessionId,
        reason,
        success: true
      });

      logger.info(`Session revoked: ${sessionId} - ${reason}`);
    }
  }

  /**
   * Revoke all sessions for user
   */
  async revokeAllUserSessions(userId, reason = 'Bulk revocation') {
    const sessions = this.getActiveSessionsForUser(userId);
    
    for (const session of sessions) {
      await this.revokeSession(session.id, reason);
    }

    logger.info(`All sessions revoked for user: ${userId}`);
  }

  /**
   * Generate access token
   */
  generateAccessToken(session) {
    const payload = {
      sessionId: session.id,
      userId: session.userId,
      permissions: session.permissions,
      mfaVerified: session.mfaVerified,
      type: 'access'
    };

    return jwt.sign(payload, this.sessionConfig.jwtSecret, {
      expiresIn: this.sessionConfig.accessTokenExpiry / 1000,
      issuer: 'ig-trading-api',
      audience: 'ig-trading-client'
    });
  }

  /**
   * Generate refresh token
   */
  generateRefreshToken(session) {
    const token = crypto.randomBytes(64).toString('hex');
    return token;
  }

  /**
   * Generate backup codes
   */
  generateBackupCodes(count = 10) {
    const codes = [];
    for (let i = 0; i < count; i++) {
      codes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
    }
    return codes;
  }

  /**
   * Generate session fingerprint
   */
  generateFingerprint(context) {
    const data = {
      userAgent: context.userAgent || '',
      acceptLanguage: context.acceptLanguage || '',
      acceptEncoding: context.acceptEncoding || '',
      screenResolution: context.screenResolution || '',
      timezone: context.timezone || '',
      platform: context.platform || process.platform
    };

    const hash = crypto.createHash('sha256');
    hash.update(JSON.stringify(data));
    return hash.digest('hex');
  }

  /**
   * Validate fingerprint
   */
  validateFingerprint(sessionId, context) {
    const storedFingerprint = this.sessionFingerprints.get(sessionId);
    const currentFingerprint = this.generateFingerprint(context);
    
    // Allow some flexibility for legitimate changes
    const similarity = this.calculateFingerprintSimilarity(storedFingerprint, currentFingerprint);
    
    return similarity > 0.7; // 70% similarity threshold
  }

  /**
   * Calculate fingerprint similarity
   */
  calculateFingerprintSimilarity(fp1, fp2) {
    if (fp1 === fp2) return 1;
    
    // Simple character-based similarity
    let matches = 0;
    for (let i = 0; i < Math.min(fp1.length, fp2.length); i++) {
      if (fp1[i] === fp2[i]) matches++;
    }
    
    return matches / Math.max(fp1.length, fp2.length);
  }

  /**
   * Track session activity
   */
  trackSessionActivity(sessionId, context) {
    const activity = this.sessionActivity.get(sessionId) || [];
    
    activity.push({
      timestamp: Date.now(),
      ipAddress: context.ipAddress,
      action: context.action || 'unknown',
      endpoint: context.endpoint
    });

    // Keep only recent activity
    const recentActivity = activity.filter(a => Date.now() - a.timestamp < 3600000);
    this.sessionActivity.set(sessionId, recentActivity);

    // Check for suspicious patterns
    this.detectSuspiciousActivity(sessionId, recentActivity);
  }

  /**
   * Detect suspicious activity
   */
  detectSuspiciousActivity(sessionId, activity) {
    // Check for IP address changes
    const ips = new Set(activity.map(a => a.ipAddress));
    if (ips.size > 3) {
      this.flagSuspiciousSession(sessionId, 'Multiple IP addresses');
    }

    // Check for rapid activity
    const rapidActions = activity.filter((a, i) => {
      if (i === 0) return false;
      return a.timestamp - activity[i-1].timestamp < 1000;
    });

    if (rapidActions.length > 20) {
      this.flagSuspiciousSession(sessionId, 'Rapid activity detected');
    }
  }

  /**
   * Flag suspicious session
   */
  flagSuspiciousSession(sessionId, reason) {
    this.suspiciousSessions.add(sessionId);
    
    const session = this.sessions.get(sessionId);
    if (session) {
      session.flags.add(reason);
      
      auditLogger.logSecurity({
        severity: 'HIGH',
        category: 'ANOMALY',
        description: 'Suspicious session detected',
        userId: session.userId,
        details: { sessionId, reason }
      });
    }
  }

  /**
   * Get active sessions for user
   */
  getActiveSessionsForUser(userId) {
    const sessions = [];
    
    for (const [id, session] of this.sessions.entries()) {
      if (session.userId === userId && Date.now() < session.expires) {
        sessions.push(session);
      }
    }
    
    return sessions;
  }

  /**
   * Get user permissions
   */
  async getUserPermissions(userId) {
    // In production, this would fetch from database
    return {
      trading: ['read', 'create', 'update', 'delete'],
      account: ['read', 'update'],
      market: ['read'],
      admin: []
    };
  }

  /**
   * Check permission
   */
  hasPermission(session, resource, action) {
    const permissions = session.permissions[resource];
    return permissions && permissions.includes(action);
  }

  /**
   * Start session cleanup
   */
  startSessionCleanup() {
    setInterval(() => {
      const now = Date.now();
      
      // Clean expired sessions
      for (const [id, session] of this.sessions.entries()) {
        if (now > session.expires || 
            now - session.lastActivity > this.sessionConfig.sessionTimeout) {
          this.revokeSession(id, 'Automatic cleanup');
        }
      }

      // Clean old activity logs
      for (const [id, activity] of this.sessionActivity.entries()) {
        const recent = activity.filter(a => now - a.timestamp < 3600000);
        if (recent.length === 0) {
          this.sessionActivity.delete(id);
        } else {
          this.sessionActivity.set(id, recent);
        }
      }
    }, 60000); // Every minute
  }

  /**
   * Get session statistics
   */
  getStatistics() {
    const now = Date.now();
    let activeSessions = 0;
    let suspiciousCount = 0;
    let mfaEnabled = 0;

    for (const session of this.sessions.values()) {
      if (now < session.expires) {
        activeSessions++;
        if (session.mfaVerified) mfaEnabled++;
      }
    }

    return {
      totalSessions: this.sessions.size,
      activeSessions,
      suspiciousSessions: this.suspiciousSessions.size,
      refreshTokens: this.refreshTokens.size,
      mfaEnabledSessions: mfaEnabled
    };
  }
}

export const sessionManager = new SessionManager();