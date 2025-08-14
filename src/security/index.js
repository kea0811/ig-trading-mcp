import { credentialManager } from './credential-manager.js';
import { validator, ValidationError } from './validator.js';
import { auditLogger } from './audit-logger.js';
import { rateLimiter } from './rate-limiter.js';
import { sessionManager } from './session-manager.js';
import { logger } from '../config.js';
import crypto from 'crypto';
import zxcvbn from 'zxcvbn';

/**
 * Comprehensive security module
 */
export class SecurityManager {
  constructor() {
    this.credentialManager = credentialManager;
    this.validator = validator;
    this.auditLogger = auditLogger;
    this.rateLimiter = rateLimiter;
    this.sessionManager = sessionManager;
    
    // Security configuration
    this.config = {
      passwordMinStrength: 3, // 0-4 scale
      maxLoginAttempts: 5,
      lockoutDuration: 15 * 60 * 1000, // 15 minutes
      requireHttps: process.env.NODE_ENV === 'production',
      csrfProtection: true,
      apiKeyRotationDays: 90,
      sessionInactivityTimeout: 30 * 60 * 1000 // 30 minutes
    };
    
    // Track security metrics
    this.metrics = {
      loginAttempts: new Map(),
      lockedAccounts: new Map(),
      apiKeyRotation: new Map(),
      securityIncidents: []
    };
    
    this.initializeSecurity();
  }

  /**
   * Initialize security features
   */
  async initializeSecurity() {
    try {
      // Create secure directories
      await this.createSecureDirectories();
      
      // Initialize CSRF tokens
      this.csrfTokens = new Map();
      
      // Start security monitoring
      this.startSecurityMonitoring();
      
      logger.info('Security manager initialized');
    } catch (error) {
      logger.error('Failed to initialize security:', error);
      throw error;
    }
  }

  /**
   * Authenticate user with comprehensive security checks
   */
  async authenticate(credentials, context = {}) {
    try {
      // Validate input
      const validatedCreds = this.validator.validateAndSanitize('credentials', credentials);
      
      // Check rate limits
      const rateLimitResult = await this.rateLimiter.checkLimit({
        userId: validatedCreds.identifier,
        ipAddress: context.ipAddress,
        endpoint: '/login',
        method: 'POST'
      });
      
      if (!rateLimitResult.allowed) {
        throw new Error(`Rate limit exceeded: ${rateLimitResult.reason}`);
      }
      
      // Check account lockout
      if (this.isAccountLocked(validatedCreds.identifier)) {
        throw new Error('Account is locked due to multiple failed attempts');
      }
      
      // Verify password strength
      this.checkPasswordStrength(validatedCreds.password);
      
      // Store credentials securely
      await this.credentialManager.storeCredentials(
        validatedCreds.identifier,
        validatedCreds
      );
      
      // Create session
      const session = await this.sessionManager.createSession(
        validatedCreds.identifier,
        validatedCreds,
        context
      );
      
      // Log successful authentication
      this.auditLogger.logAuthentication({
        action: 'LOGIN',
        userId: validatedCreds.identifier,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        success: true,
        sessionId: session.sessionId
      });
      
      // Reset login attempts
      this.metrics.loginAttempts.delete(validatedCreds.identifier);
      
      return {
        success: true,
        session,
        requiresMFA: session.requiresMFA
      };
    } catch (error) {
      // Track failed attempt
      this.trackFailedLogin(credentials.identifier, context.ipAddress);
      
      // Log failed authentication
      this.auditLogger.logAuthentication({
        action: 'LOGIN',
        userId: credentials.identifier,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        success: false,
        reason: error.message
      });
      
      throw error;
    }
  }

  /**
   * Validate API request with security checks
   */
  async validateRequest(request) {
    const { token, method, path, body, headers, ip } = request;
    
    try {
      // Validate session
      const sessionResult = await this.sessionManager.validateSession(token, {
        ipAddress: ip,
        userAgent: headers['user-agent']
      });
      
      if (!sessionResult.valid) {
        throw new Error('Invalid session');
      }
      
      // Check CSRF token for state-changing operations
      if (this.config.csrfProtection && ['POST', 'PUT', 'DELETE'].includes(method)) {
        this.validateCSRFToken(headers['x-csrf-token'], sessionResult.session.id);
      }
      
      // Validate and sanitize input
      if (body) {
        const sanitized = this.validator.sanitize(body);
        request.body = sanitized;
      }
      
      // Check for injection attempts
      this.detectInjectionAttempts(request);
      
      // Check rate limits
      const rateLimitResult = await this.rateLimiter.checkLimit({
        userId: sessionResult.session.userId,
        ipAddress: ip,
        apiKey: headers['x-api-key'],
        endpoint: path,
        method
      });
      
      if (!rateLimitResult.allowed) {
        throw new Error(`Rate limit exceeded: ${rateLimitResult.reason}`);
      }
      
      // Check permissions
      const resource = this.getResourceFromPath(path);
      const action = this.getActionFromMethod(method);
      
      if (!this.sessionManager.hasPermission(sessionResult.session, resource, action)) {
        throw new Error('Insufficient permissions');
      }
      
      // Log API call
      this.auditLogger.logApiCall({
        method,
        path,
        userId: sessionResult.session.userId,
        ipAddress: ip,
        statusCode: 200,
        rateLimit: rateLimitResult
      });
      
      return {
        valid: true,
        session: sessionResult.session,
        sanitizedBody: request.body
      };
    } catch (error) {
      // Log security violation
      this.auditLogger.logSecurity({
        severity: 'MEDIUM',
        category: 'VIOLATION',
        description: 'Request validation failed',
        userId: request.userId,
        ipAddress: ip,
        details: {
          method,
          path,
          error: error.message
        }
      });
      
      throw error;
    }
  }

  /**
   * Check password strength
   */
  checkPasswordStrength(password) {
    const result = zxcvbn(password);
    
    if (result.score < this.config.passwordMinStrength) {
      const suggestions = result.feedback.suggestions.join(' ');
      throw new Error(`Password too weak. ${suggestions}`);
    }
    
    // Check against common patterns
    const weakPatterns = [
      /^password/i,
      /^123456/,
      /^qwerty/i,
      /^admin/i
    ];
    
    for (const pattern of weakPatterns) {
      if (pattern.test(password)) {
        throw new Error('Password contains common patterns');
      }
    }
    
    return true;
  }

  /**
   * Detect injection attempts
   */
  detectInjectionAttempts(request) {
    const suspiciousPatterns = [
      // SQL Injection
      /(\bUNION\b.*\bSELECT\b|\bDROP\b.*\bTABLE\b|\bEXEC\b|\bEXECUTE\b)/i,
      // NoSQL Injection
      /(\$where|\$regex|\$ne|\$gt|\$lt)/,
      // Command Injection
      /(;|\||&&|\$\(|`)/,
      // Path Traversal
      /(\.\.\/|\.\.\\)/,
      // XSS
      /(<script|javascript:|onerror=|onload=)/i
    ];
    
    const checkValue = (value) => {
      if (typeof value === 'string') {
        for (const pattern of suspiciousPatterns) {
          if (pattern.test(value)) {
            throw new Error('Potential injection attempt detected');
          }
        }
      } else if (typeof value === 'object' && value !== null) {
        Object.values(value).forEach(checkValue);
      }
    };
    
    // Check all request components
    checkValue(request.path);
    checkValue(request.body);
    checkValue(request.headers);
  }

  /**
   * Generate CSRF token
   */
  generateCSRFToken(sessionId) {
    const token = crypto.randomBytes(32).toString('hex');
    this.csrfTokens.set(token, {
      sessionId,
      created: Date.now(),
      used: false
    });
    
    // Clean old tokens
    setTimeout(() => {
      this.csrfTokens.delete(token);
    }, 3600000); // 1 hour
    
    return token;
  }

  /**
   * Validate CSRF token
   */
  validateCSRFToken(token, sessionId) {
    if (!token) {
      throw new Error('CSRF token missing');
    }
    
    const tokenData = this.csrfTokens.get(token);
    
    if (!tokenData) {
      throw new Error('Invalid CSRF token');
    }
    
    if (tokenData.sessionId !== sessionId) {
      throw new Error('CSRF token mismatch');
    }
    
    if (tokenData.used) {
      throw new Error('CSRF token already used');
    }
    
    if (Date.now() - tokenData.created > 3600000) {
      throw new Error('CSRF token expired');
    }
    
    // Mark as used
    tokenData.used = true;
    
    return true;
  }

  /**
   * Track failed login attempts
   */
  trackFailedLogin(identifier, ipAddress) {
    const attempts = this.metrics.loginAttempts.get(identifier) || [];
    attempts.push({
      timestamp: Date.now(),
      ipAddress
    });
    
    // Keep only recent attempts
    const recentAttempts = attempts.filter(a => 
      Date.now() - a.timestamp < 3600000 // 1 hour
    );
    
    this.metrics.loginAttempts.set(identifier, recentAttempts);
    
    // Lock account if too many attempts
    if (recentAttempts.length >= this.config.maxLoginAttempts) {
      this.lockAccount(identifier);
    }
  }

  /**
   * Lock account
   */
  lockAccount(identifier) {
    this.metrics.lockedAccounts.set(identifier, {
      locked: Date.now(),
      until: Date.now() + this.config.lockoutDuration
    });
    
    this.auditLogger.logSecurity({
      severity: 'HIGH',
      category: 'VIOLATION',
      description: 'Account locked due to failed login attempts',
      userId: identifier,
      details: {
        attempts: this.metrics.loginAttempts.get(identifier)?.length || 0
      }
    });
  }

  /**
   * Check if account is locked
   */
  isAccountLocked(identifier) {
    const lockInfo = this.metrics.lockedAccounts.get(identifier);
    
    if (!lockInfo) return false;
    
    if (Date.now() > lockInfo.until) {
      this.metrics.lockedAccounts.delete(identifier);
      return false;
    }
    
    return true;
  }

  /**
   * Rotate API keys
   */
  async rotateApiKeys(userId) {
    try {
      // Generate new API key
      const newApiKey = crypto.randomBytes(32).toString('hex');
      
      // Store rotation info
      this.metrics.apiKeyRotation.set(userId, {
        rotated: Date.now(),
        nextRotation: Date.now() + (this.config.apiKeyRotationDays * 24 * 60 * 60 * 1000)
      });
      
      // Log rotation
      this.auditLogger.logConfigChange({
        action: 'API_KEY_ROTATION',
        userId,
        setting: 'api_key',
        oldValue: '***',
        newValue: '***',
        reason: 'Scheduled rotation'
      });
      
      return newApiKey;
    } catch (error) {
      logger.error('API key rotation failed:', error);
      throw error;
    }
  }

  /**
   * Get resource from path
   */
  getResourceFromPath(path) {
    if (path.includes('/positions')) return 'trading';
    if (path.includes('/accounts')) return 'account';
    if (path.includes('/markets')) return 'market';
    if (path.includes('/admin')) return 'admin';
    return 'general';
  }

  /**
   * Get action from method
   */
  getActionFromMethod(method) {
    switch (method) {
      case 'GET': return 'read';
      case 'POST': return 'create';
      case 'PUT': return 'update';
      case 'DELETE': return 'delete';
      default: return 'unknown';
    }
  }

  /**
   * Create secure directories
   */
  async createSecureDirectories() {
    const fs = await import('fs/promises');
    const path = await import('path');
    
    const dirs = [
      path.join(process.cwd(), 'logs'),
      path.join(process.cwd(), 'logs/archive'),
      path.join(process.cwd(), '.secure')
    ];
    
    for (const dir of dirs) {
      await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    }
  }

  /**
   * Start security monitoring
   */
  startSecurityMonitoring() {
    setInterval(() => {
      // Monitor for security anomalies
      this.checkSecurityAnomalies();
      
      // Clean up old data
      this.cleanupSecurityData();
      
      // Generate security metrics
      this.generateSecurityMetrics();
    }, 60000); // Every minute
  }

  /**
   * Check for security anomalies
   */
  checkSecurityAnomalies() {
    // Check for brute force attempts
    for (const [identifier, attempts] of this.metrics.loginAttempts.entries()) {
      if (attempts.length > 10) {
        this.metrics.securityIncidents.push({
          type: 'BRUTE_FORCE',
          identifier,
          timestamp: Date.now(),
          severity: 'HIGH'
        });
      }
    }
    
    // Check for unusual activity patterns
    const stats = this.rateLimiter.getStatistics();
    if (stats.blacklistedIPs > 10) {
      this.metrics.securityIncidents.push({
        type: 'DDOS_ATTEMPT',
        timestamp: Date.now(),
        severity: 'CRITICAL'
      });
    }
  }

  /**
   * Clean up old security data
   */
  cleanupSecurityData() {
    const now = Date.now();
    const oneHourAgo = now - 3600000;
    
    // Clean login attempts
    for (const [id, attempts] of this.metrics.loginAttempts.entries()) {
      const recent = attempts.filter(a => a.timestamp > oneHourAgo);
      if (recent.length === 0) {
        this.metrics.loginAttempts.delete(id);
      } else {
        this.metrics.loginAttempts.set(id, recent);
      }
    }
    
    // Clean locked accounts
    for (const [id, lock] of this.metrics.lockedAccounts.entries()) {
      if (now > lock.until) {
        this.metrics.lockedAccounts.delete(id);
      }
    }
    
    // Clean old incidents
    this.metrics.securityIncidents = this.metrics.securityIncidents.filter(
      i => now - i.timestamp < 86400000 // Keep 24 hours
    );
  }

  /**
   * Generate security metrics
   */
  generateSecurityMetrics() {
    const metrics = {
      timestamp: Date.now(),
      activeSessions: this.sessionManager.getStatistics(),
      rateLimiting: this.rateLimiter.getStatistics(),
      failedLogins: this.metrics.loginAttempts.size,
      lockedAccounts: this.metrics.lockedAccounts.size,
      securityIncidents: this.metrics.securityIncidents.length,
      csrfTokens: this.csrfTokens.size
    };
    
    // Log metrics for monitoring
    logger.info('Security metrics:', metrics);
    
    return metrics;
  }

  /**
   * Get security headers
   */
  getSecurityHeaders() {
    return {
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Content-Security-Policy': "default-src 'self'",
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    };
  }

  /**
   * Export security report
   */
  async exportSecurityReport(startDate, endDate) {
    const report = {
      period: { start: startDate, end: endDate },
      authentication: await this.auditLogger.generateAuditReport(startDate, endDate),
      rateLimiting: this.rateLimiter.getStatistics(),
      sessions: this.sessionManager.getStatistics(),
      incidents: this.metrics.securityIncidents,
      recommendations: this.generateSecurityRecommendations()
    };
    
    return report;
  }

  /**
   * Generate security recommendations
   */
  generateSecurityRecommendations() {
    const recommendations = [];
    
    if (!this.config.requireHttps && process.env.NODE_ENV === 'production') {
      recommendations.push({
        severity: 'HIGH',
        recommendation: 'Enable HTTPS in production'
      });
    }
    
    if (this.metrics.securityIncidents.length > 10) {
      recommendations.push({
        severity: 'MEDIUM',
        recommendation: 'Review security incidents and adjust protection measures'
      });
    }
    
    if (this.config.passwordMinStrength < 3) {
      recommendations.push({
        severity: 'MEDIUM',
        recommendation: 'Increase minimum password strength requirement'
      });
    }
    
    return recommendations;
  }
}

// Export singleton instance
export const securityManager = new SecurityManager();

// Export individual components
export {
  credentialManager,
  validator,
  ValidationError,
  auditLogger,
  rateLimiter,
  sessionManager
};