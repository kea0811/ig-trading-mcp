import winston from 'winston';
import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Comprehensive audit logging for security and compliance
 */
export class AuditLogger {
  constructor() {
    this.auditLog = this.initializeAuditLogger();
    this.securityLog = this.initializeSecurityLogger();
    this.tradingLog = this.initializeTradingLogger();
    this.logQueue = [];
    this.logIntegrity = new Map();
  }

  /**
   * Initialize audit logger
   */
  initializeAuditLogger() {
    return winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json(),
        winston.format.printf(info => {
          const log = {
            timestamp: info.timestamp,
            level: info.level,
            category: 'AUDIT',
            ...info
          };
          // Add integrity hash
          log.hash = this.calculateLogHash(log);
          return JSON.stringify(log);
        })
      ),
      transports: [
        new winston.transports.File({
          filename: path.join(__dirname, '../../logs/audit.log'),
          maxsize: 10485760, // 10MB
          maxFiles: 100,
          tailable: true
        }),
        new winston.transports.Console({
          level: 'error'
        })
      ]
    });
  }

  /**
   * Initialize security event logger
   */
  initializeSecurityLogger() {
    return winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new winston.transports.File({
          filename: path.join(__dirname, '../../logs/security.log'),
          maxsize: 10485760,
          maxFiles: 50
        })
      ]
    });
  }

  /**
   * Initialize trading activity logger
   */
  initializeTradingLogger() {
    return winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new winston.transports.File({
          filename: path.join(__dirname, '../../logs/trading.log'),
          maxsize: 10485760,
          maxFiles: 50
        })
      ]
    });
  }

  /**
   * Log authentication events
   */
  logAuthentication(event) {
    const logEntry = {
      eventType: 'AUTHENTICATION',
      action: event.action, // LOGIN, LOGOUT, FAILED_LOGIN
      userId: event.userId,
      identifier: this.maskSensitive(event.identifier),
      ipAddress: event.ipAddress,
      userAgent: event.userAgent,
      success: event.success,
      reason: event.reason,
      mfaUsed: event.mfaUsed || false,
      sessionId: event.sessionId,
      timestamp: new Date().toISOString()
    };

    this.auditLog.info(logEntry);
    
    // Alert on suspicious activity
    if (event.action === 'FAILED_LOGIN') {
      this.trackFailedLogin(event.identifier, event.ipAddress);
    }
  }

  /**
   * Log trading operations
   */
  logTrading(event) {
    const logEntry = {
      eventType: 'TRADING',
      action: event.action, // CREATE_POSITION, CLOSE_POSITION, etc.
      userId: event.userId,
      dealId: event.dealId,
      epic: event.epic,
      direction: event.direction,
      size: event.size,
      price: event.price,
      profit: event.profit,
      status: event.status,
      reason: event.reason,
      timestamp: new Date().toISOString()
    };

    this.tradingLog.info(logEntry);
    this.auditLog.info(logEntry);

    // Alert on large trades
    if (event.size > 1000 || Math.abs(event.profit || 0) > 10000) {
      this.alertLargeTrade(logEntry);
    }
  }

  /**
   * Log data access events
   */
  logDataAccess(event) {
    const logEntry = {
      eventType: 'DATA_ACCESS',
      action: event.action, // VIEW, EXPORT, MODIFY
      userId: event.userId,
      resource: event.resource,
      resourceId: event.resourceId,
      ipAddress: event.ipAddress,
      success: event.success,
      dataSize: event.dataSize,
      timestamp: new Date().toISOString()
    };

    this.auditLog.info(logEntry);

    // Track sensitive data access
    if (event.resource === 'ACCOUNT_DETAILS' || event.resource === 'TRADING_HISTORY') {
      this.trackSensitiveAccess(logEntry);
    }
  }

  /**
   * Log security events
   */
  logSecurity(event) {
    const logEntry = {
      eventType: 'SECURITY',
      severity: event.severity, // LOW, MEDIUM, HIGH, CRITICAL
      category: event.category, // INTRUSION, VIOLATION, ANOMALY
      description: event.description,
      userId: event.userId,
      ipAddress: event.ipAddress,
      details: event.details,
      mitigation: event.mitigation,
      timestamp: new Date().toISOString()
    };

    this.securityLog.info(logEntry);
    
    if (event.severity === 'HIGH' || event.severity === 'CRITICAL') {
      this.alertSecurityTeam(logEntry);
    }
  }

  /**
   * Log API calls
   */
  logApiCall(event) {
    const logEntry = {
      eventType: 'API_CALL',
      method: event.method,
      path: event.path,
      userId: event.userId,
      ipAddress: event.ipAddress,
      statusCode: event.statusCode,
      responseTime: event.responseTime,
      errorMessage: event.errorMessage,
      rateLimit: event.rateLimit,
      timestamp: new Date().toISOString()
    };

    this.auditLog.info(logEntry);

    // Track API abuse
    if (event.statusCode === 429 || event.rateLimit?.remaining === 0) {
      this.trackApiAbuse(event.userId, event.ipAddress);
    }
  }

  /**
   * Log configuration changes
   */
  logConfigChange(event) {
    const logEntry = {
      eventType: 'CONFIG_CHANGE',
      action: event.action,
      userId: event.userId,
      setting: event.setting,
      oldValue: this.maskSensitive(event.oldValue),
      newValue: this.maskSensitive(event.newValue),
      reason: event.reason,
      approved: event.approved,
      approvedBy: event.approvedBy,
      timestamp: new Date().toISOString()
    };

    this.auditLog.info(logEntry);
    this.securityLog.info(logEntry);
  }

  /**
   * Track failed login attempts
   */
  failedLogins = new Map();
  
  trackFailedLogin(identifier, ipAddress) {
    const key = `${identifier}:${ipAddress}`;
    const attempts = this.failedLogins.get(key) || [];
    attempts.push(Date.now());
    
    // Keep only attempts in last hour
    const recentAttempts = attempts.filter(t => Date.now() - t < 3600000);
    this.failedLogins.set(key, recentAttempts);
    
    // Alert on brute force attempts
    if (recentAttempts.length >= 5) {
      this.logSecurity({
        severity: 'HIGH',
        category: 'INTRUSION',
        description: 'Possible brute force attack detected',
        userId: identifier,
        ipAddress: ipAddress,
        details: { attempts: recentAttempts.length },
        mitigation: 'Account temporarily locked'
      });
    }
  }

  /**
   * Track sensitive data access
   */
  sensitiveAccess = new Map();
  
  trackSensitiveAccess(logEntry) {
    const key = logEntry.userId;
    const accesses = this.sensitiveAccess.get(key) || [];
    accesses.push({
      resource: logEntry.resource,
      timestamp: logEntry.timestamp
    });
    
    // Keep only last 24 hours
    const recentAccesses = accesses.filter(a => 
      Date.now() - new Date(a.timestamp).getTime() < 86400000
    );
    this.sensitiveAccess.set(key, recentAccesses);
    
    // Alert on unusual access patterns
    if (recentAccesses.length > 100) {
      this.logSecurity({
        severity: 'MEDIUM',
        category: 'ANOMALY',
        description: 'Unusual data access pattern detected',
        userId: key,
        details: { accessCount: recentAccesses.length }
      });
    }
  }

  /**
   * Track API abuse
   */
  apiAbuse = new Map();
  
  trackApiAbuse(userId, ipAddress) {
    const key = `${userId}:${ipAddress}`;
    const violations = this.apiAbuse.get(key) || 0;
    this.apiAbuse.set(key, violations + 1);
    
    if (violations >= 3) {
      this.logSecurity({
        severity: 'MEDIUM',
        category: 'VIOLATION',
        description: 'API rate limit violations',
        userId: userId,
        ipAddress: ipAddress,
        details: { violations: violations + 1 },
        mitigation: 'Consider blocking IP'
      });
    }
  }

  /**
   * Alert on large trades
   */
  alertLargeTrade(trade) {
    this.logSecurity({
      severity: 'LOW',
      category: 'MONITORING',
      description: 'Large trade executed',
      userId: trade.userId,
      details: {
        dealId: trade.dealId,
        size: trade.size,
        profit: trade.profit
      }
    });
  }

  /**
   * Alert security team
   */
  async alertSecurityTeam(event) {
    // In production, this would send alerts via email, SMS, Slack, etc.
    console.error('🚨 SECURITY ALERT:', event);
    
    // Write to critical events file
    const criticalLog = path.join(__dirname, '../../logs/critical.log');
    await fs.appendFile(criticalLog, JSON.stringify(event) + '\n');
  }

  /**
   * Calculate log hash for integrity
   */
  calculateLogHash(log) {
    const hash = crypto.createHash('sha256');
    hash.update(JSON.stringify(log));
    return hash.digest('hex');
  }

  /**
   * Verify log integrity
   */
  async verifyLogIntegrity(logFile) {
    try {
      const content = await fs.readFile(logFile, 'utf8');
      const lines = content.split('\n').filter(l => l.trim());
      
      let valid = 0;
      let invalid = 0;
      
      for (const line of lines) {
        try {
          const log = JSON.parse(line);
          const expectedHash = log.hash;
          delete log.hash;
          
          const actualHash = this.calculateLogHash(log);
          
          if (expectedHash === actualHash) {
            valid++;
          } else {
            invalid++;
            this.logSecurity({
              severity: 'CRITICAL',
              category: 'VIOLATION',
              description: 'Log tampering detected',
              details: { logFile, line: log }
            });
          }
        } catch (e) {
          invalid++;
        }
      }
      
      return { valid, invalid, total: lines.length };
    } catch (error) {
      throw new Error(`Failed to verify log integrity: ${error.message}`);
    }
  }

  /**
   * Mask sensitive information
   */
  maskSensitive(value) {
    if (!value) return value;
    
    const str = String(value);
    
    // Mask API keys
    if (str.length > 20 && /^[A-Za-z0-9]+$/.test(str)) {
      return str.substring(0, 4) + '****' + str.substring(str.length - 4);
    }
    
    // Mask email addresses
    if (str.includes('@')) {
      const [local, domain] = str.split('@');
      return local.substring(0, 2) + '***@' + domain;
    }
    
    // Mask other potentially sensitive data
    if (str.length > 10) {
      return str.substring(0, 3) + '***' + str.substring(str.length - 3);
    }
    
    return value;
  }

  /**
   * Generate audit report
   */
  async generateAuditReport(startDate, endDate) {
    const report = {
      period: { start: startDate, end: endDate },
      authentication: {
        successful: 0,
        failed: 0,
        uniqueUsers: new Set()
      },
      trading: {
        positions: 0,
        totalVolume: 0,
        totalProfit: 0
      },
      security: {
        incidents: [],
        violations: 0
      },
      api: {
        totalCalls: 0,
        errors: 0,
        averageResponseTime: 0
      }
    };
    
    // Process logs and generate report
    // This would read through log files and compile statistics
    
    return report;
  }

  /**
   * Clean old logs
   */
  async cleanOldLogs(daysToKeep = 90) {
    const logsDir = path.join(__dirname, '../../logs');
    const files = await fs.readdir(logsDir);
    const cutoffTime = Date.now() - (daysToKeep * 24 * 60 * 60 * 1000);
    
    for (const file of files) {
      const filePath = path.join(logsDir, file);
      const stats = await fs.stat(filePath);
      
      if (stats.mtime.getTime() < cutoffTime) {
        // Archive before deletion
        await this.archiveLog(filePath);
        await fs.unlink(filePath);
      }
    }
  }

  /**
   * Archive log file
   */
  async archiveLog(logFile) {
    // In production, this would upload to secure storage (S3, etc.)
    const archiveDir = path.join(__dirname, '../../logs/archive');
    await fs.mkdir(archiveDir, { recursive: true });
    
    const basename = path.basename(logFile);
    const timestamp = new Date().toISOString().replace(/:/g, '-');
    const archivePath = path.join(archiveDir, `${timestamp}_${basename}.gz`);
    
    // Compress and move file
    // Implementation would use zlib for compression
  }
}

export const auditLogger = new AuditLogger();