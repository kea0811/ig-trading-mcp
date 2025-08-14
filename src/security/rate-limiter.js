import NodeCache from 'node-cache';
import crypto from 'crypto';
import { logger } from '../config.js';
import { auditLogger } from './audit-logger.js';

/**
 * Advanced rate limiting with multiple strategies
 */
export class RateLimiter {
  constructor() {
    // Different caches for different rate limiting strategies
    this.requestCache = new NodeCache({ stdTTL: 60, checkperiod: 10 });
    this.userCache = new NodeCache({ stdTTL: 3600, checkperiod: 60 });
    this.ipCache = new NodeCache({ stdTTL: 3600, checkperiod: 60 });
    this.apiKeyCache = new NodeCache({ stdTTL: 3600, checkperiod: 60 });
    
    // Blacklists and whitelists
    this.blacklistedIPs = new Set();
    this.blacklistedUsers = new Set();
    this.whitelistedIPs = new Set(['127.0.0.1', '::1']); // localhost
    
    // Rate limit configurations
    this.limits = {
      global: {
        requests: 1000,
        window: 60000 // 1 minute
      },
      perUser: {
        requests: 100,
        window: 60000 // 1 minute
      },
      perIP: {
        requests: 50,
        window: 60000 // 1 minute
      },
      perApiKey: {
        requests: 500,
        window: 60000 // 1 minute
      },
      perEndpoint: {
        '/login': { requests: 5, window: 300000 }, // 5 per 5 minutes
        '/positions/otc': { requests: 20, window: 60000 }, // 20 per minute
        '/history': { requests: 10, window: 60000 }, // 10 per minute
        '/prices': { requests: 30, window: 60000 } // 30 per minute
      },
      burst: {
        tokens: 10,
        refillRate: 1,
        refillInterval: 1000 // 1 token per second
      }
    };
    
    // Token buckets for burst protection
    this.tokenBuckets = new Map();
    
    // Request patterns for anomaly detection
    this.requestPatterns = new Map();
    
    // Start cleanup interval
    this.startCleanup();
  }

  /**
   * Check if request should be allowed
   */
  async checkLimit(options) {
    const {
      userId,
      ipAddress,
      apiKey,
      endpoint,
      method = 'GET'
    } = options;

    // Check blacklists first
    if (this.isBlacklisted(userId, ipAddress)) {
      auditLogger.logSecurity({
        severity: 'HIGH',
        category: 'VIOLATION',
        description: 'Blacklisted entity attempted access',
        userId,
        ipAddress,
        details: { endpoint, method }
      });
      return {
        allowed: false,
        reason: 'Blacklisted',
        retryAfter: null
      };
    }

    // Skip rate limiting for whitelisted IPs
    if (this.whitelistedIPs.has(ipAddress)) {
      return {
        allowed: true,
        remaining: Infinity,
        reset: null
      };
    }

    // Check multiple rate limits
    const checks = [
      this.checkGlobalLimit(),
      this.checkUserLimit(userId),
      this.checkIPLimit(ipAddress),
      this.checkApiKeyLimit(apiKey),
      this.checkEndpointLimit(endpoint),
      this.checkBurstLimit(userId || ipAddress),
      this.checkAnomalyPatterns(userId, ipAddress, endpoint)
    ];

    const results = await Promise.all(checks);
    
    // Find the most restrictive limit
    const denied = results.find(r => !r.allowed);
    if (denied) {
      this.handleRateLimitViolation(options, denied);
      return denied;
    }

    // Calculate minimum remaining requests
    const minRemaining = Math.min(...results.map(r => r.remaining || Infinity));
    const nearestReset = Math.min(...results.map(r => r.reset || Infinity));

    // Track successful request
    this.trackRequest(options);

    return {
      allowed: true,
      remaining: minRemaining,
      reset: nearestReset,
      limits: results
    };
  }

  /**
   * Check global rate limit
   */
  checkGlobalLimit() {
    const key = 'global';
    const limit = this.limits.global;
    return this.checkWindowLimit(key, limit, this.requestCache);
  }

  /**
   * Check per-user rate limit
   */
  checkUserLimit(userId) {
    if (!userId) return { allowed: true, remaining: Infinity };
    
    const key = `user:${userId}`;
    const limit = this.limits.perUser;
    return this.checkWindowLimit(key, limit, this.userCache);
  }

  /**
   * Check per-IP rate limit
   */
  checkIPLimit(ipAddress) {
    if (!ipAddress) return { allowed: true, remaining: Infinity };
    
    const key = `ip:${ipAddress}`;
    const limit = this.limits.perIP;
    return this.checkWindowLimit(key, limit, this.ipCache);
  }

  /**
   * Check per-API key rate limit
   */
  checkApiKeyLimit(apiKey) {
    if (!apiKey) return { allowed: true, remaining: Infinity };
    
    const key = `apikey:${this.hashApiKey(apiKey)}`;
    const limit = this.limits.perApiKey;
    return this.checkWindowLimit(key, limit, this.apiKeyCache);
  }

  /**
   * Check endpoint-specific rate limit
   */
  checkEndpointLimit(endpoint) {
    if (!endpoint) return { allowed: true, remaining: Infinity };
    
    // Find matching endpoint limit
    const endpointLimit = this.limits.perEndpoint[endpoint];
    if (!endpointLimit) return { allowed: true, remaining: Infinity };
    
    const key = `endpoint:${endpoint}`;
    return this.checkWindowLimit(key, endpointLimit, this.requestCache);
  }

  /**
   * Check burst limit using token bucket algorithm
   */
  checkBurstLimit(identifier) {
    if (!identifier) return { allowed: true, remaining: Infinity };
    
    const now = Date.now();
    let bucket = this.tokenBuckets.get(identifier);
    
    if (!bucket) {
      bucket = {
        tokens: this.limits.burst.tokens,
        lastRefill: now
      };
      this.tokenBuckets.set(identifier, bucket);
    }
    
    // Refill tokens
    const timePassed = now - bucket.lastRefill;
    const tokensToAdd = Math.floor(timePassed / this.limits.burst.refillInterval) * this.limits.burst.refillRate;
    bucket.tokens = Math.min(this.limits.burst.tokens, bucket.tokens + tokensToAdd);
    bucket.lastRefill = now;
    
    // Check if request can be made
    if (bucket.tokens >= 1) {
      bucket.tokens--;
      return {
        allowed: true,
        remaining: bucket.tokens,
        reset: now + this.limits.burst.refillInterval
      };
    }
    
    return {
      allowed: false,
      reason: 'Burst limit exceeded',
      remaining: 0,
      retryAfter: this.limits.burst.refillInterval
    };
  }

  /**
   * Check for anomaly patterns
   */
  checkAnomalyPatterns(userId, ipAddress, endpoint) {
    const identifier = userId || ipAddress;
    if (!identifier) return { allowed: true };
    
    const patterns = this.requestPatterns.get(identifier) || [];
    const now = Date.now();
    
    // Add current request
    patterns.push({ endpoint, timestamp: now });
    
    // Keep only recent patterns (last 5 minutes)
    const recentPatterns = patterns.filter(p => now - p.timestamp < 300000);
    this.requestPatterns.set(identifier, recentPatterns);
    
    // Detect anomalies
    const anomalies = this.detectAnomalies(recentPatterns);
    
    if (anomalies.suspicious) {
      logger.warn(`Anomaly detected for ${identifier}: ${anomalies.reason}`);
      
      if (anomalies.severity === 'HIGH') {
        return {
          allowed: false,
          reason: 'Suspicious activity detected',
          retryAfter: 300000 // 5 minutes
        };
      }
    }
    
    return { allowed: true };
  }

  /**
   * Detect anomalies in request patterns
   */
  detectAnomalies(patterns) {
    if (patterns.length < 10) return { suspicious: false };
    
    // Check for endpoint scanning
    const uniqueEndpoints = new Set(patterns.map(p => p.endpoint));
    if (uniqueEndpoints.size > 20) {
      return {
        suspicious: true,
        severity: 'HIGH',
        reason: 'Endpoint scanning detected'
      };
    }
    
    // Check for rapid-fire requests
    const timestamps = patterns.map(p => p.timestamp).sort();
    let rapidRequests = 0;
    
    for (let i = 1; i < timestamps.length; i++) {
      if (timestamps[i] - timestamps[i-1] < 100) { // Less than 100ms apart
        rapidRequests++;
      }
    }
    
    if (rapidRequests > 10) {
      return {
        suspicious: true,
        severity: 'MEDIUM',
        reason: 'Rapid-fire requests detected'
      };
    }
    
    // Check for pattern repetition (possible bot)
    const endpointSequence = patterns.map(p => p.endpoint).join(',');
    const repeatPattern = /(.+)\1{3,}/; // Same pattern repeated 3+ times
    
    if (repeatPattern.test(endpointSequence)) {
      return {
        suspicious: true,
        severity: 'MEDIUM',
        reason: 'Repetitive pattern detected'
      };
    }
    
    return { suspicious: false };
  }

  /**
   * Generic window-based rate limit check
   */
  checkWindowLimit(key, limit, cache) {
    const now = Date.now();
    const windowKey = `${key}:${Math.floor(now / limit.window)}`;
    
    const current = cache.get(windowKey) || 0;
    
    if (current >= limit.requests) {
      const reset = Math.ceil(now / limit.window) * limit.window;
      return {
        allowed: false,
        reason: 'Rate limit exceeded',
        remaining: 0,
        reset,
        retryAfter: reset - now
      };
    }
    
    cache.set(windowKey, current + 1);
    
    return {
      allowed: true,
      remaining: limit.requests - current - 1,
      reset: Math.ceil(now / limit.window) * limit.window
    };
  }

  /**
   * Track successful request
   */
  trackRequest(options) {
    const { userId, ipAddress, endpoint, method } = options;
    
    // Log the request
    auditLogger.logApiCall({
      method,
      path: endpoint,
      userId,
      ipAddress,
      statusCode: 200,
      rateLimit: { remaining: 'varies' }
    });
  }

  /**
   * Handle rate limit violation
   */
  handleRateLimitViolation(options, result) {
    const { userId, ipAddress, endpoint } = options;
    
    logger.warn(`Rate limit exceeded: ${result.reason}`, {
      userId,
      ipAddress,
      endpoint
    });
    
    // Log security event
    auditLogger.logSecurity({
      severity: 'MEDIUM',
      category: 'VIOLATION',
      description: 'Rate limit exceeded',
      userId,
      ipAddress,
      details: {
        endpoint,
        reason: result.reason
      }
    });
    
    // Track violations
    const violationKey = userId || ipAddress;
    const violations = this.getViolationCount(violationKey);
    
    // Auto-blacklist after repeated violations
    if (violations > 10) {
      this.blacklist(userId, ipAddress, 'Repeated rate limit violations');
    }
  }

  /**
   * Get violation count for an identifier
   */
  violationCounts = new Map();
  
  getViolationCount(identifier) {
    const count = this.violationCounts.get(identifier) || 0;
    this.violationCounts.set(identifier, count + 1);
    return count + 1;
  }

  /**
   * Blacklist a user or IP
   */
  blacklist(userId, ipAddress, reason) {
    if (userId) {
      this.blacklistedUsers.add(userId);
      logger.warn(`User blacklisted: ${userId} - ${reason}`);
    }
    
    if (ipAddress && !this.whitelistedIPs.has(ipAddress)) {
      this.blacklistedIPs.add(ipAddress);
      logger.warn(`IP blacklisted: ${ipAddress} - ${reason}`);
    }
    
    auditLogger.logSecurity({
      severity: 'HIGH',
      category: 'VIOLATION',
      description: 'Entity blacklisted',
      userId,
      ipAddress,
      details: { reason }
    });
  }

  /**
   * Check if entity is blacklisted
   */
  isBlacklisted(userId, ipAddress) {
    return (userId && this.blacklistedUsers.has(userId)) ||
           (ipAddress && this.blacklistedIPs.has(ipAddress));
  }

  /**
   * Remove from blacklist
   */
  unblacklist(userId, ipAddress) {
    if (userId) {
      this.blacklistedUsers.delete(userId);
    }
    if (ipAddress) {
      this.blacklistedIPs.delete(ipAddress);
    }
  }

  /**
   * Hash API key for storage
   */
  hashApiKey(apiKey) {
    return crypto.createHash('sha256').update(apiKey).digest('hex');
  }

  /**
   * Get rate limit headers for response
   */
  getHeaders(result) {
    return {
      'X-RateLimit-Limit': result.limit || 'varies',
      'X-RateLimit-Remaining': result.remaining || 0,
      'X-RateLimit-Reset': result.reset || Date.now() + 60000,
      'Retry-After': result.retryAfter ? Math.ceil(result.retryAfter / 1000) : undefined
    };
  }

  /**
   * Reset limits for a specific identifier
   */
  resetLimits(identifier) {
    const patterns = [`user:${identifier}`, `ip:${identifier}`, `apikey:${identifier}`];
    
    patterns.forEach(pattern => {
      this.requestCache.del(pattern);
      this.userCache.del(pattern);
      this.ipCache.del(pattern);
      this.apiKeyCache.del(pattern);
    });
    
    this.tokenBuckets.delete(identifier);
    this.requestPatterns.delete(identifier);
    this.violationCounts.delete(identifier);
  }

  /**
   * Start cleanup interval
   */
  startCleanup() {
    setInterval(() => {
      // Clean up old token buckets
      const now = Date.now();
      for (const [id, bucket] of this.tokenBuckets.entries()) {
        if (now - bucket.lastRefill > 3600000) { // 1 hour idle
          this.tokenBuckets.delete(id);
        }
      }
      
      // Clean up old request patterns
      for (const [id, patterns] of this.requestPatterns.entries()) {
        const recent = patterns.filter(p => now - p.timestamp < 300000);
        if (recent.length === 0) {
          this.requestPatterns.delete(id);
        } else {
          this.requestPatterns.set(id, recent);
        }
      }
      
      // Reset violation counts daily
      if (new Date().getHours() === 0) {
        this.violationCounts.clear();
      }
    }, 60000); // Every minute
  }

  /**
   * Get current statistics
   */
  getStatistics() {
    return {
      blacklistedIPs: this.blacklistedIPs.size,
      blacklistedUsers: this.blacklistedUsers.size,
      activeTokenBuckets: this.tokenBuckets.size,
      trackedPatterns: this.requestPatterns.size,
      cacheStats: {
        request: this.requestCache.getStats(),
        user: this.userCache.getStats(),
        ip: this.ipCache.getStats(),
        apiKey: this.apiKeyCache.getStats()
      }
    };
  }
}

export const rateLimiter = new RateLimiter();