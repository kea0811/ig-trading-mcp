import Joi from 'joi';
import { logger } from '../config.js';

/**
 * Input validation and sanitization for all API inputs
 */
export class Validator {
  constructor() {
    this.schemas = this.initializeSchemas();
    this.sanitizers = this.initializeSanitizers();
  }

  /**
   * Initialize validation schemas
   */
  initializeSchemas() {
    return {
      // Credential schemas
      credentials: Joi.object({
        apiKey: Joi.string()
          .pattern(/^[A-Za-z0-9]{20,100}$/)
          .required()
          .messages({
            'string.pattern.base': 'API key must be alphanumeric and 20-100 characters'
          }),
        identifier: Joi.string()
          .min(3)
          .max(50)
          .pattern(/^[A-Za-z0-9_.-]+$/)
          .required()
          .messages({
            'string.pattern.base': 'Identifier contains invalid characters'
          }),
        password: Joi.string()
          .min(8)
          .max(128)
          .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
          .required()
          .messages({
            'string.pattern.base': 'Password must contain uppercase, lowercase, and numbers'
          }),
        isDemo: Joi.boolean().default(true)
      }),

      // Trading position ticket
      positionTicket: Joi.object({
        epic: Joi.string()
          .pattern(/^[A-Z0-9._-]+$/)
          .required(),
        direction: Joi.string()
          .valid('BUY', 'SELL')
          .required(),
        size: Joi.number()
          .positive()
          .max(10000)
          .required(),
        currencyCode: Joi.string()
          .valid('AUD', 'USD', 'EUR', 'GBP', 'CHF', 'NZD', 'JPY', 'CAD')
          .required(),
        expiry: Joi.string()
          .pattern(/^[A-Z0-9-]+$/)
          .required(),
        orderType: Joi.string()
          .valid('MARKET', 'LIMIT')
          .required(),
        level: Joi.number()
          .positive()
          .when('orderType', {
            is: 'LIMIT',
            then: Joi.required(),
            otherwise: Joi.forbidden()
          }),
        stopLevel: Joi.number().positive().optional(),
        limitLevel: Joi.number().positive().optional(),
        stopDistance: Joi.number().positive().optional(),
        limitDistance: Joi.number().positive().optional(),
        guaranteedStop: Joi.boolean().default(false),
        forceOpen: Joi.boolean().default(true),
        timeInForce: Joi.string()
          .valid('FILL_OR_KILL', 'EXECUTE_AND_ELIMINATE')
          .required(),
        trailingStop: Joi.boolean().optional(),
        trailingStopIncrement: Joi.number().positive().optional()
      }),

      // Working order ticket
      workingOrderTicket: Joi.object({
        epic: Joi.string()
          .pattern(/^[A-Z0-9._-]+$/)
          .required(),
        direction: Joi.string()
          .valid('BUY', 'SELL')
          .required(),
        size: Joi.number()
          .positive()
          .max(10000)
          .required(),
        currencyCode: Joi.string()
          .valid('AUD', 'USD', 'EUR', 'GBP', 'CHF', 'NZD', 'JPY', 'CAD')
          .required(),
        expiry: Joi.string()
          .pattern(/^[A-Z0-9-]+$/)
          .required(),
        type: Joi.string()
          .valid('LIMIT', 'STOP')
          .required(),
        level: Joi.number()
          .positive()
          .required(),
        stopLevel: Joi.number().positive().optional(),
        limitLevel: Joi.number().positive().optional(),
        guaranteedStop: Joi.boolean().default(false),
        forceOpen: Joi.boolean().default(true),
        timeInForce: Joi.string()
          .valid('GOOD_TILL_CANCELLED', 'GOOD_TILL_DATE')
          .required(),
        goodTillDate: Joi.string()
          .isoDate()
          .when('timeInForce', {
            is: 'GOOD_TILL_DATE',
            then: Joi.required()
          })
      }),

      // Market search
      marketSearch: Joi.object({
        searchTerm: Joi.string()
          .min(1)
          .max(100)
          .pattern(/^[A-Za-z0-9\s\/.-]+$/)
          .required()
          .messages({
            'string.pattern.base': 'Search term contains invalid characters'
          })
      }),

      // Deal ID
      dealId: Joi.object({
        dealId: Joi.string()
          .pattern(/^[A-Z0-9-]+$/)
          .required()
          .messages({
            'string.pattern.base': 'Invalid deal ID format'
          })
      }),

      // Account ID
      accountId: Joi.object({
        accountId: Joi.string()
          .pattern(/^[A-Z0-9-]+$/)
          .required()
          .messages({
            'string.pattern.base': 'Invalid account ID format'
          })
      }),

      // Date range
      dateRange: Joi.object({
        from: Joi.string()
          .pattern(/^\d{4}-\d{2}-\d{2}$/)
          .optional(),
        to: Joi.string()
          .pattern(/^\d{4}-\d{2}-\d{2}$/)
          .optional(),
        pageSize: Joi.number()
          .integer()
          .min(1)
          .max(1000)
          .optional(),
        pageNumber: Joi.number()
          .integer()
          .min(0)
          .optional()
      }),

      // Historical prices
      historicalPrices: Joi.object({
        epic: Joi.string()
          .pattern(/^[A-Z0-9._-]+$/)
          .required(),
        resolution: Joi.string()
          .valid('SECOND', 'MINUTE', 'MINUTE_2', 'MINUTE_3', 'MINUTE_5', 
                 'MINUTE_10', 'MINUTE_15', 'MINUTE_30', 'HOUR', 'HOUR_2', 
                 'HOUR_3', 'HOUR_4', 'DAY', 'WEEK', 'MONTH')
          .required(),
        max: Joi.number()
          .integer()
          .min(1)
          .max(10000)
          .optional(),
        from: Joi.string()
          .pattern(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/)
          .optional(),
        to: Joi.string()
          .pattern(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/)
          .optional()
      }),

      // Watchlist
      watchlist: Joi.object({
        name: Joi.string()
          .min(1)
          .max(100)
          .pattern(/^[A-Za-z0-9\s_-]+$/)
          .required(),
        epics: Joi.array()
          .items(Joi.string().pattern(/^[A-Z0-9._-]+$/))
          .max(100)
          .optional()
      })
    };
  }

  /**
   * Initialize sanitization functions
   */
  initializeSanitizers() {
    return {
      // Remove potential SQL injection patterns
      sql: (input) => {
        if (typeof input !== 'string') return input;
        
        const sqlPatterns = [
          /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|CREATE|ALTER|EXEC|EXECUTE)\b)/gi,
          /(--|\/\*|\*\/|;|'|")/g,
          /(\bOR\b\s*\d+\s*=\s*\d+)/gi,
          /(\bAND\b\s*\d+\s*=\s*\d+)/gi
        ];
        
        let sanitized = input;
        sqlPatterns.forEach(pattern => {
          sanitized = sanitized.replace(pattern, '');
        });
        
        return sanitized.trim();
      },

      // Remove potential XSS patterns
      xss: (input) => {
        if (typeof input !== 'string') return input;
        
        const xssPatterns = [
          /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
          /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
          /javascript:/gi,
          /on\w+\s*=/gi,
          /<img[^>]+src[\\s]*=[\\s]*["\']javascript:/gi
        ];
        
        let sanitized = input;
        xssPatterns.forEach(pattern => {
          sanitized = sanitized.replace(pattern, '');
        });
        
        // Escape HTML entities
        sanitized = sanitized
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#x27;')
          .replace(/\//g, '&#x2F;');
        
        return sanitized;
      },

      // Remove command injection patterns
      command: (input) => {
        if (typeof input !== 'string') return input;
        
        const commandPatterns = [
          /([;&|`$])/g,
          /(\$\(.*?\))/g,
          /(&&|\|\|)/g,
          /(\n|\r)/g
        ];
        
        let sanitized = input;
        commandPatterns.forEach(pattern => {
          sanitized = sanitized.replace(pattern, '');
        });
        
        return sanitized.trim();
      },

      // Sanitize file paths
      path: (input) => {
        if (typeof input !== 'string') return input;
        
        // Remove directory traversal patterns
        return input
          .replace(/\.\./g, '')
          .replace(/~\//g, '')
          .replace(/^\//, '')
          .replace(/\\/g, '/')
          .trim();
      },

      // Sanitize numeric values
      numeric: (input) => {
        const num = parseFloat(input);
        if (isNaN(num) || !isFinite(num)) {
          throw new Error('Invalid numeric value');
        }
        return num;
      },

      // Sanitize boolean values
      boolean: (input) => {
        if (typeof input === 'boolean') return input;
        if (typeof input === 'string') {
          return input.toLowerCase() === 'true';
        }
        return !!input;
      }
    };
  }

  /**
   * Validate input against schema
   */
  validate(schemaName, data) {
    const schema = this.schemas[schemaName];
    
    if (!schema) {
      throw new Error(`Validation schema '${schemaName}' not found`);
    }
    
    const { error, value } = schema.validate(data, {
      abortEarly: false,
      stripUnknown: true
    });
    
    if (error) {
      const details = error.details.map(d => d.message).join(', ');
      logger.warn(`Validation failed for ${schemaName}: ${details}`);
      throw new ValidationError(details, error.details);
    }
    
    return value;
  }

  /**
   * Sanitize input data
   */
  sanitize(data, type = 'general') {
    if (data === null || data === undefined) {
      return data;
    }
    
    if (typeof data === 'object' && !Array.isArray(data)) {
      const sanitized = {};
      for (const [key, value] of Object.entries(data)) {
        sanitized[this.sanitizeKey(key)] = this.sanitize(value, type);
      }
      return sanitized;
    }
    
    if (Array.isArray(data)) {
      return data.map(item => this.sanitize(item, type));
    }
    
    if (typeof data === 'string') {
      let sanitized = data;
      
      // Apply sanitizers based on type
      switch (type) {
        case 'sql':
          sanitized = this.sanitizers.sql(sanitized);
          break;
        case 'xss':
          sanitized = this.sanitizers.xss(sanitized);
          break;
        case 'command':
          sanitized = this.sanitizers.command(sanitized);
          break;
        case 'path':
          sanitized = this.sanitizers.path(sanitized);
          break;
        case 'general':
        default:
          sanitized = this.sanitizers.sql(sanitized);
          sanitized = this.sanitizers.command(sanitized);
          break;
      }
      
      // Truncate overly long strings
      if (sanitized.length > 10000) {
        sanitized = sanitized.substring(0, 10000);
      }
      
      return sanitized;
    }
    
    return data;
  }

  /**
   * Sanitize object keys
   */
  sanitizeKey(key) {
    if (typeof key !== 'string') return key;
    
    // Remove any non-alphanumeric characters except underscore and dash
    return key.replace(/[^a-zA-Z0-9_-]/g, '');
  }

  /**
   * Validate and sanitize combined
   */
  validateAndSanitize(schemaName, data) {
    // First sanitize
    const sanitized = this.sanitize(data);
    
    // Then validate
    const validated = this.validate(schemaName, sanitized);
    
    return validated;
  }

  /**
   * Check for rate limit bypass attempts
   */
  detectRateLimitBypass(headers) {
    const suspiciousHeaders = [
      'x-forwarded-for',
      'x-real-ip',
      'x-originating-ip',
      'cf-connecting-ip',
      'true-client-ip'
    ];
    
    for (const header of suspiciousHeaders) {
      if (headers[header] && headers[header].includes(',')) {
        logger.warn(`Potential rate limit bypass attempt detected: ${header}`);
        return true;
      }
    }
    
    return false;
  }

  /**
   * Validate IP address
   */
  isValidIP(ip) {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$/;
    
    if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
      return false;
    }
    
    // Check for private IPs
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[01])\./,
      /^192\.168\./,
      /^127\./,
      /^::1$/,
      /^fe80:/i
    ];
    
    for (const range of privateRanges) {
      if (range.test(ip)) {
        logger.warn(`Private IP detected: ${ip}`);
      }
    }
    
    return true;
  }
}

/**
 * Custom validation error
 */
export class ValidationError extends Error {
  constructor(message, details = []) {
    super(message);
    this.name = 'ValidationError';
    this.details = details;
  }
}

export const validator = new Validator();