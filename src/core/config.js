import { program } from 'commander';
import dotenv from 'dotenv';
import winston from 'winston';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

export class Config {
  constructor() {
    this.credentials = null;
    this.sessionTokens = null;
    this.tokenExpiryTime = null;
  }

  parseArguments() {
    program
      .option('--api-key <key>', 'IG API Key')
      .option('--identifier <id>', 'IG Account Identifier')
      .option('--password <pwd>', 'IG Account Password')
      .option('--demo <boolean>', 'Use demo account', 'true')
      .option('--config <path>', 'Path to config file')
      .parse(process.argv);

    const options = program.opts();
    
    if (options.config) {
      this.loadFromFile(options.config);
    } else {
      this.loadFromArgsOrEnv(options);
    }

    this.validateCredentials();
    return this;
  }

  loadFromFile(configPath) {
    try {
      const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      this.credentials = {
        apiKey: config.apiKey,
        identifier: config.identifier,
        password: config.password,
        isDemo: config.demo !== false
      };
    } catch (error) {
      logger.error(`Failed to load config file: ${error.message}`);
      throw error;
    }
  }

  loadFromArgsOrEnv(options) {
    this.credentials = {
      apiKey: options.apiKey || process.env.IG_API_KEY,
      identifier: options.identifier || process.env.IG_IDENTIFIER,
      password: options.password || process.env.IG_PASSWORD,
      isDemo: (options.demo || process.env.IG_DEMO || 'true').toLowerCase() === 'true'
    };
  }

  validateCredentials() {
    const missing = [];
    if (!this.credentials.apiKey) missing.push('API Key (--api-key or IG_API_KEY)');
    if (!this.credentials.identifier) missing.push('Identifier (--identifier or IG_IDENTIFIER)');
    if (!this.credentials.password) missing.push('Password (--password or IG_PASSWORD)');

    if (missing.length > 0) {
      const errorMsg = `Missing required credentials: ${missing.join(', ')}`;
      logger.error(errorMsg);
      throw new Error(errorMsg);
    }

    logger.info(`Using ${this.credentials.isDemo ? 'DEMO' : 'LIVE'} environment`);
  }

  getApiUrl() {
    // Default to demo if credentials not yet set
    if (!this.credentials) {
      return 'https://demo-api.ig.com';
    }
    return this.credentials.isDemo ? 'https://demo-api.ig.com' : 'https://api.ig.com';
  }

  setSessionTokens(tokens) {
    this.sessionTokens = {
      xSecurityToken: tokens['x-security-token'],
      cst: tokens.cst,
      lightstreamerEndpoint: tokens.lightstreamerEndpoint,
      currentAccountId: tokens.currentAccountId
    };
    this.tokenExpiryTime = Date.now() + (12 * 60 * 60 * 1000); // 12 hours
    logger.info('Session tokens updated');
  }

  getSessionTokens() {
    if (!this.sessionTokens) {
      throw new Error('No active session. Please login first.');
    }
    if (this.isTokenExpired()) {
      throw new Error('Session tokens expired. Please login again.');
    }
    return this.sessionTokens;
  }

  isTokenExpired() {
    return this.tokenExpiryTime && Date.now() > this.tokenExpiryTime;
  }

  clearSessionTokens() {
    this.sessionTokens = null;
    this.tokenExpiryTime = null;
    logger.info('Session tokens cleared');
  }
}

export const config = new Config();