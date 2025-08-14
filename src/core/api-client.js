import axios from 'axios';
import pRetry from 'p-retry';
import pThrottle from 'p-throttle';
import { config, logger } from './config.js';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { encryptPassword: pidCryptEncrypt } = require('./encryption.cjs');

export class IGApiError extends Error {
  constructor(message, status, code) {
    super(message);
    this.name = 'IGApiError';
    this.status = status;
    this.code = code;
  }
}

export class IGApiClient {
  constructor() {
    this.axiosInstance = null;
    this.throttle = pThrottle({
      limit: 60,
      interval: 60000,
      strict: true
    });
    this.initializeAxios();
  }

  initializeAxios() {
    // Delay baseURL setting until first request when config is ready
    this.axiosInstance = axios.create({
      timeout: 30000,
      headers: {
        'Accept': 'application/json; charset=UTF-8',
        'Content-Type': 'application/json; charset=UTF-8'
      }
    });

    this.axiosInstance.interceptors.request.use(
      (requestConfig) => {
        // Set baseURL dynamically when config is ready
        if (!requestConfig.baseURL) {
          requestConfig.baseURL = config.getApiUrl() + '/gateway/deal';
        }
        
        if (config.credentials?.apiKey) {
          requestConfig.headers['X-IG-API-KEY'] = config.credentials.apiKey;
        }
        
        try {
          const tokens = config.getSessionTokens();
          if (tokens) {
            requestConfig.headers['X-Security-Token'] = tokens.xSecurityToken;
            requestConfig.headers['CST'] = tokens.cst;
          }
        } catch (error) {
          // No session tokens yet, likely a login request
        }

        logger.debug(`API Request: ${requestConfig.method?.toUpperCase()} ${requestConfig.url}`);
        return requestConfig;
      },
      (error) => Promise.reject(error)
    );

    this.axiosInstance.interceptors.response.use(
      (response) => {
        logger.debug(`API Response: ${response.status} ${response.config.url}`);
        return response;
      },
      (error) => {
        if (error.response) {
          logger.error(`API Error: ${error.response.status} ${error.response.data?.errorCode || ''}`);
          throw new IGApiError(
            error.response.data?.errorCode || error.message,
            error.response.status,
            error.response.data?.errorCode
          );
        }
        throw error;
      }
    );
  }

  async request(method, path, data = null, headers = {}, version = 1) {
    const requestConfig = {
      method,
      url: path,
      headers: { ...headers, Version: version }
    };

    if (data) {
      if (method === 'GET') {
        requestConfig.params = data;
      } else {
        requestConfig.data = data;
      }
    }

    const throttledRequest = this.throttle(async () => {
      return await pRetry(
        async () => {
          const response = await this.axiosInstance(requestConfig);
          return {
            status: response.status,
            headers: response.headers,
            data: response.data
          };
        },
        {
          retries: 3,
          onFailedAttempt: (error) => {
            logger.warn(`Request failed, attempt ${error.attemptNumber}: ${error.message}`);
            if (error.attemptNumber === 3) {
              logger.error(`Request failed after ${error.attemptNumber} attempts`);
            }
          },
          shouldRetry: (error) => {
            if (error.status === 401) return false;
            if (error.status >= 500) return true;
            if (error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT') return true;
            return false;
          }
        }
      );
    });

    return await throttledRequest();
  }

  async get(path, version = 1) {
    return this.request('GET', path, null, {}, version);
  }

  async post(path, data, version = 1) {
    return this.request('POST', path, data, {}, version);
  }

  async put(path, data, version = 1) {
    return this.request('PUT', path, data, {}, version);
  }

  async delete(path, data = null, version = 1) {
    const headers = { '_method': 'DELETE' };
    return this.request('POST', path, data, headers, version);
  }

  encryptPassword(password, encryptionKey, timestamp) {
    try {
      // Use pidCrypt for IG-compatible RSA encryption
      return pidCryptEncrypt(password, encryptionKey, timestamp);
    } catch (error) {
      logger.error('Password encryption failed:', error);
      throw new Error('Failed to encrypt password');
    }
  }
}

export const apiClient = new IGApiClient();