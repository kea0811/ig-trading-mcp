/**
 * IG Trading API - Main Entry Point
 * Modern ES6+ implementation
 */

// Core modules
export { IGApiClient, IGApiError } from './core/api-client.js';
export { config, logger } from './core/config.js';

// Services
export { IGService } from './services/ig-service.js';
export { StreamingClient } from './services/streaming-service.js';

// Security modules
export * from './security/index.js';

// Indicators
export { calculateSupertrend, calculateATR } from './indicators/supertrend.js';

// Default export for convenience
import { IGService } from './services/ig-service.js';
import { config } from './core/config.js';

export default {
  IGService,
  config,
  // Helper function to initialize with credentials
  async initialize(credentials) {
    config.credentials = credentials;
    const service = new IGService();
    return service;
  }
};