import { apiClient, IGApiError } from '../core/api-client.js';
import { config, logger } from '../core/config.js';

export class IGService {
  constructor() {
    this.apiClient = apiClient;
  }

  // Account Management
  async login(useEncryption = true) {
    try {
      logger.info('Attempting login...');
      
      let loginData;
      if (useEncryption) {
        const encryptionResponse = await this.apiClient.get('/session/encryptionKey', 1);
        const { encryptionKey, timeStamp } = encryptionResponse.data;
        
        const encryptedPassword = this.apiClient.encryptPassword(
          config.credentials.password,
          encryptionKey,
          timeStamp
        );

        loginData = {
          identifier: config.credentials.identifier,
          password: encryptedPassword,
          encryptedPassword: true
        };
      } else {
        loginData = {
          identifier: config.credentials.identifier,
          password: config.credentials.password,
          encryptedPassword: false
        };
      }

      const response = await this.apiClient.post('/session', loginData, 2);
      
      config.setSessionTokens({
        'x-security-token': response.headers['x-security-token'],
        cst: response.headers.cst,
        lightstreamerEndpoint: response.data.lightstreamerEndpoint,
        currentAccountId: response.data.currentAccountId
      });

      logger.info('Login successful');
      return response.data;
    } catch (error) {
      logger.error('Login failed:', error.message);
      throw error;
    }
  }

  async logout() {
    try {
      const response = await this.apiClient.delete('/session');
      config.clearSessionTokens();
      logger.info('Logout successful');
      return response;
    } catch (error) {
      logger.error('Logout failed:', error.message);
      throw error;
    }
  }

  async switchAccount(accountId) {
    try {
      const response = await this.apiClient.put('/session', { accountId }, 1);
      
      config.setSessionTokens({
        'x-security-token': response.headers['x-security-token'],
        cst: response.headers.cst,
        lightstreamerEndpoint: config.sessionTokens.lightstreamerEndpoint,
        currentAccountId: accountId
      });

      logger.info(`Switched to account: ${accountId}`);
      return response.data;
    } catch (error) {
      logger.error('Account switch failed:', error.message);
      throw error;
    }
  }

  async getAccounts() {
    try {
      const response = await this.apiClient.get('/accounts');
      return response.data;
    } catch (error) {
      logger.error('Failed to get accounts:', error.message);
      throw error;
    }
  }

  async getAccountActivity(options = {}) {
    const {
      from = '1990-01-01',
      to = '2099-01-01',
      detailed = false,
      dealId = null,
      pageSize = 500
    } = options;

    const params = new URLSearchParams({
      from,
      to,
      detailed: detailed.toString(),
      pageSize: pageSize.toString()
    });

    if (dealId) params.append('dealId', dealId);

    try {
      const response = await this.apiClient.get(`/history/activity?${params}`, 3);
      return response.data;
    } catch (error) {
      logger.error('Failed to get account activity:', error.message);
      throw error;
    }
  }

  async getAccountTransactions(options = {}) {
    const {
      type = 'ALL',
      from = '1990-01-01',
      to = '2099-01-01',
      pageSize = 0,
      pageNumber = 0
    } = options;

    const params = new URLSearchParams({
      type,
      from,
      to,
      pageSize: pageSize.toString(),
      pageNumber: pageNumber.toString()
    });

    try {
      const response = await this.apiClient.get(`/history/transactions?${params}`, 2);
      return response.data;
    } catch (error) {
      logger.error('Failed to get transactions:', error.message);
      throw error;
    }
  }

  // Trading Operations
  async getPositions() {
    try {
      const response = await this.apiClient.get('/positions', 2);
      return response.data;
    } catch (error) {
      logger.error('Failed to get positions:', error.message);
      throw error;
    }
  }

  async createPosition(ticket) {
    this.validatePositionTicket(ticket);
    
    try {
      const response = await this.apiClient.post('/positions/otc', ticket, 2);
      
      if (response.data.dealReference) {
        const confirmation = await this.getConfirmation(response.data.dealReference);
        return {
          position: response.data,
          confirmation
        };
      }
      
      return response.data;
    } catch (error) {
      logger.error('Failed to create position:', error.message);
      throw error;
    }
  }

  async updatePosition(dealId, updates) {
    try {
      const response = await this.apiClient.put(`/positions/otc/${dealId}`, updates, 2);
      
      if (response.data.dealReference) {
        const confirmation = await this.getConfirmation(response.data.dealReference);
        return {
          position: response.data,
          confirmation
        };
      }
      
      return response.data;
    } catch (error) {
      logger.error('Failed to update position:', error.message);
      throw error;
    }
  }

  async closePosition(dealId) {
    try {
      const positions = await this.getPositions();
      const position = positions.positions.find(p => p.position.dealId === dealId);
      
      if (!position) {
        throw new Error(`Position ${dealId} not found`);
      }

      const closeTicket = {
        dealId,
        direction: position.position.direction === 'BUY' ? 'SELL' : 'BUY',
        orderType: 'MARKET',
        size: position.position.size
      };

      const response = await this.apiClient.delete('/positions/otc', closeTicket, 1);
      
      if (response.data.dealReference) {
        const confirmation = await this.getConfirmation(response.data.dealReference);
        return {
          position: response.data,
          confirmation
        };
      }
      
      return response.data;
    } catch (error) {
      logger.error(`Failed to close position ${dealId}:`, error.message);
      throw error;
    }
  }

  async closeAllPositions() {
    try {
      const positions = await this.getPositions();
      
      if (positions.positions.length === 0) {
        logger.info('No positions to close');
        return [];
      }

      const closePromises = positions.positions.map(p => 
        this.closePosition(p.position.dealId)
      );

      const results = await Promise.allSettled(closePromises);
      
      const successful = results.filter(r => r.status === 'fulfilled').map(r => r.value);
      const failed = results.filter(r => r.status === 'rejected').map(r => r.reason);
      
      if (failed.length > 0) {
        logger.warn(`Failed to close ${failed.length} positions`);
      }
      
      return { successful, failed };
    } catch (error) {
      logger.error('Failed to close all positions:', error.message);
      throw error;
    }
  }

  // Working Orders
  async getWorkingOrders() {
    try {
      const response = await this.apiClient.get('/workingorders', 2);
      return response.data;
    } catch (error) {
      logger.error('Failed to get working orders:', error.message);
      throw error;
    }
  }

  async createWorkingOrder(ticket) {
    this.validateWorkingOrderTicket(ticket);
    
    try {
      const response = await this.apiClient.post('/workingorders/otc', ticket, 2);
      
      if (response.data.dealReference) {
        const confirmation = await this.getConfirmation(response.data.dealReference);
        return {
          order: response.data,
          confirmation
        };
      }
      
      return response.data;
    } catch (error) {
      logger.error('Failed to create working order:', error.message);
      throw error;
    }
  }

  async deleteWorkingOrder(dealId) {
    try {
      const response = await this.apiClient.delete(`/workingorders/otc/${dealId}`, {}, 1);
      
      if (response.data.dealReference) {
        const confirmation = await this.getConfirmation(response.data.dealReference);
        return {
          order: response.data,
          confirmation
        };
      }
      
      return response.data;
    } catch (error) {
      logger.error(`Failed to delete working order ${dealId}:`, error.message);
      throw error;
    }
  }

  async deleteAllWorkingOrders() {
    try {
      const orders = await this.getWorkingOrders();
      
      if (orders.workingOrders.length === 0) {
        logger.info('No working orders to delete');
        return [];
      }

      const deletePromises = orders.workingOrders.map(o => 
        this.deleteWorkingOrder(o.workingOrderData.dealId)
      );

      const results = await Promise.allSettled(deletePromises);
      
      const successful = results.filter(r => r.status === 'fulfilled').map(r => r.value);
      const failed = results.filter(r => r.status === 'rejected').map(r => r.reason);
      
      if (failed.length > 0) {
        logger.warn(`Failed to delete ${failed.length} working orders`);
      }
      
      return { successful, failed };
    } catch (error) {
      logger.error('Failed to delete all working orders:', error.message);
      throw error;
    }
  }

  // Market Data
  async searchMarkets(searchTerm) {
    try {
      const response = await this.apiClient.get(`/markets?searchTerm=${encodeURIComponent(searchTerm)}`);
      return response.data;
    } catch (error) {
      logger.error('Market search failed:', error.message);
      throw error;
    }
  }

  async getMarketDetails(epics) {
    if (!Array.isArray(epics)) {
      epics = [epics];
    }

    if (epics.length > 50) {
      throw new Error('Maximum 50 epics allowed per request');
    }

    try {
      const epicString = epics.join(',');
      const response = await this.apiClient.get(`/markets?epics=${encodeURIComponent(epicString)}`);
      return response.data;
    } catch (error) {
      logger.error('Failed to get market details:', error.message);
      throw error;
    }
  }

  async getHistoricalPrices(epic, resolution, options = {}) {
    const {
      max = 10,
      pageSize = 20,
      from,
      to
    } = options;

    const params = new URLSearchParams({
      resolution,
      max: max.toString(),
      pageSize: pageSize.toString()
    });

    if (from) params.append('from', from);
    if (to) params.append('to', to);

    try {
      const response = await this.apiClient.get(`/prices/${epic}?${params}`, 3);
      return response.data;
    } catch (error) {
      logger.error('Failed to get historical prices:', error.message);
      throw error;
    }
  }

  async getClientSentiment(marketIds) {
    if (!Array.isArray(marketIds)) {
      marketIds = [marketIds];
    }

    try {
      const marketIdString = marketIds.join(',');
      const response = await this.apiClient.get(`/clientsentiment?marketIds=${encodeURIComponent(marketIdString)}`);
      return response.data;
    } catch (error) {
      logger.error('Failed to get client sentiment:', error.message);
      throw error;
    }
  }

  async getMarketNavigation(nodeId = null) {
    try {
      const path = nodeId ? `/marketnavigation/${nodeId}` : '/marketnavigation';
      const response = await this.apiClient.get(path);
      return response.data;
    } catch (error) {
      logger.error('Failed to get market navigation:', error.message);
      throw error;
    }
  }

  // Watchlists
  async getWatchlists() {
    try {
      const response = await this.apiClient.get('/watchlists');
      return response.data;
    } catch (error) {
      logger.error('Failed to get watchlists:', error.message);
      throw error;
    }
  }

  async getWatchlist(watchlistId) {
    try {
      const response = await this.apiClient.get(`/watchlists/${watchlistId}`);
      return response.data;
    } catch (error) {
      logger.error(`Failed to get watchlist ${watchlistId}:`, error.message);
      throw error;
    }
  }

  async createWatchlist(name, epics = []) {
    try {
      const response = await this.apiClient.post('/watchlists', { name, epics });
      return response.data;
    } catch (error) {
      logger.error('Failed to create watchlist:', error.message);
      throw error;
    }
  }

  async deleteWatchlist(watchlistId) {
    try {
      const response = await this.apiClient.delete(`/watchlists/${watchlistId}`);
      return response.data;
    } catch (error) {
      logger.error(`Failed to delete watchlist ${watchlistId}:`, error.message);
      throw error;
    }
  }

  async addToWatchlist(watchlistId, epic) {
    try {
      const response = await this.apiClient.put(`/watchlists/${watchlistId}`, { epic });
      return response.data;
    } catch (error) {
      logger.error(`Failed to add ${epic} to watchlist:`, error.message);
      throw error;
    }
  }

  async removeFromWatchlist(watchlistId, epic) {
    try {
      const response = await this.apiClient.delete(`/watchlists/${watchlistId}/${epic}`);
      return response.data;
    } catch (error) {
      logger.error(`Failed to remove ${epic} from watchlist:`, error.message);
      throw error;
    }
  }

  // Helper Methods
  async getConfirmation(dealReference) {
    try {
      const response = await this.apiClient.get(`/confirms/${dealReference}`);
      return response.data;
    } catch (error) {
      logger.warn(`Failed to get confirmation for ${dealReference}:`, error.message);
      return null;
    }
  }

  validatePositionTicket(ticket) {
    const required = ['currencyCode', 'direction', 'epic', 'expiry', 'size', 'forceOpen', 'orderType', 'guaranteedStop', 'timeInForce'];
    const missing = required.filter(field => ticket[field] === undefined);
    
    if (missing.length > 0) {
      throw new Error(`Missing required fields: ${missing.join(', ')}`);
    }

    const validCurrencies = ['AUD', 'USD', 'EUR', 'GBP', 'CHF', 'NZD', 'JPY', 'CAD'];
    if (!validCurrencies.includes(ticket.currencyCode)) {
      throw new Error(`Invalid currency code: ${ticket.currencyCode}`);
    }

    if (!['BUY', 'SELL'].includes(ticket.direction)) {
      throw new Error('Direction must be BUY or SELL');
    }

    if (!['LIMIT', 'MARKET'].includes(ticket.orderType)) {
      throw new Error('Order type must be LIMIT or MARKET');
    }

    if (ticket.orderType === 'LIMIT' && !ticket.level) {
      throw new Error('Level is required for LIMIT orders');
    }

    if (ticket.orderType === 'MARKET' && ticket.level) {
      throw new Error('Level should not be set for MARKET orders');
    }
  }

  validateWorkingOrderTicket(ticket) {
    const required = ['currencyCode', 'direction', 'epic', 'expiry', 'size', 'forceOpen', 'type', 'guaranteedStop', 'timeInForce', 'level'];
    const missing = required.filter(field => ticket[field] === undefined);
    
    if (missing.length > 0) {
      throw new Error(`Missing required fields: ${missing.join(', ')}`);
    }

    if (!['LIMIT', 'STOP'].includes(ticket.type)) {
      throw new Error('Order type must be LIMIT or STOP');
    }

    if (!['GOOD_TILL_CANCELLED', 'GOOD_TILL_DATE'].includes(ticket.timeInForce)) {
      throw new Error('TimeInForce must be GOOD_TILL_CANCELLED or GOOD_TILL_DATE');
    }
  }
}

export const igService = new IGService();