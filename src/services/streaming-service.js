import WebSocket from 'ws';
import { config, logger } from '../core/config.js';
import { EventEmitter } from 'events';

export class StreamingClient extends EventEmitter {
  constructor() {
    super();
    this.ws = null;
    this.subscriptions = new Map();
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectDelay = 1000;
    this.isConnected = false;
    this.heartbeatInterval = null;
  }

  async connect() {
    try {
      const tokens = config.getSessionTokens();
      if (!tokens || !tokens.lightstreamerEndpoint) {
        throw new Error('No Lightstreamer endpoint available. Please login first.');
      }

      const wsUrl = tokens.lightstreamerEndpoint.replace('https://', 'wss://');
      
      logger.info(`Connecting to Lightstreamer: ${wsUrl}`);

      this.ws = new WebSocket(wsUrl, {
        headers: {
          'X-Security-Token': tokens.xSecurityToken,
          'CST': tokens.cst
        }
      });

      this.setupEventHandlers();

      return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Connection timeout'));
        }, 30000);

        this.once('connected', () => {
          clearTimeout(timeout);
          resolve();
        });

        this.once('error', (error) => {
          clearTimeout(timeout);
          reject(error);
        });
      });
    } catch (error) {
      logger.error('Failed to connect to Lightstreamer:', error.message);
      throw error;
    }
  }

  setupEventHandlers() {
    this.ws.on('open', () => {
      logger.info('Lightstreamer connection established');
      this.isConnected = true;
      this.reconnectAttempts = 0;
      this.authenticate();
      this.startHeartbeat();
      this.emit('connected');
    });

    this.ws.on('message', (data) => {
      try {
        const message = JSON.parse(data.toString());
        this.handleMessage(message);
      } catch (error) {
        logger.error('Failed to parse message:', error.message);
      }
    });

    this.ws.on('close', (code, reason) => {
      logger.warn(`Lightstreamer connection closed: ${code} - ${reason}`);
      this.isConnected = false;
      this.stopHeartbeat();
      this.emit('disconnected', { code, reason });
      this.attemptReconnect();
    });

    this.ws.on('error', (error) => {
      logger.error('Lightstreamer error:', error.message);
      this.emit('error', error);
    });

    this.ws.on('ping', () => {
      this.ws.pong();
    });
  }

  authenticate() {
    const tokens = config.getSessionTokens();
    const authMessage = {
      type: 'AUTH',
      accountId: tokens.currentAccountId,
      cst: tokens.cst,
      xst: tokens.xSecurityToken
    };

    this.send(authMessage);
  }

  startHeartbeat() {
    this.heartbeatInterval = setInterval(() => {
      if (this.isConnected) {
        this.send({ type: 'HEARTBEAT' });
      }
    }, 30000);
  }

  stopHeartbeat() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  async subscribe(mode, items, fields, options = {}) {
    const subscriptionId = this.generateSubscriptionId();
    
    const subscription = {
      id: subscriptionId,
      mode,
      items: Array.isArray(items) ? items : [items],
      fields: Array.isArray(fields) ? fields : [fields],
      maxFrequency: options.maxFrequency || 1,
      snapshot: options.snapshot !== false
    };

    this.subscriptions.set(subscriptionId, subscription);

    const subscribeMessage = {
      type: 'SUBSCRIBE',
      id: subscriptionId,
      mode: subscription.mode,
      items: subscription.items.map(item => `L1:${item}`),
      fields: subscription.fields,
      maxFrequency: subscription.maxFrequency
    };

    this.send(subscribeMessage);

    logger.info(`Subscribed to ${subscription.items.length} items with ID: ${subscriptionId}`);
    
    return subscriptionId;
  }

  unsubscribe(subscriptionId) {
    if (!this.subscriptions.has(subscriptionId)) {
      logger.warn(`Subscription ${subscriptionId} not found`);
      return false;
    }

    const unsubscribeMessage = {
      type: 'UNSUBSCRIBE',
      id: subscriptionId
    };

    this.send(unsubscribeMessage);
    this.subscriptions.delete(subscriptionId);

    logger.info(`Unsubscribed from ${subscriptionId}`);
    return true;
  }

  unsubscribeAll() {
    for (const subscriptionId of this.subscriptions.keys()) {
      this.unsubscribe(subscriptionId);
    }
  }

  handleMessage(message) {
    switch (message.type) {
      case 'AUTH_RESULT':
        if (message.success) {
          logger.info('Authentication successful');
          this.emit('authenticated');
        } else {
          logger.error('Authentication failed:', message.error);
          this.emit('authenticationFailed', message.error);
        }
        break;

      case 'SUBSCRIPTION_UPDATE':
        this.handleSubscriptionUpdate(message);
        break;

      case 'SUBSCRIPTION_ERROR':
        logger.error(`Subscription error for ${message.id}:`, message.error);
        this.emit('subscriptionError', { id: message.id, error: message.error });
        break;

      case 'HEARTBEAT':
        // Heartbeat acknowledged
        break;

      default:
        logger.debug('Unknown message type:', message.type);
    }
  }

  handleSubscriptionUpdate(message) {
    const subscription = this.subscriptions.get(message.id);
    if (!subscription) {
      logger.warn(`Received update for unknown subscription: ${message.id}`);
      return;
    }

    const update = {
      subscriptionId: message.id,
      itemName: message.itemName,
      values: message.values,
      timestamp: new Date(message.timestamp)
    };

    this.emit('update', update);
    this.emit(`update:${message.id}`, update);
    
    if (message.itemName) {
      const epic = message.itemName.replace('L1:', '');
      this.emit(`update:${epic}`, update);
    }
  }

  send(message) {
    if (!this.isConnected || !this.ws) {
      logger.error('Cannot send message: not connected');
      return false;
    }

    try {
      this.ws.send(JSON.stringify(message));
      return true;
    } catch (error) {
      logger.error('Failed to send message:', error.message);
      return false;
    }
  }

  async attemptReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      logger.error('Max reconnection attempts reached');
      this.emit('maxReconnectAttemptsReached');
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
    
    logger.info(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
    
    setTimeout(async () => {
      try {
        await this.connect();
        this.resubscribeAll();
      } catch (error) {
        logger.error('Reconnection failed:', error.message);
      }
    }, delay);
  }

  resubscribeAll() {
    for (const subscription of this.subscriptions.values()) {
      const subscribeMessage = {
        type: 'SUBSCRIBE',
        id: subscription.id,
        mode: subscription.mode,
        items: subscription.items.map(item => `L1:${item}`),
        fields: subscription.fields,
        maxFrequency: subscription.maxFrequency
      };

      this.send(subscribeMessage);
    }

    logger.info(`Resubscribed to ${this.subscriptions.size} subscriptions`);
  }

  disconnect() {
    logger.info('Disconnecting from Lightstreamer');
    
    this.stopHeartbeat();
    this.unsubscribeAll();
    
    if (this.ws) {
      this.ws.close(1000, 'Client disconnect');
      this.ws = null;
    }
    
    this.isConnected = false;
    this.subscriptions.clear();
  }

  generateSubscriptionId() {
    return `sub_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  isConnectionActive() {
    return this.isConnected && this.ws && this.ws.readyState === WebSocket.OPEN;
  }
}

export const streamingClient = new StreamingClient();