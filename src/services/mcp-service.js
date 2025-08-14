#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import dotenv from 'dotenv';
import { config, logger } from '../core/config.js';
import { IGService } from './ig-service.js';

dotenv.config();

const igService = new IGService();

// Initialize configuration from environment or config file
const initializeConfig = () => {
  try {
    // Try to load from environment variables first
    config.credentials = {
      apiKey: process.env.IG_API_KEY,
      identifier: process.env.IG_IDENTIFIER,
      password: process.env.IG_PASSWORD,
      isDemo: process.env.IG_DEMO?.toLowerCase() === 'true'
    };

    // Validate that we have minimum required credentials
    if (!config.credentials.apiKey || !config.credentials.identifier || !config.credentials.password) {
      logger.warn('IG credentials not fully configured. Some tools may not work.');
    }
  } catch (error) {
    logger.warn('Failed to initialize config:', error.message);
  }
};

// Create MCP server
const server = new Server(
  {
    name: 'ig-trading-mcp',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Tool definitions
const TOOLS = [
  // Account Management Tools
  {
    name: 'ig_login',
    description: 'Login to IG Trading account',
    inputSchema: {
      type: 'object',
      properties: {
        apiKey: {
          type: 'string',
          description: 'IG API Key (optional if set in environment)',
        },
        identifier: {
          type: 'string',
          description: 'IG Account Identifier (optional if set in environment)',
        },
        password: {
          type: 'string',
          description: 'IG Account Password (optional if set in environment)',
        },
        isDemo: {
          type: 'boolean',
          description: 'Use demo account (default: true)',
          default: true,
        },
        useEncryption: {
          type: 'boolean',
          description: 'Use encrypted login (default: true)',
          default: true,
        },
      },
    },
  },
  {
    name: 'ig_logout',
    description: 'Logout from IG Trading account',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'ig_get_accounts',
    description: 'Get list of all trading accounts',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'ig_switch_account',
    description: 'Switch to a different trading account',
    inputSchema: {
      type: 'object',
      properties: {
        accountId: {
          type: 'string',
          description: 'Account ID to switch to',
        },
      },
      required: ['accountId'],
    },
  },
  {
    name: 'ig_get_account_activity',
    description: 'Get account activity history',
    inputSchema: {
      type: 'object',
      properties: {
        from: {
          type: 'string',
          description: 'Start date (YYYY-MM-DD)',
        },
        to: {
          type: 'string',
          description: 'End date (YYYY-MM-DD)',
        },
        detailed: {
          type: 'boolean',
          description: 'Include detailed information',
          default: false,
        },
        pageSize: {
          type: 'number',
          description: 'Number of results per page',
          default: 500,
        },
      },
    },
  },

  // Position Management Tools
  {
    name: 'ig_get_positions',
    description: 'Get all open positions',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'ig_create_position',
    description: 'Create a new trading position',
    inputSchema: {
      type: 'object',
      properties: {
        epic: {
          type: 'string',
          description: 'Market epic code',
        },
        direction: {
          type: 'string',
          enum: ['BUY', 'SELL'],
          description: 'Trade direction',
        },
        size: {
          type: 'number',
          description: 'Position size',
        },
        currencyCode: {
          type: 'string',
          description: 'Currency code (e.g., GBP, USD)',
        },
        expiry: {
          type: 'string',
          description: 'Contract expiry (e.g., DFB for daily funded bet)',
        },
        orderType: {
          type: 'string',
          enum: ['MARKET', 'LIMIT'],
          description: 'Order type',
        },
        level: {
          type: 'number',
          description: 'Price level (required for LIMIT orders)',
        },
        stopLevel: {
          type: 'number',
          description: 'Stop loss level',
        },
        limitLevel: {
          type: 'number',
          description: 'Take profit level',
        },
        guaranteedStop: {
          type: 'boolean',
          description: 'Use guaranteed stop',
          default: false,
        },
        forceOpen: {
          type: 'boolean',
          description: 'Force open a new position',
          default: true,
        },
        timeInForce: {
          type: 'string',
          enum: ['FILL_OR_KILL', 'EXECUTE_AND_ELIMINATE'],
          description: 'Time in force',
        },
      },
      required: ['epic', 'direction', 'size', 'currencyCode', 'expiry', 'orderType', 'timeInForce'],
    },
  },
  {
    name: 'ig_close_position',
    description: 'Close an open position',
    inputSchema: {
      type: 'object',
      properties: {
        dealId: {
          type: 'string',
          description: 'Deal ID of the position to close',
        },
      },
      required: ['dealId'],
    },
  },
  {
    name: 'ig_close_all_positions',
    description: 'Close all open positions',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'ig_update_position',
    description: 'Update stop/limit levels for an open position',
    inputSchema: {
      type: 'object',
      properties: {
        dealId: {
          type: 'string',
          description: 'Deal ID of the position to update',
        },
        stopLevel: {
          type: 'number',
          description: 'New stop loss level',
        },
        limitLevel: {
          type: 'number',
          description: 'New take profit level',
        },
        trailingStop: {
          type: 'boolean',
          description: 'Enable trailing stop',
        },
        trailingStopDistance: {
          type: 'number',
          description: 'Trailing stop distance',
        },
      },
      required: ['dealId'],
    },
  },

  // Working Orders Tools
  {
    name: 'ig_get_working_orders',
    description: 'Get all working orders',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'ig_create_working_order',
    description: 'Create a working order',
    inputSchema: {
      type: 'object',
      properties: {
        epic: {
          type: 'string',
          description: 'Market epic code',
        },
        direction: {
          type: 'string',
          enum: ['BUY', 'SELL'],
          description: 'Trade direction',
        },
        size: {
          type: 'number',
          description: 'Order size',
        },
        currencyCode: {
          type: 'string',
          description: 'Currency code',
        },
        expiry: {
          type: 'string',
          description: 'Contract expiry',
        },
        type: {
          type: 'string',
          enum: ['LIMIT', 'STOP'],
          description: 'Order type',
        },
        level: {
          type: 'number',
          description: 'Entry level',
        },
        stopLevel: {
          type: 'number',
          description: 'Stop loss level',
        },
        limitLevel: {
          type: 'number',
          description: 'Take profit level',
        },
        guaranteedStop: {
          type: 'boolean',
          description: 'Use guaranteed stop',
          default: false,
        },
        forceOpen: {
          type: 'boolean',
          description: 'Force open a new position',
          default: true,
        },
        timeInForce: {
          type: 'string',
          enum: ['GOOD_TILL_CANCELLED', 'GOOD_TILL_DATE'],
          description: 'Time in force',
        },
        goodTillDate: {
          type: 'string',
          description: 'Expiry date for GOOD_TILL_DATE orders',
        },
      },
      required: ['epic', 'direction', 'size', 'currencyCode', 'expiry', 'type', 'level', 'timeInForce'],
    },
  },
  {
    name: 'ig_delete_working_order',
    description: 'Delete a working order',
    inputSchema: {
      type: 'object',
      properties: {
        dealId: {
          type: 'string',
          description: 'Deal ID of the order to delete',
        },
      },
      required: ['dealId'],
    },
  },

  // Market Data Tools
  {
    name: 'ig_search_markets',
    description: 'Search for tradeable markets',
    inputSchema: {
      type: 'object',
      properties: {
        searchTerm: {
          type: 'string',
          description: 'Search term (e.g., "Oil", "EUR/USD", "Apple")',
        },
      },
      required: ['searchTerm'],
    },
  },
  {
    name: 'ig_get_market_details',
    description: 'Get detailed information about a market',
    inputSchema: {
      type: 'object',
      properties: {
        epics: {
          type: 'array',
          items: {
            type: 'string',
          },
          description: 'List of market epic codes (max 50)',
        },
      },
      required: ['epics'],
    },
  },
  {
    name: 'ig_get_historical_prices',
    description: 'Get historical price data',
    inputSchema: {
      type: 'object',
      properties: {
        epic: {
          type: 'string',
          description: 'Market epic code',
        },
        resolution: {
          type: 'string',
          enum: ['SECOND', 'MINUTE', 'MINUTE_2', 'MINUTE_3', 'MINUTE_5', 'MINUTE_10', 'MINUTE_15', 'MINUTE_30', 'HOUR', 'HOUR_2', 'HOUR_3', 'HOUR_4', 'DAY', 'WEEK', 'MONTH'],
          description: 'Time resolution',
        },
        max: {
          type: 'number',
          description: 'Maximum number of data points',
          default: 10,
        },
        from: {
          type: 'string',
          description: 'Start date/time (YYYY-MM-DDTHH:MM:SS)',
        },
        to: {
          type: 'string',
          description: 'End date/time (YYYY-MM-DDTHH:MM:SS)',
        },
      },
      required: ['epic', 'resolution'],
    },
  },
  {
    name: 'ig_get_client_sentiment',
    description: 'Get client sentiment for markets',
    inputSchema: {
      type: 'object',
      properties: {
        marketIds: {
          type: 'array',
          items: {
            type: 'string',
          },
          description: 'List of market IDs',
        },
      },
      required: ['marketIds'],
    },
  },

  // Watchlist Tools
  {
    name: 'ig_get_watchlists',
    description: 'Get all watchlists',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'ig_get_watchlist',
    description: 'Get details of a specific watchlist',
    inputSchema: {
      type: 'object',
      properties: {
        watchlistId: {
          type: 'string',
          description: 'Watchlist ID',
        },
      },
      required: ['watchlistId'],
    },
  },
  {
    name: 'ig_create_watchlist',
    description: 'Create a new watchlist',
    inputSchema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          description: 'Watchlist name',
        },
        epics: {
          type: 'array',
          items: {
            type: 'string',
          },
          description: 'Initial epics to add',
          default: [],
        },
      },
      required: ['name'],
    },
  },
  {
    name: 'ig_add_to_watchlist',
    description: 'Add an epic to a watchlist',
    inputSchema: {
      type: 'object',
      properties: {
        watchlistId: {
          type: 'string',
          description: 'Watchlist ID',
        },
        epic: {
          type: 'string',
          description: 'Epic to add',
        },
      },
      required: ['watchlistId', 'epic'],
    },
  },
];

// Handle tool listing
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: TOOLS,
  };
});

// Handle tool execution
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    // Handle credential updates if provided
    if (args.apiKey || args.identifier || args.password) {
      config.credentials = {
        apiKey: args.apiKey || config.credentials?.apiKey,
        identifier: args.identifier || config.credentials?.identifier,
        password: args.password || config.credentials?.password,
        isDemo: args.isDemo !== undefined ? args.isDemo : config.credentials?.isDemo,
      };
    }

    switch (name) {
      // Account Management
      case 'ig_login':
        const loginResult = await igService.login(args.useEncryption !== false);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                success: true,
                accountId: loginResult.currentAccountId,
                accountType: loginResult.accountType,
                currency: loginResult.currencyIsoCode,
              }, null, 2),
            },
          ],
        };

      case 'ig_logout':
        await igService.logout();
        return {
          content: [
            {
              type: 'text',
              text: 'Successfully logged out',
            },
          ],
        };

      case 'ig_get_accounts':
        const accounts = await igService.getAccounts();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(accounts, null, 2),
            },
          ],
        };

      case 'ig_switch_account':
        const switchResult = await igService.switchAccount(args.accountId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(switchResult, null, 2),
            },
          ],
        };

      case 'ig_get_account_activity':
        const activity = await igService.getAccountActivity(args);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(activity, null, 2),
            },
          ],
        };

      // Position Management
      case 'ig_get_positions':
        const positions = await igService.getPositions();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(positions, null, 2),
            },
          ],
        };

      case 'ig_create_position':
        const positionResult = await igService.createPosition(args);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(positionResult, null, 2),
            },
          ],
        };

      case 'ig_close_position':
        const closeResult = await igService.closePosition(args.dealId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(closeResult, null, 2),
            },
          ],
        };

      case 'ig_close_all_positions':
        const closeAllResult = await igService.closeAllPositions();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(closeAllResult, null, 2),
            },
          ],
        };

      case 'ig_update_position':
        const updateResult = await igService.updatePosition(args.dealId, args);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(updateResult, null, 2),
            },
          ],
        };

      // Working Orders
      case 'ig_get_working_orders':
        const orders = await igService.getWorkingOrders();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(orders, null, 2),
            },
          ],
        };

      case 'ig_create_working_order':
        const orderResult = await igService.createWorkingOrder(args);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(orderResult, null, 2),
            },
          ],
        };

      case 'ig_delete_working_order':
        const deleteResult = await igService.deleteWorkingOrder(args.dealId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(deleteResult, null, 2),
            },
          ],
        };

      // Market Data
      case 'ig_search_markets':
        const searchResults = await igService.searchMarkets(args.searchTerm);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(searchResults, null, 2),
            },
          ],
        };

      case 'ig_get_market_details':
        const marketDetails = await igService.getMarketDetails(args.epics);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(marketDetails, null, 2),
            },
          ],
        };

      case 'ig_get_historical_prices':
        const prices = await igService.getHistoricalPrices(
          args.epic,
          args.resolution,
          {
            max: args.max,
            from: args.from,
            to: args.to,
          }
        );
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(prices, null, 2),
            },
          ],
        };

      case 'ig_get_client_sentiment':
        const sentiment = await igService.getClientSentiment(args.marketIds);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(sentiment, null, 2),
            },
          ],
        };

      // Watchlists
      case 'ig_get_watchlists':
        const watchlists = await igService.getWatchlists();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(watchlists, null, 2),
            },
          ],
        };

      case 'ig_get_watchlist':
        const watchlist = await igService.getWatchlist(args.watchlistId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(watchlist, null, 2),
            },
          ],
        };

      case 'ig_create_watchlist':
        const newWatchlist = await igService.createWatchlist(args.name, args.epics || []);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(newWatchlist, null, 2),
            },
          ],
        };

      case 'ig_add_to_watchlist':
        const addResult = await igService.addToWatchlist(args.watchlistId, args.epic);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(addResult, null, 2),
            },
          ],
        };

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    logger.error(`Tool execution failed for ${name}:`, error);
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${error.message}`,
        },
      ],
      isError: true,
    };
  }
});

// Initialize and start server
async function main() {
  initializeConfig();
  
  const transport = new StdioServerTransport();
  await server.connect(transport);
  
  logger.info('IG Trading MCP Server started');
}

main().catch((error) => {
  logger.error('Failed to start MCP server:', error);
  process.exit(1);
});