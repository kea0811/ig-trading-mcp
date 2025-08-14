# ig-trading-mcp

[![npm version](https://img.shields.io/npm/v/ig-trading-mcp.svg)](https://www.npmjs.com/package/ig-trading-mcp)
[![Downloads](https://img.shields.io/npm/dm/ig-trading-mcp.svg)](https://www.npmjs.com/package/ig-trading-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org)
[![GitHub](https://img.shields.io/badge/GitHub-kea0811%2Fig--trading--mcp-blue)](https://github.com/kea0811/ig-trading-mcp)

A modern Node.js client for IG Trading API with built-in MCP (Model Context Protocol) server for AI integration. Trade forex, indices, commodities and more through IG's REST API, now with AI assistant support.

## ✨ Features

- 🤖 **MCP Server** - 21 tools for AI assistants (Claude, Cursor, etc.)
- 📊 **Complete IG REST API** - Trading, positions, orders, market data
- 🔐 **Enterprise Security** - RSA encryption, rate limiting, audit logging
- 🚀 **Modern JavaScript** - ES modules, async/await, full TypeScript support
- 🛡️ **Battle-tested** - Production-ready with comprehensive error handling

## 🚀 Quick Start

### Install & Run with npx (no installation needed)

```bash
# Run directly with npx
npx ig-trading-mcp serve --api-key YOUR_KEY --identifier YOUR_ID --password YOUR_PWD

# Or install globally
npm install -g ig-trading-mcp
ig-trading-mcp serve
```

### Basic Setup

1. **Initialize configuration:**
```bash
npx ig-trading-mcp init
```

2. **Edit `.env` with your IG credentials:**
```env
IG_API_KEY=your_api_key_here
IG_IDENTIFIER=your_username_here
IG_PASSWORD=your_password_here
IG_DEMO=true
```

3. **Test connection:**
```bash
npx ig-trading-mcp test
```

4. **Start MCP server for AI tools:**
```bash
npx ig-trading-mcp serve
```

## 🎯 Usage Examples

### Command Line Interface

```bash
# Start MCP server with credentials
npx ig-trading-mcp serve \
  --api-key YOUR_API_KEY \
  --identifier YOUR_USERNAME \
  --password YOUR_PASSWORD \
  --demo true

# Test account connection
npx ig-trading-mcp test

# List available tools
npx ig-trading-mcp tools

# Initialize config files
npx ig-trading-mcp init
```

### As a Node.js Library

```javascript
import { IGService } from 'ig-trading-mcp';

const ig = new IGService({
  apiKey: 'YOUR_API_KEY',
  identifier: 'YOUR_USERNAME',
  password: 'YOUR_PASSWORD',
  isDemo: true
});

// Login
await ig.login();

// Get accounts
const accounts = await ig.getAccounts();
console.log('Balance:', accounts.accounts[0].balance);

// Search markets
const markets = await ig.searchMarkets('EUR/USD');

// Create position
const position = await ig.createPosition({
  epic: 'CS.D.EURUSD.CFD.IP',
  direction: 'BUY',
  size: 1,
  orderType: 'MARKET',
  guaranteedStop: false,
  forceOpen: true
});

// Get positions
const positions = await ig.getPositions();

// Close position
await ig.closePosition(position.dealId);

// Logout
await ig.logout();
```

## 🤖 AI Integration (MCP)

### Configure with Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ig-trading": {
      "command": "npx",
      "args": ["ig-trading-mcp", "serve"],
      "env": {
        "IG_API_KEY": "your_api_key",
        "IG_IDENTIFIER": "your_username",
        "IG_PASSWORD": "your_password",
        "IG_DEMO": "true"
      }
    }
  }
}
```

### Configure with Cursor

Add to `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "ig-trading": {
      "command": "npx",
      "args": ["ig-trading-mcp", "serve"],
      "env": {
        "IG_API_KEY": "${IG_API_KEY}",
        "IG_IDENTIFIER": "${IG_IDENTIFIER}",
        "IG_PASSWORD": "${IG_PASSWORD}",
        "IG_DEMO": "true"
      }
    }
  }
}
```

### Available MCP Tools (21)

**Account Management (5)**
- `ig_login` - Authenticate with IG
- `ig_logout` - End session
- `ig_get_accounts` - List all accounts
- `ig_switch_account` - Change active account
- `ig_get_account_activity` - View account history

**Position Management (5)**
- `ig_get_positions` - View open positions
- `ig_create_position` - Open new position
- `ig_update_position` - Modify position
- `ig_close_position` - Close specific position
- `ig_close_all_positions` - Close all positions

**Order Management (3)**
- `ig_get_working_orders` - View pending orders
- `ig_create_working_order` - Place new order
- `ig_delete_working_order` - Cancel order

**Market Data (4)**
- `ig_search_markets` - Search tradeable markets
- `ig_get_market_details` - Get market info
- `ig_get_historical_prices` - Historical data
- `ig_get_client_sentiment` - Market sentiment

**Watchlists (4)**
- `ig_get_watchlists` - View all watchlists
- `ig_get_watchlist` - Get specific watchlist
- `ig_create_watchlist` - Create watchlist
- `ig_add_to_watchlist` - Add market to list

## 🔒 Security Features

- **RSA Encryption** - Password encryption using pidCrypt (IG-compatible)
- **Secure Storage** - Credentials encrypted with AES-256-GCM
- **Rate Limiting** - Automatic throttling (60 req/min)
- **Audit Logging** - Track all operations
- **Session Management** - JWT tokens with auto-refresh
- **Input Validation** - Joi schemas for all inputs

## 📁 Project Structure

```
ig-trading-mcp/
├── bin/
│   └── cli.js              # CLI entry point
├── src/
│   ├── core/               # Core modules
│   │   ├── api-client.js   # HTTP client
│   │   ├── config.js       # Configuration
│   │   └── encryption.cjs  # RSA encryption
│   ├── services/           # Business logic
│   │   ├── ig-service.js   # Main IG API
│   │   └── mcp-service.js  # MCP server
│   ├── security/           # Security layer
│   └── indicators/         # Trading indicators
├── examples/               # Usage examples
├── scripts/                # Utility scripts
└── package.json
```

## 🛠️ API Reference

### Account Methods
```javascript
await ig.login(useEncryption = true)
await ig.logout()
await ig.getAccounts()
await ig.switchAccount(accountId)
await ig.getAccountActivity(options)
```

### Trading Methods
```javascript
await ig.getPositions()
await ig.createPosition(ticket)
await ig.updatePosition(dealId, updates)
await ig.closePosition(dealId)
await ig.closeAllPositions()
```

### Order Methods
```javascript
await ig.getWorkingOrders()
await ig.createWorkingOrder(ticket)
await ig.deleteWorkingOrder(dealId)
```

### Market Data Methods
```javascript
await ig.searchMarkets(searchTerm)
await ig.getMarketDetails(epics)
await ig.getHistoricalPrices(epic, resolution, options)
await ig.getClientSentiment(marketIds)
```

## 📋 Requirements

- Node.js 18.0.0 or higher
- IG Trading Account (demo or live)
- API Key from IG (get from My IG > Settings > API keys)

## 🧪 Testing

```bash
# Test connection
npm test

# Test with credentials
npm run test:account
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 🏗️ Built On

This project is built on top of [gfiocco/node-ig-api](https://github.com/gfiocco/node-ig-api), enhancing it with:
- Modern ES modules and async/await patterns
- MCP (Model Context Protocol) server for AI integration
- Enhanced security with RSA encryption
- CLI interface for easy usage with npx
- Comprehensive error handling and rate limiting

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This software is for educational purposes only. Trading CFDs carries risk and you could lose more than your initial deposit. Use at your own risk. The authors are not responsible for any financial losses incurred through use of this software.

## 🔗 Resources

- [IG REST Trading API Reference](https://labs.ig.com/rest-trading-api-reference)
- [Model Context Protocol](https://modelcontextprotocol.io)
- [Get IG API Key](https://www.ig.com/uk/my-ig/api-keys)

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/kea0811/ig-trading-mcp/issues)
- **Discussions**: [GitHub Discussions](https://github.com/kea0811/ig-trading-mcp/discussions)

---

Made with ❤️ for the trading community