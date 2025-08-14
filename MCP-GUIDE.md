# MCP Server Integration Guide

## 🤖 What is MCP?

Model Context Protocol (MCP) is a standard for connecting AI assistants to external tools and data sources. This IG Trading API includes a full MCP server implementation with 25+ trading tools.

## 🚀 Quick Start

### Option 1: Direct Command
```bash
npm run mcp
```

### Option 2: Using Claude Desktop
Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "ig-trading": {
      "command": "node",
      "args": ["/path/to/node-ig-api/src/services/mcp-service.js"],
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

### Option 3: Using Environment Variables
```bash
export IG_API_KEY=your_api_key
export IG_IDENTIFIER=your_username
export IG_PASSWORD=your_password
export IG_DEMO=true
npm run mcp
```

## 📋 Available MCP Tools (21 Tools)

### Account Management (5)
- `ig_login` - Authenticate with IG
- `ig_logout` - End session
- `ig_get_accounts` - List all accounts
- `ig_switch_account` - Change active account
- `ig_get_account_activity` - View account history

### Position Management (5)
- `ig_get_positions` - View open positions
- `ig_create_position` - Open new position
- `ig_update_position` - Modify position
- `ig_close_position` - Close specific position
- `ig_close_all_positions` - Close all positions

### Order Management (3)
- `ig_get_working_orders` - View pending orders
- `ig_create_working_order` - Place new order
- `ig_delete_working_order` - Cancel order

### Market Data (4)
- `ig_search_markets` - Search tradeable markets
- `ig_get_market_details` - Get market info
- `ig_get_historical_prices` - Historical data
- `ig_get_client_sentiment` - Market sentiment

### Watchlists (4)
- `ig_get_watchlists` - View all watchlists
- `ig_get_watchlist` - Get specific watchlist
- `ig_create_watchlist` - Create watchlist
- `ig_add_to_watchlist` - Add market to list

## 💬 Example Conversations with AI

### Example 1: Check Account
```
User: "Check my IG trading account balance"
AI: I'll check your IG trading account for you.
    [Uses ig_login]
    [Uses ig_get_accounts]
    Your account Z5U9VN has a balance of SGD 199,615.22
```

### Example 2: Market Analysis
```
User: "What's the current EUR/USD price?"
AI: Let me check the EUR/USD market for you.
    [Uses ig_search_markets with "EUR/USD"]
    [Uses ig_get_market_details]
    EUR/USD is currently at:
    - Bid: 1.0925
    - Ask: 1.0927
    - Spread: 2 pips
```

### Example 3: Position Management
```
User: "Show me my open positions"
AI: I'll retrieve your open positions.
    [Uses ig_get_positions]
    You have 14 open positions:
    - EUR/USD: BUY 1 unit
    - GBP/USD: SELL 2 units
    ...
```

### Example 4: Trading Operation
```
User: "Close all my EUR/USD positions"
AI: I'll close your EUR/USD positions.
    [Uses ig_get_positions]
    [Uses ig_close_position for each EUR/USD position]
    Successfully closed 2 EUR/USD positions.
```

## 🔧 Tool Parameters

### Creating a Position
```javascript
{
  "tool": "ig_create_position",
  "parameters": {
    "epic": "CS.D.EURUSD.CFD.IP",
    "direction": "BUY",
    "size": 1,
    "orderType": "MARKET",
    "guaranteedStop": false,
    "forceOpen": true,
    "currencyCode": "USD"
  }
}
```

### Setting Stop Loss
```javascript
{
  "tool": "ig_update_position",
  "parameters": {
    "dealId": "DIAAAAA123456",
    "stopLevel": 1.0900,
    "limitLevel": 1.1000
  }
}
```

## 🔒 Security Notes

1. **Credentials**: Never share your API credentials
2. **Demo First**: Always test with demo account
3. **Rate Limits**: MCP respects IG's 60 req/min limit
4. **Encryption**: Passwords are RSA encrypted
5. **Sessions**: Auto-logout after 12 hours

## 🐛 Troubleshooting

### MCP Server Won't Start
```bash
# Check credentials
echo $IG_API_KEY
echo $IG_IDENTIFIER

# Test connection
npm run test:account

# Run with debug
LOG_LEVEL=debug npm run mcp
```

### Tool Errors
- `No active session` - Need to call `ig_login` first
- `Rate limit exceeded` - Wait 1 minute
- `Invalid parameters` - Check parameter types
- `Market closed` - Market not tradeable now

## 📚 Advanced Usage

### Custom Tool Chains
AI assistants can chain tools for complex operations:
1. Login → Get Positions → Calculate P&L → Close Losers
2. Search Market → Get Details → Check Sentiment → Place Order
3. Get Watchlist → Get Prices → Set Alerts

### Note on Streaming
Streaming functionality has been removed from MCP tools as it requires persistent connections that don't fit well with the request/response model of MCP. For real-time data, use the streaming service directly in your application code.

## 🚦 Status Codes

- ✅ **Success**: Operation completed
- ⚠️ **Warning**: Operation completed with warnings
- ❌ **Error**: Operation failed
- 🔄 **Pending**: Operation in progress
- 🔒 **Auth Required**: Need to login first

## 📈 Best Practices

1. Always login before other operations
2. Check market status before trading
3. Use stop losses on all positions
4. Monitor rate limits
5. Logout when done
6. Use demo for testing

## 🔗 Resources

- [MCP Documentation](https://modelcontextprotocol.io)
- [IG API Reference](https://labs.ig.com/rest-trading-api-reference)
- [Claude Desktop Setup](https://claude.ai/desktop)