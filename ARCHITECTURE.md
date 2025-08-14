# Architecture & Folder Structure

## 📁 Project Structure

```
node-ig-api/
├── src/                         # Source code
│   ├── core/                   # Core modules
│   │   ├── api-client.js       # HTTP client with retry & throttling
│   │   ├── config.js           # Configuration management
│   │   └── encryption.cjs      # pidCrypt RSA encryption (IG-specific)
│   │
│   ├── services/               # Business logic services
│   │   ├── ig-service.js       # Main IG Trading API service
│   │   ├── streaming-service.js # Lightstreamer real-time data
│   │   └── mcp-service.js      # MCP server for AI integration
│   │
│   ├── indicators/             # Trading indicators
│   │   └── supertrend.js       # Supertrend indicator calculation
│   │
│   ├── security/               # Security modules
│   │   ├── index.js            # Security exports
│   │   ├── audit-logger.js     # Audit trail logging
│   │   ├── credential-manager.js # Secure credential storage
│   │   ├── rate-limiter.js     # API rate limiting
│   │   ├── session-manager.js  # JWT session management
│   │   └── validator.js        # Input validation & sanitization
│   │
│   └── index.js                # Main entry point
│
├── examples/                    # Example scripts
│   ├── basic-trading.js        # Basic trading operations
│   └── streaming-example.js    # Real-time streaming example
│
├── scripts/                     # Utility scripts
│   ├── setup.js                # Interactive setup wizard
│   └── test-account.js         # Account connection test
│
├── tests/                       # Test files
│   ├── unit/                   # Unit tests (TBD)
│   └── integration/            # Integration tests (TBD)
│
├── config/                      # Configuration files
├── .env                        # Environment variables (git-ignored)
├── .env.example                # Example environment file
├── package.json                # Dependencies & scripts
├── README.md                   # Main documentation
└── LICENSE                     # License file
```

## 🏗️ Architecture Overview

### Core Layer (`src/core/`)
- **api-client.js**: Low-level HTTP client with:
  - Automatic retry logic (3 attempts)
  - Rate limiting (60 requests/minute)
  - Request/response interceptors
  - Error handling with custom `IGApiError`

- **config.js**: Centralized configuration:
  - Credential management
  - Environment detection (demo/live)
  - Session token storage
  - Winston logger setup

- **encryption.cjs**: IG-specific RSA encryption:
  - Uses pidCrypt library (required by IG)
  - CommonJS module for compatibility
  - Handles password encryption for login

### Service Layer (`src/services/`)
- **ig-service.js**: Main trading service:
  - Account management (login, logout, switch)
  - Position operations (create, update, close)
  - Order management (working orders)
  - Market data queries
  - Watchlist management

- **streaming-service.js**: Real-time data:
  - Lightstreamer client wrapper
  - Price streaming subscriptions
  - Order/position updates

- **mcp-service.js**: AI Integration:
  - Model Context Protocol server
  - 25+ tools for AI assistants
  - Async tool execution

### Security Layer (`src/security/`)
- Multi-layered security approach:
  - Credential encryption (AES-256-GCM)
  - Rate limiting (per user/IP)
  - Input validation (Joi schemas)
  - Audit logging (tamper-proof)
  - Session management (JWT tokens)

## 🔄 Data Flow

```
User Request
    ↓
[Input Validation]
    ↓
[Rate Limiting]
    ↓
[IG Service Layer]
    ↓
[API Client]
    ↓
[Encryption if needed]
    ↓
[HTTP Request to IG]
    ↓
[Response Processing]
    ↓
[Audit Logging]
    ↓
User Response
```

## 🚀 Usage Patterns

### Basic Usage
```javascript
import { IGService } from './src/services/ig-service.js';
import { config } from './src/core/config.js';

// Initialize
config.credentials = { /* ... */ };
const ig = new IGService();

// Use
await ig.login();
const positions = await ig.getPositions();
await ig.logout();
```

### Streaming Usage
```javascript
import { StreamingClient } from './src/services/streaming-service.js';

const streaming = new StreamingClient(session);
await streaming.connect();
await streaming.subscribeToPrice('CS.D.EURUSD.CFD.IP');
```

### MCP Server
```bash
npm run mcp  # Starts MCP server for AI tools
```

## 🔐 Security Best Practices

1. **Never commit credentials** - Use .env files
2. **Always use encryption** - Passwords are RSA encrypted
3. **Rate limiting enforced** - 60 requests/minute
4. **Input validation** - All inputs sanitized
5. **Audit trail** - All operations logged
6. **Session expiry** - Tokens expire after 12 hours

## 📦 Module System

- **ES Modules** (`.js`): Main codebase uses modern imports
- **CommonJS** (`.cjs`): Only for pidCrypt compatibility
- **No mixed patterns**: Clear separation of module types

## 🧪 Testing Strategy

```bash
npm test              # Run all tests
npm run test:account  # Test account connection
```

## 🎯 Design Principles

1. **Separation of Concerns**: Clear layer boundaries
2. **Single Responsibility**: Each module has one purpose
3. **DRY**: Shared code in core modules
4. **Security First**: Multiple security layers
5. **Modern JavaScript**: ES6+, async/await
6. **Error Handling**: Consistent error patterns
7. **Logging**: Comprehensive audit trail