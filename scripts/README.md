# IG Trading API Test Scripts

This folder contains test scripts to verify your IG Trading API connection and display account information.

## 🚀 Quick Start

### 1. Setup Credentials

Create a `.env` file in the project root with your IG credentials:

```env
IG_API_KEY=your_api_key_here
IG_IDENTIFIER=your_username_here
IG_PASSWORD=your_password_here
IG_DEMO=true
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Run Tests

## 📝 Available Scripts

### Simple Account Test
Quick test to display your account information:

```bash
npm run test:account
```

Or directly:
```bash
node scripts/simple-account-test.js
```

**Output includes:**
- Account details (name, type, currency)
- Balance information
- Open positions (if any)
- Recent activity

### Advanced Account Test
Comprehensive test with enhanced formatting and security features:

```bash
node scripts/test-account-info.js
```

**Features:**
- Beautiful colored output with tables
- Detailed account breakdown
- Activity history (30 days)
- Open positions with P&L
- Security mode option

**Command-line options:**
```bash
# Use command-line arguments
node scripts/test-account-info.js --api-key KEY --identifier ID --password PWD

# Use enhanced security mode
node scripts/test-account-info.js --secure

# Use live account (default is demo)
node scripts/test-account-info.js --demo false
```

## 🔒 Security Notes

1. **Never commit your `.env` file** - It's already in `.gitignore`
2. **Use DEMO account for testing** - Set `IG_DEMO=true`
3. **Keep your API key secure** - Don't share it
4. **Use secure mode** for production testing

## 📊 Example Output

```
========================================
      IG Trading Account Test
========================================

Environment: DEMO
API URL: https://demo-api.ig.com

1️⃣  Logging in...
✅ Login successful!
   Account ID: ABC123
   Account Type: CFD
   Currency: USD

2️⃣  Fetching account details...
✅ Found 2 account(s)

----------------------------------------
         ACCOUNT INFORMATION
----------------------------------------

📊 Account 1: CFD Account
   Type: CFD
   Status: ENABLED
   Currency: USD
   Preferred: Yes
   
   💰 Balance Information:
      Total Balance: USD 10000.00
      Available: USD 8500.00
      Deposit: USD 1500.00
      Profit/Loss: USD 250.00

----------------------------------------

3️⃣  Checking open positions...
✅ Found 1 open position(s):

   Position 1: EUR/USD
      Direction: BUY
      Size: 1
      Open Price: 1.0850
      Current Bid/Offer: 1.0865/1.0867
      P&L: USD 15.00

========================================
✅ Test completed successfully!
========================================
```

## 🛠️ Troubleshooting

### Common Issues

1. **"Missing credentials"**
   - Ensure `.env` file exists in project root
   - Check all required fields are filled
   - No quotes needed in `.env` file

2. **"Authentication failed"**
   - Verify API key is active in IG dashboard
   - Check username and password are correct
   - Ensure using correct environment (demo/live)

3. **"Rate limit exceeded"**
   - Wait a few minutes before retrying
   - Reduce frequency of API calls
   - Check if API key has proper permissions

4. **"Could not fetch positions"**
   - Some demo accounts may have restrictions
   - Ensure account has trading permissions
   - Try with a live account (carefully!)

## 📚 Additional Scripts (Coming Soon)

- `test-positions.js` - Test position management
- `test-market-data.js` - Test market data retrieval
- `test-streaming.js` - Test live price streaming
- `test-trading.js` - Test order placement (demo only)

## 💡 Tips

1. **Start with simple test** - Use `simple-account-test.js` first
2. **Use demo account** - Always test with demo before live
3. **Check permissions** - Ensure API key has required permissions
4. **Monitor rate limits** - Don't run tests too frequently
5. **Read the output** - Error messages provide helpful hints

## 📞 Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review IG API documentation at https://labs.ig.com
3. Check your IG account settings and API permissions
4. Create an issue on GitHub with error details