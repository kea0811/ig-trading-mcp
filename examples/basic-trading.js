#!/usr/bin/env node

/**
 * Basic Trading Example
 * Shows how to use the IG Trading API
 */

import dotenv from 'dotenv';
import { IGService } from '../src/services/ig-service.js';
import { config } from '../src/core/config.js';

dotenv.config();

async function main() {
  // Initialize with credentials
  config.credentials = {
    apiKey: process.env.IG_API_KEY,
    identifier: process.env.IG_IDENTIFIER,
    password: process.env.IG_PASSWORD,
    isDemo: process.env.IG_DEMO === 'true'
  };

  const ig = new IGService();

  try {
    // 1. Login
    console.log('Logging in...');
    const session = await ig.login();
    console.log(`✓ Logged in as ${session.currentAccountId}`);

    // 2. Get account info
    const accounts = await ig.getAccounts();
    console.log(`\nYou have ${accounts.accounts.length} account(s):`);
    accounts.accounts.forEach(acc => {
      console.log(`  - ${acc.accountId}: ${acc.currency} ${acc.balance.balance}`);
    });

    // 3. Get positions
    const positions = await ig.getPositions();
    console.log(`\nOpen positions: ${positions.positions.length}`);

    // 4. Search for a market
    const markets = await ig.searchMarkets('EUR/USD');
    console.log(`\nFound ${markets.markets.length} markets for EUR/USD`);

    // 5. Get market details
    if (markets.markets.length > 0) {
      const epic = markets.markets[0].epic;
      const details = await ig.getMarketDetails(epic);
      const market = details.marketDetails[0];
      console.log(`\nMarket: ${market.instrument.name}`);
      console.log(`  Current bid: ${market.snapshot.bid}`);
      console.log(`  Current offer: ${market.snapshot.offer}`);
    }

    // 6. Logout
    await ig.logout();
    console.log('\n✓ Logged out successfully');

  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

main();