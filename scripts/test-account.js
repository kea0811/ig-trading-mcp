#!/usr/bin/env node

/**
 * Test account information retrieval
 */

import dotenv from 'dotenv';
import { igService } from '../src/services/ig-service.js';
import { config } from '../src/core/config.js';
import chalk from 'chalk';
import Table from 'cli-table3';

dotenv.config();

// Initialize config with credentials
config.credentials = {
  apiKey: process.env.IG_API_KEY,
  identifier: process.env.IG_IDENTIFIER,
  password: process.env.IG_PASSWORD,
  isDemo: process.env.IG_DEMO === 'true'
};

async function testAccount() {
  console.log(chalk.cyan('\n📊 IG Account Test\n'));
  
  try {
    // Login
    console.log(chalk.yellow('🔐 Logging in...'));
    const loginResult = await igService.login(true);
    console.log(chalk.green('✅ Login successful!\n'));
    
    // Display account info
    const accountTable = new Table({
      head: [chalk.cyan('Property'), chalk.cyan('Value')],
      colWidths: [20, 40]
    });
    
    accountTable.push(
      ['Account ID', loginResult.currentAccountId],
      ['Account Type', loginResult.accountType],
      ['Currency', loginResult.currencyIsoCode],
      ['Timezone', `UTC+${loginResult.timezoneOffset}`]
    );
    
    console.log(chalk.bold('Account Information:'));
    console.log(accountTable.toString());
    
    // Get detailed account info
    const accounts = await igService.getAccounts();
    
    console.log(chalk.bold('\nAccount Details:'));
    const detailsTable = new Table({
      head: [
        chalk.cyan('Account'),
        chalk.cyan('Type'),
        chalk.cyan('Balance'),
        chalk.cyan('Available'),
        chalk.cyan('P&L'),
        chalk.cyan('Margin')
      ]
    });
    
    accounts.accounts.forEach(account => {
      detailsTable.push([
        account.accountId,
        account.accountType,
        `${account.currency} ${account.balance.balance.toFixed(2)}`,
        `${account.currency} ${account.balance.available.toFixed(2)}`,
        `${account.currency} ${account.balance.profitLoss.toFixed(2)}`,
        `${account.currency} ${account.balance.deposit.toFixed(2)}`
      ]);
    });
    
    console.log(detailsTable.toString());
    
    // Get positions
    const positions = await igService.getPositions();
    
    if (positions.positions.length > 0) {
      console.log(chalk.bold(`\n📈 Open Positions (${positions.positions.length}):`));
      
      const positionsTable = new Table({
        head: [
          chalk.cyan('Market'),
          chalk.cyan('Direction'),
          chalk.cyan('Size'),
          chalk.cyan('Open Price'),
          chalk.cyan('Current'),
          chalk.cyan('P&L')
        ]
      });
      
      positions.positions.forEach(pos => {
        positionsTable.push([
          pos.market.instrumentName,
          pos.position.direction === 'BUY' ? chalk.green('BUY') : chalk.red('SELL'),
          pos.position.size,
          pos.position.openLevel || 'N/A',
          pos.market.bid || 'N/A',
          pos.position.profit !== undefined ? 
            (pos.position.profit >= 0 ? 
              chalk.green(`+${pos.position.profit}`) : 
              chalk.red(pos.position.profit)) : 
            'N/A'
        ]);
      });
      
      console.log(positionsTable.toString());
    } else {
      console.log(chalk.yellow('\n📉 No open positions'));
    }
    
    // Logout
    await igService.logout();
    console.log(chalk.green('\n✅ Test completed successfully!'));
    
  } catch (error) {
    console.error(chalk.red('\n❌ Test failed:'));
    console.error(chalk.red(error.message));
    if (error.code) {
      console.error(chalk.red(`Error code: ${error.code}`));
    }
    process.exit(1);
  }
}

// Run the test
testAccount();