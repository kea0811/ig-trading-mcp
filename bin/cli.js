#!/usr/bin/env node

/**
 * IG Trading MCP CLI
 * Can be run with: npx ig-trading-mcp
 */

import { program } from 'commander';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import dotenv from 'dotenv';
import chalk from 'chalk';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env if it exists
dotenv.config();

// Package info
const packageJson = JSON.parse(
  fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8')
);

program
  .name('ig-trading-mcp')
  .description('IG Trading API with MCP server for AI integration')
  .version(packageJson.version);

// MCP Server command
program
  .command('serve')
  .description('Start the MCP server for AI tool integration')
  .option('--api-key <key>', 'IG API Key')
  .option('--identifier <id>', 'IG Account Identifier') 
  .option('--password <pwd>', 'IG Account Password')
  .option('--demo <boolean>', 'Use demo account', 'true')
  .action((options) => {
    console.log(chalk.cyan('🚀 Starting IG Trading MCP Server...\n'));
    
    // Merge CLI options with environment variables
    const env = {
      ...process.env,
      IG_API_KEY: options.apiKey || process.env.IG_API_KEY,
      IG_IDENTIFIER: options.identifier || process.env.IG_IDENTIFIER,
      IG_PASSWORD: options.password || process.env.IG_PASSWORD,
      IG_DEMO: options.demo || process.env.IG_DEMO || 'true'
    };
    
    // Check for required credentials
    if (!env.IG_API_KEY || !env.IG_IDENTIFIER || !env.IG_PASSWORD) {
      console.log(chalk.yellow('⚠️  Missing credentials. Some tools may not work.\n'));
      console.log('Provide credentials via:');
      console.log('  1. Command line: --api-key XXX --identifier XXX --password XXX');
      console.log('  2. Environment variables: IG_API_KEY, IG_IDENTIFIER, IG_PASSWORD');
      console.log('  3. .env file in current directory\n');
    }
    
    // Start MCP server
    const mcpPath = path.join(__dirname, '../src/services/mcp-service.js');
    const mcp = spawn('node', [mcpPath], {
      env,
      stdio: 'inherit'
    });
    
    mcp.on('error', (err) => {
      console.error(chalk.red('Failed to start MCP server:'), err);
      process.exit(1);
    });
    
    mcp.on('exit', (code) => {
      if (code !== 0) {
        console.error(chalk.red(`MCP server exited with code ${code}`));
        process.exit(code);
      }
    });
  });

// Test command
program
  .command('test')
  .description('Test connection to IG Trading API')
  .option('--api-key <key>', 'IG API Key')
  .option('--identifier <id>', 'IG Account Identifier')
  .option('--password <pwd>', 'IG Account Password')
  .option('--demo <boolean>', 'Use demo account', 'true')
  .action(async (options) => {
    const env = {
      ...process.env,
      IG_API_KEY: options.apiKey || process.env.IG_API_KEY,
      IG_IDENTIFIER: options.identifier || process.env.IG_IDENTIFIER,
      IG_PASSWORD: options.password || process.env.IG_PASSWORD,
      IG_DEMO: options.demo || process.env.IG_DEMO || 'true'
    };
    
    if (!env.IG_API_KEY || !env.IG_IDENTIFIER || !env.IG_PASSWORD) {
      console.error(chalk.red('❌ Missing required credentials'));
      console.log('\nUsage:');
      console.log('  npx ig-trading-mcp test --api-key XXX --identifier XXX --password XXX');
      process.exit(1);
    }
    
    console.log(chalk.cyan('🧪 Testing IG Trading API connection...\n'));
    
    // Run test script
    const testPath = path.join(__dirname, '../scripts/test-account.js');
    const test = spawn('node', [testPath], {
      env,
      stdio: 'inherit'
    });
    
    test.on('exit', (code) => {
      process.exit(code);
    });
  });

// Init command - creates config files
program
  .command('init')
  .description('Initialize configuration files')
  .action(() => {
    console.log(chalk.cyan('📁 Initializing IG Trading MCP configuration...\n'));
    
    // Create .env.example
    const envExample = `# IG Trading API Credentials
IG_API_KEY=your_api_key_here
IG_IDENTIFIER=your_username_here
IG_PASSWORD=your_password_here
IG_DEMO=true
LOG_LEVEL=info`;
    
    // Create mcp.json for Claude/Cursor
    const mcpConfig = {
      mcpServers: {
        "ig-trading": {
          command: "npx",
          args: ["ig-trading-mcp", "serve"],
          env: {
            IG_API_KEY: "${IG_API_KEY}",
            IG_IDENTIFIER: "${IG_IDENTIFIER}",
            IG_PASSWORD: "${IG_PASSWORD}",
            IG_DEMO: "${IG_DEMO}"
          }
        }
      }
    };
    
    // Write files
    if (!fs.existsSync('.env')) {
      fs.writeFileSync('.env', envExample);
      console.log(chalk.green('✓ Created .env file'));
    } else {
      console.log(chalk.yellow('⚠ .env already exists'));
    }
    
    fs.writeFileSync('mcp.json', JSON.stringify(mcpConfig, null, 2));
    console.log(chalk.green('✓ Created mcp.json for AI tools'));
    
    console.log(chalk.green('\n✅ Configuration files created!'));
    console.log('\nNext steps:');
    console.log('  1. Edit .env with your IG credentials');
    console.log('  2. Test connection: npx ig-trading-mcp test');
    console.log('  3. Start MCP server: npx ig-trading-mcp serve');
  });

// List tools command
program
  .command('tools')
  .description('List all available MCP tools')
  .action(() => {
    const tools = [
      { category: 'Account Management', count: 5 },
      { category: 'Position Management', count: 5 },
      { category: 'Order Management', count: 3 },
      { category: 'Market Data', count: 4 },
      { category: 'Watchlists', count: 4 }
    ];
    
    console.log(chalk.cyan('\n📋 Available MCP Tools (21 total)\n'));
    
    tools.forEach(({ category, count }) => {
      console.log(chalk.bold(`${category} (${count})`));
    });
    
    console.log('\nRun with --verbose for detailed tool descriptions');
  });

// Default action - show help
program
  .action(() => {
    console.log(chalk.cyan(`
╔═══════════════════════════════════════╗
║      IG Trading MCP Server v${packageJson.version}      ║
╚═══════════════════════════════════════╝
`));
    
    console.log('Quick Start:\n');
    console.log('  1. Initialize config:  npx ig-trading-mcp init');
    console.log('  2. Test connection:    npx ig-trading-mcp test');
    console.log('  3. Start MCP server:   npx ig-trading-mcp serve\n');
    
    console.log('With credentials:\n');
    console.log('  npx ig-trading-mcp serve --api-key XXX --identifier XXX --password XXX\n');
    
    console.log('For more options: npx ig-trading-mcp --help');
  });

// Parse arguments
program.parse(process.argv);

// Show default help if no command provided
if (process.argv.length === 2) {
  program.action()();
}