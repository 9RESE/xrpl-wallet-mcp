# Getting Started with XRPL Agent Wallet MCP

**Time to complete**: 5-10 minutes
**Prerequisites**: Node.js 22+, Claude Desktop (or compatible MCP client)
**Level**: Beginner

---

## What You'll Learn

In this tutorial, you'll learn how to:

1. Install and configure the XRPL Agent Wallet MCP server
2. Connect it to Claude Desktop
3. Create your first agent wallet
4. Check wallet balance
5. Sign a test transaction
6. View transaction history

By the end, you'll have a working agent wallet on the XRPL testnet that you can use for development and testing.

---

## Prerequisites

Before you begin, make sure you have:

- **Node.js 22 or later** installed ([download](https://nodejs.org/))
- **Claude Desktop** application installed ([download](https://claude.ai/download))
- Basic familiarity with terminal/command line
- A text editor for configuration files

Verify your Node.js version:

```bash
node --version
# Expected: v22.0.0 or higher
```

---

## Step 1: Install the MCP Server

### Option A: Install from npm (Recommended)

```bash
npm install -g xrpl-agent-wallet-mcp
```

Verify the installation:

```bash
xrpl-wallet-mcp --version
# Expected: 0.1.0
```

### Option B: Install from Source

Clone the repository and build:

```bash
git clone https://github.com/9RESE/xrpl-agent-wallet-mcp.git
cd xrpl-agent-wallet-mcp
npm install
npm run build
```

---

## Step 2: Configure Claude Desktop

Claude Desktop needs to know about the MCP server. Edit your Claude Desktop configuration file.

### Find your configuration file

| Operating System | Configuration Path |
|-----------------|-------------------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

### Add the MCP server configuration

Open the configuration file in your text editor and add the XRPL wallet server:

```json
{
  "mcpServers": {
    "xrpl-wallet": {
      "command": "xrpl-wallet-mcp",
      "args": [],
      "env": {
        "XRPL_NETWORK": "testnet"
      }
    }
  }
}
```

If you installed from source, use the full path:

```json
{
  "mcpServers": {
    "xrpl-wallet": {
      "command": "node",
      "args": ["/path/to/xrpl-agent-wallet-mcp/dist/index.js"],
      "env": {
        "XRPL_NETWORK": "testnet"
      }
    }
  }
}
```

### Restart Claude Desktop

Close and reopen Claude Desktop to load the new configuration.

### Verify the connection

In Claude Desktop, you should see the XRPL wallet tools available. You can ask Claude:

> "What MCP tools do you have available for XRPL?"

**Expected response**: Claude should list the wallet tools including `wallet_create`, `wallet_balance`, `wallet_sign`, and others.

---

## Step 3: Create Your First Wallet

Now let's create a testnet wallet. Ask Claude:

> "Create a new XRPL testnet wallet with a conservative policy for development testing."

Claude will use the `wallet_create` tool with a policy configuration. Here's what happens behind the scenes:

```json
{
  "network": "testnet",
  "policy": {
    "policy_id": "dev-testing-v1",
    "policy_version": "1.0.0",
    "limits": {
      "max_amount_per_tx_drops": "10000000",
      "max_daily_volume_drops": "100000000",
      "max_tx_per_hour": 60,
      "max_tx_per_day": 500
    },
    "destinations": {
      "mode": "open",
      "allow_new_destinations": true,
      "blocklist": []
    },
    "transaction_types": {
      "allowed": ["Payment"],
      "blocked": ["AccountDelete", "SetRegularKey", "SignerListSet"]
    },
    "escalation": {
      "amount_threshold_drops": "5000000",
      "new_destination": 2,
      "account_settings": 3
    }
  },
  "wallet_name": "my-first-wallet"
}
```

**Expected output**:

```
Wallet created successfully!

Address: rN7n3473SaZBCG4dFL83w7a1RXtXtbK2D9
Network: testnet
Policy ID: dev-testing-v1
Wallet ID: wallet-1706438400-xyz789

The wallet has been automatically funded with 1,000 XRP from the testnet faucet.

IMPORTANT: Save your master_key_backup securely - you'll need it for disaster recovery.
```

Note down your wallet address - you'll use it in the following steps.

---

## Step 4: Check Wallet Balance

Let's verify the wallet was created and funded. Ask Claude:

> "What's the balance of my XRPL wallet?"

Or be more specific:

> "Check the balance of wallet rN7n3473SaZBCG4dFL83w7a1RXtXtbK2D9"

**Expected output**:

```
Wallet Balance Report
---------------------
Address: rN7n3473SaZBCG4dFL83w7a1RXtXtbK2D9
Network: testnet

Balance:
  Total: 1,000.000000 XRP
  Reserved: 10.000000 XRP (base reserve)
  Available: 990.000000 XRP

Account Status:
  Sequence: 1
  Regular Key: Configured

Policy Status:
  Daily limit: 100 XRP
  Used today: 0 XRP (0%)
  Transactions this hour: 0/60
```

The balance shows:
- **Total balance**: 1,000 XRP from the testnet faucet
- **Reserved**: 10 XRP locked as the account reserve
- **Available**: What you can actually spend (990 XRP)

---

## Step 5: Sign a Test Transaction

Let's sign a simple payment transaction. For testing, we'll send a small amount to another testnet address.

Ask Claude:

> "Send 5 XRP to rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe on testnet with the context 'Testing my first transaction'"

**What happens**:

1. Claude builds an unsigned Payment transaction
2. The policy engine evaluates the transaction:
   - Amount (5 XRP) is within limits
   - Destination is not blocklisted
   - Transaction type (Payment) is allowed
3. Since 5 XRP equals the tier 1/2 threshold, it gets **Tier 1 (autonomous)** approval
4. The transaction is signed immediately

**Expected output**:

```
Transaction Signed Successfully!
--------------------------------
Status: approved
Tier: 1 (Autonomous)

Transaction Details:
  Type: Payment
  Amount: 5.000000 XRP
  Destination: rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe
  Fee: 0.000012 XRP

Transaction Hash: E08D6E9754025BA2534A78707605E0601F03ACE063687A0CA1BDDACFCD1698C7

Remaining Limits:
  Daily volume: 95 XRP remaining (5/100 used)
  Hourly transactions: 59 remaining

The signed transaction is ready for submission.
Would you like me to submit it to the XRPL testnet?
```

If you want to submit the transaction, reply:

> "Yes, submit the transaction"

**After submission**:

```
Transaction Submitted!
----------------------
Hash: E08D6E9754025BA2534A78707605E0601F03ACE063687A0CA1BDDACFCD1698C7
Status: Validated (tesSUCCESS)
Ledger: 85432100

View on explorer: https://testnet.xrpl.org/transactions/E08D6E9754025BA2534A78707605E0601F03ACE063687A0CA1BDDACFCD1698C7
```

---

## Step 6: View Transaction History

Now let's see our transaction in the history. Ask Claude:

> "Show me the transaction history for my wallet"

**Expected output**:

```
Transaction History
-------------------
Address: rN7n3473SaZBCG4dFL83w7a1RXtXtbK2D9
Network: testnet

Recent Transactions (newest first):

1. Payment (SENT)
   Hash: E08D6E9754025BA2534A78707605E0601F03ACE063687A0CA1BDDACFCD1698C7
   Date: 2026-01-28 14:30:05 UTC
   Amount: -5.000012 XRP (including fee)
   To: rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe
   Status: Success (tesSUCCESS)

2. Payment (RECEIVED)
   Hash: ABC123DEF456...
   Date: 2026-01-28 14:25:00 UTC
   Amount: +1,000.000000 XRP
   From: Testnet Faucet
   Status: Success (tesSUCCESS)

Showing 2 of 2 transactions
```

You can also filter the history:

> "Show me only successful payment transactions from the last 24 hours"

---

## Next Steps

Congratulations! You've successfully:

- Installed the XRPL Agent Wallet MCP server
- Connected it to Claude Desktop
- Created a testnet wallet with policy controls
- Checked your wallet balance
- Signed and submitted a transaction
- Viewed your transaction history

### What to explore next

1. **Learn about policies**: Read [How to Configure Policies](../how-to/configure-policies.md) to understand the tiered approval system
2. **Try larger transactions**: Send more than 5 XRP to see Tier 2 (delayed approval) in action
3. **Explore escrows**: The wallet supports EscrowCreate, EscrowFinish, and EscrowCancel
4. **Set up multi-signature**: Configure human co-signers for high-value operations
5. **Review the API**: See the full [API Reference](../reference/api.md) for all available tools

### Moving to production

Before using on mainnet:

1. Review the [Security Model](../explanation/security-model.md)
2. Configure appropriate policies for your use case
3. Set up backup and recovery procedures
4. Enable webhook notifications for Tier 2/3 transactions

---

## Troubleshooting Common Issues

### "MCP server not found" error

**Symptom**: Claude doesn't recognize the XRPL wallet tools.

**Solutions**:
1. Verify the configuration file path is correct for your OS
2. Check that the command path is correct (try running it in terminal)
3. Restart Claude Desktop after configuration changes
4. Check the Claude Desktop logs for connection errors

### "Network error" when creating wallet

**Symptom**: Wallet creation fails with a network error.

**Solutions**:
1. Check your internet connection
2. Try again - testnet nodes can occasionally be unavailable
3. Verify `XRPL_NETWORK` is set to `testnet` (not `mainnet`)

### "Rate limit exceeded" error

**Symptom**: Operations fail with rate limit errors.

**Solutions**:
1. Wait a few minutes before retrying
2. The testnet faucet has rate limits - try again later
3. For signing operations, you're limited to 5 per 5 minutes per wallet

### "Policy violation" for allowed transactions

**Symptom**: A transaction that should be allowed is rejected.

**Solutions**:
1. Check your daily limits haven't been exceeded
2. Verify the destination isn't accidentally blocklisted
3. Ensure the transaction type is in the `allowed` list
4. Review the policy with `wallet_balance` (includes policy status)

### Transaction signed but not appearing on ledger

**Symptom**: Transaction was signed but doesn't appear in explorers.

**Solutions**:
1. Make sure you also submitted the transaction (signing doesn't submit)
2. Wait a few seconds for ledger validation
3. Check the transaction hash on the testnet explorer
4. Review the submission response for any errors

---

## Getting Help

- **GitHub Issues**: [Report bugs or request features](https://github.com/9RESE/xrpl-agent-wallet-mcp/issues)
- **Documentation**: Browse the [full documentation](../../index.md)
- **XRPL Resources**: [XRPL.org](https://xrpl.org/docs.html) for general XRPL documentation

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Documentation Manager | Initial tutorial |

---

*XRPL Agent Wallet MCP - Getting Started Tutorial*
