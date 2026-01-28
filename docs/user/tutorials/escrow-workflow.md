# End-to-End Escrow Workflow Tutorial

**Time to complete**: 15-20 minutes
**Prerequisites**: Completed [Getting Started](./getting-started.md) tutorial
**Level**: Intermediate

---

## What You'll Build

In this tutorial, you'll implement a complete escrow workflow using two MCP servers working together:

- **xrpl-escrow-mcp**: Builds escrow transactions and generates cryptographic conditions
- **xrpl-wallet-mcp**: Securely signs and submits transactions with policy controls

By the end, you'll have:

1. Created an agent wallet with escrow-friendly policies
2. Generated a cryptographic condition/fulfillment pair
3. Created, signed, and submitted an EscrowCreate transaction
4. Monitored the escrow on the ledger
5. Finished the escrow by providing the fulfillment

This workflow demonstrates trustless AI agent commerce, where an AI agent can autonomously manage escrow-based payments within policy boundaries.

---

## Prerequisites

Before starting this tutorial, ensure you have:

- Completed the [Getting Started](./getting-started.md) tutorial
- Node.js 22 or later installed
- Claude Desktop (or compatible MCP client) configured
- Basic understanding of XRPL escrows ([XRPL Escrow Documentation](https://xrpl.org/escrow.html))

---

## Architecture Overview

```
                          +-------------------+
                          |   AI Agent        |
                          | (Claude Desktop)  |
                          +--------+----------+
                                   |
                    +--------------+--------------+
                    |                             |
           +--------v--------+          +---------v--------+
           | xrpl-escrow-mcp |          | xrpl-wallet-mcp  |
           | (Transaction    |          | (Signing &       |
           |  Builder)       |          |  Security)       |
           +--------+--------+          +---------+--------+
                    |                             |
                    +-------------+---------------+
                                  |
                          +-------v-------+
                          |  XRPL Testnet |
                          +---------------+
```

**xrpl-escrow-mcp** handles:
- Generating crypto-conditions (preimage/hash pairs)
- Building EscrowCreate, EscrowFinish, and EscrowCancel transactions
- Computing escrow IDs and sequences

**xrpl-wallet-mcp** handles:
- Secure key storage (AES-256-GCM encrypted)
- Policy evaluation (tiered approval)
- Transaction signing
- Network submission

---

## Step 1: Set Up Both MCP Servers

### 1.1 Configure Claude Desktop

Edit your Claude Desktop configuration file to include both MCP servers.

**Configuration file locations:**

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

Add the following configuration:

```json
{
  "mcpServers": {
    "xrpl-escrow": {
      "command": "npx",
      "args": ["-y", "xrpl-escrow-mcp"],
      "env": {
        "XRPL_NETWORK": "testnet"
      }
    },
    "xrpl-wallet": {
      "command": "npx",
      "args": ["-y", "xrpl-agent-wallet-mcp"],
      "env": {
        "XRPL_NETWORK": "testnet",
        "XRPL_WALLET_PASSWORD": "your-secure-password-here"
      }
    }
  }
}
```

**Security Note**: In production, use environment variable references (`${KEYSTORE_PASSWORD}`) instead of plaintext passwords.

### 1.2 Restart Claude Desktop

Close and reopen Claude Desktop to load the new configuration.

### 1.3 Verify Both Servers Are Connected

Ask Claude:

> "What MCP tools do you have available for XRPL escrows and wallets?"

**Expected response**: Claude should list tools from both servers, including:
- From xrpl-escrow: `escrow_create`, `escrow_finish`, `escrow_cancel`, `generate_condition`
- From xrpl-wallet: `wallet_create`, `wallet_sign`, `wallet_balance`, `tx_submit`

---

## Step 2: Create Agent Wallet

Create a wallet configured for escrow operations. The policy allows EscrowCreate, EscrowFinish, and EscrowCancel transaction types.

Ask Claude:

> "Create a new XRPL testnet wallet for my escrow agent. Configure it with a policy that allows escrow transactions (EscrowCreate, EscrowFinish, EscrowCancel) and standard payments, with a maximum of 100 XRP per transaction and 500 XRP daily limit."

Claude will use the `wallet_create` tool with an escrow-appropriate policy:

```json
{
  "network": "testnet",
  "policy": {
    "policy_id": "escrow-agent-v1",
    "policy_version": "1.0.0",
    "limits": {
      "max_amount_per_tx_drops": "100000000",
      "max_daily_volume_drops": "500000000",
      "max_tx_per_hour": 30,
      "max_tx_per_day": 100
    },
    "destinations": {
      "mode": "open",
      "allow_new_destinations": true,
      "blocklist": []
    },
    "transaction_types": {
      "allowed": ["Payment", "EscrowCreate", "EscrowFinish", "EscrowCancel"],
      "blocked": ["AccountDelete", "SetRegularKey", "SignerListSet"]
    },
    "escalation": {
      "amount_threshold_drops": "50000000",
      "new_destination": 2,
      "account_settings": 3
    }
  },
  "wallet_name": "escrow-agent"
}
```

**Expected output**:

```
Wallet created successfully!

Address: rEscrowAgent123456789ABCDEF...
Network: testnet
Policy ID: escrow-agent-v1
Wallet ID: wallet-1706438400-escrow

The wallet has been funded with 1,000 XRP from the testnet faucet.

IMPORTANT: Save the master_key_backup securely for disaster recovery.
```

**Record your wallet address** - you'll use it throughout this tutorial.

---

## Step 3: Generate Condition and Fulfillment

XRPL escrows can include cryptographic conditions that must be fulfilled to release the escrowed funds. We'll generate a PREIMAGE-SHA-256 condition.

Ask Claude:

> "Generate a cryptographic condition and fulfillment pair for my escrow. Use the PREIMAGE-SHA-256 algorithm."

Claude will use the `generate_condition` tool from xrpl-escrow-mcp:

**Expected output**:

```
Condition/Fulfillment Generated
-------------------------------
Algorithm: PREIMAGE-SHA-256

Condition (hex): A0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100
Condition (base64): oCWAIOOwxEKY/BwUmvv0yJlvuSQnrkHkZJuTTKSVmRt4UrhVgQEA

Fulfillment (hex): A0058020...
Fulfillment (base64): oAWAI...

IMPORTANT SECURITY NOTICE:
- The CONDITION is safe to include in transactions (it's a hash)
- The FULFILLMENT is SECRET - store it securely!
- Anyone with the fulfillment can release the escrow
- Never share the fulfillment until you're ready to release funds
```

**Save both values**:
- **Condition**: Goes into the EscrowCreate transaction (public)
- **Fulfillment**: Needed for EscrowFinish (keep secret until release)

---

## Step 4: Create the Escrow Transaction

Now we'll build the EscrowCreate transaction. This locks XRP until either:
- The condition is fulfilled AND the finish time has passed, OR
- The cancel time passes (allowing recovery)

### 4.1 Build the Escrow Transaction

Ask Claude:

> "Create an escrow transaction from my wallet rEscrowAgent123... to recipient rRecipient456... for 25 XRP. Use the condition we generated. Set the finish time to 5 minutes from now and cancel time to 24 hours from now."

Claude will use the `escrow_create` tool from xrpl-escrow-mcp:

**Expected output**:

```
EscrowCreate Transaction Built
------------------------------
Transaction Type: EscrowCreate
Sender: rEscrowAgent123...
Recipient: rRecipient456...
Amount: 25,000,000 drops (25 XRP)

Timing:
  FinishAfter: 2026-01-28T15:05:00Z (5 minutes from now)
  CancelAfter: 2026-01-29T15:00:00Z (24 hours from now)

Condition: A0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100

Unsigned Transaction Blob:
120001228000000024000000016140000000017D784068400000000000000C8114...

This transaction is UNSIGNED. Use wallet_sign to sign it before submission.
```

### 4.2 Understanding the Transaction

| Field | Value | Meaning |
|-------|-------|---------|
| **TransactionType** | EscrowCreate | Creates a new escrow |
| **Amount** | 25000000 | 25 XRP in drops |
| **Destination** | rRecipient... | Who can claim the funds |
| **FinishAfter** | (timestamp) | Earliest time escrow can be finished |
| **CancelAfter** | (timestamp) | After this time, sender can cancel |
| **Condition** | (hex blob) | Crypto-condition that must be fulfilled |

---

## Step 5: Sign and Submit the Escrow

### 5.1 Check Policy Before Signing

First, let's verify the transaction will be approved by the wallet's policy.

Ask Claude:

> "Check if my escrow transaction will be approved by the wallet policy before signing."

Claude will use the `wallet_policy_check` tool:

**Expected output**:

```
Policy Check Result
-------------------
Would Approve: YES
Tier: 1 (Autonomous)

Evaluation:
  Transaction Type: EscrowCreate - ALLOWED
  Amount: 25 XRP - Within autonomous limit (50 XRP threshold)
  Destination: rRecipient... - New destination, allowed
  Daily Limit: 475 XRP remaining (5% used)

The transaction meets all policy requirements for autonomous signing.
```

### 5.2 Sign the Transaction

Now sign the transaction with the wallet's secure key.

Ask Claude:

> "Sign the escrow create transaction with my agent wallet."

Claude will use the `wallet_sign` tool:

**Expected output**:

```
Transaction Signed Successfully!
--------------------------------
Status: approved
Tier: 1 (Autonomous)

Transaction Details:
  Type: EscrowCreate
  Amount: 25.000000 XRP
  Destination: rRecipient456...
  Fee: 0.000012 XRP

Transaction Hash: A1B2C3D4E5F6...
Signed Blob: 1200012280000000240000000161400000000...

Remaining Limits:
  Daily volume: 475 XRP remaining (25/500 used)
  Hourly transactions: 29 remaining

Ready for submission to the XRPL network.
```

### 5.3 Submit to the Network

Submit the signed transaction to the XRPL testnet.

Ask Claude:

> "Submit the signed escrow transaction to the XRPL testnet and wait for validation."

Claude will use the `tx_submit` tool:

**Expected output**:

```
Transaction Submitted!
----------------------
Status: validated
Transaction Hash: A1B2C3D4E5F6...
Result: tesSUCCESS
Ledger Index: 85432150

Escrow Details:
  Escrow ID: E1F2A3B4C5D6...
  Sequence: 1
  Amount Locked: 25 XRP

View on explorer: https://testnet.xrpl.org/transactions/A1B2C3D4E5F6...

The escrow is now active on the ledger. Funds are locked until the condition
is fulfilled after the FinishAfter time, or until the CancelAfter time passes.
```

**Record the Escrow ID and Sequence** - you'll need these to finish the escrow.

---

## Step 6: Monitor Escrow Status

### 6.1 Check Escrow Details

Monitor the escrow's current state on the ledger.

Ask Claude:

> "Check the status of escrow E1F2A3B4C5D6... on testnet."

Claude will query the XRPL for the escrow object:

**Expected output**:

```
Escrow Status
-------------
Escrow ID: E1F2A3B4C5D6...
Status: PENDING

Details:
  Sender: rEscrowAgent123...
  Recipient: rRecipient456...
  Amount: 25,000,000 drops (25 XRP)

Timing:
  Created: 2026-01-28T15:00:05Z
  FinishAfter: 2026-01-28T15:05:00Z (4 minutes remaining)
  CancelAfter: 2026-01-29T15:00:00Z (23 hours remaining)

Condition: Present (PREIMAGE-SHA-256)
  - Fulfillment required to finish

Current Time: 2026-01-28T15:01:00Z

Status: Cannot be finished yet. FinishAfter time not reached.
```

### 6.2 Wait for Finish Time

The escrow cannot be finished until the `FinishAfter` time has passed. In our example, we set this to 5 minutes.

Ask Claude periodically:

> "Is the escrow ready to be finished?"

Once the time passes:

```
Escrow Status: READY TO FINISH
The FinishAfter time has passed. You can now finish the escrow
by providing the fulfillment.
```

---

## Step 7: Finish the Escrow

### 7.1 Build the EscrowFinish Transaction

Now that the finish time has passed, we can release the escrowed funds by providing the fulfillment.

Ask Claude:

> "Finish the escrow E1F2A3B4C5D6... using the fulfillment A0058020... The escrow was created by rEscrowAgent123... with sequence 1."

Claude will use the `escrow_finish` tool from xrpl-escrow-mcp:

**Expected output**:

```
EscrowFinish Transaction Built
------------------------------
Transaction Type: EscrowFinish
Owner: rEscrowAgent123...
Escrow Sequence: 1

Fulfillment: A0058020...
Condition: A0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100

Unsigned Transaction Blob:
120002228000000024000000026140000000000000...

This transaction is UNSIGNED. Use wallet_sign to sign it.

Note: EscrowFinish can be submitted by anyone - it doesn't require
the owner's signature. We'll sign with the agent wallet for convenience.
```

### 7.2 Sign and Submit the Finish Transaction

Sign and submit the EscrowFinish transaction:

> "Sign and submit the escrow finish transaction."

**Expected output**:

```
EscrowFinish Completed!
-----------------------
Status: validated
Transaction Hash: F7E8D9C0B1A2...
Result: tesSUCCESS
Ledger Index: 85432200

Escrow Released:
  Amount: 25 XRP
  Recipient: rRecipient456...

The escrowed funds have been released to the recipient.
The escrow object has been removed from the ledger.

View on explorer: https://testnet.xrpl.org/transactions/F7E8D9C0B1A2...
```

### 7.3 Verify the Transfer

Confirm the funds were transferred:

> "Check the balance of rRecipient456..."

**Expected output**:

```
Wallet Balance Report
---------------------
Address: rRecipient456...
Network: testnet

Balance:
  Previous: 1,000.000000 XRP
  Received: +25.000000 XRP (from escrow)
  Current: 1,025.000000 XRP

Recent Transactions:
  1. EscrowFinish (RECEIVED)
     Amount: +25.000000 XRP
     From Escrow: E1F2A3B4C5D6...
     Hash: F7E8D9C0B1A2...
```

---

## Cleanup and Next Steps

### Cleanup

Your testnet wallet and any remaining escrows will persist on the testnet. Testnet periodically resets, so don't rely on it for long-term storage.

To clean up local state:

```bash
# Remove local keystore (optional)
rm -rf ~/.xrpl-wallet-mcp/testnet/
```

### Alternative Scenario: Cancel an Escrow

If the escrow condition cannot be fulfilled, the sender can cancel the escrow after the `CancelAfter` time:

> "Cancel escrow E1F2A3B4C5D6... - the cancel time has passed and we need to recover the funds."

Claude will build, sign, and submit an `EscrowCancel` transaction:

```
EscrowCancel Completed!
-----------------------
Status: validated
Result: tesSUCCESS

Funds Returned:
  Amount: 25 XRP
  Returned to: rEscrowAgent123... (sender)

The escrow has been cancelled and funds returned to the sender.
```

### What You've Learned

In this tutorial, you've:

1. **Configured dual MCP servers** - xrpl-escrow-mcp for transaction building and xrpl-wallet-mcp for secure signing
2. **Created a policy-controlled wallet** - With escrow-specific transaction types enabled
3. **Generated cryptographic conditions** - Using PREIMAGE-SHA-256 for trustless release
4. **Built and signed an EscrowCreate** - Locking funds with time and condition constraints
5. **Monitored escrow status** - Checking readiness on the ledger
6. **Finished the escrow** - Releasing funds by providing the fulfillment

### Advanced Topics

Explore these next:

1. **Time-locked escrows without conditions**: Create escrows that release automatically after a time
2. **Multi-party escrows**: Configure escrows where different parties can cancel vs. finish
3. **Escrow chains**: Build sequential escrows for milestone-based payments
4. **Policy tiers for escrows**: Configure Tier 2 (delayed) or Tier 3 (co-sign) approval for large escrows
5. **Webhook notifications**: Get notified when escrows are ready to finish

### Related Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](./getting-started.md) | Basic wallet setup and transactions |
| [Configure Policies](../how-to/configure-policies.md) | Detailed policy configuration guide |
| [Security Model](../explanation/security-model.md) | Understanding the tiered approval system |
| [API Reference](../reference/api.md) | Complete tool specifications |
| [XRPL Escrow Docs](https://xrpl.org/escrow.html) | Official XRPL escrow documentation |

---

## Troubleshooting

### "escrow_create tool not found"

**Symptom**: Claude doesn't recognize escrow tools.

**Solutions**:
1. Verify xrpl-escrow-mcp is in your configuration
2. Restart Claude Desktop after configuration changes
3. Check for typos in the server name

### "Cannot finish escrow - time not reached"

**Symptom**: EscrowFinish fails with `tecNO_PERMISSION`.

**Solutions**:
1. Wait until the `FinishAfter` time has passed
2. Check the current ledger time vs. the escrow's FinishAfter
3. Remember XRPL uses ledger close time, not wall clock time

### "Invalid fulfillment"

**Symptom**: EscrowFinish fails with `tecCRYPTOCONDITION_ERROR`.

**Solutions**:
1. Verify you're using the exact fulfillment that matches the condition
2. Don't modify the fulfillment hex - use it exactly as generated
3. Ensure the condition in EscrowCreate matches

### "Policy violation for EscrowCreate"

**Symptom**: Signing fails with policy error.

**Solutions**:
1. Verify `EscrowCreate` is in the `allowed` transaction types
2. Check if the amount exceeds your policy limits
3. Review the policy with `wallet_balance` (includes policy status)

### "Transaction expired (tecNO_ENTRY)"

**Symptom**: EscrowFinish fails because escrow was cancelled.

**Solutions**:
1. The escrow was cancelled after `CancelAfter` time
2. Create a new escrow with a longer cancel window
3. Monitor escrows to finish them before cancel time

---

## Complete Code Reference

For developers integrating programmatically, here's the complete workflow in TypeScript:

```typescript
// Step 1: Create escrow-enabled wallet
const wallet = await mcpClient.callTool("xrpl-wallet", "wallet_create", {
  network: "testnet",
  policy: {
    policy_id: "escrow-agent-v1",
    policy_version: "1.0.0",
    limits: {
      max_amount_per_tx_drops: "100000000",
      max_daily_volume_drops: "500000000",
      max_tx_per_hour: 30,
      max_tx_per_day: 100
    },
    destinations: { mode: "open", allow_new_destinations: true, blocklist: [] },
    transaction_types: {
      allowed: ["Payment", "EscrowCreate", "EscrowFinish", "EscrowCancel"],
      blocked: ["AccountDelete", "SetRegularKey", "SignerListSet"]
    },
    escalation: {
      amount_threshold_drops: "50000000",
      new_destination: 2,
      account_settings: 3
    }
  },
  wallet_name: "escrow-agent"
});

// Step 2: Generate condition/fulfillment
const condition = await mcpClient.callTool("xrpl-escrow", "generate_condition", {
  algorithm: "PREIMAGE-SHA-256"
});

// Step 3: Build EscrowCreate transaction
const escrowTx = await mcpClient.callTool("xrpl-escrow", "escrow_create", {
  sender: wallet.address,
  recipient: "rRecipient456...",
  amount_drops: "25000000",
  condition: condition.condition_hex,
  finish_after_minutes: 5,
  cancel_after_hours: 24
});

// Step 4: Sign transaction
const signed = await mcpClient.callTool("xrpl-wallet", "wallet_sign", {
  wallet_address: wallet.address,
  unsigned_tx: escrowTx.unsigned_tx_blob,
  context: "Creating escrow for service agreement"
});

// Step 5: Submit to network
const result = await mcpClient.callTool("xrpl-wallet", "tx_submit", {
  signed_tx: signed.signed_tx,
  network: "testnet",
  wait_for_final: true
});

console.log("Escrow created:", result.tx_hash);

// ... wait for finish time ...

// Step 6: Build and submit EscrowFinish
const finishTx = await mcpClient.callTool("xrpl-escrow", "escrow_finish", {
  owner: wallet.address,
  escrow_sequence: escrowTx.sequence,
  fulfillment: condition.fulfillment_hex,
  condition: condition.condition_hex
});

const signedFinish = await mcpClient.callTool("xrpl-wallet", "wallet_sign", {
  wallet_address: wallet.address,
  unsigned_tx: finishTx.unsigned_tx_blob,
  context: "Finishing escrow - service delivered"
});

const finishResult = await mcpClient.callTool("xrpl-wallet", "tx_submit", {
  signed_tx: signedFinish.signed_tx,
  network: "testnet",
  wait_for_final: true
});

console.log("Escrow finished:", finishResult.tx_hash);
```

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Documentation Manager | Initial tutorial |

---

*XRPL Agent Wallet MCP - Escrow Workflow Tutorial*
