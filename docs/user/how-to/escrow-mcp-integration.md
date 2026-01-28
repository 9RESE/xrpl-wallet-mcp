# How to Integrate with XRPL Escrow MCP

This guide walks you through integrating the XRPL Agent Wallet MCP server with the companion xrpl-escrow-mcp server. Together, these MCPs enable AI agents to create, manage, and execute escrow transactions on the XRP Ledger with policy-controlled signing.

---

## Introduction

The XRPL ecosystem supports native escrow functionality, allowing funds to be locked until specific conditions are met. The xrpl-escrow-mcp server provides tools for constructing escrow transactions, while the xrpl-wallet-mcp server handles secure signing and policy enforcement.

### Why Two MCPs?

The architecture follows the principle of **separation of concerns**:

| MCP | Responsibility |
|-----|----------------|
| **xrpl-escrow-mcp** | Constructs unsigned escrow transactions (EscrowCreate, EscrowFinish, EscrowCancel) |
| **xrpl-wallet-mcp** | Validates, evaluates policy, and signs transactions |

This separation provides several benefits:

- **Security isolation**: Key material never leaves the wallet MCP
- **Policy enforcement**: All transactions pass through the same security boundary
- **Modularity**: Each MCP can be updated independently
- **Composability**: Other MCPs can use wallet signing the same way

### Supported Escrow Operations

| Operation | Description | Transaction Type |
|-----------|-------------|------------------|
| **Create Escrow** | Lock funds until conditions are met | EscrowCreate |
| **Finish Escrow** | Release funds to recipient (when conditions met) | EscrowFinish |
| **Cancel Escrow** | Return funds to sender (after cancel time) | EscrowCancel |

---

## Prerequisites

Before integrating the MCPs, ensure you have:

- Node.js 22 or later installed
- Claude Desktop (or compatible MCP client)
- Basic familiarity with XRPL escrow concepts
- An XRPL wallet with sufficient XRP balance

### XRPL Escrow Concepts

If you are new to XRPL escrows, understand these key concepts:

| Concept | Description |
|---------|-------------|
| **FinishAfter** | Timestamp when the escrow can be finished (recipient can claim funds) |
| **CancelAfter** | Timestamp when the escrow can be cancelled (sender can reclaim funds) |
| **Condition** | Optional crypto-condition that must be fulfilled to finish |
| **Fulfillment** | Preimage that satisfies the condition |
| **Sequence** | The escrow creator's sequence number at creation time (used to identify the escrow) |

---

## Step 1: Installing Both MCPs

### Install xrpl-wallet-mcp

If you have not already installed the wallet MCP, follow the [Getting Started](../tutorials/getting-started.md) guide or run:

```bash
npm install -g xrpl-agent-wallet-mcp
```

### Install xrpl-escrow-mcp

Install the escrow MCP server:

```bash
npm install -g xrpl-escrow-mcp
```

Verify both installations:

```bash
xrpl-wallet-mcp --version
# Expected: 0.1.0 or later

xrpl-escrow-mcp --version
# Expected: 0.1.0 or later
```

---

## Step 2: Configuration for Combined Use

### Claude Desktop Configuration

Configure both MCP servers in your Claude Desktop configuration file.

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
**Linux**: `~/.config/Claude/claude_desktop_config.json`

Add both servers to the configuration:

```json
{
  "mcpServers": {
    "xrpl-wallet": {
      "command": "xrpl-wallet-mcp",
      "args": [],
      "env": {
        "XRPL_NETWORK": "testnet"
      }
    },
    "xrpl-escrow": {
      "command": "xrpl-escrow-mcp",
      "args": [],
      "env": {
        "XRPL_NETWORK": "testnet"
      }
    }
  }
}
```

### Network Consistency

Both MCPs must target the same XRPL network. Set `XRPL_NETWORK` to the same value for both:

| Environment | Value | Use Case |
|-------------|-------|----------|
| `testnet` | XRPL Testnet | Development and testing |
| `devnet` | XRPL Devnet | Rapid iteration |
| `mainnet` | XRPL Mainnet | Production (real XRP) |

### Restart Claude Desktop

After saving the configuration, restart Claude Desktop to load both MCP servers.

### Verify Both Servers

Ask Claude to list available tools:

> "What MCP tools do you have available for XRPL wallets and escrows?"

**Expected response**: Claude should list tools from both servers:

- Wallet tools: `wallet_create`, `wallet_balance`, `wallet_sign`, `wallet_policy_check`, etc.
- Escrow tools: `escrow_create`, `escrow_finish`, `escrow_cancel`, `escrow_status`, etc.

---

## Step 3: Workflow - Create Escrow with Wallet Signing

This workflow demonstrates creating an escrow that locks funds until a future date.

### Step 3.1: Check Policy Before Creating

Before constructing the escrow, verify the transaction would be allowed by policy:

Ask Claude:

> "Check if I can create an escrow for 50 XRP to rRecipientAddress123 that releases in 24 hours"

Claude uses `wallet_policy_check` to evaluate without signing:

```json
{
  "tool": "wallet_policy_check",
  "params": {
    "wallet_address": "rAgentWallet123...",
    "transaction": {
      "TransactionType": "EscrowCreate",
      "Account": "rAgentWallet123...",
      "Destination": "rRecipientAddress123...",
      "Amount": "50000000"
    }
  }
}
```

**Expected response**:

```
Policy Check Result
-------------------
Would be allowed: Yes
Tier: autonomous
Reason: Within autonomous limits

Daily remaining: 950 XRP (50 would be locked)
Hourly transactions: 59 remaining
```

If the policy check shows the transaction would be denied, adjust the parameters or request approval before proceeding.

### Step 3.2: Create the Unsigned Escrow Transaction

Ask Claude to create the escrow:

> "Create an escrow for 50 XRP to rRecipientAddress123 that can be finished after 24 hours and cancelled after 48 hours"

Claude uses `escrow_create` from the escrow MCP:

```json
{
  "tool": "escrow_create",
  "params": {
    "source_account": "rAgentWallet123...",
    "destination": "rRecipientAddress123...",
    "amount_xrp": 50,
    "finish_after_hours": 24,
    "cancel_after_hours": 48
  }
}
```

**Response from escrow MCP**:

```json
{
  "success": true,
  "unsigned_transaction": {
    "TransactionType": "EscrowCreate",
    "Account": "rAgentWallet123...",
    "Destination": "rRecipientAddress123...",
    "Amount": "50000000",
    "FinishAfter": 750000000,
    "CancelAfter": 750086400
  },
  "unsigned_tx_blob": "1200012280000000240000000120...",
  "escrow_details": {
    "amount_xrp": "50.000000",
    "finish_after": "2026-01-29T14:30:00Z",
    "cancel_after": "2026-01-30T14:30:00Z"
  }
}
```

### Step 3.3: Sign the Escrow Transaction

Now sign the unsigned transaction using the wallet MCP:

> "Sign that escrow transaction with my wallet"

Claude uses `wallet_sign` from the wallet MCP:

```json
{
  "tool": "wallet_sign",
  "params": {
    "wallet_address": "rAgentWallet123...",
    "unsigned_tx": "1200012280000000240000000120...",
    "context": "Creating escrow for 50 XRP to rRecipient, finishes after 24h"
  }
}
```

**Response from wallet MCP** (Tier 1 autonomous approval):

```json
{
  "status": "approved",
  "signed_tx": "1200012280000000240000000120...744089...",
  "tx_hash": "E08D6E9754025BA2534A78707605E0601F03ACE063687A0CA1BDDACFCD1698C7",
  "policy_tier": 1,
  "limits_after": {
    "daily_remaining_drops": "950000000",
    "hourly_tx_remaining": 59,
    "daily_tx_remaining": 499
  },
  "signed_at": "2026-01-28T14:30:00Z"
}
```

### Step 3.4: Submit the Transaction

Submit the signed transaction to the XRPL:

> "Submit the signed escrow transaction to the network"

Claude uses `tx_submit` from the wallet MCP:

```json
{
  "tool": "tx_submit",
  "params": {
    "signed_tx": "1200012280000000240000000120...744089...",
    "network": "testnet"
  }
}
```

**Response**:

```
Transaction Submitted Successfully
----------------------------------
Hash: E08D6E9754025BA2534A78707605E0601F03ACE063687A0CA1BDDACFCD1698C7
Status: Validated (tesSUCCESS)
Ledger: 85432100

Escrow Created:
  Source: rAgentWallet123...
  Destination: rRecipientAddress123...
  Amount: 50.000000 XRP
  Finish After: 2026-01-29T14:30:00Z
  Cancel After: 2026-01-30T14:30:00Z
  Escrow Sequence: 12345

View on explorer: https://testnet.xrpl.org/transactions/E08D6E9754025BA2534A...
```

Record the **Escrow Sequence** (12345 in this example) - you will need it to finish or cancel the escrow.

---

## Step 4: Workflow - Finish Escrow with Wallet Signing

When the FinishAfter time has passed, the escrow can be finished to release funds to the recipient.

### Step 4.1: Check Escrow Status

First, verify the escrow is ready to be finished:

> "Check the status of escrow 12345 from rAgentWallet123"

Claude uses `escrow_status` from the escrow MCP:

```json
{
  "tool": "escrow_status",
  "params": {
    "owner": "rAgentWallet123...",
    "sequence": 12345
  }
}
```

**Response**:

```
Escrow Status
-------------
Owner: rAgentWallet123...
Sequence: 12345
Status: Ready to Finish

Amount: 50.000000 XRP
Destination: rRecipientAddress123...
Finish After: 2026-01-29T14:30:00Z (PASSED)
Cancel After: 2026-01-30T14:30:00Z (not yet)

Current time: 2026-01-29T16:00:00Z
Can finish: Yes
Can cancel: No (cancel time not reached)
```

### Step 4.2: Create Unsigned EscrowFinish

> "Create an EscrowFinish transaction for escrow 12345"

Claude uses `escrow_finish` from the escrow MCP:

```json
{
  "tool": "escrow_finish",
  "params": {
    "owner": "rAgentWallet123...",
    "sequence": 12345,
    "finisher": "rAgentWallet123..."
  }
}
```

**Response**:

```json
{
  "success": true,
  "unsigned_transaction": {
    "TransactionType": "EscrowFinish",
    "Account": "rAgentWallet123...",
    "Owner": "rAgentWallet123...",
    "OfferSequence": 12345
  },
  "unsigned_tx_blob": "1200022280000000240000000220..."
}
```

### Step 4.3: Sign and Submit

> "Sign and submit the EscrowFinish transaction"

Claude signs using `wallet_sign` and submits using `tx_submit`:

```
Transaction Signed and Submitted
--------------------------------
Status: approved (Tier 1 - Autonomous)
Hash: F19E7F8854036BC3645B89808706E1702F04BDF174798B1CB2EDDBEGED2809D8
Result: tesSUCCESS

Escrow Finished:
  Amount released: 50.000000 XRP
  From: rAgentWallet123...
  To: rRecipientAddress123...
```

---

## Step 5: Workflow - Cancel Escrow

If the CancelAfter time has passed and the escrow has not been finished, the sender can cancel it to reclaim the funds.

### Step 5.1: Verify Cancellation is Possible

> "Can I cancel escrow 12345?"

```
Escrow Status
-------------
Status: Ready to Cancel

Cancel After: 2026-01-30T14:30:00Z (PASSED)
Current time: 2026-01-31T10:00:00Z
Can cancel: Yes
```

### Step 5.2: Create and Sign EscrowCancel

> "Cancel escrow 12345 and return the funds to my wallet"

Claude creates, signs, and submits the cancellation:

```json
{
  "tool": "escrow_cancel",
  "params": {
    "owner": "rAgentWallet123...",
    "sequence": 12345,
    "canceller": "rAgentWallet123..."
  }
}
```

**Final response**:

```
Escrow Cancelled
----------------
Status: tesSUCCESS
Hash: G20F8G9965047CD4756C90919817F2813G15CEG285809C2DC3FEECFHFE3910E9

Funds returned: 50.000000 XRP
From escrow: 12345
To: rAgentWallet123...
```

---

## Step 6: Policy Considerations for Escrow Operations

### Default Tier Classification

Escrow transactions are classified into tiers based on the wallet policy:

| Transaction Type | Default Tier | Notes |
|------------------|--------------|-------|
| EscrowCreate | Depends on amount | Amount-based tier classification |
| EscrowFinish | Usually autonomous | Completes a previously approved escrow |
| EscrowCancel | Usually autonomous | Returns funds to sender |

### Recommended Policy Configuration

For escrow-focused agents, configure the policy to allow escrow operations:

```json
{
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 1000,
      "daily_limit_xrp": 10000,
      "require_known_destination": true,
      "allowed_transaction_types": [
        "Payment",
        "EscrowCreate",
        "EscrowFinish",
        "EscrowCancel"
      ]
    },
    "delayed": {
      "max_amount_xrp": 10000,
      "delay_seconds": 600
    },
    "prohibited": {
      "prohibited_transaction_types": [
        "AccountSet",
        "SetRegularKey"
      ]
    }
  }
}
```

### Escrow Amount Considerations

When creating escrows, the **locked amount** counts against daily limits:

| Scenario | Policy Impact |
|----------|---------------|
| Create 100 XRP escrow | 100 XRP deducted from daily limit |
| Finish escrow | No additional deduction (funds already locked) |
| Cancel escrow | Funds returned, but original limit deduction remains for the day |

### High-Value Escrow Approval

For escrows exceeding autonomous limits, the wallet MCP returns a pending approval:

```json
{
  "status": "pending_approval",
  "approval_id": "550e8400-e29b-41d4-a716-446655440000",
  "reason": "exceeds_autonomous_limit",
  "policy_tier": 2,
  "auto_approve_in_seconds": 600
}
```

The agent must wait for human approval or the delay period before the transaction is signed.

### Destination Allowlist for Escrows

If `require_known_destination` is enabled, escrow destinations must be in the allowlist:

```json
{
  "allowlist": {
    "addresses": [
      "rKnownRecipient111111111111111111111",
      "rTrustedPartner222222222222222222222"
    ]
  }
}
```

Escrows to unknown destinations will require Tier 2 or Tier 3 approval.

---

## Step 7: Error Handling Across MCPs

### Error Categories

Errors can originate from either MCP:

| Error Source | Example Errors | Handling |
|--------------|----------------|----------|
| **Escrow MCP** | Invalid parameters, escrow not found, condition mismatch | Fix parameters, verify escrow state |
| **Wallet MCP** | Policy violation, rate limit, wallet locked | Adjust transaction, wait, authenticate |
| **XRPL Network** | tecNO_PERMISSION, tecNO_TARGET, tecPRE_SEQ | Verify account state, timing |

### Common Integration Errors

#### Escrow Not Found

**Error**: `escrow_status` returns "Escrow not found"

**Causes**:
- Incorrect owner address or sequence number
- Escrow was already finished or cancelled
- Looking on wrong network

**Solution**:
- Verify the owner and sequence from the original EscrowCreate transaction
- Check transaction history for finish/cancel transactions

#### Policy Violation on EscrowCreate

**Error**: `wallet_sign` returns `status: rejected` with `POLICY_VIOLATION`

**Causes**:
- Amount exceeds limits
- EscrowCreate not in allowed transaction types
- Destination not in allowlist (if required)

**Solution**:
- Check policy configuration
- Add EscrowCreate to `allowed_transaction_types`
- Add destination to allowlist or disable `require_known_destination`

#### Timing Errors

**Error**: XRPL returns `tecNO_PERMISSION` for EscrowFinish

**Causes**:
- Current ledger time is before FinishAfter time
- Crypto-condition not satisfied

**Solution**:
- Wait until the FinishAfter time has passed
- Provide the correct fulfillment if a condition was set

**Error**: XRPL returns `tecNO_PERMISSION` for EscrowCancel

**Causes**:
- Current ledger time is before CancelAfter time
- Escrow has already been finished

**Solution**:
- Wait until the CancelAfter time has passed
- Verify the escrow still exists

#### Rate Limiting

**Error**: `wallet_sign` returns `RATE_LIMIT_EXCEEDED`

**Solution**:
- Wait for the rate limit window to reset (shown in response)
- The wallet MCP limits signing to 5 requests per 5 minutes per wallet

### Error Handling Example

```typescript
async function createAndSignEscrow(params: EscrowParams): Promise<EscrowResult> {
  // Step 1: Create unsigned escrow
  const escrowResult = await escrowMcp.callTool("escrow_create", params);

  if (!escrowResult.success) {
    throw new Error(`Escrow creation failed: ${escrowResult.error.message}`);
  }

  // Step 2: Sign with wallet MCP
  const signResult = await walletMcp.callTool("wallet_sign", {
    wallet_address: params.source_account,
    unsigned_tx: escrowResult.unsigned_tx_blob,
    context: `Creating escrow for ${params.amount_xrp} XRP`
  });

  // Handle different response types
  switch (signResult.status) {
    case "approved":
      // Signed successfully, proceed to submit
      return await submitTransaction(signResult.signed_tx);

    case "pending_approval":
      // Requires human approval
      console.log(`Approval required. ID: ${signResult.approval_id}`);
      console.log(`Reason: ${signResult.reason}`);
      if (signResult.auto_approve_in_seconds) {
        console.log(`Auto-approves in ${signResult.auto_approve_in_seconds}s`);
      }
      return { status: "pending", approval_id: signResult.approval_id };

    case "rejected":
      // Policy violation
      console.error(`Signing rejected: ${signResult.reason}`);
      if (signResult.policy_violation) {
        console.error(`Rule: ${signResult.policy_violation.rule}`);
        console.error(`Limit: ${signResult.policy_violation.limit}`);
      }
      throw new PolicyViolationError(signResult.reason);

    default:
      throw new Error(`Unexpected response: ${signResult.status}`);
  }
}
```

---

## Step 8: Complete Example Workflow

This section demonstrates a complete end-to-end escrow workflow using both MCPs.

### Scenario: Time-Locked Payment

An AI agent needs to create a time-locked payment of 100 XRP that releases in 7 days, with the option to cancel after 14 days if not claimed.

### Complete Conversation Flow

**User**: "Create an escrow payment of 100 XRP to rMerchantWallet123 that can be released after 7 days. Allow cancellation after 14 days if not claimed."

**Claude** (internal steps):

1. **Policy check** (wallet MCP):

```json
{
  "tool": "wallet_policy_check",
  "params": {
    "wallet_address": "rAgentWallet456...",
    "transaction": {
      "TransactionType": "EscrowCreate",
      "Amount": "100000000",
      "Destination": "rMerchantWallet123..."
    }
  }
}
```

Response: Allowed at Tier 1

2. **Create unsigned escrow** (escrow MCP):

```json
{
  "tool": "escrow_create",
  "params": {
    "source_account": "rAgentWallet456...",
    "destination": "rMerchantWallet123...",
    "amount_xrp": 100,
    "finish_after_days": 7,
    "cancel_after_days": 14
  }
}
```

3. **Sign transaction** (wallet MCP):

```json
{
  "tool": "wallet_sign",
  "params": {
    "wallet_address": "rAgentWallet456...",
    "unsigned_tx": "<blob>",
    "context": "Time-locked payment to merchant, 7 day release"
  }
}
```

4. **Submit transaction** (wallet MCP):

```json
{
  "tool": "tx_submit",
  "params": {
    "signed_tx": "<signed_blob>"
  }
}
```

**Claude** (response to user):

```
Escrow Created Successfully
---------------------------
Transaction Hash: ABC123...
Ledger: 85500000
Status: tesSUCCESS

Escrow Details:
  Amount: 100.000000 XRP
  From: rAgentWallet456...
  To: rMerchantWallet123...
  Escrow Sequence: 54321

Timeline:
  Created: 2026-01-28T14:30:00Z
  Can finish after: 2026-02-04T14:30:00Z (7 days)
  Can cancel after: 2026-02-11T14:30:00Z (14 days)

Policy Impact:
  Daily limit used: 100 XRP (900 remaining)
  Tier: Autonomous (Tier 1)

To finish this escrow after Feb 4th, say:
  "Finish escrow 54321 from rAgentWallet456"

To cancel after Feb 11th if not claimed:
  "Cancel escrow 54321"
```

### Seven Days Later - Finishing the Escrow

**User**: "Finish escrow 54321 from rAgentWallet456"

**Claude** (internal steps):

1. Check escrow status
2. Create unsigned EscrowFinish
3. Sign with wallet MCP
4. Submit to network

**Claude** (response):

```
Escrow Finished Successfully
----------------------------
Transaction Hash: DEF456...
Status: tesSUCCESS

Funds Released:
  Amount: 100.000000 XRP
  To: rMerchantWallet123...

Escrow 54321 is now complete.
```

---

## Troubleshooting

### Both MCPs Not Connecting

**Symptom**: Claude does not recognize tools from one or both MCPs.

**Solutions**:
1. Verify both entries exist in `claude_desktop_config.json`
2. Check command paths are correct
3. Restart Claude Desktop
4. Review Claude Desktop logs for connection errors

### Network Mismatch

**Symptom**: Escrow MCP creates transaction for wrong network.

**Solutions**:
1. Verify `XRPL_NETWORK` is set identically for both MCPs
2. Check that the wallet exists on the specified network
3. Restart both MCP servers after configuration changes

### Escrow Transaction Malformed

**Symptom**: Wallet MCP returns `INVALID_TRANSACTION` when signing.

**Solutions**:
1. Verify escrow MCP is up to date
2. Check that all required fields are present
3. Validate the unsigned transaction blob format

### Permission Issues

**Symptom**: EscrowFinish fails with `tecNO_PERMISSION`.

**Solutions**:
1. Verify current time is after FinishAfter
2. If using conditions, ensure correct fulfillment is provided
3. Verify the finisher account is authorized (creator or destination)

---

## Best Practices

### Security

1. **Use testnet first**: Always test escrow workflows on testnet before mainnet
2. **Verify destinations**: Add trusted destinations to the allowlist
3. **Set appropriate limits**: Configure escrow amount limits matching your use case
4. **Monitor pending escrows**: Track open escrows to manage liquidity

### Operational

1. **Record escrow sequences**: Store the sequence number for each created escrow
2. **Set realistic timeframes**: Allow adequate time for FinishAfter and CancelAfter
3. **Handle pending approvals**: Implement workflows for Tier 2/3 escalations
4. **Test cancellation paths**: Verify cancel functionality works before relying on it

### Policy Configuration

1. **Include all escrow types**: Add EscrowCreate, EscrowFinish, EscrowCancel to allowed types
2. **Consider separate limits**: Escrows lock funds - factor this into daily limits
3. **Allowlist regular counterparties**: Pre-approve frequent escrow destinations

---

## Next Steps

- Review the [Policy Schema Reference](../../api/policy-schema.md) for detailed policy configuration
- Set up [human approval workflows](./set-up-human-approval.md) for high-value escrows
- Explore [crypto-conditions](https://xrpl.org/escrow.html#crypto-conditions) for conditional escrows
- See the [escrow MCP documentation](https://github.com/example/xrpl-escrow-mcp) for advanced features

---

## Related Documentation

- [Configure Policies](./configure-policies.md)
- [Getting Started Tutorial](../tutorials/getting-started.md)
- [wallet_sign Tool Reference](../../api/tools/wallet-sign.md)
- [wallet_policy_check Tool Reference](../../api/tools/wallet-policy-check.md)
- [ADR-008: Integration Design](../../architecture/09-decisions/ADR-008-integration-design.md)
- [ADR-009: Transaction Scope](../../architecture/09-decisions/ADR-009-transaction-scope.md)
- [XRPL Escrow Documentation](https://xrpl.org/escrow.html)

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Documentation Manager | Initial guide |

---

*XRPL Agent Wallet MCP - Escrow Integration Guide*
