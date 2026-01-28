# ADR-008: Integration Design

**Status:** Accepted
**Date:** 2026-01-28
**Decision Makers:** Tech Lead, Security Specialist

---

## Context

The XRPL Agent Wallet MCP server is designed to work within a composable MCP ecosystem. Other MCP servers (such as xrpl-escrow-mcp) create unsigned transactions, which are then sent to the wallet MCP for signing.

Key design considerations:
1. **Separation of Concerns**: Transaction construction vs. signing are distinct responsibilities
2. **Interoperability**: Must work with various upstream transaction sources
3. **Security Boundary**: Wallet MCP is the trust boundary - it validates everything
4. **Extensibility**: New transaction types and MCPs should integrate seamlessly
5. **Simplicity**: Clear, minimal interface that's hard to misuse

## Decision

**We will implement a composable MCP ecosystem design where the wallet MCP receives unsigned transactions, validates them against policy, and returns signed transaction blobs or rejection reasons.**

### Integration Architecture

```
+-------------------+     +-------------------+     +-------------------+
|                   |     |                   |     |                   |
| xrpl-escrow-mcp   |     | xrpl-amm-mcp      |     | custom-mcp        |
|                   |     | (future)          |     |                   |
| Creates unsigned  |     | Creates unsigned  |     | Creates unsigned  |
| escrow TXs        |     | AMM TXs           |     | custom TXs        |
|                   |     |                   |     |                   |
+--------+----------+     +--------+----------+     +--------+----------+
         |                         |                         |
         |   Unsigned TX           |   Unsigned TX           |   Unsigned TX
         |   (JSON)                |   (JSON)                |   (JSON)
         v                         v                         v
+------------------------------------------------------------------------+
|                                                                        |
|                        xrpl-wallet-mcp                                 |
|                                                                        |
|  +----------------+    +----------------+    +------------------+       |
|  | Input          |    | Policy         |    | Signing          |      |
|  | Validation     |--->| Evaluation     |--->| Layer            |      |
|  | (Zod schemas)  |    | (JSON policy)  |    | (Regular Key)    |      |
|  +----------------+    +----------------+    +------------------+       |
|                                                       |                |
|                                                       v                |
|                                              +------------------+      |
|                                              | Audit            |      |
|                                              | Logging          |      |
|                                              +------------------+      |
|                                                                        |
+------------------------------------------------------------------------+
         |
         |   Signed TX Blob (or Rejection)
         v
+-------------------+
|                   |
| XRPL Network      |
| (submitted by     |
|  upstream MCP     |
|  or wallet MCP)   |
|                   |
+-------------------+
```

### Standard Transaction Flow

```typescript
// 1. Upstream MCP creates unsigned transaction
const unsignedTx: UnsignedTransaction = {
  TransactionType: 'EscrowCreate',
  Account: 'rAgentWallet123...',
  Destination: 'rEscrowTarget456...',
  Amount: '10000000',  // 10 XRP
  FinishAfter: 750000000,
  CancelAfter: 751000000
  // Note: No Sequence, Fee, or signatures
};

// 2. Upstream MCP calls wallet MCP's sign_transaction tool
const signRequest = {
  transaction: unsignedTx,
  wallet_address: 'rAgentWallet123...',
  network: 'mainnet'
};

// 3. Wallet MCP validates, evaluates policy, signs (if allowed)
const response = await walletMcp.callTool('sign_transaction', signRequest);

// 4. Response contains signed blob or rejection
if (response.success) {
  const signedBlob = response.signed_tx_blob;
  // Upstream can now submit to XRPL
} else {
  const reason = response.error.message;
  // Handle rejection (policy violation, etc.)
}
```

### Interface Contract

```typescript
// Input: Unsigned transaction from any source
interface SignTransactionInput {
  // The unsigned transaction (partial - missing autofilled fields)
  transaction: {
    TransactionType: string;
    Account: string;
    [key: string]: unknown;  // Type-specific fields
  };

  // Which wallet should sign
  wallet_address: string;

  // Which network
  network: 'mainnet' | 'testnet' | 'devnet';

  // Optional: Request autofill of Sequence/Fee
  autofill?: boolean;  // Default: true
}

// Output: Signed blob or detailed rejection
interface SignTransactionOutput {
  success: boolean;

  // On success
  signed_tx_blob?: string;
  tx_hash?: string;

  // On failure
  error?: {
    code: 'VALIDATION_ERROR' | 'POLICY_DENIED' | 'SIGNING_ERROR' | 'WALLET_LOCKED';
    message: string;
    details?: {
      tier?: string;
      matched_rule?: string;
      policy_reason?: string;
    };
  };
}
```

### Autofill Behavior

The wallet MCP can autofill missing transaction fields:

```typescript
async function autofillTransaction(
  tx: PartialTransaction,
  network: Network
): Promise<Transaction> {
  const client = getClient(network);

  // Autofill Sequence if missing
  if (tx.Sequence === undefined) {
    const accountInfo = await client.request({
      command: 'account_info',
      account: tx.Account
    });
    tx.Sequence = accountInfo.result.account_data.Sequence;
  }

  // Autofill Fee if missing (use conservative estimate)
  if (tx.Fee === undefined) {
    const serverInfo = await client.request({ command: 'server_info' });
    const baseFee = serverInfo.result.info.validated_ledger.base_fee_xrp;
    tx.Fee = String(Math.ceil(parseFloat(baseFee) * 1_000_000 * 1.2));  // 20% buffer
  }

  // Autofill LastLedgerSequence if missing
  if (tx.LastLedgerSequence === undefined) {
    const ledger = await client.request({ command: 'ledger_current' });
    tx.LastLedgerSequence = ledger.result.ledger_current_index + 20;  // ~1 minute window
  }

  return tx as Transaction;
}
```

### Submission Options

The wallet MCP supports two modes:

```typescript
// Mode 1: Sign-only (default)
// Wallet signs and returns blob, upstream submits
const signOnlyResponse = await walletMcp.callTool('sign_transaction', {
  transaction: unsignedTx,
  wallet_address: 'rAgent...',
  network: 'mainnet',
  submit: false  // Default
});
// Returns: { signed_tx_blob: '...', tx_hash: '...' }

// Mode 2: Sign-and-submit
// Wallet signs AND submits to network
const signAndSubmitResponse = await walletMcp.callTool('sign_transaction', {
  transaction: unsignedTx,
  wallet_address: 'rAgent...',
  network: 'mainnet',
  submit: true
});
// Returns: { signed_tx_blob: '...', tx_hash: '...', submission_result: {...} }
```

### Dry-Run Policy Check

Upstream MCPs can check if a transaction would be allowed before constructing it:

```typescript
// Check policy without signing
const policyCheck = await walletMcp.callTool('check_policy', {
  transaction: {
    TransactionType: 'Payment',
    Account: 'rAgent...',
    Destination: 'rRecipient...',
    Amount: '50000000'  // 50 XRP
  },
  wallet_address: 'rAgent...',
  network: 'mainnet'
});

// Response indicates what tier and whether it would be allowed
{
  "would_be_allowed": true,
  "tier": "autonomous",
  "reason": "Within autonomous limits",
  "matched_rule": "rule-999",
  "daily_remaining_xrp": 950  // 1000 limit - 50 already spent
}
```

## Consequences

### Positive

- **Clean Separation**: Transaction construction and signing are independent
- **Ecosystem Composability**: Any MCP can use wallet signing
- **Single Security Boundary**: All signing goes through one audited component
- **Upstream Flexibility**: MCPs can sign-only or sign-and-submit
- **Policy Transparency**: Dry-run checks before constructing transactions
- **Type Agnostic**: Wallet doesn't need to understand transaction semantics
- **Future Proof**: New transaction types work automatically

### Negative

- **Round-Trip Latency**: Upstream must call wallet for each signing
- **Coordination Complexity**: Upstream needs to handle rejections gracefully
- **Partial State**: If upstream crashes between sign and submit, TX may be lost
- **Network Dependency**: Autofill requires XRPL network access

### Neutral

- Wallet MCP doesn't construct transactions (by design)
- Upstream MCPs handle transaction-specific logic
- Multiple MCPs can use the same wallet simultaneously

## Alternatives Considered

| Option | Pros | Cons | Why Not Chosen |
|--------|------|------|----------------|
| **Monolithic MCP** | Single server, simpler deployment | Bloated codebase, hard to audit, coupling | Violates separation of concerns |
| **Shared Key Access** | No round-trips | Multiple components with key access | Unacceptable security risk |
| **Signing Service (gRPC)** | High performance | Non-MCP protocol, additional infrastructure | Doesn't fit MCP ecosystem |
| **Event-Driven (Queue)** | Decoupled, async | Complexity, eventual consistency issues | Overkill for synchronous signing |

## Implementation Notes

### MCP Tool Definition

```typescript
// sign_transaction tool definition
const signTransactionTool: MCPTool = {
  name: 'sign_transaction',
  description: 'Sign an unsigned XRPL transaction with policy enforcement',
  inputSchema: SignTransactionInputSchema,

  async handler(input: SignTransactionInput, context: MCPContext): Promise<SignTransactionOutput> {
    const correlationId = context.correlationId;

    // 1. Validate input
    const validated = await validateAndProcess(
      SignTransactionInputSchema,
      input,
      'sign_transaction',
      correlationId
    );

    // 2. Check wallet is unlocked
    const keystore = await getKeystore(validated.network);
    if (!keystore.isUnlocked()) {
      return {
        success: false,
        error: {
          code: 'WALLET_LOCKED',
          message: 'Wallet must be unlocked before signing'
        }
      };
    }

    // 3. Autofill if requested
    let transaction = validated.transaction;
    if (validated.autofill !== false) {
      transaction = await autofillTransaction(transaction, validated.network);
    }

    // 4. Evaluate policy
    const policyResult = await policyEngine.evaluate({
      transaction,
      wallet: {
        address: validated.wallet_address,
        daily_spent_xrp: await getDailySpent(validated.wallet_address),
        hourly_transaction_count: await getHourlyCount(validated.wallet_address)
      },
      timestamp: new Date().toISOString()
    });

    if (!policyResult.allowed) {
      await auditLog.log({
        eventType: 'TX_SIGN_DENIED',
        correlationId,
        operation: {
          name: 'sign_transaction',
          parameters: sanitizeTransaction(transaction),
          result: 'denied',
          errorMessage: policyResult.reason
        }
      });

      return {
        success: false,
        error: {
          code: 'POLICY_DENIED',
          message: 'Transaction not permitted by policy',
          details: {
            tier: policyResult.tier,
            matched_rule: policyResult.matched_rule,
            policy_reason: policyResult.reason
          }
        }
      };
    }

    // 5. Handle tiered approval
    if (policyResult.tier === 'delayed') {
      return await handleDelayedSigning(transaction, policyResult, correlationId);
    }

    if (policyResult.tier === 'cosign') {
      return await handleCosignRequest(transaction, policyResult, correlationId);
    }

    // 6. Sign (autonomous tier)
    const wallet = keystore.getWallet(validated.wallet_address);
    const signed = wallet.sign(transaction);

    await auditLog.log({
      eventType: 'TX_SIGN_SUCCESS',
      correlationId,
      operation: {
        name: 'sign_transaction',
        parameters: sanitizeTransaction(transaction),
        result: 'success'
      },
      context: {
        transactionHash: signed.hash
      }
    });

    // 7. Submit if requested
    if (validated.submit) {
      const submitResult = await submitTransaction(signed.tx_blob, validated.network);
      return {
        success: true,
        signed_tx_blob: signed.tx_blob,
        tx_hash: signed.hash,
        submission_result: submitResult
      };
    }

    return {
      success: true,
      signed_tx_blob: signed.tx_blob,
      tx_hash: signed.hash
    };
  }
};
```

### Error Handling at Integration Boundary

```typescript
// Upstream MCP error handling example
async function handleSigningResponse(response: SignTransactionOutput): Promise<void> {
  if (response.success) {
    // Transaction signed, proceed with submission or further processing
    return;
  }

  switch (response.error?.code) {
    case 'WALLET_LOCKED':
      // Prompt user to unlock wallet, retry
      throw new Error('Wallet is locked. Please unlock and try again.');

    case 'POLICY_DENIED':
      // Transaction not allowed - may need human approval
      if (response.error.details?.tier === 'cosign') {
        // Initiate co-sign flow
        await initiateCosignApproval(response);
      } else {
        // Policy violation - inform user
        throw new PolicyViolationError(response.error.details?.policy_reason);
      }
      break;

    case 'VALIDATION_ERROR':
      // Transaction malformed - fix and retry
      throw new ValidationError(response.error.message);

    case 'SIGNING_ERROR':
      // Internal error - may be transient
      throw new RetryableError(response.error.message);
  }
}
```

## Security Considerations

### Trust Boundaries

```
+----------------------------------------------------------------------+
|                        UNTRUSTED ZONE                                |
|                                                                      |
|   +-------------------+    +-------------------+                     |
|   | Upstream MCP 1    |    | Upstream MCP 2    |                     |
|   | (may be malicious |    | (may be malicious |                     |
|   |  or compromised)  |    |  or compromised)  |                     |
|   +--------+----------+    +--------+----------+                     |
|            |                        |                                |
+----------------------------------------------------------------------+
             |                        |
             v                        v
+----------------------------------------------------------------------+
|                        TRUST BOUNDARY                                |
|  +----------------------------------------------------------------+  |
|  |                    xrpl-wallet-mcp                             |  |
|  |                                                                |  |
|  |  - Validates ALL input (never trust upstream)                  |  |
|  |  - Enforces policy regardless of source                        |  |
|  |  - Audits all operations                                       |  |
|  |  - Rate limits per-client                                      |  |
|  |  - Keys never leave this boundary                              |  |
|  |                                                                |  |
|  +----------------------------------------------------------------+  |
+----------------------------------------------------------------------+
```

### Never Trust Upstream

- All transactions re-validated (even from trusted MCPs)
- Policy applies universally
- Rate limits apply to all callers
- Audit logs all requests regardless of source

### Compliance Mapping

| Concern | Implementation |
|---------|----------------|
| Input Validation | ADR-006 applies to all upstream input |
| Policy Enforcement | ADR-003 policy evaluates all transactions |
| Audit Trail | ADR-005 logs all signing attempts |
| Rate Limiting | ADR-007 applies per upstream client |

## References

- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [XRPL Transaction Types](https://xrpl.org/transaction-types.html)
- [xrpl-escrow-mcp](https://github.com/example/xrpl-escrow-mcp) (companion project)

## Related ADRs

- [ADR-003: Policy Engine](ADR-003-policy-engine.md) - Evaluates incoming transactions
- [ADR-006: Input Validation](ADR-006-input-validation.md) - Validates all upstream input
- [ADR-009: Transaction Scope](ADR-009-transaction-scope.md) - Supported transaction types

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Tech Lead | Initial ADR |
