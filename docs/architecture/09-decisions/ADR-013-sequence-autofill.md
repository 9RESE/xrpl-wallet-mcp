# ADR-013: Transaction Sequence Autofill with Local Tracking

**Status**: Accepted
**Date**: 2026-01-29
**Updated**: 2026-01-29 (v2.1.0 - Added local sequence tracking)
**Context**: Multi-transaction workflow failures in escrow integration testing

## Decision Drivers

- Sequential transactions from the same wallet fail with `tefPAST_SEQ` errors
- The wallet MCP signs transactions as-received without verifying sequence freshness
- Escrow workflows require multiple transactions (create → finish) from the same account
- Separation of concerns between escrow-mcp (builds TX) and wallet-mcp (signs TX) creates a timing gap
- **Race condition**: Ledger queries may return stale sequence if previous TX hasn't propagated yet

## Problem Statement

When an AI agent executes multiple transactions in sequence:

1. Transaction A is built by escrow-mcp (autofilled with sequence N)
2. Transaction A is signed by wallet-mcp
3. Transaction A is submitted and validated (account sequence now N+1)
4. Transaction B is built by escrow-mcp (may autofill with stale sequence N)
5. Transaction B fails with `tefPAST_SEQ`

**Additional Race Condition** (discovered in v2.0.0 testing):
- Even with ledger query, if TX A was just submitted, the ledger may still return sequence N
- This creates intermittent failures (~33% success rate in rapid multi-tx workflows)

The root cause is that the unsigned transaction's sequence may be stale by the time it reaches wallet_sign, AND the ledger query itself may return stale data due to propagation delays.

## Considered Options

### Option 1: Document and Require Caller to Handle
- Let escrow-mcp or callers manage sequence
- Wallet-mcp signs whatever it receives
- **Rejected**: Creates fragile workflows, error-prone

### Option 2: Track Sequence Locally After Submit
- Maintain per-wallet sequence in memory
- Increment after successful submission
- **Rejected**: Complex state management, doesn't handle external transactions

### Option 3: Autofill Fresh Sequence Before Signing (v2.0.0)
- Query ledger for current sequence before signing
- Apply fresh sequence if transaction has stale/missing sequence
- **Partially Effective**: Works ~33% of the time due to race condition

### Option 4: Hybrid - Local Track + Ledger Query (Selected - v2.1.0)
- Query ledger for current sequence
- Also track locally-signed sequences per address
- Use `MAX(ledger_sequence, last_signed_sequence + 1)`
- Entries expire after 60 seconds to handle failed/abandoned TXs
- **Selected**: Handles race condition while respecting external transactions

## Decision

**Implement Option 4**: Hybrid local tracking + ledger query for sequence management.

### Behavior

1. When `wallet_sign` is called with `auto_sequence: true` (default):
   - Decode the unsigned transaction
   - Query `account_info` from validated ledger to get `ledgerSequence`
   - Get `SequenceTracker` singleton (shared across all signing operations)
   - Calculate `nextSequence = MAX(ledgerSequence, lastSignedSequence + 1)`
   - Update transaction's Sequence if different
   - Also autofill Fee and LastLedgerSequence if missing
   - Re-encode and sign the transaction
   - **After successful signing**: Record the sequence in tracker

2. Parameter `auto_sequence` (default: `true`):
   - When `true`: Use hybrid tracking + ledger query
   - When `false`: Use sequence from unsigned_tx as-is (legacy behavior)

3. Sequence entries expire after 60 seconds:
   - Handles abandoned/failed transactions that never submitted
   - Prevents memory growth from old entries

### Implementation Details

```typescript
// src/xrpl/sequence-tracker.ts
export class SequenceTracker {
  private sequences: Map<string, { sequence: number; timestamp: number }>;
  private ttlMs: number = 60000;

  getNextSequence(address: string, ledgerSequence: number): number {
    const entry = this.sequences.get(address);
    if (!entry || (Date.now() - entry.timestamp) > this.ttlMs) {
      return ledgerSequence; // No tracked entry or expired
    }
    // Use MAX to handle race condition
    return Math.max(ledgerSequence, entry.sequence + 1);
  }

  recordSignedSequence(address: string, sequence: number): void {
    // Only update if new sequence is greater
    const existing = this.sequences.get(address);
    if (!existing || sequence > existing.sequence) {
      this.sequences.set(address, { sequence, timestamp: Date.now() });
    }
  }
}

// In wallet-sign.ts handler
if (input.auto_sequence !== false) {
  const sequenceTracker = getSequenceTracker();
  const accountInfo = await xrplClient.getAccountInfo(input.wallet_address);
  const ledgerSequence = accountInfo.sequence;

  // Use MAX(ledger, tracked+1) to handle race condition
  const nextSequence = sequenceTracker.getNextSequence(
    input.wallet_address,
    ledgerSequence
  );

  decoded.Sequence = nextSequence;
  // ... autofill Fee, LastLedgerSequence ...
  transactionBlob = encode(decoded);
}

// After successful signing:
sequenceTracker.recordSignedSequence(input.wallet_address, usedSequence);

// In tx-submit.ts (dual tracking for belt-and-suspenders):
if (result.resultCode === 'tesSUCCESS' && account && sequenceUsed !== undefined) {
  const sequenceTracker = getSequenceTracker();
  sequenceTracker.recordSignedSequence(account, sequenceUsed);
  nextSequence = sequenceUsed + 1;  // Returned in response
}

// tx_submit response includes:
{
  tx_hash: "...",
  sequence_used: 100,
  next_sequence: 101  // Use this for next TX instead of ledger query!
}
```

### Debug Logging

Both `wallet_sign` and `tx_submit` include debug logging for sequence tracking:

```
[wallet_sign] Sequence calculation for rXXX: ledger=100, tracked=100, using=101
[tx_submit] Recorded sequence 101 for rXXX, next tx should use 102
```

## Consequences

### Positive

- Multi-transaction workflows work reliably (100% success rate, not ~33%)
- Escrow integration (create → finish) succeeds without manual delays
- Backwards compatible (new behavior is opt-out)
- Handles race condition where ledger query returns stale data
- Local tracking ensures consecutive signings use incrementing sequences
- 60-second TTL prevents issues with abandoned transactions
- Still respects external transactions (ledger query catches external increments)

### Negative

- Additional ledger query per sign operation (~100-500ms latency)
- In-memory state (sequence tracker) - lost on server restart
- Requires network connectivity for signing (previously could sign offline with pre-filled TX)
- If ledger is slow/unavailable, signing fails

### Mitigations

- `auto_sequence: false` allows offline signing when caller knows the exact sequence
- Sequence tracker is a simple singleton - no persistence needed (60s TTL handles edge cases)
- Connection pooling in XRPL client reduces latency
- Server restart resets tracker but ledger query provides baseline (only affects rapid multi-tx immediately after restart)

## Test Cases

```typescript
describe('Sequence Autofill', () => {
  it('should handle multiple sequential transactions', async () => {
    // Create and fund wallet
    const wallet = await createAndFundWallet();

    // Submit 3 transactions in sequence
    for (let i = 0; i < 3; i++) {
      const unsigned = buildPaymentTx(wallet.address, destination, '1000000');
      const signed = await walletSign({
        wallet_address: wallet.address,
        unsigned_tx: unsigned,
        // auto_sequence defaults to true
      });

      const result = await txSubmit({ signed_tx: signed.signed_tx });
      expect(result.result.success).toBe(true);
    }
  });

  it('should respect auto_sequence: false', async () => {
    // Build TX with specific sequence
    const unsigned = buildTxWithSequence(wallet.address, 42);

    const signed = await walletSign({
      wallet_address: wallet.address,
      unsigned_tx: unsigned,
      auto_sequence: false, // Use sequence from TX
    });

    // Transaction should have sequence 42
    const decoded = decode(signed.signed_tx);
    expect(decoded.Sequence).toBe(42);
  });
});
```

## Related

- [ADR-012: Escrow Integration Improvements](./ADR-012-escrow-integration-improvements.md)
- [MCP Integration Assessment](../../development/mcp-integration-assessment.md)
- [Network Timing Reference](../../user/reference/network-timing.md)
