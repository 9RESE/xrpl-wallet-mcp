# ADR-013: Transaction Sequence Autofill

**Status**: Accepted
**Date**: 2026-01-29
**Context**: Multi-transaction workflow failures in escrow integration testing

## Decision Drivers

- Sequential transactions from the same wallet fail with `tefPAST_SEQ` errors
- The wallet MCP signs transactions as-received without verifying sequence freshness
- Escrow workflows require multiple transactions (create → finish) from the same account
- Separation of concerns between escrow-mcp (builds TX) and wallet-mcp (signs TX) creates a timing gap

## Problem Statement

When an AI agent executes multiple transactions in sequence:

1. Transaction A is built by escrow-mcp (autofilled with sequence N)
2. Transaction A is signed by wallet-mcp
3. Transaction A is submitted and validated (account sequence now N+1)
4. Transaction B is built by escrow-mcp (may autofill with stale sequence N)
5. Transaction B fails with `tefPAST_SEQ`

The root cause is that the unsigned transaction's sequence may be stale by the time it reaches wallet_sign.

## Considered Options

### Option 1: Document and Require Caller to Handle
- Let escrow-mcp or callers manage sequence
- Wallet-mcp signs whatever it receives
- **Rejected**: Creates fragile workflows, error-prone

### Option 2: Track Sequence Locally After Submit
- Maintain per-wallet sequence in memory
- Increment after successful submission
- **Rejected**: Complex state management, doesn't handle external transactions

### Option 3: Autofill Fresh Sequence Before Signing (Selected)
- Query ledger for current sequence before signing
- Apply fresh sequence if transaction has stale/missing sequence
- Optionally allow caller to disable this behavior

### Option 4: Hybrid - Local Track + Ledger Validation
- Track locally for performance
- Validate against ledger periodically
- **Considered but simplified**: Option 3 is simpler and sufficient

## Decision

**Implement Option 3**: Autofill fresh sequence from ledger before signing.

### Behavior

1. When `wallet_sign` is called:
   - Decode the unsigned transaction
   - Query `account_info` from validated ledger to get current sequence
   - If transaction's Sequence differs from ledger, update it
   - Also autofill Fee and LastLedgerSequence if missing
   - Re-encode and sign the transaction

2. New parameter `auto_sequence` (default: `true`):
   - When `true`: Always fetch fresh sequence from ledger
   - When `false`: Use sequence from unsigned_tx as-is (legacy behavior)

### Implementation Details

```typescript
// In wallet-sign.ts handler
if (input.auto_sequence !== false) {
  // Get fresh account info from ledger
  const accountInfo = await xrplClient.getAccountInfo(input.wallet_address);

  // Update sequence in decoded transaction
  decoded.Sequence = accountInfo.sequence;

  // Autofill Fee if missing (use network fee)
  if (!decoded.Fee) {
    decoded.Fee = await xrplClient.getFee();
  }

  // Set LastLedgerSequence if missing (current + 20)
  if (!decoded.LastLedgerSequence) {
    const currentLedger = await xrplClient.getCurrentLedgerIndex();
    decoded.LastLedgerSequence = currentLedger + 20;
  }

  // Re-encode for signing
  unsignedTx = encode(decoded);
}
```

## Consequences

### Positive

- Multi-transaction workflows work reliably
- Escrow integration (create → finish) succeeds without manual delays
- Backwards compatible (new behavior is opt-out)
- Single source of truth for sequence (ledger)
- Handles external transactions that may have incremented sequence

### Negative

- Additional ledger query per sign operation (~100-500ms latency)
- Requires network connectivity for signing (previously could sign offline with pre-filled TX)
- If ledger is slow/unavailable, signing fails

### Mitigations

- `auto_sequence: false` allows offline signing when caller knows the exact sequence
- Caching could be added later for performance (with short TTL)
- Connection pooling in XRPL client reduces latency

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
