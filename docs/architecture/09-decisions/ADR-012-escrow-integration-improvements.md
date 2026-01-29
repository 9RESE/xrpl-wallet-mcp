# ADR-012: Escrow Integration Improvements

**Status**: Accepted
**Date**: 2026-01-29
**Context**: xrpl-wallet-mcp + xrpl-escrow-mcp integration testing

## Decision Drivers

- Two-bot escrow testing revealed timing issues between wallet and escrow MCPs
- Balance queries returned stale data after transactions
- Faucet funding had no retry logic, causing `actNotFound` errors
- No way to track escrow transactions for finish/cancel operations

## Considered Options

1. Document workarounds and let consumers handle timing
2. Add timing parameters and enhanced responses to wallet MCP
3. Create a separate timing/coordination MCP

## Decision

Option 2: Enhance wallet MCP with timing-aware parameters and escrow-friendly responses.

## Changes Implemented

### 1. wallet_fund Enhancements

**Problem**: Faucet funding returns immediately but account isn't queryable for 5-20 seconds.

**Solution**:
- Added `wait_for_confirmation` parameter (default: true)
- Implemented retry loop: 15 attempts, 2-second intervals
- Return `initial_balance_drops` for test verification (don't hardcode faucet amounts)
- Return `account_ready` and `ledger_index` for status confirmation

```typescript
// New response fields
{
  status: 'funded',
  initial_balance_drops: '100000000',  // Use this, not hardcoded values
  account_ready: true,
  ledger_index: 12345678
}
```

### 2. wallet_balance Enhancements

**Problem**: Balance queries immediately after transactions return stale values.

**Solution**:
- Added `wait_after_tx` parameter (0-30000ms)
- Added `ledger_index` to response for consistency verification

```typescript
// Input
{ wallet_address: 'rXXX', wait_after_tx: 5000 }

// Response now includes
{ ledger_index: 12345678 }
```

### 3. tx_submit Enhancements

**Problem**: No way to track escrow transactions for subsequent finish/cancel.

**Solution**:
- Decode transaction before submission to extract metadata
- Return `tx_type` for routing logic
- Return `sequence_used` for escrow tracking
- Return `escrow_reference` for EscrowCreate transactions

```typescript
// Response for EscrowCreate
{
  tx_hash: 'ABC...',
  tx_type: 'EscrowCreate',
  sequence_used: 42,
  escrow_reference: {
    owner: 'rXXX...',
    sequence: 42  // Use this for EscrowFinish/EscrowCancel
  }
}
```

### 4. Configuration Updates

- Updated faucet amounts from 1000 to 100 XRP (reflects current testnet behavior)
- Added documentation warning not to hardcode faucet amounts

## Consequences

### Positive

- Automated workflows work reliably without manual delays
- Tests can use actual balances instead of hardcoded values
- Escrow lifecycle is fully trackable through tx_submit responses
- Ledger consistency is verifiable across queries

### Negative

- `wait_for_confirmation: true` adds 3-30 seconds to wallet_fund calls
- Additional response fields increase payload size slightly

### Neutral

- Existing consumers continue to work (new fields are additive)
- Network timing documentation helps developers understand XRPL behavior

## Related

- [MCP Integration Assessment](../../development/mcp-integration-assessment.md)
- [Network Timing Reference](../../user/reference/network-timing.md)
- [ADR-008: Integration Design](./ADR-008-integration-design.md)
