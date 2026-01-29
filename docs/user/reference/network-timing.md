# XRPL Network Timing Reference

This document explains timing considerations when working with the XRPL network, particularly for testnet/devnet development and escrow integration.

## Key Concepts

### Ledger Time vs Local Time

**Critical**: The XRPL validates time-based operations against the ledger close time, not your local wall clock time.

```
Local Time:    2026-01-29 10:00:00 UTC
Ledger Time:   2026-01-29 09:59:55 UTC (5 seconds behind)
```

The ledger close time may differ from local time by several seconds. This affects:
- Escrow FinishAfter/CancelAfter validation
- Time-locked transactions
- Status determination

**Solution**: Always use `ledger_index: 'validated'` and check `current_ledger_time` from responses.

### Ripple Epoch

XRPL uses the "Ripple Epoch" which starts at **January 1, 2000 00:00:00 UTC**.

```typescript
const RIPPLE_EPOCH = 946684800; // Unix timestamp

// Convert Unix to Ripple time
const rippleTime = unixTimestamp - RIPPLE_EPOCH;

// Convert Ripple to Unix time
const unixTime = rippleTime + RIPPLE_EPOCH;
```

---

## Network-Specific Timing

### Faucet Funding Delays

| Network | Faucet Amount | Account Active Delay |
|---------|--------------|---------------------|
| Testnet | ~100 XRP | 5-20 seconds |
| Devnet | ~100 XRP | 5-15 seconds |
| Mainnet | N/A | N/A |

**Note**: The faucet previously provided 1000 XRP. As of early 2026, testnet provides ~100 XRP.

### Transaction Confirmation

| Stage | Expected Time |
|-------|---------------|
| Submit to Pending | Immediate |
| Pending to Validated | 3-5 seconds |
| Balance Update | 0-3 seconds after validation |

### Balance Propagation

After a transaction is validated, the balance may take 0-3 additional seconds to reflect in `account_info` queries.

**Recommendation**: Use `wait_after_tx` parameter or add a 3-5 second delay before balance verification.

---

## Tool Parameters for Timing

### wallet_fund

```json
{
  "wallet_address": "rXXX...",
  "network": "testnet",
  "wait_for_confirmation": true  // Default: true
}
```

When `wait_for_confirmation` is `true`:
- Retries `account_info` up to 15 times
- 2-second delay between retries
- Total max wait: ~30 seconds

**Response includes**:
- `account_ready`: Whether account is queryable
- `initial_balance_drops`: Use this for test verification
- `ledger_index`: Ledger where account was confirmed

### wallet_balance

```json
{
  "wallet_address": "rXXX...",
  "wait_after_tx": 5000  // Wait 5 seconds before query
}
```

Use `wait_after_tx` after submitting transactions to ensure balance is updated.

**Response includes**:
- `ledger_index`: Use for consistency verification

### tx_submit

**Response includes**:
- `ledger_index`: Ledger where validated
- `sequence_used`: Sequence number consumed
- `escrow_reference`: For EscrowCreate, provides `owner` + `sequence` for finish/cancel

---

## Common Timing Issues

### 1. "actNotFound" After Faucet

**Symptom**: `account_info` fails immediately after `wallet_fund`.

**Cause**: Account not yet on validated ledger.

**Solution**:
```typescript
// Option A: Use wait_for_confirmation (recommended)
const fundResult = await wallet_fund({
  wallet_address: address,
  network: 'testnet',
  wait_for_confirmation: true  // Handles retry internally
});

// Option B: Manual retry (if wait_for_confirmation: false)
for (let i = 0; i < 10; i++) {
  try {
    const balance = await wallet_balance({ wallet_address: address });
    break;
  } catch {
    await sleep(2000);
  }
}
```

### 2. "tecNO_PERMISSION" on EscrowFinish

**Symptom**: Escrow shows as ready locally but `tecNO_PERMISSION` on finish.

**Cause**: Local time shows FinishAfter passed, but ledger time hasn't reached it.

**Solution**: Use `escrow_status` from escrow-mcp which uses ledger close time.

### 3. Stale Balance After Transaction

**Symptom**: Balance doesn't reflect transaction immediately.

**Cause**: Balance propagation delay (0-3 seconds).

**Solution**:
```typescript
const submitResult = await tx_submit({
  signed_tx: blob,
  network: 'testnet',
  wait_for_validation: true
});

// Wait before checking balance
const balance = await wallet_balance({
  wallet_address: address,
  wait_after_tx: 5000  // 5 second delay
});
```

---

## Best Practices

### 1. Always Use Validated Ledger

All queries should specify `ledger_index: 'validated'` (this is the default in our tools).

### 2. Verify with ledger_index

Compare `ledger_index` across responses to ensure consistency:

```typescript
const balance1 = await wallet_balance({ wallet_address: address });
// ... some operations ...
const balance2 = await wallet_balance({ wallet_address: address });

if (balance2.ledger_index > balance1.ledger_index) {
  console.log('Balance is from a later ledger');
}
```

### 3. Use initial_balance_drops for Tests

Don't hardcode expected balances:

```typescript
// Bad: Hardcoded expectation
expect(balance).toBeGreaterThan(100_000_000_000); // Assumes 1000 XRP

// Good: Use actual initial balance
const fundResult = await wallet_fund({ ... });
const initialBalance = parseInt(fundResult.initial_balance_drops);
expect(finalBalance).toBeGreaterThan(initialBalance - 10_000_000);
```

### 4. Build in Retry Logic for Critical Operations

```typescript
async function retryOperation<T>(
  operation: () => Promise<T>,
  maxRetries: number = 5,
  delayMs: number = 2000
): Promise<T> {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await operation();
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      await sleep(delayMs);
    }
  }
  throw new Error('Should not reach here');
}
```

---

## Escrow-Specific Timing

### Time Constraint Rules

1. `CancelAfter` must be greater than `FinishAfter` when both are specified
2. Both times must be in the future at transaction submission
3. Times are validated against ledger close time, not local time

### Escrow Lifecycle Timing

```
Create      Finish Window          Cancel Window
  |              |                      |
  v              v                      v
  [FinishAfter] --> [CancelAfter] --> [Expired]
       ^                  ^
       |                  |
   Can finish         Can cancel
```

### Status Determination

The `escrow_status` tool uses ledger close time for accurate status:

- `pending`: Before FinishAfter (or has condition not yet fulfilled)
- `ready_to_finish`: FinishAfter passed, before CancelAfter
- `ready_to_cancel`: CancelAfter passed

---

## Reference: Network Endpoints

| Network | WebSocket URL | Faucet URL |
|---------|--------------|------------|
| Mainnet | `wss://xrplcluster.com` | N/A |
| Testnet | `wss://s.altnet.rippletest.net:51233` | `https://faucet.altnet.rippletest.net/accounts` |
| Devnet | `wss://s.devnet.rippletest.net:51233` | `https://faucet.devnet.rippletest.net/accounts` |

---

*Last updated: 2026-01-29*
