# MCP Integration Assessment: Wallet + Escrow

**Date**: 2026-01-29
**Reviewer**: Claude
**Based On**: agent2escrow test findings and code review
**Status**: Assessment Complete

---

## Executive Summary

The two-bot escrow test framework revealed several critical integration issues between `xrpl-wallet-mcp` and `xrpl-escrow-mcp`. This assessment consolidates findings, identifies current gaps, and proposes improvements for seamless interoperability.

**Key Finding**: The escrow MCP has already addressed most critical issues identified in testing. The wallet MCP requires significant implementation work.

---

## Current State Analysis

### xrpl-escrow-mcp: Well-Implemented ✅

| Issue | Status | Evidence |
|-------|--------|----------|
| Ledger time for status | ✅ Fixed | `escrow-status.ts:106-110` queries validated ledger |
| Time constraint validation | ✅ Fixed | `escrow-create.ts:110-122` validates finish_after < cancel_after |
| Escrow index calculation | ✅ Implemented | `escrow-status.ts:17-35` uses proper keylet pattern |
| list_escrows uses ledger time | ✅ Fixed | `list-escrows.ts:61-65` queries ledger close_time |
| Fulfillment pre-validation | ✅ Implemented | `escrow-finish.ts:74-107` validates before network call |

### xrpl-wallet-mcp: Needs Work ⚠️

| Feature | Status | Location |
|---------|--------|----------|
| wallet_fund implementation | ❌ Placeholder | `wallet-fund.ts:30-45` returns error |
| Faucet retry logic | ❌ Missing | Not implemented |
| wait_for_confirmation | ❌ Missing | Not in schema |
| ledger_index in balance | ❌ Missing | `wallet-balance.ts` doesn't return it |
| tx_submit has ledger_index | ✅ Present | `tx-submit.ts:50` |

---

## Critical Issues Requiring Action

### 1. Wallet Faucet Implementation (P0 - Blocking)

**Current State**: `wallet_fund` returns a placeholder error directing users to the manual faucet.

**Impact**:
- Tests required custom workarounds
- Cannot automate wallet setup
- Breaks agent autonomy

**Required Implementation**:
```typescript
// wallet-fund.ts - Required implementation
export async function handleWalletFund(
  context: ServerContext,
  input: WalletFundInput
): Promise<WalletFundOutput> {
  const { xrplClient } = context;

  // Use xrpl.js fundWallet method
  const fundResult = await xrplClient.fundWallet(input.wallet_address);

  // Retry loop until account is queryable on validated ledger
  const maxRetries = 10;
  const retryDelay = 2000; // 2 seconds

  for (let i = 0; i < maxRetries; i++) {
    try {
      const accountInfo = await xrplClient.getAccountInfo(input.wallet_address);
      return {
        status: 'success',
        balance_drops: accountInfo.balance,
        initial_balance_drops: accountInfo.balance,
        tx_hash: fundResult.hash,
        account_ready: true,
      };
    } catch {
      await new Promise(r => setTimeout(r, retryDelay));
    }
  }

  // Account not yet confirmed but funding submitted
  return {
    status: 'pending',
    tx_hash: fundResult.hash,
    account_ready: false,
    message: 'Funding submitted but account not yet confirmed. Retry getBalance in 5-10 seconds.',
  };
}
```

**Schema Changes Needed**:
```typescript
// Add to WalletFundOutput
export const WalletFundOutputSchema = z.object({
  status: z.enum(['success', 'pending', 'failed']),
  balance_drops: z.string().optional(),
  initial_balance_drops: z.string().optional(),  // NEW
  tx_hash: z.string().optional(),
  account_ready: z.boolean().optional(),         // NEW
  error: z.string().optional(),
  message: z.string().optional(),
});
```

---

### 2. Balance Query Timing (P1)

**Problem**: Balance queries after transactions return stale data.

**Current Workaround in Tests**: 5-second sleep before balance check.

**Recommended Solutions**:

**Option A: Add delay parameter to wallet_balance**
```typescript
// Schema addition
wait_after_tx: z.number().min(0).max(10000).optional(),
// Usage: wait N ms before querying

// Implementation
if (input.wait_after_tx) {
  await new Promise(r => setTimeout(r, input.wait_after_tx));
}
const accountInfo = await xrplClient.getAccountInfo(input.wallet_address);
```

**Option B: Add ledger_index to response for verification**
```typescript
// Add to WalletBalanceOutput
ledger_index: z.number(),

// Implementation - use specific ledger
const ledgerResponse = await xrplClient.request({
  command: 'ledger',
  ledger_index: 'validated',
});
return {
  ...balanceData,
  ledger_index: ledgerResponse.result.ledger.ledger_index,
};
```

---

### 3. Network-Aware Documentation (P2)

**Issue**: Testnet faucet amounts changed from 1000 XRP to 100 XRP.

**Impact**: Hard-coded test expectations fail.

**Solution**: Document network-specific behaviors.

```markdown
## Network Configuration Reference

| Network | Faucet URL | Amount | Account Delay |
|---------|------------|--------|---------------|
| Testnet | altnet.rippletest.net | ~100 XRP | 5-20s |
| Devnet | s.devnet.rippletest.net | ~100 XRP | 5-15s |
| Mainnet | N/A | N/A | N/A |

### Expected Delays
- **Faucet → Account Active**: 5-20 seconds
- **TX Submit → Balance Update**: 3-8 seconds
- **Escrow Create → Status Available**: 3-8 seconds
```

---

## Integration Improvements

### 4. Shared Error Codes

**Current**: Each MCP uses different error structures.

**Proposed**: Standardize error codes across both MCPs.

```typescript
// Shared error catalog (proposed)
export const XrplMcpErrors = {
  // Network errors
  NETWORK_UNREACHABLE: { code: 'NET001', recoverable: true },
  LEDGER_NOT_FOUND: { code: 'NET002', recoverable: true },

  // Account errors
  ACCOUNT_NOT_FOUND: { code: 'ACC001', recoverable: true },
  ACCOUNT_UNFUNDED: { code: 'ACC002', recoverable: true },
  INSUFFICIENT_BALANCE: { code: 'ACC003', recoverable: false },

  // Escrow errors
  ESCROW_NOT_FOUND: { code: 'ESC001', recoverable: false },
  ESCROW_TIME_NOT_REACHED: { code: 'ESC002', recoverable: true },
  ESCROW_EXPIRED: { code: 'ESC003', recoverable: false },

  // Transaction errors
  TX_SUBMISSION_FAILED: { code: 'TX001', recoverable: true },
  TX_VALIDATION_FAILED: { code: 'TX002', recoverable: false },
} as const;
```

### 5. Response Field Consistency

**Observation**: Different field naming conventions.

| Field | wallet-mcp | escrow-mcp | Recommendation |
|-------|------------|------------|----------------|
| Time | `queried_at` | `current_ledger_time` | Add both |
| Ledger | `ledger_index` (in tx_submit) | Not in escrow responses | Add `ledger_index` to both |
| Address | `address` | `owner` / `sender` | Consistent with XRPL terms |

### 6. Transaction Lifecycle Coordination

**Problem**: No built-in way to verify escrow creation succeeded.

**Current Flow**:
```
escrow_create (unsigned_tx) → wallet_sign → tx_submit → ??? → escrow_status
                                                        ^
                                               (Unknown delay)
```

**Proposed Enhancement**: `tx_submit` should return enough context.

```typescript
// Enhanced tx_submit response
export interface TxSubmitOutput {
  tx_hash: string;
  result: TxResult;
  ledger_index: number;
  submitted_at: string;
  validated_at?: string;

  // NEW: Transaction type-specific data
  tx_type: string;          // 'EscrowCreate', 'EscrowFinish', etc.
  sequence_used?: number;   // Account sequence consumed

  // For EscrowCreate: enough info to query status
  escrow_reference?: {
    owner: string;
    sequence: number;       // The OfferSequence for finish/cancel
  };
}
```

---

## New Feature Proposals

### 7. Escrow Index Tracking (Medium Priority)

**Problem**: Escrow identification relies on sequence number, which requires a transaction lookup.

**Proposal**: Return and track escrow ledger entry index.

**Escrow MCP Enhancement**:
```typescript
// escrow-create response addition
export interface EscrowCreateResponse {
  unsigned_tx: string;
  transaction: EscrowCreate;
  // NEW: Pre-calculated index for direct lookup after creation
  expected_escrow_index?: string;  // Can be calculated from account + sequence
}

// New tool: escrow_lookup_by_index
export interface EscrowLookupByIndexInput {
  escrow_index: string;  // 64-char hex ledger entry index
}
```

### 8. Batch Operations (Low Priority)

**Use Case**: Multi-party escrows, bulk status checks.

**Proposal**: Add batch tools.

```typescript
// Batch status check
export interface BatchEscrowStatusInput {
  escrows: Array<{
    owner: string;
    sequence: number;
  }>;
}

// Batch balance check
export interface BatchBalanceInput {
  addresses: string[];
}
```

### 9. Event Subscription (Future)

**Use Case**: Real-time notification when escrow becomes finishable.

**Proposal**: WebSocket subscription for escrow events.

```typescript
// Subscribe to escrow state changes
export interface EscrowSubscribeInput {
  owner: string;
  sequence: number;
  notify_on: ('ready_to_finish' | 'ready_to_cancel' | 'finished' | 'canceled')[];
}
```

---

## Documentation Gaps

### For Both MCPs

| Gap | Impact | Priority |
|-----|--------|----------|
| Ledger time vs local time explanation | Test failures | High |
| Reserve requirements by network | Balance calculation errors | Medium |
| Transaction lifecycle timing | Race conditions | High |
| Multi-escrow management patterns | Complex workflows | Low |

### Proposed Documentation Structure

```
docs/
├── integration/
│   ├── wallet-escrow-workflow.md      # Full workflow guide
│   ├── timing-considerations.md       # Ledger time, delays
│   ├── error-handling-patterns.md     # Error recovery
│   └── testing-with-testnet.md        # Test best practices
└── api/
    └── shared-error-codes.md          # Cross-MCP error reference
```

---

## Implementation Priority Matrix

| Priority | Item | MCP | Effort | Impact |
|----------|------|-----|--------|--------|
| **P0** | Implement wallet_fund with retry | wallet | Medium | Critical |
| **P1** | Add ledger_index to wallet_balance | wallet | Low | High |
| **P1** | Add wait_for_confirmation to wallet_fund | wallet | Low | High |
| **P1** | Document timing expectations | both | Low | High |
| **P2** | Standardize error codes | both | Medium | Medium |
| **P2** | Add sequence_used to tx_submit | wallet | Low | Medium |
| **P3** | Escrow index tracking | escrow | Medium | Low |
| **P3** | Batch operations | both | High | Low |

---

## Test Coverage Recommendations

### Integration Test Suite

```typescript
describe('Wallet + Escrow Integration', () => {
  describe('Full Escrow Lifecycle', () => {
    test('time-based escrow: create → wait → finish');
    test('conditional escrow: create → fulfill → finish');
    test('escrow cancellation after timeout');
    test('escrow with insufficient balance');
  });

  describe('Timing Edge Cases', () => {
    test('balance check immediately after faucet');
    test('escrow status at exact finish time');
    test('finish attempt before ledger time reached');
  });

  describe('Error Recovery', () => {
    test('retry on network disconnect');
    test('handle stale balance');
    test('recover from partial workflow');
  });
});
```

---

## Summary of Required Changes

### xrpl-wallet-mcp (12 items)

1. ✅ **tx_submit**: Already returns ledger_index
2. ❌ **wallet_fund**: Implement faucet integration
3. ❌ **wallet_fund**: Add retry until account queryable
4. ❌ **wallet_fund**: Return initial_balance_drops
5. ❌ **wallet_fund**: Return account_ready flag
6. ❌ **wallet_balance**: Add ledger_index to response
7. ❌ **wallet_balance**: Add optional wait_after_tx parameter
8. ❌ **tx_submit**: Return sequence_used
9. ❌ **tx_submit**: Return escrow_reference for EscrowCreate
10. ❌ **Schema**: Update WalletFundOutput
11. ❌ **Schema**: Update WalletBalanceOutput
12. ❌ **Docs**: Network timing documentation

### xrpl-escrow-mcp (4 items - mostly complete)

1. ✅ **escrow_status**: Uses ledger close time
2. ✅ **escrow_create**: Validates time constraints
3. ✅ **list_escrows**: Uses ledger close time
4. ❌ **Docs**: Add timing/delay documentation

---

## Appendix: Test Findings Traceability

| Finding | Document Reference | Status |
|---------|-------------------|--------|
| Ledger time vs local time | escrow-test-findings.md §1 | Fixed in escrow MCP |
| Account propagation delay | escrow-test-findings.md §2 | Wallet MCP needs work |
| Balance check timing | escrow-test-findings.md §3 | Wallet MCP needs work |
| CancelAfter > FinishAfter | escrow-test-findings.md §4 | Fixed in escrow MCP |
| Escrow identification | escrow-test-findings.md §5 | Enhancement proposed |
| Conditional escrow fees | escrow-test-findings.md §6 | Uses autofill (acceptable) |
| Faucet balance changes | escrow-test-findings.md §7 | Documentation needed |

---

*Assessment completed 2026-01-29*
