# wallet_fund

Fund a wallet from the testnet or devnet faucet.

## Overview

| Property | Value |
|----------|-------|
| **Tool Name** | `wallet_fund` |
| **Sensitivity** | HIGH |
| **Rate Limit** | 5/hour per wallet |
| **Networks** | testnet, devnet only |
| **Version** | 2.0.0 (Updated 2026-01-29) |

## Description

Requests test XRP from the XRPL faucet for development and testing purposes. This tool only works on testnet and devnet - it will reject requests for mainnet wallets.

**Important**: As of early 2026, the testnet/devnet faucets provide approximately **100 XRP** (previously 1000 XRP). Do not hardcode expected balances - use the `initial_balance_drops` field from the response instead.

## Input Schema

```typescript
{
  network: 'testnet' | 'devnet',  // Required: target network
  wallet_address: string,         // Required: XRPL address to fund
  wait_for_confirmation?: boolean // Optional: wait for account to be queryable (default: true)
}
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `network` | `'testnet' \| 'devnet'` | Yes | - | Target network (mainnet not allowed) |
| `wallet_address` | `string` | Yes | - | XRPL address to receive test XRP |
| `wait_for_confirmation` | `boolean` | No | `true` | Wait for account to be queryable on the ledger |

### wait_for_confirmation Parameter

When `wait_for_confirmation` is `true` (default):
- The tool retries `account_info` up to **15 times** with **2-second intervals**
- Includes a 3-second initial wait after faucet response
- Total maximum wait: approximately **30 seconds**
- Returns `account_ready: true` only when the account is confirmed queryable

This is critical for escrow integration and automated workflows where you need to immediately use the funded account.

## Output Schema

### Success Response

```typescript
{
  status: 'funded',
  wallet_address: string,       // Funded address
  network: string,              // Network funded on
  faucet_url: string,           // Faucet endpoint used
  initial_balance_drops: string,// Actual balance in drops (use this, not hardcoded values!)
  account_ready: boolean,       // Whether account is queryable
  ledger_index?: number,        // Ledger where account was confirmed
  message: string               // Human-readable status message
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `status` | `'funded'` | Always 'funded' on success |
| `wallet_address` | `string` | The funded XRPL address |
| `network` | `string` | Network where funding occurred |
| `faucet_url` | `string` | The faucet endpoint that was used |
| `initial_balance_drops` | `string` | **Use this value** for balance verification in tests |
| `account_ready` | `boolean` | `true` if account is queryable on the validated ledger |
| `ledger_index` | `number` | Ledger index where the account was confirmed (when available) |
| `message` | `string` | Human-readable status (e.g., "Account funded and confirmed ready") |

### Error Response

```typescript
{
  error: {
    code: string,
    message: string,
    recovery?: string
  }
}
```

## Error Codes

| Code | Description | Recovery |
|------|-------------|----------|
| `NETWORK_NOT_SUPPORTED` | Mainnet funding not available | Use testnet or devnet |
| `FAUCET_UNAVAILABLE` | Faucet service unavailable | Retry later |
| `RATE_LIMITED` | Too many faucet requests | Wait and retry |
| `INVALID_ADDRESS` | Invalid XRPL address format | Check address format |

## Examples

### Fund Testnet Wallet (Default - Wait for Confirmation)

**Input:**
```json
{
  "network": "testnet",
  "wallet_address": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
}
```

**Output:**
```json
{
  "status": "funded",
  "wallet_address": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
  "network": "testnet",
  "faucet_url": "https://faucet.altnet.rippletest.net/accounts",
  "initial_balance_drops": "100000000",
  "account_ready": true,
  "ledger_index": 85432100,
  "message": "Account funded and confirmed ready"
}
```

### Fund Without Waiting

**Input:**
```json
{
  "network": "testnet",
  "wallet_address": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
  "wait_for_confirmation": false
}
```

**Output:**
```json
{
  "status": "funded",
  "wallet_address": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
  "network": "testnet",
  "faucet_url": "https://faucet.altnet.rippletest.net/accounts",
  "initial_balance_drops": "100000000",
  "account_ready": false,
  "message": "Account funded (confirmation not awaited)"
}
```

> **Note**: When `wait_for_confirmation: false`, the `account_ready` field will be `false` and `ledger_index` will not be present. The account may not be immediately queryable.

### Mainnet Rejection

**Input:**
```json
{
  "network": "mainnet",
  "wallet_address": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
}
```

**Output:**
```json
{
  "error": {
    "code": "NETWORK_NOT_SUPPORTED",
    "message": "Faucet funding is only available on testnet and devnet",
    "recovery": "Use testnet or devnet for testing, or fund mainnet wallets through exchanges"
  }
}
```

## Security Considerations

1. **Network Restriction**: Only testnet/devnet supported to prevent confusion
2. **Rate Limiting**: Prevents abuse of faucet resources
3. **Audit Logging**: All funding requests are logged
4. **Balance Verification**: Use `initial_balance_drops` for tests - never hardcode expected values

## Timing Considerations

The XRPL faucet funding process involves ledger propagation delays:

| Stage | Typical Duration |
|-------|------------------|
| Faucet API response | Immediate |
| Account visible on ledger | 5-20 seconds |
| Balance queryable | 0-3 seconds after visibility |

**Common Issue**: `actNotFound` errors occur when querying the account immediately after the faucet responds. The `wait_for_confirmation: true` option handles this automatically with retry logic.

**Best Practice for Tests**:
```typescript
// GOOD: Use actual balance from response
const fundResult = await wallet_fund({ wallet_address: addr, network: 'testnet' });
const initialBalance = parseInt(fundResult.initial_balance_drops);
// ... perform operations ...
expect(finalBalance).toBeLessThan(initialBalance);

// BAD: Hardcoded expectation (may fail if faucet amount changes)
expect(balance).toBe('100000000000'); // Assumes 1000 XRP - WRONG!
```

## Faucet Endpoints

| Network | Faucet URL |
|---------|------------|
| Testnet | `https://faucet.altnet.rippletest.net/accounts` |
| Devnet | `https://faucet.devnet.rippletest.net/accounts` |

## Related Tools

- [`wallet_create`](./wallet-create.md) - Create wallet before funding
- [`wallet_balance`](./wallet-balance.md) - Check balance after funding

## Related Documentation

- [Network Timing Reference](../../user/reference/network-timing.md) - Comprehensive guide on XRPL timing considerations
- [ADR-012: Escrow Integration Improvements](../../architecture/09-decisions/ADR-012-escrow-integration-improvements.md) - Decision record for timing enhancements

---

**Document History**

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-28 | Initial specification |
| 2.0.0 | 2026-01-29 | Added `wait_for_confirmation`, updated output schema, documented timing |
