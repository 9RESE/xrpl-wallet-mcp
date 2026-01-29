# wallet_fund

Fund a wallet from the testnet or devnet faucet.

## Overview

| Property | Value |
|----------|-------|
| **Tool Name** | `wallet_fund` |
| **Sensitivity** | HIGH |
| **Rate Limit** | 5/hour per wallet |
| **Networks** | testnet, devnet only |

## Description

Requests test XRP from the XRPL faucet for development and testing purposes. This tool only works on testnet and devnet - it will reject requests for mainnet wallets.

## Input Schema

```typescript
{
  network: 'testnet' | 'devnet',  // Required: target network
  wallet_address: string          // Required: XRPL address to fund
}
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `network` | `'testnet' \| 'devnet'` | Yes | Target network (mainnet not allowed) |
| `wallet_address` | `string` | Yes | XRPL address to receive test XRP |

## Output Schema

### Success Response

```typescript
{
  success: true,
  wallet_address: string,    // Funded address
  amount_xrp: string,        // Amount received (usually "1000")
  tx_hash: string,           // Faucet transaction hash
  network: string,           // Network funded on
  balance_after_xrp: string  // New balance
}
```

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

### Fund Testnet Wallet

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
  "success": true,
  "wallet_address": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
  "amount_xrp": "1000",
  "tx_hash": "A1B2C3D4E5F6789...",
  "network": "testnet",
  "balance_after_xrp": "1000"
}
```

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

## Faucet Endpoints

| Network | Faucet URL |
|---------|------------|
| Testnet | `https://faucet.altnet.rippletest.net/accounts` |
| Devnet | `https://faucet.devnet.rippletest.net/accounts` |

## Related Tools

- [`wallet_create`](./wallet-create.md) - Create wallet before funding
- [`wallet_balance`](./wallet-balance.md) - Check balance after funding
