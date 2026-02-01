# wallet_import

Import an existing XRPL wallet from a seed with a simple default policy.

## Overview

The `wallet_import` tool provides a simple way to import an existing XRPL wallet without configuring a complex policy. It's ideal for:

- Importing existing wallets for testing
- Quick setup without policy configuration
- Development and prototyping

For production use with custom policies, see [wallet_create](./wallet-create.md).

## Input Schema

```json
{
  "seed": "sEdT83jpRVETN98Kr934Dcgn2LTm7jh",
  "network": "testnet",      // Optional - defaults to server's network
  "wallet_name": "my-escrow-wallet"
}
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `seed` | string | Yes | XRPL seed (starts with 's') |
| `network` | string | No | Target network: `mainnet`, `testnet`, or `devnet`. Defaults to server's configured network (XRPL_NETWORK env var) |
| `wallet_name` | string | No | Human-readable name for the wallet |

### Seed Format

The seed must:
- Start with 's'
- Be 20-40 characters long
- Use valid Base58 characters (no 0, O, I, l)

Example valid seeds:
- `sEdT83jpRVETN98Kr934Dcgn2LTm7jh` (Ed25519)
- `snoPBrXtMeMyMHUVTgbuqAfg1SUTb` (secp256k1)

## Output Schema

```json
{
  "address": "rUVfn16TBbbTN67cNuDs2VHmNQAeGENac5",
  "public_key": "ED...",
  "wallet_id": "my-escrow-wallet",
  "network": "testnet",
  "policy_id": "testnet-default-1706745600000",
  "imported_at": "2026-01-31T19:00:00.000Z"
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `address` | string | XRPL r-address derived from the seed |
| `public_key` | string | Public key (hex encoded) |
| `wallet_id` | string | ID for future operations |
| `network` | string | Network the wallet is registered on |
| `policy_id` | string | ID of the applied default policy |
| `imported_at` | string | ISO 8601 timestamp |

## Default Policy

The imported wallet uses a simple default policy appropriate for the network:

### Testnet/Devnet Default

- **Autonomous tier**: Up to 10,000 XRP per transaction
- **Daily limit**: 100,000 XRP
- **Allowed types**: Payment, EscrowCreate, EscrowFinish, EscrowCancel
- **No destination restrictions**

### Mainnet Default

- **Autonomous tier**: Up to 100 XRP per transaction
- **Daily limit**: 1,000 XRP
- **Allowed types**: Payment, EscrowFinish, EscrowCancel
- **Known destinations required**

## Examples

### Basic Import

```json
{
  "tool": "wallet_import",
  "arguments": {
    "seed": "sEdT83jpRVETN98Kr934Dcgn2LTm7jh",
    "network": "testnet"
  }
}
```

### Import with Custom Name

```json
{
  "tool": "wallet_import",
  "arguments": {
    "seed": "sEdT83jpRVETN98Kr934Dcgn2LTm7jh",
    "network": "testnet",
    "wallet_name": "puzzle-escrow-wallet"
  }
}
```

## Security Considerations

1. **Seed Handling**: The seed is encrypted and stored securely using AES-256-GCM
2. **Memory Safety**: Seed material is zeroed after import using SecureBuffer
3. **Audit Trail**: Import event is logged to the tamper-evident audit log
4. **Network Isolation**: Wallet is registered for the specified network only

## Error Handling

| Error | Cause | Resolution |
|-------|-------|------------|
| `Invalid seed format` | Seed doesn't start with 's' or has invalid characters | Use a valid XRPL seed |
| `Invalid seed` | Seed fails cryptographic validation | Verify the seed is correct |
| `XRPL_WALLET_PASSWORD not set` | Missing environment variable | Set the password in environment |

## Comparison with wallet_create

| Feature | wallet_import | wallet_create |
|---------|--------------|---------------|
| Complexity | Simple | Complex |
| Policy | Default (automatic) | Custom (required) |
| Use case | Existing wallets | New wallets with specific policies |
| Input | Just seed + network | Full policy configuration |

## Related Tools

- [wallet_create](./wallet-create.md) - Create new wallet with custom policy
- [wallet_balance](./wallet-balance.md) - Check imported wallet balance
- [wallet_sign](./wallet-sign.md) - Sign transactions with imported wallet
- [wallet_list](./wallet-list.md) - List all wallets including imported ones
