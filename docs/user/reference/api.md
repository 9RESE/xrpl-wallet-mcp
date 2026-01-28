# API Reference

Quick reference for XRPL Agent Wallet MCP tools. For detailed specifications, see the individual tool documentation in [/docs/api/tools/](/docs/api/tools/).

---

## Overview

The XRPL Agent Wallet MCP server exposes 10 tools for AI agents to interact with the XRP Ledger securely. All tools follow the Model Context Protocol (MCP) specification and enforce policy-based security controls.

### Tool Categories

| Category | Tools | Purpose |
|----------|-------|---------|
| **Wallet Management** | `wallet_create`, `wallet_list`, `wallet_balance`, `wallet_rotate` | Wallet lifecycle and state |
| **Transaction** | `wallet_sign`, `tx_submit`, `tx_decode` | Transaction signing and submission |
| **Policy** | `wallet_policy_check`, `policy_set` | Security policy management |
| **History** | `wallet_history` | Transaction history retrieval |

---

## Tool Summary

| Tool | Sensitivity | Description | Rate Limit |
|------|-------------|-------------|------------|
| [`wallet_create`](#wallet_create) | Administrative | Create new XRPL wallet with policy | N/A |
| [`wallet_list`](#wallet_list) | Low | List managed wallets | Standard |
| [`wallet_balance`](#wallet_balance) | Low | Query wallet balance and state | Standard |
| [`wallet_history`](#wallet_history) | Low | Retrieve transaction history | Standard |
| [`wallet_sign`](#wallet_sign) | CRITICAL | Sign transactions with policy enforcement | 10/min |
| [`wallet_rotate`](#wallet_rotate) | DESTRUCTIVE | Rotate wallet regular key | 1/24h |
| [`wallet_policy_check`](#wallet_policy_check) | Medium | Dry-run policy evaluation | Standard |
| [`policy_set`](#policy_set) | CRITICAL | Update wallet security policy | N/A |
| [`tx_decode`](#tx_decode) | Low | Decode transaction blob | Standard |
| [`tx_submit`](#tx_submit) | HIGH | Submit signed transaction to XRPL | 10/min |

---

## Common Patterns

### Request Format

All tool calls follow the MCP JSON-RPC format:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "tool_name",
    "arguments": {
      "param1": "value1",
      "param2": "value2"
    }
  },
  "id": "request-id"
}
```

### Response Format

**Success Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "success": true,
    "data": { ... }
  },
  "id": "request-id"
}
```

**Error Response:**

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32000,
    "message": "Error description",
    "data": {
      "code": "ERROR_CODE",
      "details": { ... }
    }
  },
  "id": "request-id"
}
```

### Error Handling

Tools use discriminated union responses for predictable error handling:

```typescript
// Check response type using discriminator field
if (response.status === 'validated') {
  // Transaction succeeded
} else if (response.status === 'pending_approval') {
  // Requires human approval (Tier 2 or 3)
} else if (response.status === 'rejected') {
  // Policy violation or error
}
```

### Common Validation Rules

| Field Type | Pattern | Example |
|------------|---------|---------|
| XRPL Address | `^r[1-9A-HJ-NP-Za-km-z]{24,34}$` | `rN7n3473SaZBCG4dFL83w7a1RXtXtbK2D9` |
| Transaction Hash | `^[A-Fa-f0-9]{64}$` | `E08D6E9754025BA2534A78707605E0601F03ACE...` |
| Drops Amount | `^\d+$` | `"50000000"` (50 XRP) |
| Network | `mainnet`, `testnet`, `devnet` | `"testnet"` |

---

## Tool Reference

### wallet_create

Creates a new XRPL wallet with policy-based security controls.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `network` | enum | Yes | `mainnet`, `testnet`, or `devnet` |
| `policy` | object | Yes | Security policy configuration |
| `wallet_name` | string | No | Human-readable name (max 64 chars) |
| `funding_source` | string | No | XRPL address for funding |
| `initial_funding_drops` | string | No | Suggested funding amount |

**Output:**

| Field | Type | Description |
|-------|------|-------------|
| `wallet_id` | string | Unique wallet identifier |
| `address` | string | XRPL account address |
| `public_key` | string | Public key (hex) |
| `network` | string | Target network |
| `policy_id` | string | Associated policy ID |

**Example:**

```typescript
const result = await mcp.callTool("wallet_create", {
  network: "testnet",
  wallet_name: "trading-agent-alpha",
  policy: {
    limits: { max_amount_per_tx_drops: "50000000" },
    destinations: { mode: "open" }
  }
});
```

See: [/docs/api/tools/wallet-create.md](/docs/api/tools/wallet-create.md)

---

### wallet_list

Lists all managed wallets with optional filtering.

**Input:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `network` | enum | No | all | Filter by network |
| `include_inactive` | boolean | No | true | Include inactive wallets |
| `sort_by` | enum | No | `created_at` | Sort field |
| `limit` | number | No | 50 | Results per page (max 100) |
| `offset` | number | No | 0 | Pagination offset |

**Output:**

| Field | Type | Description |
|-------|------|-------------|
| `wallets` | array | List of wallet summaries |
| `total` | number | Total wallet count |
| `has_more` | boolean | More results available |

**Example:**

```typescript
const wallets = await mcp.callTool("wallet_list", {
  network: "mainnet",
  include_policy_summary: true
});
```

See: [/docs/api/tools/wallet-list.md](/docs/api/tools/wallet-list.md)

---

### wallet_balance

Queries current balance and account state for a wallet.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `wallet_id` | string | One of | Managed wallet ID |
| `address` | string | One of | XRPL r-address |
| `include_signer_list` | boolean | No | Include signer config |
| `include_policy_status` | boolean | No | Include policy limits |
| `ledger_index` | string/number | No | Ledger to query |

**Output:**

| Field | Type | Description |
|-------|------|-------------|
| `address` | string | XRPL address |
| `balance.xrp` | string | Total XRP balance |
| `balance.drops` | string | Balance in drops |
| `balance.available_xrp` | string | Spendable after reserves |
| `reserves.base_drops` | string | Base reserve (10 XRP) |
| `reserves.owner_drops` | string | Owner reserve per object |
| `account.sequence` | number | Account sequence |
| `account.regular_key` | string | Regular key (if set) |

**Example:**

```typescript
const balance = await mcp.callTool("wallet_balance", {
  address: "rN7n3473SaZBCG4dFL83w7a1RXtXtbK2D9",
  include_policy_status: true
});
// balance.balance.available_xrp = "89.5"
```

See: [/docs/api/tools/wallet-balance.md](/docs/api/tools/wallet-balance.md)

---

### wallet_history

Retrieves transaction history with filtering and pagination.

**Input:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `wallet_id` | string | One of | - | Managed wallet ID |
| `address` | string | One of | - | XRPL r-address |
| `limit` | number | No | 20 | Max transactions (1-100) |
| `marker` | object | No | - | Pagination marker |
| `filters.transaction_types` | array | No | all | Filter by TX types |
| `filters.start_time` | string | No | - | ISO 8601 start time |
| `filters.end_time` | string | No | - | ISO 8601 end time |

**Output:**

| Field | Type | Description |
|-------|------|-------------|
| `transactions` | array | Transaction list |
| `marker` | object | Next page marker |
| `has_more` | boolean | More pages available |

**Example:**

```typescript
const history = await mcp.callTool("wallet_history", {
  address: "rN7n3473SaZBCG4dFL83w7a1RXtXtbK2D9",
  limit: 10,
  filters: { transaction_types: ["Payment"] }
});
```

See: [/docs/api/tools/wallet-history.md](/docs/api/tools/wallet-history.md)

---

### wallet_sign

Signs a transaction with policy enforcement. Most security-critical tool.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `wallet_address` | string | Yes | XRPL address to sign with |
| `unsigned_tx` | string | Yes | Hex-encoded unsigned TX blob |
| `context` | string | No | Reason for audit trail (max 500 chars) |

**Output (Discriminated Union):**

| Status | Description |
|--------|-------------|
| `approved` | Transaction signed (Tier 1) |
| `pending_approval` | Awaiting approval (Tier 2/3) |
| `rejected` | Policy violation |

**Approved Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `signed_tx` | string | Signed transaction blob |
| `tx_hash` | string | Transaction hash |
| `policy_tier` | number | Tier level (1) |

**Example:**

```typescript
const result = await mcp.callTool("wallet_sign", {
  wallet_address: "rN7n3473SaZBCG4dFL83w7a1RXtXtbK2D9",
  unsigned_tx: "1200002280000000240000000161...",
  context: "Payment for invoice #12345"
});

if (result.status === "approved") {
  // Submit signed transaction
  await mcp.callTool("tx_submit", {
    signed_tx: result.signed_tx,
    network: "mainnet"
  });
}
```

See: [/docs/api/tools/wallet-sign.md](/docs/api/tools/wallet-sign.md)

---

### wallet_rotate

Rotates the regular key for a wallet. Requires Tier 3 human approval.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `wallet_address` | string | Yes | Wallet to rotate |
| `reason` | enum | Yes | Rotation reason |
| `reason_description` | string | Conditional | Required for `other`/`incident_response` |
| `create_backup` | boolean | No | Create encrypted backup (default: true) |
| `force` | boolean | No | Bypass 24h cooldown |

**Reason Values:** `scheduled`, `personnel_change`, `suspected_compromise`, `security_upgrade`, `incident_response`, `compliance`, `other`

**Output (Discriminated Union):**

| Status | Description |
|--------|-------------|
| `pending_approval` | Awaiting Tier 3 approval |
| `completed` | Rotation complete |
| `rejected` | Rotation rejected or failed |

See: [/docs/api/tools/wallet-rotate.md](/docs/api/tools/wallet-rotate.md)

---

### wallet_policy_check

Dry-run policy evaluation without signing.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `wallet_address` | string | Yes | Wallet address |
| `transaction` | object | Yes | Proposed transaction |
| `include_limit_details` | boolean | No | Include full limit tracking |

**Transaction Object:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `transaction_type` | string | Yes | XRPL transaction type |
| `destination` | string | No | Destination address |
| `amount_xrp` | string | No | Amount in XRP |
| `amount_drops` | string | No | Amount in drops |

**Output:**

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | boolean | Would transaction be allowed |
| `tier` | object | Policy tier classification |
| `tier.level` | number | Tier level (1-4) |
| `tier.name` | string | `autonomous`, `delayed`, `cosign`, `prohibited` |
| `reason` | string | Human-readable explanation |
| `violations` | array | Policy violations (if any) |
| `limits` | object | Remaining limits |

**Example:**

```typescript
const check = await mcp.callTool("wallet_policy_check", {
  wallet_address: "rN7n3473SaZBCG4dFL83w7a1RXtXtbK2D9",
  transaction: {
    transaction_type: "Payment",
    destination: "rDestination123456789012345678",
    amount_xrp: "100"
  }
});

if (check.tier.level <= 1) {
  // Can sign autonomously
} else {
  // Inform user about approval requirements
}
```

See: [/docs/api/tools/wallet-policy-check.md](/docs/api/tools/wallet-policy-check.md)

---

### policy_set

Updates wallet security policy. Critical operation.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `wallet_address` | string | Yes | Wallet to update |
| `policy` | object | Yes | Policy fields to update |
| `mode` | enum | No | `merge` (default) or `replace` |
| `reason` | string | Yes | Change reason (min 10 chars) |
| `approval_id` | string | Conditional | Required for restricted fields |

**Restricted Fields (Require Tier 3 Approval):**
- Increasing `limits.max_amount_per_tx_drops`
- Increasing `limits.max_daily_volume_drops`
- Changing `escalation` thresholds
- Adding to `transaction_types.allowed`
- Changing `destinations.mode` to `open`

**Output (Discriminated Union):**

| Status | Description |
|--------|-------------|
| `success: true` | Policy updated |
| `success: false, status: pending_approval` | Awaiting approval |
| Error | Validation or permission error |

**Example:**

```typescript
const result = await mcp.callTool("policy_set", {
  wallet_address: "rN7n3473SaZBCG4dFL83w7a1RXtXtbK2D9",
  policy: {
    destinations: {
      allowlist: ["rTrustedAddress123456789012345"]
    }
  },
  mode: "merge",
  reason: "Adding trusted payment destination for vendor payments"
});
```

See: [/docs/api/tools/policy-set.md](/docs/api/tools/policy-set.md)

---

### tx_decode

Decodes unsigned transaction blob for inspection.

**Input:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `unsigned_tx` | string | Yes | - | Hex-encoded transaction blob |
| `include_raw_fields` | boolean | No | false | Include raw values |
| `format_amounts` | boolean | No | true | Convert drops to XRP |

**Output:**

| Field | Type | Description |
|-------|------|-------------|
| `transaction` | object | Decoded transaction fields |
| `transaction_type_info` | object | Transaction type metadata |
| `flags_readable` | array | Human-readable flag names |
| `amounts_formatted` | object | Amounts in XRP |
| `warnings` | array | Potential issues |

**Example:**

```typescript
const decoded = await mcp.callTool("tx_decode", {
  unsigned_tx: "1200002280000000240000000161D4838D7EA4C6800000..."
});
// decoded.transaction.TransactionType = "Payment"
// decoded.amounts_formatted.Amount = "50.0 XRP"
```

See: [/docs/api/tools/tx-decode.md](/docs/api/tools/tx-decode.md)

---

### tx_submit

Submits signed transaction to XRPL network.

**Input:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `signed_tx` | string | Yes | - | Signed transaction blob |
| `network` | enum | Yes | - | Target network |
| `wait_for_final` | boolean | No | true | Wait for ledger validation |
| `timeout_seconds` | number | No | 30 | Validation timeout (5-60) |
| `fail_if_pending` | boolean | No | false | Fail if already pending |

**Output (Discriminated Union):**

| Status | Description |
|--------|-------------|
| `validated` | Transaction validated in ledger |
| `pending` | Submitted but not yet validated |
| `failed` | Submission or validation failed |

**Validated Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `tx_hash` | string | Transaction hash |
| `result_code` | string | XRPL result code |
| `ledger_index` | number | Validation ledger |
| `transaction_succeeded` | boolean | Achieved intended effect |
| `fee_drops` | string | Fee consumed |

**Example:**

```typescript
const result = await mcp.callTool("tx_submit", {
  signed_tx: signResult.signed_tx,
  network: "mainnet",
  wait_for_final: true
});

if (result.status === "validated" && result.result_code === "tesSUCCESS") {
  console.log(`Transaction confirmed in ledger ${result.ledger_index}`);
}
```

See: [/docs/api/tools/tx-submit.md](/docs/api/tools/tx-submit.md)

---

## Error Codes Reference

### Common Error Codes

| Code | HTTP | Description |
|------|------|-------------|
| `VALIDATION_ERROR` | 400 | Input validation failed |
| `INVALID_ADDRESS` | 400 | XRPL address format invalid |
| `WALLET_NOT_FOUND` | 404 | Wallet not in keystore |
| `WALLET_LOCKED` | 403 | Wallet not unlocked |
| `POLICY_VIOLATION` | 403 | Transaction violates policy |
| `RATE_LIMITED` | 429 | Rate limit exceeded |
| `NETWORK_ERROR` | 503 | XRPL network unreachable |
| `INTERNAL_ERROR` | 500 | Unexpected server error |

### Signing Error Codes

| Code | Description |
|------|-------------|
| `POLICY_REJECTED` | Policy evaluation rejected transaction |
| `APPROVAL_REQUIRED` | Requires Tier 2/3 approval |
| `APPROVAL_EXPIRED` | Approval request timed out |
| `APPROVAL_REJECTED` | Human rejected the request |
| `DESTINATION_BLOCKED` | Destination on blocklist |
| `LIMIT_EXCEEDED` | Transaction exceeds limits |

### Submission Error Codes

| Code | Description |
|------|-------------|
| `INVALID_BLOB` | Transaction blob cannot be decoded |
| `MISSING_SIGNATURE` | Transaction not signed |
| `NETWORK_MISMATCH` | Transaction for different network |
| `TRANSACTION_EXPIRED` | LastLedgerSequence passed |
| `VALIDATION_TIMEOUT` | Timed out waiting for validation |

### XRPL Result Codes

| Prefix | Category | Description |
|--------|----------|-------------|
| `tes` | Success | Transaction succeeded |
| `tec` | Claimed Cost | Included but failed objective |
| `tef` | Failed | Account state prevents execution |
| `tel` | Local | Server rejected before relay |
| `tem` | Malformed | Invalid transaction structure |
| `ter` | Retry | Temporary failure, may succeed later |

---

## Rate Limiting

### Rate Limit Tiers

| Tier | Limit | Window | Tools |
|------|-------|--------|-------|
| **Standard** | 60/min | Per client | `wallet_list`, `wallet_balance`, `wallet_history`, `tx_decode` |
| **Medium** | 30/min | Per client | `wallet_policy_check` |
| **HIGH** | 10/min | Per wallet | `wallet_sign`, `tx_submit` |
| **DESTRUCTIVE** | 1/24h | Per wallet | `wallet_rotate` |

### Rate Limit Response

```json
{
  "code": "RATE_LIMITED",
  "message": "Rate limit exceeded",
  "details": {
    "limit": 10,
    "window_seconds": 60,
    "retry_after_seconds": 45
  }
}
```

---

## TypeScript Types

### Core Types

```typescript
// Network identifiers
type Network = 'mainnet' | 'testnet' | 'devnet';

// XRPL address (r-address format)
type XRPLAddress = string; // Pattern: ^r[1-9A-HJ-NP-Za-km-z]{24,34}$

// Transaction hash (64 hex characters)
type TxHash = string; // Pattern: ^[A-Fa-f0-9]{64}$

// Amount in drops (string for precision)
type DropsAmount = string; // Pattern: ^\d+$

// Policy tier levels
type TierLevel = 1 | 2 | 3 | 4;
type TierName = 'autonomous' | 'delayed' | 'cosign' | 'prohibited';

interface PolicyTier {
  level: TierLevel;
  name: TierName;
  description: string;
}
```

### Response Types

```typescript
// Discriminated union for signing responses
type WalletSignResponse =
  | { status: 'approved'; signed_tx: string; tx_hash: string; policy_tier: 1 }
  | { status: 'pending_approval'; approval_id: string; policy_tier: 2 | 3; expires_at: string }
  | { status: 'rejected'; reason: string; code: string; violations: string[] };

// Discriminated union for submission responses
type TxSubmitResponse =
  | { status: 'validated'; tx_hash: string; result_code: string; ledger_index: number }
  | { status: 'pending'; tx_hash: string; preliminary_result: string }
  | { status: 'failed'; result_code: string; result_message: string; retryable: boolean };
```

### Input Schemas (Zod)

```typescript
import { z } from 'zod';

export const XRPLAddressSchema = z
  .string()
  .min(25)
  .max(35)
  .regex(/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/);

export const NetworkSchema = z.enum(['mainnet', 'testnet', 'devnet']);

export const DropsAmountSchema = z.string().regex(/^\d+$/);

export const TxHashSchema = z
  .string()
  .length(64)
  .regex(/^[A-Fa-f0-9]{64}$/)
  .transform(val => val.toUpperCase());
```

---

## Typical Workflow

```
1. wallet_balance      -> Check available funds
2. wallet_policy_check -> Verify transaction policy
3. tx_decode           -> Inspect unsigned transaction
4. wallet_sign         -> Sign with policy enforcement
5. tx_submit           -> Submit to network
6. wallet_history      -> Verify transaction recorded
```

---

## Related Documentation

- [Tool Specifications](/docs/api/tools/) - Detailed tool documentation
- [Policy Schema](/docs/api/schemas/policy-schema.md) - Full policy configuration
- [Security Model](/docs/architecture/09-decisions/ADR-002-security-model.md) - Security architecture
- [Tier System](/docs/architecture/09-decisions/ADR-003-tier-system.md) - Policy tier details

---

*XRPL Agent Wallet MCP - API Reference v1.0.0*
