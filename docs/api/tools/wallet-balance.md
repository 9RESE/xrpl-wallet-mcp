# MCP Tool: wallet_balance

**Tool Name**: `wallet_balance`
**Version**: 1.0.0
**Sensitivity**: Low (Read-only)
**Rate Limit Tier**: Standard

---

## Table of Contents

1. [Description](#1-description)
2. [Input Schema](#2-input-schema)
3. [Output Schema](#3-output-schema)
4. [XRPL account_info Query](#4-xrpl-account_info-query)
5. [Reserve Calculation](#5-reserve-calculation)
6. [Signer List Information](#6-signer-list-information)
7. [Policy Status](#7-policy-status)
8. [Caching Considerations](#8-caching-considerations)
9. [Error Codes](#9-error-codes)
10. [Examples](#10-examples)
11. [Security Considerations](#11-security-considerations)
12. [Related Tools](#12-related-tools)

---

## 1. Description

The `wallet_balance` tool queries the current balance and account state for a managed XRPL wallet. This is a read-only operation that fetches account information from the XRPL network and enriches it with local wallet metadata, policy status, and reserve calculations.

### Purpose

- Retrieve current XRP balance for a wallet
- Calculate available (spendable) balance after reserves
- Provide account state information (sequence, flags, regular key)
- Include signer list configuration if multi-sign is enabled
- Report current policy limits and utilization

### Use Cases

- AI agent checking available funds before initiating a transaction
- Monitoring wallet health and balance status
- Verifying account configuration (regular key, multi-sign setup)
- Checking policy limit utilization before signing

---

## 2. Input Schema

### JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "wallet_id": {
      "type": "string",
      "description": "Unique identifier of the managed wallet",
      "minLength": 1,
      "maxLength": 64,
      "pattern": "^[a-zA-Z0-9_-]+$"
    },
    "address": {
      "type": "string",
      "description": "XRPL address (r-address). Alternative to wallet_id for querying any account.",
      "pattern": "^r[1-9A-HJ-NP-Za-km-z]{24,34}$"
    },
    "include_signer_list": {
      "type": "boolean",
      "description": "Include signer list configuration in response",
      "default": true
    },
    "include_policy_status": {
      "type": "boolean",
      "description": "Include policy limit utilization (only for managed wallets)",
      "default": true
    },
    "ledger_index": {
      "type": ["string", "integer"],
      "description": "Ledger to query: 'validated', 'current', 'closed', or specific ledger index",
      "default": "validated"
    }
  },
  "oneOf": [
    { "required": ["wallet_id"] },
    { "required": ["address"] }
  ],
  "additionalProperties": false
}
```

### TypeScript Interface

```typescript
interface WalletBalanceInput {
  /** Unique identifier of managed wallet (mutually exclusive with address) */
  wallet_id?: string;

  /** XRPL r-address to query (mutually exclusive with wallet_id) */
  address?: string;

  /** Include signer list in response (default: true) */
  include_signer_list?: boolean;

  /** Include policy status (default: true, only for managed wallets) */
  include_policy_status?: boolean;

  /** Ledger to query (default: 'validated') */
  ledger_index?: 'validated' | 'current' | 'closed' | number;
}
```

### Validation Rules

| Field | Rule | Error Code |
|-------|------|------------|
| `wallet_id` | Must match existing managed wallet | `WALLET_NOT_FOUND` |
| `address` | Must pass XRPL checksum validation | `INVALID_ADDRESS` |
| `wallet_id` / `address` | Exactly one must be provided | `INVALID_INPUT` |
| `ledger_index` | Must be valid ledger specifier | `INVALID_LEDGER_INDEX` |

---

## 3. Output Schema

### JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "success": {
      "type": "boolean",
      "description": "Whether the query succeeded"
    },
    "wallet_id": {
      "type": "string",
      "description": "Managed wallet identifier (if queried by wallet_id)"
    },
    "address": {
      "type": "string",
      "description": "XRPL account address"
    },
    "balance": {
      "type": "object",
      "properties": {
        "xrp": {
          "type": "string",
          "description": "Total XRP balance as decimal string"
        },
        "drops": {
          "type": "string",
          "description": "Total balance in drops (integer string)"
        },
        "available_xrp": {
          "type": "string",
          "description": "Spendable XRP after reserves"
        },
        "available_drops": {
          "type": "string",
          "description": "Spendable drops after reserves"
        }
      },
      "required": ["xrp", "drops", "available_xrp", "available_drops"]
    },
    "reserve": {
      "type": "object",
      "properties": {
        "base_reserve_xrp": {
          "type": "string",
          "description": "Base reserve requirement"
        },
        "owner_reserve_xrp": {
          "type": "string",
          "description": "Per-object reserve requirement"
        },
        "owner_count": {
          "type": "integer",
          "description": "Number of owned objects"
        },
        "total_reserve_xrp": {
          "type": "string",
          "description": "Total reserve requirement"
        }
      },
      "required": ["base_reserve_xrp", "owner_reserve_xrp", "owner_count", "total_reserve_xrp"]
    },
    "account_state": {
      "type": "object",
      "properties": {
        "sequence": {
          "type": "integer",
          "description": "Current account sequence number"
        },
        "flags": {
          "type": "integer",
          "description": "Account flags bitmap"
        },
        "flags_readable": {
          "type": "array",
          "items": { "type": "string" },
          "description": "Human-readable account flags"
        },
        "regular_key": {
          "type": ["string", "null"],
          "description": "Regular key address if set"
        },
        "domain": {
          "type": ["string", "null"],
          "description": "Account domain if set (hex decoded)"
        },
        "email_hash": {
          "type": ["string", "null"],
          "description": "Email hash for Gravatar"
        },
        "transfer_rate": {
          "type": ["integer", "null"],
          "description": "Transfer rate (for issuers)"
        }
      },
      "required": ["sequence", "flags", "flags_readable"]
    },
    "signer_list": {
      "type": ["object", "null"],
      "properties": {
        "signer_quorum": {
          "type": "integer",
          "description": "Required signer weight"
        },
        "signers": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "account": { "type": "string" },
              "weight": { "type": "integer" }
            },
            "required": ["account", "weight"]
          }
        }
      }
    },
    "policy_status": {
      "type": ["object", "null"],
      "properties": {
        "daily_volume_xrp": {
          "type": "string",
          "description": "XRP volume signed today"
        },
        "daily_limit_xrp": {
          "type": "string",
          "description": "Daily limit from policy"
        },
        "daily_utilization_percent": {
          "type": "number",
          "description": "Percentage of daily limit used"
        },
        "hourly_transaction_count": {
          "type": "integer",
          "description": "Transactions signed this hour"
        },
        "hourly_limit": {
          "type": "integer",
          "description": "Hourly transaction limit"
        },
        "autonomous_available_xrp": {
          "type": "string",
          "description": "Maximum autonomous transaction amount"
        },
        "policy_version": {
          "type": "string",
          "description": "Current policy version hash"
        }
      }
    },
    "ledger_info": {
      "type": "object",
      "properties": {
        "ledger_index": {
          "type": "integer",
          "description": "Ledger index of query"
        },
        "ledger_hash": {
          "type": "string",
          "description": "Ledger hash"
        },
        "validated": {
          "type": "boolean",
          "description": "Whether ledger is validated"
        }
      },
      "required": ["ledger_index", "validated"]
    },
    "queried_at": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 timestamp of query"
    }
  },
  "required": ["success", "address", "balance", "reserve", "account_state", "ledger_info", "queried_at"]
}
```

### TypeScript Interface

```typescript
interface WalletBalanceOutput {
  success: true;
  wallet_id?: string;
  address: string;

  balance: {
    xrp: string;           // "100.000000"
    drops: string;         // "100000000"
    available_xrp: string; // "87.000000" (after reserves)
    available_drops: string;
  };

  reserve: {
    base_reserve_xrp: string;    // "10.000000"
    owner_reserve_xrp: string;   // "2.000000"
    owner_count: number;
    total_reserve_xrp: string;   // "14.000000"
  };

  account_state: {
    sequence: number;
    flags: number;
    flags_readable: string[];    // ["lsfDefaultRipple", "lsfRequireDestTag"]
    regular_key: string | null;
    domain: string | null;
    email_hash: string | null;
    transfer_rate: number | null;
  };

  signer_list?: {
    signer_quorum: number;
    signers: Array<{
      account: string;
      weight: number;
    }>;
  } | null;

  policy_status?: {
    daily_volume_xrp: string;
    daily_limit_xrp: string;
    daily_utilization_percent: number;
    hourly_transaction_count: number;
    hourly_limit: number;
    autonomous_available_xrp: string;
    policy_version: string;
  } | null;

  ledger_info: {
    ledger_index: number;
    ledger_hash?: string;
    validated: boolean;
  };

  queried_at: string;  // ISO 8601
}
```

---

## 4. XRPL account_info Query

### Request Construction

The tool uses the XRPL `account_info` command with optional signer list retrieval.

```typescript
// account_info request
const accountInfoRequest = {
  command: 'account_info',
  account: address,
  ledger_index: input.ledger_index || 'validated',
  signer_lists: input.include_signer_list
};
```

### XRPL Response Mapping

| XRPL Field | Output Field | Notes |
|------------|--------------|-------|
| `account_data.Balance` | `balance.drops` | Integer string in drops |
| `account_data.Sequence` | `account_state.sequence` | Current sequence |
| `account_data.Flags` | `account_state.flags` | Account flags bitmap |
| `account_data.OwnerCount` | `reserve.owner_count` | Object count |
| `account_data.RegularKey` | `account_state.regular_key` | Optional |
| `account_data.Domain` | `account_state.domain` | Hex to UTF-8 |
| `account_data.EmailHash` | `account_state.email_hash` | Optional |
| `account_data.TransferRate` | `account_state.transfer_rate` | Optional |
| `account_data.signer_lists[0]` | `signer_list` | If requested |
| `ledger_index` | `ledger_info.ledger_index` | Query ledger |
| `validated` | `ledger_info.validated` | Validation status |

### Account Flags Decoding

```typescript
const ACCOUNT_FLAGS = {
  lsfDefaultRipple: 0x00800000,
  lsfDepositAuth: 0x01000000,
  lsfDisableMaster: 0x00100000,
  lsfDisallowXRP: 0x00080000,
  lsfGlobalFreeze: 0x00400000,
  lsfNoFreeze: 0x00200000,
  lsfPasswordSpent: 0x00010000,
  lsfRequireAuth: 0x00040000,
  lsfRequireDestTag: 0x00020000,
  lsfAllowTrustLineClawback: 0x80000000
} as const;

function decodeAccountFlags(flags: number): string[] {
  return Object.entries(ACCOUNT_FLAGS)
    .filter(([_, value]) => (flags & value) !== 0)
    .map(([name]) => name);
}
```

---

## 5. Reserve Calculation

### XRPL Reserve Model

XRPL uses a reserve system where accounts must maintain a minimum XRP balance:

```
Total Reserve = Base Reserve + (Owner Count * Owner Reserve)
Available Balance = Total Balance - Total Reserve
```

### Current Reserve Values

| Parameter | Mainnet | Testnet | Notes |
|-----------|---------|---------|-------|
| Base Reserve | 10 XRP | 10 XRP | Required for account activation |
| Owner Reserve | 2 XRP | 2 XRP | Per owned object (trust lines, offers, etc.) |

### Implementation

```typescript
interface ReserveInfo {
  base_reserve_drops: bigint;
  owner_reserve_drops: bigint;
}

async function getServerReserves(client: XrplClient): Promise<ReserveInfo> {
  const serverInfo = await client.request({ command: 'server_info' });
  return {
    base_reserve_drops: BigInt(serverInfo.result.info.validated_ledger.reserve_base_xrp) * 1_000_000n,
    owner_reserve_drops: BigInt(serverInfo.result.info.validated_ledger.reserve_inc_xrp) * 1_000_000n
  };
}

function calculateAvailableBalance(
  totalDrops: bigint,
  ownerCount: number,
  reserves: ReserveInfo
): bigint {
  const totalReserve = reserves.base_reserve_drops +
                       (BigInt(ownerCount) * reserves.owner_reserve_drops);

  const available = totalDrops - totalReserve;
  return available > 0n ? available : 0n;
}
```

### Reserve Considerations for Agents

- Agents should use `available_xrp` for planning transactions
- Attempting to spend below reserve will fail with `tecUNFUNDED_PAYMENT`
- Creating new objects (trust lines, offers) increases `owner_count`
- Deleting objects frees up reserve

---

## 6. Signer List Information

### When Included

Signer list information is included when:
1. `include_signer_list` is `true` (default)
2. The account has a SignerList object configured

### Signer List Response

```typescript
interface SignerList {
  signer_quorum: number;  // Minimum weight required to sign
  signers: Array<{
    account: string;      // Signer's XRPL address
    weight: number;       // Signer's weight
  }>;
}
```

### Multi-Sign Context

| Field | Description | Relevance |
|-------|-------------|-----------|
| `signer_quorum` | Weight threshold for valid multi-sign | Agent must collect signatures meeting this threshold |
| `signers[].account` | Approved signer addresses | Policy may require specific signers |
| `signers[].weight` | Each signer's voting weight | Determines required signer combination |

### Example Signer List

```json
{
  "signer_quorum": 3,
  "signers": [
    { "account": "rHuman1Address...", "weight": 2 },
    { "account": "rHuman2Address...", "weight": 2 },
    { "account": "rAgentWallet...", "weight": 1 }
  ]
}
```

In this example, the agent (weight=1) plus one human (weight=2) can authorize transactions (1+2=3).

---

## 7. Policy Status

### Purpose

Policy status provides the AI agent with awareness of its current operational limits without needing to query policy separately.

### Policy Status Fields

| Field | Description | Agent Action |
|-------|-------------|--------------|
| `daily_volume_xrp` | XRP signed today | Track cumulative spend |
| `daily_limit_xrp` | Maximum daily XRP | Avoid exceeding limit |
| `daily_utilization_percent` | Percentage used | Warn at high utilization |
| `hourly_transaction_count` | Transactions this hour | Rate awareness |
| `hourly_limit` | Max transactions/hour | Pace operations |
| `autonomous_available_xrp` | Max per autonomous tx | Single transaction limit |
| `policy_version` | Policy hash | Verify policy unchanged |

### Policy Status Retrieval

```typescript
async function getPolicyStatus(
  walletId: string,
  policyEngine: PolicyEngine,
  limitTracker: LimitTracker
): Promise<PolicyStatus> {
  const limits = await limitTracker.getLimitStatus(walletId);
  const policy = policyEngine.getPolicy();

  return {
    daily_volume_xrp: dropsToXRP(limits.daily_spent_drops),
    daily_limit_xrp: policy.tiers.autonomous.daily_limit_xrp.toString(),
    daily_utilization_percent: (limits.daily_spent_drops /
      (policy.tiers.autonomous.daily_limit_xrp * 1_000_000)) * 100,
    hourly_transaction_count: limits.hourly_tx_count,
    hourly_limit: policy.limits.max_transactions_per_hour,
    autonomous_available_xrp: policy.tiers.autonomous.max_amount_xrp.toString(),
    policy_version: policyEngine.getPolicyHash().slice(0, 8)
  };
}
```

### Availability

Policy status is only available when:
1. Querying by `wallet_id` (managed wallet)
2. `include_policy_status` is `true` (default)
3. Wallet has an associated policy

For external addresses queried by `address`, `policy_status` will be `null`.

---

## 8. Caching Considerations

### Cache Strategy

Balance queries are cached to reduce XRPL network load while maintaining reasonable freshness.

### Cache Configuration

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| TTL | 5 seconds | Balance can change with each ledger close |
| Cache Key | `balance:{address}:{ledger_index}` | Per-address, per-ledger |
| Bypass | `ledger_index: 'current'` | Always fresh for current ledger |
| Policy Status TTL | 30 seconds | Changes less frequently |

### Implementation

```typescript
interface CacheEntry<T> {
  data: T;
  timestamp: number;
  ledger_index: number;
}

class BalanceCache {
  private cache: Map<string, CacheEntry<AccountInfo>> = new Map();
  private readonly TTL_MS = 5000;

  async getBalance(
    address: string,
    ledgerIndex: string | number,
    fetcher: () => Promise<AccountInfo>
  ): Promise<AccountInfo> {
    const cacheKey = `${address}:${ledgerIndex}`;

    // Bypass cache for 'current' ledger
    if (ledgerIndex === 'current') {
      return fetcher();
    }

    const cached = this.cache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.TTL_MS) {
      return cached.data;
    }

    const data = await fetcher();
    this.cache.set(cacheKey, {
      data,
      timestamp: Date.now(),
      ledger_index: data.ledger_index
    });

    return data;
  }

  invalidate(address: string): void {
    for (const key of this.cache.keys()) {
      if (key.startsWith(`${address}:`)) {
        this.cache.delete(key);
      }
    }
  }
}
```

### Cache Invalidation

Cache is invalidated when:
1. Transaction is signed for the wallet
2. Transaction is submitted
3. TTL expires
4. `ledger_index: 'current'` is requested

---

## 9. Error Codes

### Error Response Schema

```typescript
interface WalletBalanceError {
  success: false;
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
}
```

### Error Codes

| Code | HTTP-like | Description | Recovery Action |
|------|-----------|-------------|-----------------|
| `WALLET_NOT_FOUND` | 404 | Wallet ID not in keystore | Verify wallet_id or create wallet |
| `ACCOUNT_NOT_FOUND` | 404 | Address not activated on XRPL | Fund account with base reserve |
| `INVALID_ADDRESS` | 400 | Address fails checksum validation | Correct the address |
| `INVALID_INPUT` | 400 | Missing or invalid parameters | Fix input format |
| `INVALID_LEDGER_INDEX` | 400 | Invalid ledger specifier | Use valid ledger index |
| `NETWORK_ERROR` | 503 | Cannot reach XRPL network | Retry with backoff |
| `LEDGER_NOT_FOUND` | 404 | Specified ledger not available | Use 'validated' or recent ledger |
| `RATE_LIMITED` | 429 | Too many requests | Wait and retry |
| `INTERNAL_ERROR` | 500 | Unexpected server error | Contact support |

### Error Examples

**Account Not Found (Not Activated)**:
```json
{
  "success": false,
  "error": {
    "code": "ACCOUNT_NOT_FOUND",
    "message": "Account rExampleAddress... is not activated on the XRPL network",
    "details": {
      "address": "rExampleAddress...",
      "network": "mainnet",
      "minimum_activation": "10 XRP"
    }
  }
}
```

**Invalid Address**:
```json
{
  "success": false,
  "error": {
    "code": "INVALID_ADDRESS",
    "message": "Address checksum validation failed",
    "details": {
      "provided": "rInvalidAddress123",
      "hint": "XRPL addresses start with 'r' followed by 24-34 base58 characters"
    }
  }
}
```

---

## 10. Examples

### Example 1: Basic Balance Query

**Request**:
```json
{
  "name": "wallet_balance",
  "arguments": {
    "wallet_id": "agent-wallet-001"
  }
}
```

**Response**:
```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"success\":true,\"wallet_id\":\"agent-wallet-001\",\"address\":\"rAgentWallet123...\",\"balance\":{\"xrp\":\"150.000000\",\"drops\":\"150000000\",\"available_xrp\":\"136.000000\",\"available_drops\":\"136000000\"},\"reserve\":{\"base_reserve_xrp\":\"10.000000\",\"owner_reserve_xrp\":\"2.000000\",\"owner_count\":2,\"total_reserve_xrp\":\"14.000000\"},\"account_state\":{\"sequence\":42,\"flags\":262144,\"flags_readable\":[\"lsfRequireDestTag\"],\"regular_key\":null,\"domain\":null,\"email_hash\":null,\"transfer_rate\":null},\"signer_list\":{\"signer_quorum\":3,\"signers\":[{\"account\":\"rHuman1...\",\"weight\":2},{\"account\":\"rHuman2...\",\"weight\":2},{\"account\":\"rAgentWallet123...\",\"weight\":1}]},\"policy_status\":{\"daily_volume_xrp\":\"45.000000\",\"daily_limit_xrp\":\"1000.000000\",\"daily_utilization_percent\":4.5,\"hourly_transaction_count\":3,\"hourly_limit\":100,\"autonomous_available_xrp\":\"100.000000\",\"policy_version\":\"a1b2c3d4\"},\"ledger_info\":{\"ledger_index\":85432100,\"ledger_hash\":\"ABC123...\",\"validated\":true},\"queried_at\":\"2026-01-28T14:30:00.123Z\"}"
    }
  ]
}
```

### Example 2: Query External Address

**Request**:
```json
{
  "name": "wallet_balance",
  "arguments": {
    "address": "rExternalAddress123...",
    "include_policy_status": false
  }
}
```

**Response**:
```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"success\":true,\"address\":\"rExternalAddress123...\",\"balance\":{\"xrp\":\"500.000000\",\"drops\":\"500000000\",\"available_xrp\":\"488.000000\",\"available_drops\":\"488000000\"},\"reserve\":{\"base_reserve_xrp\":\"10.000000\",\"owner_reserve_xrp\":\"2.000000\",\"owner_count\":1,\"total_reserve_xrp\":\"12.000000\"},\"account_state\":{\"sequence\":156,\"flags\":0,\"flags_readable\":[],\"regular_key\":null,\"domain\":\"6578616d706c652e636f6d\",\"email_hash\":null,\"transfer_rate\":null},\"signer_list\":null,\"policy_status\":null,\"ledger_info\":{\"ledger_index\":85432100,\"validated\":true},\"queried_at\":\"2026-01-28T14:30:05.456Z\"}"
    }
  ]
}
```

### Example 3: Query Specific Ledger

**Request**:
```json
{
  "name": "wallet_balance",
  "arguments": {
    "wallet_id": "agent-wallet-001",
    "ledger_index": 85430000,
    "include_signer_list": false,
    "include_policy_status": false
  }
}
```

### Example 4: Error - Account Not Found

**Request**:
```json
{
  "name": "wallet_balance",
  "arguments": {
    "address": "rNewUnfundedAccount..."
  }
}
```

**Response**:
```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"success\":false,\"error\":{\"code\":\"ACCOUNT_NOT_FOUND\",\"message\":\"Account rNewUnfundedAccount... is not activated on the XRPL network\",\"details\":{\"address\":\"rNewUnfundedAccount...\",\"network\":\"mainnet\",\"minimum_activation\":\"10 XRP\"}}}"
    }
  ],
  "isError": true
}
```

---

## 11. Security Considerations

### Read-Only Classification

This tool is classified as **Low** sensitivity because:
- No key material is accessed
- No transactions are signed
- No state is modified
- Only publicly available blockchain data is returned

### Privacy Considerations

| Data | Exposure | Mitigation |
|------|----------|------------|
| Address | Required for query | Inherently public on XRPL |
| Balance | Returned | Public on XRPL |
| Policy Status | Returned | Only for managed wallets |
| Signer List | Returned | Public on XRPL |

### Rate Limiting

| Limit | Value | Scope |
|-------|-------|-------|
| Requests per minute | 100 | Per wallet_id |
| Requests per minute | 60 | Per address (external) |
| Burst allowance | 10 | Additional requests |

### Audit Logging

All balance queries are logged with event type `WALLET_BALANCE`:

```typescript
await auditLogger.log({
  eventType: AuditEventType.WALLET_BALANCE,
  correlationId,
  actor: { type: 'agent' },
  operation: {
    name: 'wallet_balance',
    parameters: {
      wallet_id: input.wallet_id,
      address: input.address,
      ledger_index: input.ledger_index
    },
    result: 'success'
  },
  context: {
    network: 'mainnet',
    walletAddress: address
  }
});
```

### Input Validation

```typescript
import { z } from 'zod';

const WalletBalanceInputSchema = z.object({
  wallet_id: z.string()
    .min(1)
    .max(64)
    .regex(/^[a-zA-Z0-9_-]+$/)
    .optional(),
  address: z.string()
    .regex(/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/)
    .refine(isValidXRPLChecksum, 'Invalid XRPL address checksum')
    .optional(),
  include_signer_list: z.boolean().default(true),
  include_policy_status: z.boolean().default(true),
  ledger_index: z.union([
    z.literal('validated'),
    z.literal('current'),
    z.literal('closed'),
    z.number().int().positive()
  ]).default('validated')
}).refine(
  data => (data.wallet_id !== undefined) !== (data.address !== undefined),
  { message: 'Exactly one of wallet_id or address must be provided' }
);
```

---

## 12. Related Tools

| Tool | Relationship |
|------|--------------|
| `list_wallets` | Lists all managed wallets (use to get wallet_id) |
| `sign_transaction` | Signs transactions (check balance first) |
| `get_transaction_status` | Check transaction results |
| `check_policy` | Dry-run policy evaluation |
| `get_policy` | Retrieve full policy details |

### Typical Workflow

```
1. list_wallets        → Get available wallet IDs
2. wallet_balance      → Check available funds and policy status
3. check_policy        → Verify transaction would be allowed
4. sign_transaction    → Sign the transaction
5. get_transaction_status → Verify submission
```

---

## References

- [XRPL account_info Reference](https://xrpl.org/account_info.html)
- [XRPL Reserves](https://xrpl.org/reserves.html)
- [XRPL SignerList](https://xrpl.org/signerlist.html)
- [MCP Tool Specification](https://modelcontextprotocol.io/specification)

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | JavaScript Developer | Initial specification |

---

*MCP Tool Documentation - XRPL Agent Wallet*
