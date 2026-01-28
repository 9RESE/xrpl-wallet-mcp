# MCP Tool: wallet_list

**Tool Name**: `wallet_list`
**Version**: 1.0.0
**Sensitivity**: Low (Read-only)
**Rate Limit Tier**: Standard

---

## Table of Contents

1. [Description](#1-description)
2. [Input Schema](#2-input-schema)
3. [Output Schema](#3-output-schema)
4. [Wallet Summary Fields](#4-wallet-summary-fields)
5. [Filtering Options](#5-filtering-options)
6. [Pagination](#6-pagination)
7. [Error Codes](#7-error-codes)
8. [Examples](#8-examples)
9. [Security Considerations](#9-security-considerations)
10. [Related Tools](#10-related-tools)

---

## 1. Description

The `wallet_list` tool retrieves a list of all managed XRPL wallets in the MCP server's keystore. This is a read-only operation that provides wallet metadata without exposing sensitive key material.

### Purpose

- Enumerate all wallets managed by the MCP server
- Filter wallets by network or activity status
- Provide wallet summaries for agent decision-making
- Support pagination for environments with many wallets
- Enable wallet discovery for multi-wallet agents

### Use Cases

- AI agent discovering available wallets before initiating operations
- Listing wallets by network for targeted operations
- Identifying inactive wallets for cleanup or review
- Building dashboard views of wallet portfolio
- Auditing managed wallet inventory

---

## 2. Input Schema

### JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "network": {
      "type": "string",
      "description": "Filter wallets by XRPL network",
      "enum": ["mainnet", "testnet", "devnet"]
    },
    "include_inactive": {
      "type": "boolean",
      "description": "Include wallets with no recent activity (default: true)",
      "default": true
    },
    "inactive_days_threshold": {
      "type": "integer",
      "description": "Number of days without activity to consider a wallet inactive (default: 30)",
      "minimum": 1,
      "maximum": 365,
      "default": 30
    },
    "sort_by": {
      "type": "string",
      "description": "Field to sort results by",
      "enum": ["name", "created_at", "last_activity", "network"],
      "default": "created_at"
    },
    "sort_order": {
      "type": "string",
      "description": "Sort order",
      "enum": ["asc", "desc"],
      "default": "desc"
    },
    "limit": {
      "type": "integer",
      "description": "Maximum number of wallets to return per page",
      "minimum": 1,
      "maximum": 100,
      "default": 50
    },
    "offset": {
      "type": "integer",
      "description": "Number of wallets to skip for pagination",
      "minimum": 0,
      "default": 0
    },
    "search": {
      "type": "string",
      "description": "Search term to filter by wallet name or address",
      "minLength": 1,
      "maxLength": 64
    },
    "include_policy_summary": {
      "type": "boolean",
      "description": "Include policy summary for each wallet (default: false)",
      "default": false
    },
    "include_balance": {
      "type": "boolean",
      "description": "Include current balance for each wallet (requires network call, default: false)",
      "default": false
    }
  },
  "additionalProperties": false
}
```

### TypeScript Interface

```typescript
interface WalletListInput {
  /** Filter wallets by XRPL network */
  network?: 'mainnet' | 'testnet' | 'devnet';

  /** Include wallets with no recent activity (default: true) */
  include_inactive?: boolean;

  /** Days without activity to consider inactive (default: 30) */
  inactive_days_threshold?: number;

  /** Field to sort results by (default: 'created_at') */
  sort_by?: 'name' | 'created_at' | 'last_activity' | 'network';

  /** Sort order (default: 'desc') */
  sort_order?: 'asc' | 'desc';

  /** Maximum wallets per page (default: 50, max: 100) */
  limit?: number;

  /** Offset for pagination (default: 0) */
  offset?: number;

  /** Search term for name or address filtering */
  search?: string;

  /** Include policy summary per wallet (default: false) */
  include_policy_summary?: boolean;

  /** Include balance per wallet - requires network calls (default: false) */
  include_balance?: boolean;
}
```

### Validation Rules

| Field | Rule | Error Code |
|-------|------|------------|
| `network` | Must be valid network enum if provided | `INVALID_NETWORK` |
| `inactive_days_threshold` | Must be 1-365 | `INVALID_INPUT` |
| `limit` | Must be 1-100 | `INVALID_INPUT` |
| `offset` | Must be >= 0 | `INVALID_INPUT` |
| `search` | Must be 1-64 characters if provided | `INVALID_INPUT` |
| `sort_by` | Must be valid sort field if provided | `INVALID_INPUT` |
| `sort_order` | Must be 'asc' or 'desc' if provided | `INVALID_INPUT` |

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
    "wallets": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/WalletSummary"
      },
      "description": "List of wallet summaries"
    },
    "pagination": {
      "type": "object",
      "properties": {
        "total": {
          "type": "integer",
          "description": "Total number of wallets matching filters"
        },
        "limit": {
          "type": "integer",
          "description": "Maximum wallets per page"
        },
        "offset": {
          "type": "integer",
          "description": "Current offset"
        },
        "has_more": {
          "type": "boolean",
          "description": "Whether more wallets are available"
        },
        "total_pages": {
          "type": "integer",
          "description": "Total number of pages"
        },
        "current_page": {
          "type": "integer",
          "description": "Current page number (1-indexed)"
        }
      },
      "required": ["total", "limit", "offset", "has_more"]
    },
    "summary": {
      "type": "object",
      "properties": {
        "total_wallets": {
          "type": "integer",
          "description": "Total wallets in keystore (before filters)"
        },
        "filtered_count": {
          "type": "integer",
          "description": "Wallets matching applied filters"
        },
        "by_network": {
          "type": "object",
          "additionalProperties": {
            "type": "integer"
          },
          "description": "Wallet count per network"
        },
        "active_count": {
          "type": "integer",
          "description": "Number of active wallets"
        },
        "inactive_count": {
          "type": "integer",
          "description": "Number of inactive wallets"
        }
      },
      "required": ["total_wallets", "filtered_count"]
    },
    "filters_applied": {
      "type": "object",
      "description": "Summary of filters that were applied",
      "properties": {
        "network": { "type": "string" },
        "include_inactive": { "type": "boolean" },
        "search": { "type": "string" }
      }
    },
    "queried_at": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 timestamp of query"
    }
  },
  "required": ["success", "wallets", "pagination", "summary", "queried_at"],
  "$defs": {
    "WalletSummary": {
      "type": "object",
      "properties": {
        "wallet_id": {
          "type": "string",
          "description": "Unique wallet identifier"
        },
        "address": {
          "type": "string",
          "description": "XRPL Classic Address (r-address)"
        },
        "name": {
          "type": ["string", "null"],
          "description": "Human-readable wallet name"
        },
        "network": {
          "type": "string",
          "enum": ["mainnet", "testnet", "devnet"],
          "description": "XRPL network this wallet operates on"
        },
        "created_at": {
          "type": "string",
          "format": "date-time",
          "description": "Wallet creation timestamp (ISO 8601)"
        },
        "last_activity": {
          "type": ["string", "null"],
          "format": "date-time",
          "description": "Last transaction activity timestamp"
        },
        "is_active": {
          "type": "boolean",
          "description": "Whether wallet has recent activity"
        },
        "has_regular_key": {
          "type": "boolean",
          "description": "Whether a regular key is configured"
        },
        "is_funded": {
          "type": "boolean",
          "description": "Whether the account is funded on XRPL"
        },
        "policy_id": {
          "type": ["string", "null"],
          "description": "Associated policy identifier"
        },
        "policy_summary": {
          "type": ["object", "null"],
          "description": "Policy summary (when include_policy_summary is true)",
          "properties": {
            "max_amount_per_tx_xrp": { "type": "string" },
            "max_daily_volume_xrp": { "type": "string" },
            "allowed_transaction_types": {
              "type": "array",
              "items": { "type": "string" }
            },
            "destination_mode": {
              "type": "string",
              "enum": ["allowlist", "blocklist", "open"]
            }
          }
        },
        "balance": {
          "type": ["object", "null"],
          "description": "Current balance (when include_balance is true)",
          "properties": {
            "xrp": { "type": "string" },
            "available_xrp": { "type": "string" }
          }
        },
        "tags": {
          "type": "array",
          "items": { "type": "string" },
          "description": "User-defined tags for wallet categorization"
        }
      },
      "required": [
        "wallet_id",
        "address",
        "network",
        "created_at",
        "is_active",
        "has_regular_key",
        "is_funded"
      ]
    }
  }
}
```

### TypeScript Interface

```typescript
interface WalletListOutput {
  success: true;
  wallets: WalletSummary[];

  pagination: {
    total: number;
    limit: number;
    offset: number;
    has_more: boolean;
    total_pages?: number;
    current_page?: number;
  };

  summary: {
    total_wallets: number;
    filtered_count: number;
    by_network?: {
      mainnet?: number;
      testnet?: number;
      devnet?: number;
    };
    active_count?: number;
    inactive_count?: number;
  };

  filters_applied?: {
    network?: string;
    include_inactive?: boolean;
    search?: string;
  };

  queried_at: string;
}

interface WalletSummary {
  /** Unique wallet identifier */
  wallet_id: string;

  /** XRPL Classic Address */
  address: string;

  /** Human-readable wallet name */
  name: string | null;

  /** XRPL network */
  network: 'mainnet' | 'testnet' | 'devnet';

  /** Wallet creation timestamp */
  created_at: string;

  /** Last transaction activity timestamp */
  last_activity: string | null;

  /** Whether wallet has recent activity */
  is_active: boolean;

  /** Whether a regular key is configured */
  has_regular_key: boolean;

  /** Whether the account is funded on XRPL */
  is_funded: boolean;

  /** Associated policy identifier */
  policy_id: string | null;

  /** Policy summary (when requested) */
  policy_summary?: PolicySummary | null;

  /** Current balance (when requested) */
  balance?: {
    xrp: string;
    available_xrp: string;
  } | null;

  /** User-defined tags */
  tags?: string[];
}

interface PolicySummary {
  max_amount_per_tx_xrp: string;
  max_daily_volume_xrp: string;
  allowed_transaction_types: string[];
  destination_mode: 'allowlist' | 'blocklist' | 'open';
}
```

---

## 4. Wallet Summary Fields

### Core Fields

| Field | Type | Description | Source |
|-------|------|-------------|--------|
| `wallet_id` | `string` | Unique identifier for the wallet | Keystore |
| `address` | `string` | XRPL Classic Address (r-address) | Keystore |
| `name` | `string \| null` | Human-readable name | Keystore metadata |
| `network` | `enum` | XRPL network (mainnet/testnet/devnet) | Keystore |
| `created_at` | `string` | ISO 8601 creation timestamp | Keystore metadata |
| `last_activity` | `string \| null` | Last transaction timestamp | Activity tracker |
| `is_active` | `boolean` | Has activity within threshold days | Computed |
| `has_regular_key` | `boolean` | Regular key configured | Keystore |
| `is_funded` | `boolean` | Account activated on XRPL | Keystore/cached |
| `policy_id` | `string \| null` | Associated policy identifier | Policy engine |

### Optional Fields

| Field | Type | Condition | Source |
|-------|------|-----------|--------|
| `policy_summary` | `object \| null` | `include_policy_summary: true` | Policy engine |
| `balance` | `object \| null` | `include_balance: true` | XRPL network |
| `tags` | `string[]` | Always included if set | Keystore metadata |

### Activity Status Calculation

```typescript
function calculateActivityStatus(
  lastActivity: Date | null,
  thresholdDays: number
): boolean {
  if (!lastActivity) {
    return false;
  }

  const now = new Date();
  const thresholdMs = thresholdDays * 24 * 60 * 60 * 1000;
  const timeSinceActivity = now.getTime() - lastActivity.getTime();

  return timeSinceActivity <= thresholdMs;
}
```

### Last Activity Tracking

Last activity is tracked from:
1. Transactions signed by the MCP server for this wallet
2. On-chain transaction history (if available)
3. Wallet balance check operations

```typescript
interface ActivityRecord {
  wallet_id: string;
  last_signed_at: Date | null;      // Last transaction signed
  last_on_chain_at: Date | null;    // Last on-chain activity
  last_query_at: Date | null;       // Last balance/history query
}

function getLastActivity(record: ActivityRecord): Date | null {
  const dates = [
    record.last_signed_at,
    record.last_on_chain_at,
  ].filter((d): d is Date => d !== null);

  if (dates.length === 0) {
    return null;
  }

  return new Date(Math.max(...dates.map(d => d.getTime())));
}
```

---

## 5. Filtering Options

### Network Filter

Filter wallets by XRPL network environment.

```typescript
// Filter by network
const filteredWallets = wallets.filter(
  w => !input.network || w.network === input.network
);
```

### Activity Filter

Include or exclude inactive wallets based on threshold.

```typescript
// Filter by activity status
if (!input.include_inactive) {
  filteredWallets = filteredWallets.filter(w => w.is_active);
}
```

### Search Filter

Search by wallet name or address (case-insensitive partial match).

```typescript
function matchesSearch(wallet: Wallet, searchTerm: string): boolean {
  const term = searchTerm.toLowerCase();

  // Match wallet name
  if (wallet.name?.toLowerCase().includes(term)) {
    return true;
  }

  // Match wallet address (exact prefix match for security)
  if (wallet.address.toLowerCase().startsWith(term)) {
    return true;
  }

  // Match wallet ID
  if (wallet.wallet_id.toLowerCase().includes(term)) {
    return true;
  }

  return false;
}
```

### Filter Combination

All filters are combined with AND logic.

```typescript
function applyFilters(
  wallets: Wallet[],
  input: WalletListInput
): Wallet[] {
  return wallets.filter(wallet => {
    // Network filter
    if (input.network && wallet.network !== input.network) {
      return false;
    }

    // Activity filter
    if (!input.include_inactive && !wallet.is_active) {
      return false;
    }

    // Search filter
    if (input.search && !matchesSearch(wallet, input.search)) {
      return false;
    }

    return true;
  });
}
```

---

## 6. Pagination

### Offset-Based Pagination

The `wallet_list` tool uses offset-based pagination for simplicity and random access capabilities.

```
                    Full Wallet List
                          |
                          v
            +---------------------------+
            | [wallet-1] [wallet-2] ... |
            | [wallet-3] [wallet-4] ... |
            | [wallet-5] [wallet-6] ... |
            | ...                       |
            | [wallet-99] [wallet-100]  |
            +---------------------------+
                          |
            +-------------+-------------+
            |                           |
            v                           v
    Page 1 (offset: 0)          Page 2 (offset: 50)
    +------------------+        +------------------+
    | wallets[0..49]   |        | wallets[50..99]  |
    | has_more: true   |        | has_more: true   |
    +------------------+        +------------------+
```

### Pagination Calculation

```typescript
interface PaginationResult {
  items: Wallet[];
  pagination: {
    total: number;
    limit: number;
    offset: number;
    has_more: boolean;
    total_pages: number;
    current_page: number;
  };
}

function paginate(
  wallets: Wallet[],
  limit: number,
  offset: number
): PaginationResult {
  const total = wallets.length;
  const items = wallets.slice(offset, offset + limit);
  const hasMore = offset + limit < total;
  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  return {
    items,
    pagination: {
      total,
      limit,
      offset,
      has_more: hasMore,
      total_pages: totalPages,
      current_page: currentPage,
    },
  };
}
```

### Pagination Examples

**First Page**:
```json
{
  "limit": 20,
  "offset": 0
}
```

**Response**:
```json
{
  "pagination": {
    "total": 75,
    "limit": 20,
    "offset": 0,
    "has_more": true,
    "total_pages": 4,
    "current_page": 1
  }
}
```

**Second Page**:
```json
{
  "limit": 20,
  "offset": 20
}
```

**Last Page**:
```json
{
  "limit": 20,
  "offset": 60
}
```

**Response**:
```json
{
  "pagination": {
    "total": 75,
    "limit": 20,
    "offset": 60,
    "has_more": false,
    "total_pages": 4,
    "current_page": 4
  }
}
```

### Sorting

Wallets can be sorted before pagination.

```typescript
type SortField = 'name' | 'created_at' | 'last_activity' | 'network';
type SortOrder = 'asc' | 'desc';

function sortWallets(
  wallets: Wallet[],
  sortBy: SortField,
  sortOrder: SortOrder
): Wallet[] {
  return [...wallets].sort((a, b) => {
    let comparison = 0;

    switch (sortBy) {
      case 'name':
        comparison = (a.name || '').localeCompare(b.name || '');
        break;
      case 'created_at':
        comparison = new Date(a.created_at).getTime() -
                     new Date(b.created_at).getTime();
        break;
      case 'last_activity':
        const aTime = a.last_activity ? new Date(a.last_activity).getTime() : 0;
        const bTime = b.last_activity ? new Date(b.last_activity).getTime() : 0;
        comparison = aTime - bTime;
        break;
      case 'network':
        comparison = a.network.localeCompare(b.network);
        break;
    }

    return sortOrder === 'desc' ? -comparison : comparison;
  });
}
```

---

## 7. Error Codes

### Error Response Schema

```typescript
interface WalletListError {
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
| `INVALID_INPUT` | 400 | Invalid input parameters | Fix input format |
| `INVALID_NETWORK` | 400 | Invalid network value | Use mainnet/testnet/devnet |
| `KEYSTORE_ERROR` | 500 | Cannot access keystore | Check server configuration |
| `NETWORK_ERROR` | 503 | Cannot fetch balances (when requested) | Retry without balance flag |
| `RATE_LIMITED` | 429 | Too many requests | Wait and retry |
| `INTERNAL_ERROR` | 500 | Unexpected server error | Contact support |

### Error Examples

**Invalid Input**:
```json
{
  "success": false,
  "error": {
    "code": "INVALID_INPUT",
    "message": "Limit must be between 1 and 100",
    "details": {
      "field": "limit",
      "received": 500,
      "min": 1,
      "max": 100
    }
  }
}
```

**Invalid Network**:
```json
{
  "success": false,
  "error": {
    "code": "INVALID_NETWORK",
    "message": "Invalid network specified",
    "details": {
      "received": "prodnet",
      "valid_options": ["mainnet", "testnet", "devnet"]
    }
  }
}
```

**Keystore Error**:
```json
{
  "success": false,
  "error": {
    "code": "KEYSTORE_ERROR",
    "message": "Unable to access wallet keystore",
    "details": {
      "reason": "Keystore file locked or corrupted"
    }
  }
}
```

**Network Error (Balance Fetch)**:
```json
{
  "success": false,
  "error": {
    "code": "NETWORK_ERROR",
    "message": "Unable to fetch wallet balances from XRPL network",
    "details": {
      "network": "mainnet",
      "hint": "Try again without include_balance flag for faster results"
    }
  }
}
```

---

## 8. Examples

### Example 1: Basic List All Wallets

**Request**:
```json
{
  "name": "wallet_list",
  "arguments": {}
}
```

**Response**:
```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"success\":true,\"wallets\":[{\"wallet_id\":\"wallet-1706438400-abc123\",\"address\":\"rN7n3473SaZBCG4dFL83w7a1RXtXtbK2D9\",\"name\":\"trading-agent-alpha\",\"network\":\"mainnet\",\"created_at\":\"2026-01-15T10:30:00.000Z\",\"last_activity\":\"2026-01-28T14:25:30.000Z\",\"is_active\":true,\"has_regular_key\":true,\"is_funded\":true,\"policy_id\":\"conservative-v1\",\"tags\":[\"production\",\"trading\"]},{\"wallet_id\":\"wallet-1706438500-def456\",\"address\":\"rKLpjpCoXgLQQYQyj13zgay73rsgmzNH13\",\"name\":\"escrow-manager\",\"network\":\"mainnet\",\"created_at\":\"2026-01-16T11:00:00.000Z\",\"last_activity\":\"2026-01-27T09:15:00.000Z\",\"is_active\":true,\"has_regular_key\":true,\"is_funded\":true,\"policy_id\":\"escrow-manager-v1\",\"tags\":[\"production\",\"escrow\"]},{\"wallet_id\":\"wallet-1706438600-ghi789\",\"address\":\"rTestWallet123456789ABCDEF\",\"name\":\"dev-test-wallet\",\"network\":\"testnet\",\"created_at\":\"2026-01-20T14:00:00.000Z\",\"last_activity\":\"2026-01-28T10:00:00.000Z\",\"is_active\":true,\"has_regular_key\":true,\"is_funded\":true,\"policy_id\":\"dev-testing-v1\",\"tags\":[\"development\"]}],\"pagination\":{\"total\":3,\"limit\":50,\"offset\":0,\"has_more\":false,\"total_pages\":1,\"current_page\":1},\"summary\":{\"total_wallets\":3,\"filtered_count\":3,\"by_network\":{\"mainnet\":2,\"testnet\":1},\"active_count\":3,\"inactive_count\":0},\"queried_at\":\"2026-01-28T14:30:00.123Z\"}"
    }
  ]
}
```

### Example 2: Filter by Network

**Request**:
```json
{
  "name": "wallet_list",
  "arguments": {
    "network": "mainnet"
  }
}
```

**Response**:
```json
{
  "success": true,
  "wallets": [
    {
      "wallet_id": "wallet-1706438400-abc123",
      "address": "rN7n3473SaZBCG4dFL83w7a1RXtXtbK2D9",
      "name": "trading-agent-alpha",
      "network": "mainnet",
      "created_at": "2026-01-15T10:30:00.000Z",
      "last_activity": "2026-01-28T14:25:30.000Z",
      "is_active": true,
      "has_regular_key": true,
      "is_funded": true,
      "policy_id": "conservative-v1"
    },
    {
      "wallet_id": "wallet-1706438500-def456",
      "address": "rKLpjpCoXgLQQYQyj13zgay73rsgmzNH13",
      "name": "escrow-manager",
      "network": "mainnet",
      "created_at": "2026-01-16T11:00:00.000Z",
      "last_activity": "2026-01-27T09:15:00.000Z",
      "is_active": true,
      "has_regular_key": true,
      "is_funded": true,
      "policy_id": "escrow-manager-v1"
    }
  ],
  "pagination": {
    "total": 2,
    "limit": 50,
    "offset": 0,
    "has_more": false
  },
  "summary": {
    "total_wallets": 3,
    "filtered_count": 2,
    "by_network": {
      "mainnet": 2
    }
  },
  "filters_applied": {
    "network": "mainnet"
  },
  "queried_at": "2026-01-28T14:30:00.456Z"
}
```

### Example 3: Exclude Inactive Wallets

**Request**:
```json
{
  "name": "wallet_list",
  "arguments": {
    "include_inactive": false,
    "inactive_days_threshold": 7
  }
}
```

**Response**:
```json
{
  "success": true,
  "wallets": [
    {
      "wallet_id": "wallet-1706438400-abc123",
      "address": "rN7n3473SaZBCG4dFL83w7a1RXtXtbK2D9",
      "name": "trading-agent-alpha",
      "network": "mainnet",
      "created_at": "2026-01-15T10:30:00.000Z",
      "last_activity": "2026-01-28T14:25:30.000Z",
      "is_active": true,
      "has_regular_key": true,
      "is_funded": true,
      "policy_id": "conservative-v1"
    }
  ],
  "pagination": {
    "total": 1,
    "limit": 50,
    "offset": 0,
    "has_more": false
  },
  "summary": {
    "total_wallets": 3,
    "filtered_count": 1,
    "active_count": 1,
    "inactive_count": 2
  },
  "filters_applied": {
    "include_inactive": false
  },
  "queried_at": "2026-01-28T14:30:00.789Z"
}
```

### Example 4: Paginated Request

**Request (Page 1)**:
```json
{
  "name": "wallet_list",
  "arguments": {
    "limit": 2,
    "offset": 0,
    "sort_by": "created_at",
    "sort_order": "desc"
  }
}
```

**Response (Page 1)**:
```json
{
  "success": true,
  "wallets": [
    {
      "wallet_id": "wallet-1706438600-ghi789",
      "address": "rTestWallet123456789ABCDEF",
      "name": "dev-test-wallet",
      "network": "testnet",
      "created_at": "2026-01-20T14:00:00.000Z",
      "last_activity": "2026-01-28T10:00:00.000Z",
      "is_active": true,
      "has_regular_key": true,
      "is_funded": true,
      "policy_id": "dev-testing-v1"
    },
    {
      "wallet_id": "wallet-1706438500-def456",
      "address": "rKLpjpCoXgLQQYQyj13zgay73rsgmzNH13",
      "name": "escrow-manager",
      "network": "mainnet",
      "created_at": "2026-01-16T11:00:00.000Z",
      "last_activity": "2026-01-27T09:15:00.000Z",
      "is_active": true,
      "has_regular_key": true,
      "is_funded": true,
      "policy_id": "escrow-manager-v1"
    }
  ],
  "pagination": {
    "total": 3,
    "limit": 2,
    "offset": 0,
    "has_more": true,
    "total_pages": 2,
    "current_page": 1
  },
  "summary": {
    "total_wallets": 3,
    "filtered_count": 3
  },
  "queried_at": "2026-01-28T14:30:01.000Z"
}
```

**Request (Page 2)**:
```json
{
  "name": "wallet_list",
  "arguments": {
    "limit": 2,
    "offset": 2,
    "sort_by": "created_at",
    "sort_order": "desc"
  }
}
```

**Response (Page 2)**:
```json
{
  "success": true,
  "wallets": [
    {
      "wallet_id": "wallet-1706438400-abc123",
      "address": "rN7n3473SaZBCG4dFL83w7a1RXtXtbK2D9",
      "name": "trading-agent-alpha",
      "network": "mainnet",
      "created_at": "2026-01-15T10:30:00.000Z",
      "last_activity": "2026-01-28T14:25:30.000Z",
      "is_active": true,
      "has_regular_key": true,
      "is_funded": true,
      "policy_id": "conservative-v1"
    }
  ],
  "pagination": {
    "total": 3,
    "limit": 2,
    "offset": 2,
    "has_more": false,
    "total_pages": 2,
    "current_page": 2
  },
  "summary": {
    "total_wallets": 3,
    "filtered_count": 3
  },
  "queried_at": "2026-01-28T14:30:02.000Z"
}
```

### Example 5: Search by Name

**Request**:
```json
{
  "name": "wallet_list",
  "arguments": {
    "search": "trading"
  }
}
```

**Response**:
```json
{
  "success": true,
  "wallets": [
    {
      "wallet_id": "wallet-1706438400-abc123",
      "address": "rN7n3473SaZBCG4dFL83w7a1RXtXtbK2D9",
      "name": "trading-agent-alpha",
      "network": "mainnet",
      "created_at": "2026-01-15T10:30:00.000Z",
      "last_activity": "2026-01-28T14:25:30.000Z",
      "is_active": true,
      "has_regular_key": true,
      "is_funded": true,
      "policy_id": "conservative-v1"
    }
  ],
  "pagination": {
    "total": 1,
    "limit": 50,
    "offset": 0,
    "has_more": false
  },
  "summary": {
    "total_wallets": 3,
    "filtered_count": 1
  },
  "filters_applied": {
    "search": "trading"
  },
  "queried_at": "2026-01-28T14:30:03.000Z"
}
```

### Example 6: Include Policy Summary and Balance

**Request**:
```json
{
  "name": "wallet_list",
  "arguments": {
    "network": "mainnet",
    "include_policy_summary": true,
    "include_balance": true,
    "limit": 1
  }
}
```

**Response**:
```json
{
  "success": true,
  "wallets": [
    {
      "wallet_id": "wallet-1706438400-abc123",
      "address": "rN7n3473SaZBCG4dFL83w7a1RXtXtbK2D9",
      "name": "trading-agent-alpha",
      "network": "mainnet",
      "created_at": "2026-01-15T10:30:00.000Z",
      "last_activity": "2026-01-28T14:25:30.000Z",
      "is_active": true,
      "has_regular_key": true,
      "is_funded": true,
      "policy_id": "conservative-v1",
      "policy_summary": {
        "max_amount_per_tx_xrp": "50.000000",
        "max_daily_volume_xrp": "500.000000",
        "allowed_transaction_types": ["Payment", "EscrowFinish"],
        "destination_mode": "allowlist"
      },
      "balance": {
        "xrp": "150.000000",
        "available_xrp": "136.000000"
      },
      "tags": ["production", "trading"]
    }
  ],
  "pagination": {
    "total": 2,
    "limit": 1,
    "offset": 0,
    "has_more": true
  },
  "summary": {
    "total_wallets": 3,
    "filtered_count": 2,
    "by_network": {
      "mainnet": 2
    }
  },
  "filters_applied": {
    "network": "mainnet"
  },
  "queried_at": "2026-01-28T14:30:04.000Z"
}
```

### Example 7: Empty Results

**Request**:
```json
{
  "name": "wallet_list",
  "arguments": {
    "network": "devnet"
  }
}
```

**Response**:
```json
{
  "success": true,
  "wallets": [],
  "pagination": {
    "total": 0,
    "limit": 50,
    "offset": 0,
    "has_more": false,
    "total_pages": 0,
    "current_page": 0
  },
  "summary": {
    "total_wallets": 3,
    "filtered_count": 0,
    "by_network": {
      "devnet": 0
    }
  },
  "filters_applied": {
    "network": "devnet"
  },
  "queried_at": "2026-01-28T14:30:05.000Z"
}
```

### Example 8: Error - Invalid Network

**Request**:
```json
{
  "name": "wallet_list",
  "arguments": {
    "network": "prodnet"
  }
}
```

**Response**:
```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"success\":false,\"error\":{\"code\":\"INVALID_NETWORK\",\"message\":\"Invalid network specified\",\"details\":{\"received\":\"prodnet\",\"valid_options\":[\"mainnet\",\"testnet\",\"devnet\"]}}}"
    }
  ],
  "isError": true
}
```

---

## 9. Security Considerations

### Read-Only Classification

This tool is classified as **Low** sensitivity because:
- No key material is exposed
- No transactions are signed
- No state is modified
- Only wallet metadata is returned
- Addresses are publicly visible on XRPL

### Data Exposure

| Data | Exposure Level | Notes |
|------|---------------|-------|
| `wallet_id` | Internal identifier | Not sensitive |
| `address` | Public | Inherently public on XRPL |
| `name` | User-defined | May contain organizational info |
| `policy_id` | Internal identifier | Not sensitive |
| `policy_summary` | Operational limits | Reveals security posture |
| `balance` | Public | Available on XRPL |
| `tags` | User-defined | May contain organizational info |

### Privacy Considerations

- Wallet names may contain organizational information
- Tags may reveal wallet purpose or ownership
- Policy summaries reveal operational constraints
- Consider access control for sensitive environments

### Rate Limiting

| Limit | Value | Scope |
|-------|-------|-------|
| Requests per minute | 60 | Per client |
| Burst allowance | 10 | Additional requests |
| With balance flag | 10 | Per minute (network calls) |

### Audit Logging

All list queries are logged with event type `WALLET_LIST_QUERY`:

```typescript
await auditLogger.log({
  eventType: AuditEventType.WALLET_LIST_QUERY,
  correlationId,
  actor: { type: 'agent' },
  operation: {
    name: 'wallet_list',
    parameters: {
      network: input.network,
      include_inactive: input.include_inactive,
      search: input.search ? '[REDACTED]' : undefined,
      limit: input.limit,
      offset: input.offset,
      include_balance: input.include_balance,
    },
    result: 'success',
  },
  context: {
    returned_count: result.wallets.length,
    total_count: result.pagination.total,
  },
});
```

### Input Validation

```typescript
import { z } from 'zod';

const WalletListInputSchema = z.object({
  network: z.enum(['mainnet', 'testnet', 'devnet']).optional(),
  include_inactive: z.boolean().default(true),
  inactive_days_threshold: z.number().int().min(1).max(365).default(30),
  sort_by: z.enum(['name', 'created_at', 'last_activity', 'network'])
    .default('created_at'),
  sort_order: z.enum(['asc', 'desc']).default('desc'),
  limit: z.number().int().min(1).max(100).default(50),
  offset: z.number().int().min(0).default(0),
  search: z.string().min(1).max(64).optional(),
  include_policy_summary: z.boolean().default(false),
  include_balance: z.boolean().default(false),
}).strict();
```

---

## 10. Related Tools

| Tool | Relationship |
|------|--------------|
| `wallet_create` | Creates new wallets (adds to list) |
| `wallet_balance` | Get detailed balance for single wallet |
| `wallet_history` | Get transaction history for single wallet |
| `wallet_sign` | Sign transactions (requires wallet_id from list) |
| `wallet_policy_check` | Check policy for single wallet |
| `policy_set` | Update wallet policy |

### Typical Workflow

```
1. wallet_list            --> Get available wallet IDs
2. wallet_balance         --> Check specific wallet balance
3. wallet_policy_check    --> Verify transaction would be allowed
4. wallet_sign            --> Sign the transaction
5. wallet_list            --> Verify wallet still active
```

### Use Case Matrix

| Use Case | Tool Sequence |
|----------|---------------|
| Find available wallets | `wallet_list` |
| Check wallet before operation | `wallet_list` -> `wallet_balance` |
| Find mainnet production wallets | `wallet_list(network: mainnet, search: production)` |
| Inventory all wallets with balances | `wallet_list(include_balance: true)` |
| Clean up inactive wallets | `wallet_list(include_inactive: true)` -> manual review |

---

## References

- [MCP Tool Specification](https://modelcontextprotocol.io/specification)
- [XRPL Account Concepts](https://xrpl.org/accounts.html)
- [XRPL Address Encoding](https://xrpl.org/addresses.html)

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | JavaScript Developer | Initial specification |

---

*MCP Tool Documentation - XRPL Agent Wallet*
