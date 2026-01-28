# MCP Tool: wallet_history

**Tool Name**: `wallet_history`
**Version**: 1.0.0
**Sensitivity**: Low (Read-only)
**Rate Limit Tier**: Standard

---

## Table of Contents

1. [Description](#1-description)
2. [Input Schema](#2-input-schema)
3. [Output Schema](#3-output-schema)
4. [XRPL account_tx Query Mapping](#4-xrpl-account_tx-query-mapping)
5. [Pagination with Marker](#5-pagination-with-marker)
6. [Filtering Options](#6-filtering-options)
7. [Audit Context Attachment](#7-audit-context-attachment)
8. [Error Codes](#8-error-codes)
9. [Examples](#9-examples)
10. [Security Considerations](#10-security-considerations)
11. [Related Tools](#11-related-tools)

---

## 1. Description

The `wallet_history` tool retrieves transaction history for a managed XRPL wallet or any XRPL address. It provides a comprehensive view of past transactions with support for pagination, filtering, and correlation tracking for audit purposes.

### Purpose

- Retrieve historical transactions for a wallet or address
- Support pagination for large transaction histories
- Filter transactions by type, date range, and amount
- Link queries to audit trail via correlation IDs
- Provide enriched transaction metadata for analysis

### Use Cases

- AI agent reviewing past transactions before making decisions
- Auditing transaction history for a specific wallet
- Monitoring transaction patterns and anomalies
- Verifying completion of expected transactions
- Building transaction summaries for reporting

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
    "limit": {
      "type": "integer",
      "description": "Maximum number of transactions to return per page",
      "minimum": 1,
      "maximum": 100,
      "default": 20
    },
    "marker": {
      "type": "object",
      "description": "Pagination marker from previous response",
      "properties": {
        "ledger": {
          "type": "integer",
          "description": "Ledger index for pagination"
        },
        "seq": {
          "type": "integer",
          "description": "Transaction sequence for pagination"
        }
      },
      "required": ["ledger", "seq"]
    },
    "ledger_index_min": {
      "type": "integer",
      "description": "Earliest ledger index to include (-1 for earliest available)",
      "minimum": -1,
      "default": -1
    },
    "ledger_index_max": {
      "type": "integer",
      "description": "Latest ledger index to include (-1 for latest validated)",
      "minimum": -1,
      "default": -1
    },
    "forward": {
      "type": "boolean",
      "description": "If true, return oldest transactions first; if false, newest first",
      "default": false
    },
    "filters": {
      "type": "object",
      "description": "Optional filters to narrow transaction results",
      "properties": {
        "transaction_types": {
          "type": "array",
          "description": "Filter to specific transaction types",
          "items": {
            "type": "string",
            "enum": [
              "Payment",
              "EscrowCreate",
              "EscrowFinish",
              "EscrowCancel",
              "TrustSet",
              "OfferCreate",
              "OfferCancel",
              "AccountSet",
              "SetRegularKey",
              "SignerListSet",
              "TicketCreate",
              "NFTokenMint",
              "NFTokenBurn",
              "NFTokenCreateOffer",
              "NFTokenCancelOffer",
              "NFTokenAcceptOffer",
              "Clawback",
              "AMMCreate",
              "AMMDeposit",
              "AMMWithdraw",
              "AMMVote",
              "AMMBid",
              "AMMDelete"
            ]
          },
          "minItems": 1
        },
        "start_time": {
          "type": "string",
          "format": "date-time",
          "description": "Filter transactions on or after this timestamp (ISO 8601)"
        },
        "end_time": {
          "type": "string",
          "format": "date-time",
          "description": "Filter transactions on or before this timestamp (ISO 8601)"
        },
        "min_amount_drops": {
          "type": "string",
          "description": "Minimum amount in drops for Payment transactions",
          "pattern": "^[0-9]+$"
        },
        "max_amount_drops": {
          "type": "string",
          "description": "Maximum amount in drops for Payment transactions",
          "pattern": "^[0-9]+$"
        },
        "destination": {
          "type": "string",
          "description": "Filter by destination address",
          "pattern": "^r[1-9A-HJ-NP-Za-km-z]{24,34}$"
        },
        "source": {
          "type": "string",
          "description": "Filter by source address (for incoming payments)",
          "pattern": "^r[1-9A-HJ-NP-Za-km-z]{24,34}$"
        },
        "result": {
          "type": "string",
          "description": "Filter by transaction result",
          "enum": ["success", "failed", "all"],
          "default": "all"
        }
      },
      "additionalProperties": false
    },
    "include_metadata": {
      "type": "boolean",
      "description": "Include enriched metadata (balances changes, memo decoded)",
      "default": true
    },
    "correlation_id": {
      "type": "string",
      "description": "Correlation ID for linking this query to an audit context",
      "maxLength": 64,
      "pattern": "^[a-zA-Z0-9_-]+$"
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
interface WalletHistoryInput {
  /** Unique identifier of managed wallet (mutually exclusive with address) */
  wallet_id?: string;

  /** XRPL r-address to query (mutually exclusive with wallet_id) */
  address?: string;

  /** Maximum transactions per page (default: 20, max: 100) */
  limit?: number;

  /** Pagination marker from previous response */
  marker?: {
    ledger: number;
    seq: number;
  };

  /** Earliest ledger index (-1 for earliest available) */
  ledger_index_min?: number;

  /** Latest ledger index (-1 for latest validated) */
  ledger_index_max?: number;

  /** Return oldest first if true (default: false, newest first) */
  forward?: boolean;

  /** Optional filters to narrow results */
  filters?: TransactionFilters;

  /** Include enriched metadata (default: true) */
  include_metadata?: boolean;

  /** Correlation ID for audit linkage */
  correlation_id?: string;
}

interface TransactionFilters {
  /** Filter to specific transaction types */
  transaction_types?: TransactionType[];

  /** Filter transactions on or after this timestamp */
  start_time?: string;

  /** Filter transactions on or before this timestamp */
  end_time?: string;

  /** Minimum amount in drops (Payment transactions only) */
  min_amount_drops?: string;

  /** Maximum amount in drops (Payment transactions only) */
  max_amount_drops?: string;

  /** Filter by destination address */
  destination?: string;

  /** Filter by source address */
  source?: string;

  /** Filter by result: 'success', 'failed', or 'all' */
  result?: 'success' | 'failed' | 'all';
}
```

### Validation Rules

| Field | Rule | Error Code |
|-------|------|------------|
| `wallet_id` | Must match existing managed wallet | `WALLET_NOT_FOUND` |
| `address` | Must pass XRPL checksum validation | `INVALID_ADDRESS` |
| `wallet_id` / `address` | Exactly one must be provided | `INVALID_INPUT` |
| `limit` | Must be 1-100 | `INVALID_INPUT` |
| `marker` | Must have both `ledger` and `seq` if provided | `INVALID_MARKER` |
| `start_time` / `end_time` | Must be valid ISO 8601 timestamps | `INVALID_DATE_RANGE` |
| `min_amount_drops` / `max_amount_drops` | Must be non-negative integers | `INVALID_AMOUNT` |
| `destination` / `source` | Must be valid XRPL addresses | `INVALID_ADDRESS` |

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
    "transactions": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/TransactionEntry"
      }
    },
    "pagination": {
      "type": "object",
      "properties": {
        "has_more": {
          "type": "boolean",
          "description": "Whether more transactions are available"
        },
        "marker": {
          "type": "object",
          "properties": {
            "ledger": { "type": "integer" },
            "seq": { "type": "integer" }
          },
          "description": "Marker to use for next page request"
        },
        "total_available": {
          "type": "integer",
          "description": "Estimated total transactions (if available)"
        }
      },
      "required": ["has_more"]
    },
    "summary": {
      "type": "object",
      "properties": {
        "returned_count": {
          "type": "integer",
          "description": "Number of transactions in this response"
        },
        "filtered_count": {
          "type": "integer",
          "description": "Transactions matching filters (may differ from returned_count)"
        },
        "ledger_range": {
          "type": "object",
          "properties": {
            "min": { "type": "integer" },
            "max": { "type": "integer" }
          }
        },
        "time_range": {
          "type": "object",
          "properties": {
            "earliest": { "type": "string", "format": "date-time" },
            "latest": { "type": "string", "format": "date-time" }
          }
        }
      }
    },
    "audit": {
      "type": "object",
      "properties": {
        "correlation_id": {
          "type": "string",
          "description": "Correlation ID linking to audit context"
        },
        "query_logged_at": {
          "type": "string",
          "format": "date-time",
          "description": "Timestamp when query was logged"
        },
        "audit_seq": {
          "type": "integer",
          "description": "Audit log sequence number for this query"
        }
      }
    },
    "queried_at": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 timestamp of query"
    }
  },
  "required": ["success", "address", "transactions", "pagination", "summary", "queried_at"],
  "$defs": {
    "TransactionEntry": {
      "type": "object",
      "properties": {
        "hash": {
          "type": "string",
          "description": "Transaction hash (64 hex characters)"
        },
        "type": {
          "type": "string",
          "description": "Transaction type"
        },
        "result": {
          "type": "string",
          "description": "Transaction result code (e.g., tesSUCCESS)"
        },
        "result_success": {
          "type": "boolean",
          "description": "Whether transaction was successful"
        },
        "ledger_index": {
          "type": "integer",
          "description": "Ledger index where transaction was included"
        },
        "ledger_close_time": {
          "type": "string",
          "format": "date-time",
          "description": "Ledger close time (ISO 8601)"
        },
        "account": {
          "type": "string",
          "description": "Transaction sender address"
        },
        "destination": {
          "type": "string",
          "description": "Transaction destination (if applicable)"
        },
        "amount": {
          "type": "object",
          "properties": {
            "value": { "type": "string" },
            "currency": { "type": "string" },
            "issuer": { "type": "string" }
          },
          "description": "Delivered amount (for successful payments)"
        },
        "fee_drops": {
          "type": "string",
          "description": "Transaction fee in drops"
        },
        "sequence": {
          "type": "integer",
          "description": "Account sequence number"
        },
        "direction": {
          "type": "string",
          "enum": ["sent", "received", "self", "other"],
          "description": "Direction relative to queried account"
        },
        "metadata": {
          "type": "object",
          "properties": {
            "balance_changes": {
              "type": "array",
              "items": {
                "type": "object",
                "properties": {
                  "account": { "type": "string" },
                  "currency": { "type": "string" },
                  "value": { "type": "string" },
                  "issuer": { "type": "string" }
                }
              }
            },
            "memo": {
              "type": "array",
              "items": {
                "type": "object",
                "properties": {
                  "type": { "type": "string" },
                  "data": { "type": "string" }
                }
              }
            },
            "flags_readable": {
              "type": "array",
              "items": { "type": "string" }
            }
          },
          "description": "Enriched metadata (when include_metadata is true)"
        }
      },
      "required": ["hash", "type", "result", "result_success", "ledger_index", "account"]
    }
  }
}
```

### TypeScript Interface

```typescript
interface WalletHistoryOutput {
  success: true;
  wallet_id?: string;
  address: string;

  transactions: TransactionEntry[];

  pagination: {
    has_more: boolean;
    marker?: {
      ledger: number;
      seq: number;
    };
    total_available?: number;
  };

  summary: {
    returned_count: number;
    filtered_count?: number;
    ledger_range?: {
      min: number;
      max: number;
    };
    time_range?: {
      earliest: string;
      latest: string;
    };
  };

  audit?: {
    correlation_id: string;
    query_logged_at: string;
    audit_seq: number;
  };

  queried_at: string;
}

interface TransactionEntry {
  /** Transaction hash */
  hash: string;

  /** Transaction type (Payment, EscrowCreate, etc.) */
  type: TransactionType;

  /** Result code (tesSUCCESS, tecUNFUNDED_PAYMENT, etc.) */
  result: string;

  /** Whether transaction succeeded */
  result_success: boolean;

  /** Ledger index */
  ledger_index: number;

  /** Ledger close time */
  ledger_close_time?: string;

  /** Transaction sender */
  account: string;

  /** Transaction destination (if applicable) */
  destination?: string;

  /** Delivered amount (successful payments) */
  amount?: {
    value: string;
    currency: string;
    issuer?: string;
  };

  /** Fee in drops */
  fee_drops: string;

  /** Account sequence */
  sequence: number;

  /** Direction relative to queried account */
  direction: 'sent' | 'received' | 'self' | 'other';

  /** Enriched metadata */
  metadata?: TransactionMetadata;
}

interface TransactionMetadata {
  /** Balance changes for all affected accounts */
  balance_changes?: Array<{
    account: string;
    currency: string;
    value: string;
    issuer?: string;
  }>;

  /** Decoded memos */
  memo?: Array<{
    type?: string;
    data?: string;
  }>;

  /** Human-readable transaction flags */
  flags_readable?: string[];
}
```

---

## 4. XRPL account_tx Query Mapping

### Request Construction

The tool maps input parameters to the XRPL `account_tx` command.

```typescript
// account_tx request
const accountTxRequest = {
  command: 'account_tx',
  account: address,
  ledger_index_min: input.ledger_index_min ?? -1,
  ledger_index_max: input.ledger_index_max ?? -1,
  limit: input.limit ?? 20,
  forward: input.forward ?? false,
  ...(input.marker && { marker: input.marker }),
};
```

### XRPL Response Mapping

| XRPL Field | Output Field | Notes |
|------------|--------------|-------|
| `transactions[].tx` | `transactions[]` | Transaction data container |
| `tx.hash` | `hash` | 64-character hex |
| `tx.TransactionType` | `type` | XRPL transaction type enum |
| `meta.TransactionResult` | `result` | Result code string |
| `validated` + `result` | `result_success` | Computed: `validated && result.startsWith('tes')` |
| `tx.ledger_index` | `ledger_index` | Ledger containing transaction |
| `tx.date` | `ledger_close_time` | Ripple epoch to ISO 8601 |
| `tx.Account` | `account` | Transaction sender |
| `tx.Destination` | `destination` | Payment/escrow destination |
| `meta.delivered_amount` | `amount` | Actual delivered amount |
| `tx.Fee` | `fee_drops` | Transaction fee |
| `tx.Sequence` | `sequence` | Account sequence number |
| `marker` | `pagination.marker` | Pagination cursor |

### Ripple Epoch Conversion

XRPL timestamps are in "Ripple Epoch" format (seconds since January 1, 2000 00:00:00 UTC).

```typescript
const RIPPLE_EPOCH_OFFSET = 946684800; // Seconds from Unix epoch to Ripple epoch

function rippleTimeToISO(rippleTime: number): string {
  const unixTime = rippleTime + RIPPLE_EPOCH_OFFSET;
  return new Date(unixTime * 1000).toISOString();
}

function isoToRippleTime(isoString: string): number {
  const unixTime = Math.floor(new Date(isoString).getTime() / 1000);
  return unixTime - RIPPLE_EPOCH_OFFSET;
}
```

### Direction Calculation

```typescript
function calculateDirection(
  tx: Transaction,
  queryAddress: string
): 'sent' | 'received' | 'self' | 'other' {
  const sender = tx.Account;
  const recipient = tx.Destination;

  if (sender === queryAddress && recipient === queryAddress) {
    return 'self';
  }
  if (sender === queryAddress) {
    return 'sent';
  }
  if (recipient === queryAddress) {
    return 'received';
  }
  // Account affected by transaction but not sender/recipient
  // (e.g., escrow intermediary, trust line issuer)
  return 'other';
}
```

### Delivered Amount Extraction

```typescript
function extractDeliveredAmount(
  tx: Transaction,
  meta: TransactionMeta
): Amount | undefined {
  // Only extract for successful Payment transactions
  if (tx.TransactionType !== 'Payment') {
    return undefined;
  }

  // Use delivered_amount from metadata (handles partial payments)
  const delivered = meta.delivered_amount;

  if (typeof delivered === 'string') {
    // XRP amount in drops
    return {
      value: dropsToXRP(delivered),
      currency: 'XRP',
    };
  }

  if (typeof delivered === 'object') {
    // Issued currency
    return {
      value: delivered.value,
      currency: delivered.currency,
      issuer: delivered.issuer,
    };
  }

  return undefined;
}
```

---

## 5. Pagination with Marker

### XRPL Marker System

The XRPL uses an opaque marker object for pagination. The marker contains:
- `ledger`: Ledger index
- `seq`: Transaction sequence within the ledger

### Pagination Flow

```
                    Initial Request
                          |
                          v
                 +------------------+
                 | limit: 20        |
                 | marker: null     |
                 +------------------+
                          |
                          v
            +---------------------------+
            | Response:                 |
            | transactions[0..19]       |
            | marker: {ledger: X, seq: Y}|
            | has_more: true            |
            +---------------------------+
                          |
                          v
                    Next Request
                          |
                          v
                 +------------------+
                 | limit: 20        |
                 | marker: {X, Y}   |
                 +------------------+
                          |
                          v
            +---------------------------+
            | Response:                 |
            | transactions[20..39]      |
            | marker: {ledger: Z, seq: W}|
            | has_more: true            |
            +---------------------------+
                          |
                          v
                       ...
                          |
                          v
            +---------------------------+
            | Response:                 |
            | transactions[80..85]      |
            | marker: null              |
            | has_more: false           |
            +---------------------------+
```

### Implementation

```typescript
async function fetchTransactionHistory(
  client: XrplClient,
  address: string,
  options: FetchOptions
): Promise<HistoryResult> {
  const request: AccountTxRequest = {
    command: 'account_tx',
    account: address,
    ledger_index_min: options.ledgerIndexMin ?? -1,
    ledger_index_max: options.ledgerIndexMax ?? -1,
    limit: options.limit ?? 20,
    forward: options.forward ?? false,
  };

  // Include marker for pagination
  if (options.marker) {
    request.marker = options.marker;
  }

  const response = await client.request(request);

  return {
    transactions: response.result.transactions,
    marker: response.result.marker ?? null,
    hasMore: !!response.result.marker,
  };
}
```

### Pagination Best Practices

| Practice | Description |
|----------|-------------|
| **Preserve marker exactly** | Pass the marker object unchanged to the next request |
| **Handle marker expiration** | Markers may become invalid after ledger pruning |
| **Set reasonable limits** | Use 20-50 for interactive queries, 100 for batch processing |
| **Forward vs reverse** | Use `forward: false` (default) for most recent transactions first |

### Marker Validation

```typescript
import { z } from 'zod';

const MarkerSchema = z.object({
  ledger: z.number().int().positive(),
  seq: z.number().int().nonnegative(),
}).strict();

function validateMarker(marker: unknown): marker is Marker {
  return MarkerSchema.safeParse(marker).success;
}
```

---

## 6. Filtering Options

### Server-Side vs Client-Side Filtering

The XRPL `account_tx` command has limited filtering capabilities. The tool implements a hybrid approach:

| Filter | Location | Notes |
|--------|----------|-------|
| `ledger_index_min/max` | Server-side | XRPL native support |
| `transaction_types` | Client-side | Post-fetch filtering |
| `start_time/end_time` | Client-side | Converted to ledger range when possible |
| `min/max_amount_drops` | Client-side | Payment transactions only |
| `destination/source` | Client-side | Post-fetch filtering |
| `result` | Client-side | Success/failure filtering |

### Filter Implementation

```typescript
interface FilterContext {
  queryAddress: string;
  filters: TransactionFilters;
}

function applyFilters(
  transactions: RawTransaction[],
  context: FilterContext
): TransactionEntry[] {
  return transactions.filter(tx => {
    // Transaction type filter
    if (context.filters.transaction_types) {
      if (!context.filters.transaction_types.includes(tx.TransactionType)) {
        return false;
      }
    }

    // Time range filter
    if (context.filters.start_time) {
      const startRipple = isoToRippleTime(context.filters.start_time);
      if (tx.date < startRipple) {
        return false;
      }
    }

    if (context.filters.end_time) {
      const endRipple = isoToRippleTime(context.filters.end_time);
      if (tx.date > endRipple) {
        return false;
      }
    }

    // Amount filter (Payment transactions only)
    if (tx.TransactionType === 'Payment') {
      const amountDrops = getAmountInDrops(tx);

      if (context.filters.min_amount_drops) {
        const min = BigInt(context.filters.min_amount_drops);
        if (amountDrops < min) {
          return false;
        }
      }

      if (context.filters.max_amount_drops) {
        const max = BigInt(context.filters.max_amount_drops);
        if (amountDrops > max) {
          return false;
        }
      }
    }

    // Destination filter
    if (context.filters.destination) {
      if (tx.Destination !== context.filters.destination) {
        return false;
      }
    }

    // Source filter
    if (context.filters.source) {
      if (tx.Account !== context.filters.source) {
        return false;
      }
    }

    // Result filter
    if (context.filters.result && context.filters.result !== 'all') {
      const isSuccess = tx.meta?.TransactionResult?.startsWith('tes');
      if (context.filters.result === 'success' && !isSuccess) {
        return false;
      }
      if (context.filters.result === 'failed' && isSuccess) {
        return false;
      }
    }

    return true;
  });
}
```

### Time Range Optimization

When possible, convert time ranges to ledger ranges for server-side filtering:

```typescript
async function optimizeDateRangeToLedgers(
  client: XrplClient,
  startTime?: string,
  endTime?: string
): Promise<{ min: number; max: number }> {
  // Get ledger index estimates based on average close time (3-4 seconds)
  const AVERAGE_LEDGER_CLOSE_SECONDS = 3.5;

  let min = -1;
  let max = -1;

  if (startTime) {
    const startUnix = new Date(startTime).getTime() / 1000;
    const nowUnix = Date.now() / 1000;
    const secondsAgo = nowUnix - startUnix;
    const ledgersAgo = Math.ceil(secondsAgo / AVERAGE_LEDGER_CLOSE_SECONDS);

    // Get current validated ledger
    const serverInfo = await client.request({ command: 'server_info' });
    const currentLedger = serverInfo.result.info.validated_ledger.seq;

    min = Math.max(1, currentLedger - ledgersAgo);
  }

  // Similar logic for endTime -> max

  return { min, max };
}
```

### Filter Combination Matrix

| Filter A | Filter B | Behavior |
|----------|----------|----------|
| `transaction_types` | `start_time` | AND: Both must match |
| `min_amount_drops` | `transaction_types` | AND: Amount filter only applies if type matches |
| `destination` | `source` | AND: Both addresses must match |
| `result: success` | Any filter | AND: Only successful transactions |

---

## 7. Audit Context Attachment

### Correlation ID Linking

The `correlation_id` parameter links transaction history queries to a broader audit context, enabling:

- Tracing agent decision-making processes
- Correlating queries with subsequent signing operations
- Building complete audit trails for investigations

### Audit Integration Flow

```
+------------------+     +------------------+     +------------------+
|  Agent Decision  |     |  wallet_history  |     |  wallet_sign     |
|  Process         |     |  Query           |     |  Request         |
+------------------+     +------------------+     +------------------+
        |                        |                        |
        | correlation_id:       | correlation_id:        | correlation_id:
        | "decision-123"        | "decision-123"         | "decision-123"
        |                        |                        |
        v                        v                        v
+------------------------------------------------------------------+
|                       AUDIT LOG                                  |
|                                                                  |
| [seq: 1001] agent_decision_start  | correlation_id: decision-123 |
| [seq: 1002] wallet_history_query  | correlation_id: decision-123 |
| [seq: 1003] wallet_sign_request   | correlation_id: decision-123 |
| [seq: 1004] signing_approved      | correlation_id: decision-123 |
+------------------------------------------------------------------+
```

### Audit Event for History Query

```typescript
interface HistoryQueryAuditEvent {
  seq: number;
  timestamp: string;
  event: 'wallet_history_query';
  correlation_id?: string;

  // Query context
  wallet_id?: string;
  wallet_address: string;

  // Query parameters (non-sensitive)
  query_params: {
    limit: number;
    has_marker: boolean;
    ledger_range: {
      min: number;
      max: number;
    };
    filters_applied: string[];  // Names of active filters
  };

  // Result summary
  result: {
    returned_count: number;
    has_more: boolean;
  };

  // Audit chain
  prev_hash: string;
  hash: string;
}
```

### Audit Logging Implementation

```typescript
async function logHistoryQuery(
  input: WalletHistoryInput,
  result: WalletHistoryOutput,
  correlationId?: string
): Promise<AuditLogEntry> {
  const auditEvent: HistoryQueryAuditEvent = {
    seq: await getNextAuditSeq(),
    timestamp: new Date().toISOString(),
    event: 'wallet_history_query',
    correlation_id: correlationId,
    wallet_id: input.wallet_id,
    wallet_address: result.address,
    query_params: {
      limit: input.limit ?? 20,
      has_marker: !!input.marker,
      ledger_range: {
        min: input.ledger_index_min ?? -1,
        max: input.ledger_index_max ?? -1,
      },
      filters_applied: getActiveFilterNames(input.filters),
    },
    result: {
      returned_count: result.transactions.length,
      has_more: result.pagination.has_more,
    },
    prev_hash: await getLastAuditHash(),
    hash: '', // Computed below
  };

  auditEvent.hash = computeAuditHash(auditEvent);

  await appendToAuditLog(auditEvent);

  return auditEvent;
}
```

### Correlation ID Best Practices

| Practice | Description |
|----------|-------------|
| **Generate early** | Create correlation ID at decision start |
| **Pass through** | Include in all related tool calls |
| **Unique per decision** | Use UUID or similar for uniqueness |
| **Include in response** | Return in audit field for confirmation |

---

## 8. Error Codes

### Error Response Schema

```typescript
interface WalletHistoryError {
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
| `ACCOUNT_NOT_FOUND` | 404 | Address not found on XRPL (no transactions) | Verify address or fund account |
| `INVALID_ADDRESS` | 400 | Address fails checksum validation | Correct the address |
| `INVALID_INPUT` | 400 | Missing or invalid parameters | Fix input format |
| `INVALID_MARKER` | 400 | Marker format invalid or expired | Start pagination from beginning |
| `INVALID_DATE_RANGE` | 400 | Start time after end time | Correct date range |
| `INVALID_AMOUNT` | 400 | Amount filter value invalid | Use positive integer string |
| `NETWORK_ERROR` | 503 | Cannot reach XRPL network | Retry with backoff |
| `LEDGER_NOT_FOUND` | 404 | Specified ledger range not available | Use broader range or -1 |
| `RATE_LIMITED` | 429 | Too many requests | Wait and retry |
| `INTERNAL_ERROR` | 500 | Unexpected server error | Contact support |

### Error Examples

**Invalid Marker**:
```json
{
  "success": false,
  "error": {
    "code": "INVALID_MARKER",
    "message": "Pagination marker is invalid or has expired",
    "details": {
      "marker": { "ledger": 85000000, "seq": 999 },
      "hint": "Markers may expire after ledger history is pruned. Start pagination from the beginning."
    }
  }
}
```

**Account Not Found**:
```json
{
  "success": false,
  "error": {
    "code": "ACCOUNT_NOT_FOUND",
    "message": "No transaction history found for this address",
    "details": {
      "address": "rNewUnfundedAccount...",
      "reason": "Account may not exist or has no transactions"
    }
  }
}
```

**Invalid Date Range**:
```json
{
  "success": false,
  "error": {
    "code": "INVALID_DATE_RANGE",
    "message": "Start time must be before end time",
    "details": {
      "start_time": "2026-02-01T00:00:00Z",
      "end_time": "2026-01-01T00:00:00Z"
    }
  }
}
```

---

## 9. Examples

### Example 1: Basic History Query

**Request**:
```json
{
  "name": "wallet_history",
  "arguments": {
    "wallet_id": "agent-wallet-001",
    "limit": 10
  }
}
```

**Response**:
```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"success\":true,\"wallet_id\":\"agent-wallet-001\",\"address\":\"rAgentWallet123...\",\"transactions\":[{\"hash\":\"ABC123DEF456...\",\"type\":\"Payment\",\"result\":\"tesSUCCESS\",\"result_success\":true,\"ledger_index\":85432100,\"ledger_close_time\":\"2026-01-28T14:25:30Z\",\"account\":\"rAgentWallet123...\",\"destination\":\"rRecipient456...\",\"amount\":{\"value\":\"10.000000\",\"currency\":\"XRP\"},\"fee_drops\":\"12\",\"sequence\":42,\"direction\":\"sent\",\"metadata\":{\"balance_changes\":[{\"account\":\"rAgentWallet123...\",\"currency\":\"XRP\",\"value\":\"-10.000012\"},{\"account\":\"rRecipient456...\",\"currency\":\"XRP\",\"value\":\"10.000000\"}],\"memo\":[{\"type\":\"text/plain\",\"data\":\"Payment for order #123\"}]}},{\"hash\":\"DEF789GHI012...\",\"type\":\"Payment\",\"result\":\"tesSUCCESS\",\"result_success\":true,\"ledger_index\":85432050,\"ledger_close_time\":\"2026-01-28T14:20:15Z\",\"account\":\"rSender789...\",\"destination\":\"rAgentWallet123...\",\"amount\":{\"value\":\"50.000000\",\"currency\":\"XRP\"},\"fee_drops\":\"12\",\"sequence\":156,\"direction\":\"received\"}],\"pagination\":{\"has_more\":true,\"marker\":{\"ledger\":85432000,\"seq\":3}},\"summary\":{\"returned_count\":10,\"ledger_range\":{\"min\":85432000,\"max\":85432100},\"time_range\":{\"earliest\":\"2026-01-28T14:00:00Z\",\"latest\":\"2026-01-28T14:25:30Z\"}},\"queried_at\":\"2026-01-28T14:30:00.123Z\"}"
    }
  ]
}
```

### Example 2: Paginated Query

**First Request**:
```json
{
  "name": "wallet_history",
  "arguments": {
    "wallet_id": "agent-wallet-001",
    "limit": 20
  }
}
```

**First Response** (truncated):
```json
{
  "success": true,
  "transactions": ["...20 transactions..."],
  "pagination": {
    "has_more": true,
    "marker": {
      "ledger": 85430000,
      "seq": 5
    }
  }
}
```

**Second Request** (using marker):
```json
{
  "name": "wallet_history",
  "arguments": {
    "wallet_id": "agent-wallet-001",
    "limit": 20,
    "marker": {
      "ledger": 85430000,
      "seq": 5
    }
  }
}
```

**Second Response**:
```json
{
  "success": true,
  "transactions": ["...next 20 transactions..."],
  "pagination": {
    "has_more": true,
    "marker": {
      "ledger": 85428000,
      "seq": 12
    }
  }
}
```

### Example 3: Filtered Query by Transaction Type and Date Range

**Request**:
```json
{
  "name": "wallet_history",
  "arguments": {
    "wallet_id": "agent-wallet-001",
    "limit": 50,
    "filters": {
      "transaction_types": ["Payment", "EscrowFinish"],
      "start_time": "2026-01-01T00:00:00Z",
      "end_time": "2026-01-28T23:59:59Z",
      "result": "success"
    }
  }
}
```

**Response** (truncated):
```json
{
  "success": true,
  "address": "rAgentWallet123...",
  "transactions": [
    {
      "hash": "ABC...",
      "type": "Payment",
      "result": "tesSUCCESS",
      "result_success": true,
      "direction": "sent"
    },
    {
      "hash": "DEF...",
      "type": "EscrowFinish",
      "result": "tesSUCCESS",
      "result_success": true,
      "direction": "other"
    }
  ],
  "pagination": {
    "has_more": false
  },
  "summary": {
    "returned_count": 25,
    "filtered_count": 25,
    "time_range": {
      "earliest": "2026-01-03T10:15:00Z",
      "latest": "2026-01-28T14:25:30Z"
    }
  }
}
```

### Example 4: Amount Filter for Large Payments

**Request**:
```json
{
  "name": "wallet_history",
  "arguments": {
    "address": "rExternalAddress123...",
    "limit": 20,
    "filters": {
      "transaction_types": ["Payment"],
      "min_amount_drops": "100000000",
      "result": "success"
    }
  }
}
```

**Response**:
```json
{
  "success": true,
  "address": "rExternalAddress123...",
  "transactions": [
    {
      "hash": "LARGE001...",
      "type": "Payment",
      "result": "tesSUCCESS",
      "result_success": true,
      "ledger_index": 85400000,
      "account": "rExternalAddress123...",
      "destination": "rTreasury...",
      "amount": {
        "value": "500.000000",
        "currency": "XRP"
      },
      "direction": "sent"
    }
  ],
  "pagination": {
    "has_more": false
  },
  "summary": {
    "returned_count": 3,
    "filtered_count": 3
  }
}
```

### Example 5: Query with Correlation ID

**Request**:
```json
{
  "name": "wallet_history",
  "arguments": {
    "wallet_id": "agent-wallet-001",
    "limit": 5,
    "filters": {
      "destination": "rVendorAddress...",
      "result": "success"
    },
    "correlation_id": "decision-abc-123"
  }
}
```

**Response**:
```json
{
  "success": true,
  "wallet_id": "agent-wallet-001",
  "address": "rAgentWallet123...",
  "transactions": [
    {
      "hash": "VENDOR001...",
      "type": "Payment",
      "result": "tesSUCCESS",
      "result_success": true,
      "destination": "rVendorAddress...",
      "direction": "sent"
    }
  ],
  "pagination": {
    "has_more": false
  },
  "summary": {
    "returned_count": 3
  },
  "audit": {
    "correlation_id": "decision-abc-123",
    "query_logged_at": "2026-01-28T14:30:00.456Z",
    "audit_seq": 1042
  },
  "queried_at": "2026-01-28T14:30:00.456Z"
}
```

### Example 6: Query Oldest Transactions First

**Request**:
```json
{
  "name": "wallet_history",
  "arguments": {
    "wallet_id": "agent-wallet-001",
    "limit": 10,
    "forward": true,
    "ledger_index_min": 85000000
  }
}
```

**Response**:
```json
{
  "success": true,
  "transactions": [
    {
      "hash": "OLDEST001...",
      "ledger_index": 85000001,
      "ledger_close_time": "2026-01-01T00:00:05Z"
    },
    {
      "hash": "OLDEST002...",
      "ledger_index": 85000005,
      "ledger_close_time": "2026-01-01T00:00:20Z"
    }
  ],
  "pagination": {
    "has_more": true,
    "marker": {
      "ledger": 85000100,
      "seq": 1
    }
  }
}
```

### Example 7: Error - Invalid Marker

**Request**:
```json
{
  "name": "wallet_history",
  "arguments": {
    "wallet_id": "agent-wallet-001",
    "marker": {
      "ledger": 1,
      "seq": 9999
    }
  }
}
```

**Response**:
```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"success\":false,\"error\":{\"code\":\"INVALID_MARKER\",\"message\":\"Pagination marker is invalid or has expired\",\"details\":{\"marker\":{\"ledger\":1,\"seq\":9999},\"hint\":\"The specified ledger may no longer be available in history. Start pagination from the beginning.\"}}}"
    }
  ],
  "isError": true
}
```

---

## 10. Security Considerations

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
| Transaction history | Returned | Public on XRPL |
| Memo data | Decoded if present | May contain user data; logged as-is |
| Correlation ID | Logged | Links queries to audit context |

### Rate Limiting

| Limit | Value | Scope |
|-------|-------|-------|
| Requests per minute | 60 | Per wallet_id |
| Requests per minute | 30 | Per address (external) |
| Burst allowance | 5 | Additional requests |
| Max transactions per request | 100 | Per request |

### Audit Logging

All history queries are logged with event type `WALLET_HISTORY_QUERY`:

```typescript
await auditLogger.log({
  eventType: AuditEventType.WALLET_HISTORY_QUERY,
  correlationId,
  actor: { type: 'agent' },
  operation: {
    name: 'wallet_history',
    parameters: {
      wallet_id: input.wallet_id,
      address: input.address,
      limit: input.limit,
      has_marker: !!input.marker,
      filters: Object.keys(input.filters || {}),
    },
    result: 'success',
  },
  context: {
    network: 'mainnet',
    walletAddress: address,
    returnedCount: result.transactions.length,
  },
});
```

### Input Validation

```typescript
import { z } from 'zod';

const WalletHistoryInputSchema = z.object({
  wallet_id: z.string()
    .min(1)
    .max(64)
    .regex(/^[a-zA-Z0-9_-]+$/)
    .optional(),
  address: z.string()
    .regex(/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/)
    .refine(isValidXRPLChecksum, 'Invalid XRPL address checksum')
    .optional(),
  limit: z.number().int().min(1).max(100).default(20),
  marker: z.object({
    ledger: z.number().int().positive(),
    seq: z.number().int().nonnegative(),
  }).optional(),
  ledger_index_min: z.number().int().min(-1).default(-1),
  ledger_index_max: z.number().int().min(-1).default(-1),
  forward: z.boolean().default(false),
  filters: TransactionFiltersSchema.optional(),
  include_metadata: z.boolean().default(true),
  correlation_id: z.string()
    .max(64)
    .regex(/^[a-zA-Z0-9_-]+$/)
    .optional(),
}).refine(
  data => (data.wallet_id !== undefined) !== (data.address !== undefined),
  { message: 'Exactly one of wallet_id or address must be provided' }
);
```

---

## 11. Related Tools

| Tool | Relationship |
|------|--------------|
| `wallet_balance` | Check current balance (use history for past activity) |
| `wallet_sign` | Sign new transactions (history shows past signed transactions) |
| `get_transaction_status` | Check status of specific transaction by hash |
| `list_wallets` | List all managed wallets (to get wallet_id) |

### Typical Workflow

```
1. list_wallets          --> Get available wallet IDs
2. wallet_history        --> Review recent transactions
3. wallet_balance        --> Check current funds
4. wallet_sign           --> Sign new transaction
5. get_transaction_status --> Verify submission
6. wallet_history        --> Confirm in history
```

### History Query Use Cases

| Use Case | Recommended Filters |
|----------|---------------------|
| Find payment to vendor | `destination`, `transaction_types: ["Payment"]` |
| Review large transactions | `min_amount_drops`, `result: "success"` |
| Check escrow completions | `transaction_types: ["EscrowFinish"]` |
| Audit specific period | `start_time`, `end_time` |
| Find failed transactions | `result: "failed"` |
| Track incoming payments | `source` (sender address) |

---

## References

- [XRPL account_tx Reference](https://xrpl.org/account_tx.html)
- [XRPL Transaction Types](https://xrpl.org/transaction-types.html)
- [XRPL Transaction Results](https://xrpl.org/transaction-results.html)
- [MCP Tool Specification](https://modelcontextprotocol.io/specification)

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | JavaScript Developer | Initial specification |

---

*MCP Tool Documentation - XRPL Agent Wallet*
