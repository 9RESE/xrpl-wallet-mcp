# MCP Tool: tx_decode

**Tool Name**: `tx_decode`
**Version**: 1.0.0
**Sensitivity**: Low (Read-only)
**Rate Limit Tier**: Standard

---

## Table of Contents

1. [Description](#1-description)
2. [Input Schema](#2-input-schema)
3. [Output Schema](#3-output-schema)
4. [XRPL Binary Codec Usage](#4-xrpl-binary-codec-usage)
5. [Field Mapping to Human-Readable Names](#5-field-mapping-to-human-readable-names)
6. [Amount Formatting](#6-amount-formatting)
7. [Security Uses](#7-security-uses)
8. [Error Codes](#8-error-codes)
9. [Examples](#9-examples)
10. [Implementation Details](#10-implementation-details)
11. [Related Tools](#11-related-tools)

---

## 1. Description

The `tx_decode` tool decodes an unsigned XRPL transaction blob (hex-encoded binary format) into a human-readable JSON representation. This is a **read-only inspection tool** that does not sign, submit, or modify transactions in any way.

### Purpose

- Decode binary transaction blobs for human inspection
- Verify transaction contents before signing
- Display amounts in human-readable format (XRP vs drops)
- Map XRPL field codes to readable field names
- Support security review of unsigned transactions

### Security Classification

This tool is classified as **Low** sensitivity because:
- No key material is accessed or used
- No transactions are signed or submitted
- No state is modified
- Operation is purely computational (decoding)
- Output is informational only

### Primary Use Case

**Pre-signing verification**: Before an AI agent signs a transaction using `wallet_sign`, it should use `tx_decode` to:
1. Verify the transaction type matches the intended operation
2. Confirm the destination address is correct
3. Validate the amount is as expected
4. Check that no unexpected fields are present

### Tool Registration

```typescript
{
  name: 'tx_decode',
  description: 'Decode an unsigned XRPL transaction blob into human-readable JSON. ' +
    'Use this to inspect and verify transaction contents before signing. ' +
    'This is a read-only operation that does not modify or sign the transaction.',
  inputSchema: TxDecodeInputSchema,
  outputSchema: TxDecodeOutputSchema,
}
```

---

## 2. Input Schema

### JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "unsigned_tx": {
      "type": "string",
      "description": "Hex-encoded unsigned XRPL transaction blob",
      "minLength": 20,
      "maxLength": 1000000,
      "pattern": "^[A-Fa-f0-9]+$"
    },
    "include_raw_fields": {
      "type": "boolean",
      "description": "Include raw field values alongside human-readable versions",
      "default": false
    },
    "format_amounts": {
      "type": "boolean",
      "description": "Convert drops to XRP in amount fields",
      "default": true
    }
  },
  "required": ["unsigned_tx"],
  "additionalProperties": false
}
```

### TypeScript Interface

```typescript
import { z } from 'zod';

export const TxDecodeInputSchema = z.object({
  /**
   * Hex-encoded unsigned XRPL transaction blob.
   * Must be valid hexadecimal without 0x prefix.
   */
  unsigned_tx: z
    .string()
    .min(20, 'Transaction blob too short to be valid')
    .max(1000000, 'Transaction blob exceeds maximum size (1MB)')
    .regex(/^[A-Fa-f0-9]+$/, 'Transaction blob must be hexadecimal (no 0x prefix)')
    .describe('Hex-encoded unsigned XRPL transaction blob'),

  /**
   * Include raw field values alongside human-readable versions.
   * When true, amount fields include both 'drops' and 'xrp' values.
   */
  include_raw_fields: z
    .boolean()
    .default(false)
    .describe('Include raw field values alongside human-readable versions'),

  /**
   * Convert amount fields from drops to XRP.
   * When true, amounts display as XRP with 6 decimal places.
   * When false, amounts display as drops (integer string).
   */
  format_amounts: z
    .boolean()
    .default(true)
    .describe('Convert drops to XRP in amount fields'),
}).describe('Decode an unsigned XRPL transaction for inspection');

export type TxDecodeInput = z.infer<typeof TxDecodeInputSchema>;
```

### Input Validation

| Field | Rule | Error Code |
|-------|------|------------|
| `unsigned_tx` | Minimum 20 hex characters | `INVALID_TRANSACTION` |
| `unsigned_tx` | Maximum 1,000,000 characters | `TRANSACTION_TOO_LARGE` |
| `unsigned_tx` | Valid hexadecimal only | `INVALID_HEX_FORMAT` |
| `unsigned_tx` | Must decode to valid transaction | `DECODE_FAILED` |

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
      "const": true
    },
    "transaction": {
      "type": "object",
      "properties": {
        "TransactionType": {
          "type": "string",
          "description": "Human-readable transaction type name"
        },
        "Account": {
          "type": "string",
          "description": "Source account address (r-address)"
        },
        "Destination": {
          "type": "string",
          "description": "Destination account address (if applicable)"
        },
        "Amount": {
          "type": ["string", "object"],
          "description": "Transaction amount (formatted based on format_amounts)"
        },
        "Fee": {
          "type": "string",
          "description": "Transaction fee"
        },
        "Sequence": {
          "type": "integer",
          "description": "Account sequence number"
        },
        "Flags": {
          "type": "integer",
          "description": "Transaction flags bitmap"
        }
      },
      "required": ["TransactionType", "Account"],
      "additionalProperties": true
    },
    "transaction_type_info": {
      "type": "object",
      "properties": {
        "name": {
          "type": "string"
        },
        "description": {
          "type": "string"
        },
        "category": {
          "type": "string",
          "enum": ["payment", "trust_line", "offer", "escrow", "check", "payment_channel", "account_settings", "multi_sign", "nft", "amm", "other"]
        }
      }
    },
    "flags_readable": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Human-readable flag names"
    },
    "amounts_formatted": {
      "type": "object",
      "description": "All amount fields with human-readable formatting",
      "additionalProperties": {
        "type": "object",
        "properties": {
          "value": { "type": "string" },
          "currency": { "type": "string" },
          "issuer": { "type": "string" },
          "drops": { "type": "string" },
          "xrp": { "type": "string" }
        }
      }
    },
    "warnings": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "code": { "type": "string" },
          "message": { "type": "string" },
          "field": { "type": "string" }
        }
      },
      "description": "Potential issues or notable aspects of the transaction"
    },
    "metadata": {
      "type": "object",
      "properties": {
        "blob_size_bytes": { "type": "integer" },
        "field_count": { "type": "integer" },
        "is_signed": { "type": "boolean" },
        "decoded_at": { "type": "string", "format": "date-time" }
      }
    }
  },
  "required": ["success", "transaction", "metadata"]
}
```

### TypeScript Interface

```typescript
export interface TxDecodeOutput {
  success: true;

  /** Decoded transaction fields */
  transaction: {
    TransactionType: string;
    Account: string;
    Destination?: string;
    Amount?: string | AmountObject;
    Fee?: string;
    Sequence?: number;
    Flags?: number;
    [key: string]: unknown;
  };

  /** Information about the transaction type */
  transaction_type_info: {
    name: string;
    description: string;
    category: TransactionCategory;
  };

  /** Human-readable flag names */
  flags_readable: string[];

  /** All amount fields with human-readable formatting */
  amounts_formatted: Record<string, FormattedAmount>;

  /** Potential issues or notable aspects */
  warnings: TransactionWarning[];

  /** Decoding metadata */
  metadata: {
    blob_size_bytes: number;
    field_count: number;
    is_signed: boolean;
    decoded_at: string;
  };
}

interface AmountObject {
  value: string;
  currency: string;
  issuer: string;
}

interface FormattedAmount {
  value: string;
  currency: string;
  issuer?: string;
  drops?: string;
  xrp?: string;
}

interface TransactionWarning {
  code: string;
  message: string;
  field?: string;
}

type TransactionCategory =
  | 'payment'
  | 'trust_line'
  | 'offer'
  | 'escrow'
  | 'check'
  | 'payment_channel'
  | 'account_settings'
  | 'multi_sign'
  | 'nft'
  | 'amm'
  | 'other';
```

---

## 4. XRPL Binary Codec Usage

### Overview

The XRPL uses a binary serialization format for transactions. The `xrpl` npm package (v4.x) provides the `decode` function from the binary codec module to convert hex-encoded transaction blobs back to JSON.

### Using xrpl.js Binary Codec

```typescript
import { decode } from 'xrpl';

// Or import from the specific module
import { decode, encode } from 'xrpl/dist/npm/utils/hashes';

async function decodeTransaction(hexBlob: string): Promise<DecodedTransaction> {
  try {
    // Normalize hex string (remove any 0x prefix, uppercase)
    const normalizedHex = hexBlob.replace(/^0x/i, '').toUpperCase();

    // Decode the binary blob to JSON
    const decoded = decode(normalizedHex);

    return {
      success: true,
      transaction: decoded,
      is_signed: hasSignature(decoded),
    };
  } catch (error) {
    if (error instanceof Error) {
      throw new DecodeError('DECODE_FAILED', error.message);
    }
    throw new DecodeError('DECODE_FAILED', 'Unknown decode error');
  }
}

function hasSignature(tx: Record<string, unknown>): boolean {
  return 'TxnSignature' in tx || 'Signers' in tx;
}
```

### Binary Codec Architecture

```
   Hex Transaction Blob
           |
           v
   +------------------+
   | Normalize Input  |  Remove 0x prefix, validate hex
   +------------------+
           |
           v
   +------------------+
   | Field Type Decode|  Parse field ID bytes
   +------------------+
           |
           v
   +------------------+
   | Length Decode    |  Variable length field parsing
   +------------------+
           |
           v
   +------------------+
   | Value Decode     |  Type-specific value decoding
   +------------------+
           |
           v
   +------------------+
   | Field Name Map   |  Numeric ID to human name
   +------------------+
           |
           v
   Decoded JSON Transaction
```

### XRPL Binary Format Overview

The XRPL binary format encodes transactions as a series of field-value pairs:

| Component | Size | Description |
|-----------|------|-------------|
| Field Code | 1-3 bytes | Identifies field type and ID |
| Length | 0-4 bytes | For variable-length fields |
| Value | variable | Encoded field value |

Field types include:
- **UInt16/UInt32**: Fixed-size integers (transaction type, sequence)
- **Amount**: XRP drops (64-bit) or issued currency (160-bit)
- **AccountID**: 160-bit account identifier
- **Blob**: Variable-length binary data (memos, signatures)
- **STObject**: Nested object (amount with currency/issuer)
- **STArray**: Array of objects (signers, NFTs)

---

## 5. Field Mapping to Human-Readable Names

### Transaction Type Codes

| Code | Name | Description | Category |
|------|------|-------------|----------|
| 0 | Payment | Send XRP or issued currency | payment |
| 1 | EscrowCreate | Create time-locked escrow | escrow |
| 2 | EscrowFinish | Complete an escrow | escrow |
| 3 | AccountSet | Modify account settings | account_settings |
| 4 | EscrowCancel | Cancel an escrow | escrow |
| 5 | RegularKeySet | Set regular key | account_settings |
| 6 | NickNameSet | Set account nickname (deprecated) | other |
| 7 | OfferCreate | Create DEX offer | offer |
| 8 | OfferCancel | Cancel DEX offer | offer |
| 9 | Contract | Smart contract (deprecated) | other |
| 10 | TicketCreate | Create tickets | account_settings |
| 11 | TicketCancel | Cancel tickets (deprecated) | other |
| 12 | SignerListSet | Set multi-sign list | multi_sign |
| 13 | PaymentChannelCreate | Create payment channel | payment_channel |
| 14 | PaymentChannelFund | Fund payment channel | payment_channel |
| 15 | PaymentChannelClaim | Claim from payment channel | payment_channel |
| 16 | CheckCreate | Create a check | check |
| 17 | CheckCash | Cash a check | check |
| 18 | CheckCancel | Cancel a check | check |
| 19 | DepositPreauth | Preauthorize deposit | account_settings |
| 20 | TrustSet | Create/modify trust line | trust_line |
| 21 | AccountDelete | Delete account | account_settings |
| 22 | SetHook | Set hooks (amendment) | other |
| 25 | NFTokenMint | Mint NFT | nft |
| 26 | NFTokenBurn | Burn NFT | nft |
| 27 | NFTokenCreateOffer | Create NFT offer | nft |
| 28 | NFTokenCancelOffer | Cancel NFT offer | nft |
| 29 | NFTokenAcceptOffer | Accept NFT offer | nft |
| 30 | Clawback | Clawback issued currency | trust_line |
| 35 | AMMCreate | Create AMM pool | amm |
| 36 | AMMDeposit | Deposit to AMM | amm |
| 37 | AMMWithdraw | Withdraw from AMM | amm |
| 38 | AMMVote | Vote on AMM fees | amm |
| 39 | AMMBid | Bid for AMM auction slot | amm |
| 40 | AMMDelete | Delete empty AMM | amm |
| 41 | XChainCreateBridge | Create cross-chain bridge | other |
| 42 | XChainCreateClaimID | Create cross-chain claim ID | other |
| 43 | XChainCommit | Commit to cross-chain transfer | other |
| 44 | XChainClaim | Claim cross-chain transfer | other |
| 45 | XChainAccountCreateCommit | Create account via bridge | other |
| 46 | XChainAddClaimAttestation | Add attestation | other |
| 47 | XChainAddAccountCreateAttestation | Add account create attestation | other |
| 48 | XChainModifyBridge | Modify bridge settings | other |
| 49 | DIDSet | Set DID document | other |
| 50 | DIDDelete | Delete DID document | other |
| 51 | OracleSet | Set price oracle | other |
| 52 | OracleDelete | Delete price oracle | other |

### Transaction Type Information

```typescript
const TRANSACTION_TYPE_INFO: Record<string, TransactionTypeInfo> = {
  Payment: {
    name: 'Payment',
    description: 'Send XRP or issued currency to another account',
    category: 'payment',
    required_fields: ['Account', 'Destination', 'Amount'],
    optional_fields: ['Fee', 'Sequence', 'DestinationTag', 'InvoiceID', 'Paths', 'SendMax', 'DeliverMin'],
  },
  EscrowCreate: {
    name: 'EscrowCreate',
    description: 'Create a time-locked or condition-locked escrow of XRP',
    category: 'escrow',
    required_fields: ['Account', 'Destination', 'Amount'],
    optional_fields: ['CancelAfter', 'FinishAfter', 'Condition', 'DestinationTag'],
  },
  TrustSet: {
    name: 'TrustSet',
    description: 'Create or modify a trust line to hold issued currency',
    category: 'trust_line',
    required_fields: ['Account', 'LimitAmount'],
    optional_fields: ['QualityIn', 'QualityOut'],
  },
  OfferCreate: {
    name: 'OfferCreate',
    description: 'Create an offer to trade in the decentralized exchange',
    category: 'offer',
    required_fields: ['Account', 'TakerGets', 'TakerPays'],
    optional_fields: ['Expiration', 'OfferSequence'],
  },
  AccountSet: {
    name: 'AccountSet',
    description: 'Modify account settings and flags',
    category: 'account_settings',
    required_fields: ['Account'],
    optional_fields: ['SetFlag', 'ClearFlag', 'Domain', 'EmailHash', 'MessageKey', 'TransferRate'],
  },
  SignerListSet: {
    name: 'SignerListSet',
    description: 'Configure multi-signature settings for the account',
    category: 'multi_sign',
    required_fields: ['Account', 'SignerQuorum'],
    optional_fields: ['SignerEntries'],
  },
  NFTokenMint: {
    name: 'NFTokenMint',
    description: 'Mint a new non-fungible token',
    category: 'nft',
    required_fields: ['Account', 'NFTokenTaxon'],
    optional_fields: ['URI', 'TransferFee', 'Issuer'],
  },
  // ... additional types
};
```

### Common Field Names

| Field ID | Name | Description | Format |
|----------|------|-------------|--------|
| 1 | TransactionType | Transaction type code | UInt16 -> name |
| 2 | Flags | Transaction flags | UInt32 |
| 3 | SourceTag | Source identifying tag | UInt32 |
| 4 | Sequence | Account sequence number | UInt32 |
| 5 | PreviousTxnLgrSeq | Previous txn ledger seq | UInt32 |
| 6 | LedgerSequence | Ledger sequence | UInt32 |
| 7 | CloseTime | Close time | UInt32 |
| 8 | ParentCloseTime | Parent close time | UInt32 |
| 9 | SigningTime | Signing time | UInt32 |
| 10 | Expiration | Offer expiration | UInt32 |
| 14 | DestinationTag | Destination identifying tag | UInt32 |
| 27 | QualityIn | Trust line quality in | UInt32 |
| 28 | QualityOut | Trust line quality out | UInt32 |

### Flag Mappings by Transaction Type

```typescript
const PAYMENT_FLAGS: Record<number, string> = {
  0x00010000: 'tfNoDirectRipple',     // Do not use default path
  0x00020000: 'tfPartialPayment',     // Allow partial payment
  0x00040000: 'tfLimitQuality',       // Limit to quality
};

const TRUST_SET_FLAGS: Record<number, string> = {
  0x00010000: 'tfSetfAuth',           // Authorize trust line
  0x00020000: 'tfSetNoRipple',        // Disable rippling
  0x00040000: 'tfClearNoRipple',      // Enable rippling
  0x00100000: 'tfSetFreeze',          // Freeze trust line
  0x00200000: 'tfClearFreeze',        // Unfreeze trust line
};

const OFFER_CREATE_FLAGS: Record<number, string> = {
  0x00010000: 'tfPassive',            // Passive offer
  0x00020000: 'tfImmediateOrCancel',  // IOC order
  0x00040000: 'tfFillOrKill',         // FOK order
  0x00080000: 'tfSell',               // Sell offer
};

const ACCOUNT_SET_FLAGS: Record<number, string> = {
  0x00010000: 'tfRequireDestTag',     // Require destination tag
  0x00020000: 'tfOptionalDestTag',    // Optional destination tag
  0x00040000: 'tfRequireAuth',        // Require auth for trust lines
  0x00080000: 'tfOptionalAuth',       // Optional auth
  0x00100000: 'tfDisallowXRP',        // Disallow XRP payments
  0x00200000: 'tfAllowXRP',           // Allow XRP payments
};

function decodeTransactionFlags(txType: string, flags: number): string[] {
  const flagMap = {
    Payment: PAYMENT_FLAGS,
    TrustSet: TRUST_SET_FLAGS,
    OfferCreate: OFFER_CREATE_FLAGS,
    AccountSet: ACCOUNT_SET_FLAGS,
    // ... other types
  }[txType] || {};

  return Object.entries(flagMap)
    .filter(([value]) => (flags & Number(value)) !== 0)
    .map(([, name]) => name);
}
```

---

## 6. Amount Formatting

### XRP Amount Conversion

XRP amounts in the XRPL are stored in "drops" where 1 XRP = 1,000,000 drops.

```typescript
const DROPS_PER_XRP = 1_000_000n;

/**
 * Convert drops to XRP with 6 decimal precision.
 * @param drops - Amount in drops as string or bigint
 * @returns XRP amount as decimal string (e.g., "10.500000")
 */
function dropsToXrp(drops: string | bigint): string {
  const dropsBigInt = typeof drops === 'string' ? BigInt(drops) : drops;
  const whole = dropsBigInt / DROPS_PER_XRP;
  const fractional = dropsBigInt % DROPS_PER_XRP;

  // Pad fractional part to 6 digits
  const fractionalStr = fractional.toString().padStart(6, '0');

  return `${whole}.${fractionalStr}`;
}

/**
 * Convert XRP to drops.
 * @param xrp - Amount in XRP as string (e.g., "10.5")
 * @returns Drops as string
 */
function xrpToDrops(xrp: string): string {
  const [whole, fractional = '0'] = xrp.split('.');
  const paddedFractional = fractional.padEnd(6, '0').slice(0, 6);
  const dropsBigInt = BigInt(whole) * DROPS_PER_XRP + BigInt(paddedFractional);
  return dropsBigInt.toString();
}
```

### Issued Currency Amounts

Issued currencies use a different format with value, currency, and issuer:

```typescript
interface IssuedCurrencyAmount {
  value: string;     // Decimal string (e.g., "100.50")
  currency: string;  // 3-char ISO code or 40-char hex
  issuer: string;    // r-address of the issuer
}

/**
 * Format an amount field for display.
 */
function formatAmount(
  amount: string | IssuedCurrencyAmount,
  formatToXrp: boolean = true
): FormattedAmount {
  // XRP amount (string of drops)
  if (typeof amount === 'string') {
    const drops = amount;
    return {
      value: formatToXrp ? dropsToXrp(drops) : drops,
      currency: 'XRP',
      drops: drops,
      xrp: dropsToXrp(drops),
    };
  }

  // Issued currency amount (object)
  return {
    value: amount.value,
    currency: formatCurrencyCode(amount.currency),
    issuer: amount.issuer,
  };
}

/**
 * Format currency code (handle hex codes).
 */
function formatCurrencyCode(currency: string): string {
  // Standard 3-character ISO code
  if (currency.length === 3) {
    return currency;
  }

  // 40-character hex code (non-standard currency)
  if (currency.length === 40 && /^[A-Fa-f0-9]+$/.test(currency)) {
    // Try to decode as ASCII
    const decoded = Buffer.from(currency, 'hex')
      .toString('ascii')
      .replace(/\0/g, '')
      .trim();

    // If readable ASCII, return it; otherwise return truncated hex
    if (/^[A-Za-z0-9]+$/.test(decoded) && decoded.length > 0) {
      return decoded;
    }
    return `0x${currency.slice(0, 8)}...`;
  }

  return currency;
}
```

### Amount Field Extraction

```typescript
const AMOUNT_FIELDS = [
  'Amount',           // Payment amount
  'Fee',              // Transaction fee (always drops)
  'Balance',          // Channel balance
  'SendMax',          // Maximum to send
  'DeliverMin',       // Minimum to deliver
  'TakerGets',        // DEX offer - what taker receives
  'TakerPays',        // DEX offer - what taker pays
  'LimitAmount',      // Trust line limit
  'LowLimit',         // Trust line low limit
  'HighLimit',        // Trust line high limit
  'BidMin',           // AMM minimum bid
  'BidMax',           // AMM maximum bid
  'Amount2',          // AMM secondary amount
  'EPrice',           // AMM effective price
  'LPTokenOut',       // AMM LP token output
  'LPTokenIn',        // AMM LP token input
] as const;

function extractAllAmounts(
  tx: Record<string, unknown>,
  formatAmounts: boolean
): Record<string, FormattedAmount> {
  const amounts: Record<string, FormattedAmount> = {};

  for (const field of AMOUNT_FIELDS) {
    if (field in tx && tx[field] !== undefined) {
      amounts[field] = formatAmount(
        tx[field] as string | IssuedCurrencyAmount,
        formatAmounts
      );
    }
  }

  return amounts;
}
```

### Amount Display Examples

| Raw Value | Formatted (XRP) | Currency |
|-----------|-----------------|----------|
| `"1000000"` | `"1.000000"` | XRP |
| `"10000000000"` | `"10000.000000"` | XRP |
| `"123456"` | `"0.123456"` | XRP |
| `{"value":"100","currency":"USD","issuer":"r..."}` | `"100"` | USD |
| `{"value":"0.001","currency":"BTC","issuer":"r..."}` | `"0.001"` | BTC |

---

## 7. Security Uses

### Pre-Signing Verification

The primary security use case for `tx_decode` is **verifying transaction contents before signing**. This is critical for AI agent security.

```
                 AI Agent Workflow
                        |
                        v
           +------------------------+
           | Receive unsigned_tx    |
           | from external source   |
           +------------------------+
                        |
                        v
           +------------------------+
           | tx_decode(unsigned_tx) |  <-- VERIFY BEFORE SIGNING
           +------------------------+
                        |
            +-----------+-----------+
            |                       |
            v                       v
     +-------------+        +---------------+
     | Matches     |        | Unexpected    |
     | expectations|        | contents      |
     +-------------+        +---------------+
            |                       |
            v                       v
     +-------------+        +---------------+
     | wallet_sign |        | REJECT / ALERT|
     +-------------+        +---------------+
```

### Security Checks to Perform

After decoding, the AI agent should verify:

| Check | What to Verify | Risk Mitigated |
|-------|----------------|----------------|
| **Transaction Type** | Matches intended operation | Wrong operation type |
| **Destination** | Expected recipient address | Funds sent to wrong address |
| **Amount** | Within expected range | Excessive fund transfer |
| **Fee** | Reasonable fee amount | Fee drain attack |
| **DestinationTag** | Present if required | Lost funds (exchange deposits) |
| **Flags** | No unexpected flags | Unintended behavior |
| **Memos** | No malicious content | Data injection |
| **Paths** | Expected routing | Path manipulation |

### Example Security Verification

```typescript
interface TransactionVerification {
  expectedType: string;
  expectedDestination?: string;
  maxAmount?: bigint;
  maxFee?: bigint;
  requireDestinationTag?: boolean;
}

function verifyDecodedTransaction(
  decoded: TxDecodeOutput,
  expectations: TransactionVerification
): { valid: boolean; issues: string[] } {
  const issues: string[] = [];
  const tx = decoded.transaction;

  // Verify transaction type
  if (tx.TransactionType !== expectations.expectedType) {
    issues.push(
      `Transaction type mismatch: expected ${expectations.expectedType}, ` +
      `got ${tx.TransactionType}`
    );
  }

  // Verify destination
  if (expectations.expectedDestination && tx.Destination !== expectations.expectedDestination) {
    issues.push(
      `Destination mismatch: expected ${expectations.expectedDestination}, ` +
      `got ${tx.Destination}`
    );
  }

  // Verify amount
  if (expectations.maxAmount && decoded.amounts_formatted.Amount) {
    const amountDrops = BigInt(decoded.amounts_formatted.Amount.drops || '0');
    if (amountDrops > expectations.maxAmount) {
      issues.push(
        `Amount ${dropsToXrp(amountDrops.toString())} XRP exceeds maximum ` +
        `${dropsToXrp(expectations.maxAmount.toString())} XRP`
      );
    }
  }

  // Verify fee
  if (expectations.maxFee && decoded.amounts_formatted.Fee) {
    const feeDrops = BigInt(decoded.amounts_formatted.Fee.drops || '0');
    if (feeDrops > expectations.maxFee) {
      issues.push(`Fee ${feeDrops} drops exceeds maximum ${expectations.maxFee} drops`);
    }
  }

  // Verify destination tag requirement
  if (expectations.requireDestinationTag && !('DestinationTag' in tx)) {
    issues.push('Missing required DestinationTag');
  }

  return {
    valid: issues.length === 0,
    issues,
  };
}
```

### Warning Generation

The tool generates warnings for potentially problematic transactions:

```typescript
function generateWarnings(tx: Record<string, unknown>): TransactionWarning[] {
  const warnings: TransactionWarning[] = [];

  // High fee warning
  if (tx.Fee) {
    const feeDrops = BigInt(tx.Fee as string);
    if (feeDrops > 100000n) { // 0.1 XRP
      warnings.push({
        code: 'HIGH_FEE',
        message: `Transaction fee of ${dropsToXrp(feeDrops.toString())} XRP is unusually high`,
        field: 'Fee',
      });
    }
  }

  // Large amount warning
  if (tx.Amount && typeof tx.Amount === 'string') {
    const amountDrops = BigInt(tx.Amount);
    if (amountDrops > 1000000000000n) { // 1,000,000 XRP
      warnings.push({
        code: 'LARGE_AMOUNT',
        message: `Transaction amount of ${dropsToXrp(amountDrops.toString())} XRP is very large`,
        field: 'Amount',
      });
    }
  }

  // Missing destination tag for known exchanges
  if (tx.Destination && !('DestinationTag' in tx)) {
    // Check against known exchange addresses that require tags
    if (isKnownExchangeAddress(tx.Destination as string)) {
      warnings.push({
        code: 'MISSING_DEST_TAG',
        message: 'Destination appears to be an exchange that may require a destination tag',
        field: 'DestinationTag',
      });
    }
  }

  // Account-level changes
  if (tx.TransactionType === 'AccountSet') {
    warnings.push({
      code: 'ACCOUNT_SETTINGS',
      message: 'This transaction modifies account settings - verify all changes carefully',
      field: 'TransactionType',
    });
  }

  // Multi-sign changes
  if (tx.TransactionType === 'SignerListSet') {
    warnings.push({
      code: 'MULTISIG_CHANGE',
      message: 'This transaction modifies multi-signature settings - verify signer list carefully',
      field: 'TransactionType',
    });
  }

  // Partial payment flag
  if (tx.Flags && (Number(tx.Flags) & 0x00020000) !== 0) {
    warnings.push({
      code: 'PARTIAL_PAYMENT',
      message: 'Partial payment flag is set - delivered amount may be less than specified',
      field: 'Flags',
    });
  }

  return warnings;
}
```

---

## 8. Error Codes

### Error Response Schema

```typescript
interface TxDecodeError {
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
| `INVALID_HEX_FORMAT` | 400 | Input is not valid hexadecimal | Remove non-hex characters, ensure no 0x prefix |
| `TRANSACTION_TOO_SHORT` | 400 | Transaction blob too short | Provide complete transaction blob |
| `TRANSACTION_TOO_LARGE` | 400 | Transaction exceeds 1MB limit | Check for corruption or split transaction |
| `DECODE_FAILED` | 400 | Binary codec cannot parse blob | Verify blob is valid XRPL transaction |
| `UNKNOWN_TRANSACTION_TYPE` | 400 | Unrecognized transaction type code | May be new/unsupported transaction type |
| `MALFORMED_AMOUNT` | 400 | Amount field has invalid format | Check amount encoding |
| `INVALID_ADDRESS_FORMAT` | 400 | Address field has invalid format | Verify address encoding |
| `INTERNAL_ERROR` | 500 | Unexpected decoding error | Contact support with blob sample |

### Error Examples

**Invalid Hex Format**:
```json
{
  "success": false,
  "error": {
    "code": "INVALID_HEX_FORMAT",
    "message": "Transaction blob contains non-hexadecimal characters",
    "details": {
      "provided_length": 150,
      "invalid_characters_at": [48, 49],
      "hint": "Remove any 0x prefix and ensure only characters 0-9 and A-F are used"
    }
  }
}
```

**Decode Failed**:
```json
{
  "success": false,
  "error": {
    "code": "DECODE_FAILED",
    "message": "Failed to decode transaction blob",
    "details": {
      "codec_error": "Unknown field code at position 42",
      "blob_preview": "12000022800000002400000001...",
      "hint": "Ensure the blob is a valid unsigned XRPL transaction"
    }
  }
}
```

**Unknown Transaction Type**:
```json
{
  "success": false,
  "error": {
    "code": "UNKNOWN_TRANSACTION_TYPE",
    "message": "Transaction type code 99 is not recognized",
    "details": {
      "type_code": 99,
      "known_types": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 25, 26, 27, 28, 29, 30, 35, 36, 37, 38, 39, 40],
      "hint": "This may be a new transaction type not yet supported"
    }
  }
}
```

---

## 9. Examples

### Example 1: Decode Simple Payment

**Request**:
```json
{
  "name": "tx_decode",
  "arguments": {
    "unsigned_tx": "1200002280000000240000000161D4838D7EA4C680000000000000000000000000005553440000000000000000000000000000000000000000000000000168400000000000000A732103AB40A0490F9B7ED8DF29D246BF2D6269820A0EE7742ACDD457BEA7C7D0931EDB"
  }
}
```

**Response**:
```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"success\":true,\"transaction\":{\"TransactionType\":\"Payment\",\"Flags\":2147483648,\"Sequence\":1,\"Amount\":\"10000000\",\"Fee\":\"10\",\"Account\":\"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh\",\"Destination\":\"rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe\"},\"transaction_type_info\":{\"name\":\"Payment\",\"description\":\"Send XRP or issued currency to another account\",\"category\":\"payment\"},\"flags_readable\":[\"tfFullyCanonicalSig\"],\"amounts_formatted\":{\"Amount\":{\"value\":\"10.000000\",\"currency\":\"XRP\",\"drops\":\"10000000\",\"xrp\":\"10.000000\"},\"Fee\":{\"value\":\"0.000010\",\"currency\":\"XRP\",\"drops\":\"10\",\"xrp\":\"0.000010\"}},\"warnings\":[],\"metadata\":{\"blob_size_bytes\":97,\"field_count\":7,\"is_signed\":false,\"decoded_at\":\"2026-01-28T12:00:00.000Z\"}}"
    }
  ]
}
```

### Example 2: Decode Payment with Issued Currency

**Request**:
```json
{
  "name": "tx_decode",
  "arguments": {
    "unsigned_tx": "12000022800000002400000002201B00C35C5061D5071AFD498D00000000000000000000000000555344000000000004B4E9C06F24296074F7BC48F92A97916C6DC5EA968400000000000000C69D4838D7EA4C6800000000000000000000000000055534400000000004B4E9C06F24296074F7BC48F92A97916C6DC5EA9",
    "format_amounts": true,
    "include_raw_fields": true
  }
}
```

**Response**:
```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"success\":true,\"transaction\":{\"TransactionType\":\"Payment\",\"Flags\":2147483648,\"Sequence\":2,\"LastLedgerSequence\":12803152,\"Amount\":{\"value\":\"100\",\"currency\":\"USD\",\"issuer\":\"rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq\"},\"Fee\":\"12\",\"SendMax\":{\"value\":\"10\",\"currency\":\"USD\",\"issuer\":\"rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq\"},\"Account\":\"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh\",\"Destination\":\"rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe\"},\"transaction_type_info\":{\"name\":\"Payment\",\"description\":\"Send XRP or issued currency to another account\",\"category\":\"payment\"},\"flags_readable\":[\"tfFullyCanonicalSig\"],\"amounts_formatted\":{\"Amount\":{\"value\":\"100\",\"currency\":\"USD\",\"issuer\":\"rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq\"},\"Fee\":{\"value\":\"0.000012\",\"currency\":\"XRP\",\"drops\":\"12\",\"xrp\":\"0.000012\"},\"SendMax\":{\"value\":\"10\",\"currency\":\"USD\",\"issuer\":\"rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq\"}},\"warnings\":[],\"metadata\":{\"blob_size_bytes\":182,\"field_count\":9,\"is_signed\":false,\"decoded_at\":\"2026-01-28T12:01:00.000Z\"}}"
    }
  ]
}
```

### Example 3: Decode EscrowCreate

**Request**:
```json
{
  "name": "tx_decode",
  "arguments": {
    "unsigned_tx": "120001228000000024000000012019678D2E2020678D2E4061400000003B9ACA0068400000000000000A7321EDXXXXXXXXXXXXXXXXXXXXXXXX81143A8B0C9F84B32F34C3B77F6F8C80D9F2E77F6F8C814BXXXXXXXXXXXXXXXXXXXXXXXX"
  }
}
```

**Response**:
```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"success\":true,\"transaction\":{\"TransactionType\":\"EscrowCreate\",\"Flags\":2147483648,\"Sequence\":1,\"CancelAfter\":729999918,\"FinishAfter\":729999920,\"Amount\":\"1000000000\",\"Fee\":\"10\",\"Account\":\"rN7n3473SaZBCG4dFL83w7a1RXtXtbLRjW\",\"Destination\":\"rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn\"},\"transaction_type_info\":{\"name\":\"EscrowCreate\",\"description\":\"Create a time-locked or condition-locked escrow of XRP\",\"category\":\"escrow\"},\"flags_readable\":[\"tfFullyCanonicalSig\"],\"amounts_formatted\":{\"Amount\":{\"value\":\"1000.000000\",\"currency\":\"XRP\",\"drops\":\"1000000000\",\"xrp\":\"1000.000000\"},\"Fee\":{\"value\":\"0.000010\",\"currency\":\"XRP\",\"drops\":\"10\",\"xrp\":\"0.000010\"}},\"warnings\":[{\"code\":\"LARGE_AMOUNT\",\"message\":\"Transaction amount of 1000.000000 XRP is notable\",\"field\":\"Amount\"}],\"metadata\":{\"blob_size_bytes\":145,\"field_count\":8,\"is_signed\":false,\"decoded_at\":\"2026-01-28T12:02:00.000Z\"}}"
    }
  ]
}
```

### Example 4: Decode AccountSet (with warnings)

**Request**:
```json
{
  "name": "tx_decode",
  "arguments": {
    "unsigned_tx": "1200032280000000240000000120210000000368400000000000000F7321EDXXXXXXXXXXXXXXXXXXXXXXXX811443A8B0C9F84B32F34C3B77F6F8C80D9F2E77"
  }
}
```

**Response**:
```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"success\":true,\"transaction\":{\"TransactionType\":\"AccountSet\",\"Flags\":2147483648,\"Sequence\":1,\"SetFlag\":3,\"Fee\":\"15\",\"Account\":\"rN7n3473SaZBCG4dFL83w7a1RXtXtbLRjW\"},\"transaction_type_info\":{\"name\":\"AccountSet\",\"description\":\"Modify account settings and flags\",\"category\":\"account_settings\"},\"flags_readable\":[\"tfFullyCanonicalSig\"],\"amounts_formatted\":{\"Fee\":{\"value\":\"0.000015\",\"currency\":\"XRP\",\"drops\":\"15\",\"xrp\":\"0.000015\"}},\"warnings\":[{\"code\":\"ACCOUNT_SETTINGS\",\"message\":\"This transaction modifies account settings - verify all changes carefully\",\"field\":\"TransactionType\"},{\"code\":\"SETS_FLAG\",\"message\":\"Setting account flag 3 (asfRequireDestTag): Require destination tag for incoming payments\",\"field\":\"SetFlag\"}],\"metadata\":{\"blob_size_bytes\":85,\"field_count\":6,\"is_signed\":false,\"decoded_at\":\"2026-01-28T12:03:00.000Z\"}}"
    }
  ]
}
```

### Example 5: Decode SignerListSet

**Request**:
```json
{
  "name": "tx_decode",
  "arguments": {
    "unsigned_tx": "12000C228000000024000000012026000000037321EDXXXXXXXXXXXXXXXXXXXXXXXX811443A8B0C9F84B32F34C3B77F6F8C80D9F2E77F4EB1300028114XXXXXXXXXXXXXXXX2614YYYYYYYYYYYYYYYYYYY130002E14ZZZZZZZZZZZZZZZZZZZF1"
  }
}
```

**Response**:
```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"success\":true,\"transaction\":{\"TransactionType\":\"SignerListSet\",\"Flags\":2147483648,\"Sequence\":1,\"SignerQuorum\":3,\"Fee\":\"12\",\"Account\":\"rN7n3473SaZBCG4dFL83w7a1RXtXtbLRjW\",\"SignerEntries\":[{\"SignerEntry\":{\"Account\":\"rHuman1...\",\"SignerWeight\":2}},{\"SignerEntry\":{\"Account\":\"rHuman2...\",\"SignerWeight\":2}},{\"SignerEntry\":{\"Account\":\"rAgent...\",\"SignerWeight\":1}}]},\"transaction_type_info\":{\"name\":\"SignerListSet\",\"description\":\"Configure multi-signature settings for the account\",\"category\":\"multi_sign\"},\"flags_readable\":[\"tfFullyCanonicalSig\"],\"amounts_formatted\":{\"Fee\":{\"value\":\"0.000012\",\"currency\":\"XRP\",\"drops\":\"12\",\"xrp\":\"0.000012\"}},\"warnings\":[{\"code\":\"MULTISIG_CHANGE\",\"message\":\"This transaction modifies multi-signature settings - verify signer list carefully\",\"field\":\"TransactionType\"}],\"metadata\":{\"blob_size_bytes\":210,\"field_count\":7,\"is_signed\":false,\"decoded_at\":\"2026-01-28T12:04:00.000Z\"}}"
    }
  ]
}
```

### Example 6: Invalid Transaction (Error)

**Request**:
```json
{
  "name": "tx_decode",
  "arguments": {
    "unsigned_tx": "INVALID_NOT_HEX!!!"
  }
}
```

**Response**:
```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"success\":false,\"error\":{\"code\":\"INVALID_HEX_FORMAT\",\"message\":\"Transaction blob contains non-hexadecimal characters\",\"details\":{\"invalid_at_position\":7,\"expected\":\"hexadecimal characters (0-9, A-F)\",\"hint\":\"Ensure the blob contains only hexadecimal characters without 0x prefix\"}}}"
    }
  ],
  "isError": true
}
```

### Example 7: Decode Without Amount Formatting

**Request**:
```json
{
  "name": "tx_decode",
  "arguments": {
    "unsigned_tx": "1200002280000000240000000161D4838D7EA4C680000000000000000000000000005553440000000000000000000000000000000000000000000000000168400000000000000A",
    "format_amounts": false
  }
}
```

**Response**:
```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"success\":true,\"transaction\":{\"TransactionType\":\"Payment\",\"Flags\":2147483648,\"Sequence\":1,\"Amount\":\"10000000\",\"Fee\":\"10\",\"Account\":\"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh\",\"Destination\":\"rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe\"},\"transaction_type_info\":{\"name\":\"Payment\",\"description\":\"Send XRP or issued currency to another account\",\"category\":\"payment\"},\"flags_readable\":[\"tfFullyCanonicalSig\"],\"amounts_formatted\":{\"Amount\":{\"value\":\"10000000\",\"currency\":\"XRP\",\"drops\":\"10000000\",\"xrp\":\"10.000000\"},\"Fee\":{\"value\":\"10\",\"currency\":\"XRP\",\"drops\":\"10\",\"xrp\":\"0.000010\"}},\"warnings\":[],\"metadata\":{\"blob_size_bytes\":97,\"field_count\":7,\"is_signed\":false,\"decoded_at\":\"2026-01-28T12:05:00.000Z\"}}"
    }
  ]
}
```

---

## 10. Implementation Details

### Implementation Skeleton

```typescript
import { decode } from 'xrpl';
import { z } from 'zod';

export async function handleTxDecode(
  input: TxDecodeInput
): Promise<TxDecodeOutput | TxDecodeError> {
  const startTime = Date.now();

  try {
    // Step 1: Validate and normalize input
    const normalizedHex = normalizeHexInput(input.unsigned_tx);

    // Step 2: Decode using XRPL binary codec
    const decoded = decode(normalizedHex);

    // Step 3: Extract transaction type info
    const typeInfo = getTransactionTypeInfo(decoded.TransactionType);

    // Step 4: Decode flags
    const flagsReadable = decodeTransactionFlags(
      decoded.TransactionType,
      decoded.Flags || 0
    );

    // Step 5: Format amounts
    const amountsFormatted = extractAllAmounts(decoded, input.format_amounts);

    // Step 6: Generate warnings
    const warnings = generateWarnings(decoded);

    // Step 7: Build metadata
    const metadata = {
      blob_size_bytes: normalizedHex.length / 2,
      field_count: Object.keys(decoded).length,
      is_signed: hasSignature(decoded),
      decoded_at: new Date().toISOString(),
    };

    return {
      success: true,
      transaction: decoded,
      transaction_type_info: typeInfo,
      flags_readable: flagsReadable,
      amounts_formatted: amountsFormatted,
      warnings,
      metadata,
    };

  } catch (error) {
    return handleDecodeError(error);
  }
}

function normalizeHexInput(hex: string): string {
  // Remove 0x prefix if present
  let normalized = hex.replace(/^0x/i, '');

  // Validate hex characters
  if (!/^[A-Fa-f0-9]+$/.test(normalized)) {
    throw new ValidationError('INVALID_HEX_FORMAT', 'Non-hex characters found');
  }

  // Uppercase for consistency
  return normalized.toUpperCase();
}

function hasSignature(tx: Record<string, unknown>): boolean {
  return 'TxnSignature' in tx || 'Signers' in tx;
}

function handleDecodeError(error: unknown): TxDecodeError {
  if (error instanceof ValidationError) {
    return {
      success: false,
      error: {
        code: error.code,
        message: error.message,
        details: error.details,
      },
    };
  }

  if (error instanceof Error) {
    // Handle xrpl.js codec errors
    if (error.message.includes('Unknown field')) {
      return {
        success: false,
        error: {
          code: 'DECODE_FAILED',
          message: 'Unknown field in transaction blob',
          details: { codec_error: error.message },
        },
      };
    }

    return {
      success: false,
      error: {
        code: 'DECODE_FAILED',
        message: error.message,
      },
    };
  }

  return {
    success: false,
    error: {
      code: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred during decoding',
    },
  };
}
```

### Rate Limiting

| Limit | Value | Scope |
|-------|-------|-------|
| Requests per minute | 100 | Per client |
| Max blob size | 1 MB | Per request |
| Burst allowance | 10 | Additional requests |

### Audit Logging

Decode operations are logged with event type `TX_DECODE`:

```typescript
await auditLogger.log({
  eventType: AuditEventType.TX_DECODE,
  correlationId,
  actor: { type: 'agent' },
  operation: {
    name: 'tx_decode',
    parameters: {
      blob_size_bytes: input.unsigned_tx.length / 2,
      include_raw_fields: input.include_raw_fields,
      format_amounts: input.format_amounts,
    },
    result: 'success',
  },
  context: {
    transaction_type: decoded.TransactionType,
    is_signed: metadata.is_signed,
    warning_count: warnings.length,
  },
});
```

---

## 11. Related Tools

| Tool | Relationship |
|------|--------------|
| `wallet_sign` | Signs decoded transaction after verification |
| `wallet_policy_check` | Dry-run policy against decoded transaction |
| `tx_submit` | Submits signed transaction to network |
| `tx_status` | Check status of submitted transaction |

### Recommended Workflow

```
1. tx_decode          --> Inspect unsigned transaction
2. wallet_policy_check --> Verify transaction would be allowed
3. [Verify contents match expectations]
4. wallet_sign        --> Sign the transaction
5. tx_submit          --> Submit to XRPL network
6. tx_status          --> Monitor transaction result
```

### Integration with wallet_sign

The `wallet_sign` tool internally calls decode functionality, but AI agents should use `tx_decode` explicitly for:

1. **Transparency**: See exactly what will be signed
2. **Verification**: Compare against expected values
3. **Audit Trail**: Document pre-signing inspection
4. **Human Escalation**: Share decoded output with humans for Tier 2/3 approvals

---

## References

- [XRPL Binary Codec Documentation](https://xrpl.org/serialization.html)
- [XRPL Transaction Types](https://xrpl.org/transaction-types.html)
- [XRPL Transaction Flags](https://xrpl.org/transaction-common-fields.html#flags-field)
- [xrpl.js Binary Codec](https://js.xrpl.org/modules.html)
- [MCP Tool Specification](https://modelcontextprotocol.io/specification)

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | JavaScript Developer Agent | Initial specification |

---

*MCP Tool Documentation - XRPL Agent Wallet*
