# AgentWalletPolicy Schema Documentation

**Version:** 1.0.0
**Date:** 2026-01-28
**Status:** Approved
**Schema:** [policies/schema.json](../../policies/schema.json)

---

## Table of Contents

1. [Overview](#1-overview)
2. [Policy Structure](#2-policy-structure)
3. [Tier Configuration](#3-tier-configuration)
4. [Rules System](#4-rules-system)
5. [Lists (Blocklist/Allowlist)](#5-lists-blocklistallowlist)
6. [Limits Configuration](#6-limits-configuration)
7. [Transaction Type Configuration](#7-transaction-type-configuration)
8. [Escalation Configuration](#8-escalation-configuration)
9. [Network-Specific Defaults](#9-network-specific-defaults)
10. [Policy Examples by Use Case](#10-policy-examples-by-use-case)
11. [Security Considerations](#11-security-considerations)
12. [Migration Guide](#12-migration-guide)

---

## 1. Overview

### Purpose

The AgentWalletPolicy schema defines the authorization rules, limits, and security controls for AI agents operating XRPL wallets through the MCP server. The policy engine evaluates every transaction against these rules before signing.

### Design Principles

1. **Immutability at Runtime**: Policies are loaded at startup; agents cannot modify them via MCP tools
2. **Fail-Secure**: Errors or missing configuration result in denial, never bypass
3. **Defense in Depth**: Multiple layers (tiers, rules, limits) all must pass
4. **Network Isolation**: Each network (mainnet/testnet/devnet) has its own policy
5. **Auditability**: Every decision is logged with the matched rule

### Schema Format

- **Format**: JSON Schema Draft-07
- **File Location**: `~/.xrpl-wallet-mcp/{network}/policy.json`
- **Encoding**: UTF-8
- **Maximum Size**: 1MB (recommended under 100KB)

---

## 2. Policy Structure

### Root Schema

```json
{
  "version": "1.0",
  "name": "my-policy-name",
  "description": "Optional description",
  "network": "mainnet",
  "enabled": true,
  "tiers": { ... },
  "rules": [ ... ],
  "blocklist": { ... },
  "allowlist": { ... },
  "limits": { ... },
  "transaction_types": { ... },
  "escalation": { ... },
  "metadata": { ... }
}
```

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | Schema version (e.g., "1.0"). Used for migration compatibility. |
| `name` | string | Unique policy identifier. 1-128 characters, alphanumeric with hyphens/underscores. |
| `network` | enum | Target network: "mainnet", "testnet", or "devnet". |
| `tiers` | object | Tier configuration for all four approval levels. |
| `rules` | array | Ordered list of policy rules. |
| `limits` | object | Global rate and volume limits. |

### Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `description` | string | - | Human-readable policy description. |
| `enabled` | boolean | `true` | If false, all transactions are rejected. |
| `blocklist` | object | `{}` | Addresses and patterns to always block. |
| `allowlist` | object | `{}` | Pre-approved destinations. |
| `transaction_types` | object | `{}` | Per-type configuration overrides. |
| `escalation` | object | `{}` | Human escalation configuration. |
| `metadata` | object | `{}` | Arbitrary metadata for management. |

---

## 3. Tier Configuration

The policy engine classifies transactions into four tiers based on risk. Each tier has different approval requirements.

### Tier Hierarchy

```
Tier 4: Prohibited     -> Transaction blocked, never executed
Tier 3: Co-Sign        -> Requires human co-signature
Tier 2: Delayed        -> Held for review period, can be vetoed
Tier 1: Autonomous     -> Immediate execution (within limits)
```

### 3.1 Autonomous Tier (Tier 1)

Transactions approved automatically without human intervention.

```json
{
  "autonomous": {
    "max_amount_xrp": 100,
    "daily_limit_xrp": 1000,
    "require_known_destination": true,
    "allowed_transaction_types": ["Payment", "EscrowFinish"],
    "max_fee_drops": 100000
  }
}
```

| Field | Type | Default | Constraints | Security Impact |
|-------|------|---------|-------------|-----------------|
| `max_amount_xrp` | number | 100 | 0-1,000,000 | **High**: Single transaction cap. Lower = safer. |
| `daily_limit_xrp` | number | 1000 | 0-10,000,000 | **High**: Cumulative daily cap. Limits total exposure. |
| `require_known_destination` | boolean | true | - | **High**: If true, only allowlisted destinations qualify. |
| `allowed_transaction_types` | array | See below | Valid XRPL types | **Medium**: Restricts what agents can do autonomously. |
| `max_fee_drops` | integer | 100000 | 10-100,000,000 | **Medium**: Prevents fee escalation attacks. |

**Default `allowed_transaction_types`:**
```json
["Payment", "EscrowFinish", "EscrowCancel", "OfferCancel", "CheckCash", "CheckCancel", "NFTokenCancelOffer"]
```

### 3.2 Delayed Tier (Tier 2)

Transactions held for a review period before execution.

```json
{
  "delayed": {
    "max_amount_xrp": 1000,
    "daily_limit_xrp": 10000,
    "delay_seconds": 300,
    "veto_enabled": true,
    "notify_on_queue": true
  }
}
```

| Field | Type | Default | Constraints | Security Impact |
|-------|------|---------|-------------|-----------------|
| `max_amount_xrp` | number | 1000 | 0-10,000,000 | **High**: Upper bound for delayed tier. |
| `daily_limit_xrp` | number | 10000 | 0-100,000,000 | **High**: Daily cap across all delayed transactions. |
| `delay_seconds` | integer | 300 | 60-86,400 | **High**: Review window. Longer = more time to catch issues. |
| `veto_enabled` | boolean | true | - | **Critical**: If false, delayed transactions cannot be stopped. |
| `notify_on_queue` | boolean | true | - | **Medium**: Alerts humans when transactions are queued. |

### 3.3 Co-Sign Tier (Tier 3)

Transactions requiring explicit human approval via multi-signature.

```json
{
  "cosign": {
    "min_amount_xrp": 1000,
    "new_destination_always": true,
    "signer_quorum": 2,
    "approval_timeout_hours": 24,
    "notify_signers": true,
    "signer_addresses": ["rHUMANsigner1...", "rHUMANsigner2..."]
  }
}
```

| Field | Type | Default | Constraints | Security Impact |
|-------|------|---------|-------------|-----------------|
| `min_amount_xrp` | number | 1000 | 0+ | **High**: Threshold triggering co-sign requirement. |
| `new_destination_always` | boolean | true | - | **Critical**: First transaction to new address requires approval. |
| `signer_quorum` | integer | 2 | 1-32 | **Critical**: Number of signatures needed. Higher = more secure. |
| `approval_timeout_hours` | integer | 24 | 1-168 | **Medium**: Time before pending approval expires. |
| `notify_signers` | boolean | true | - | **Medium**: Alerts designated signers. |
| `signer_addresses` | array | `[]` | Valid XRPL addresses | **Critical**: Who can co-sign. Must be preconfigured. |

### 3.4 Prohibited Tier (Tier 4)

Transactions that are never allowed.

```json
{
  "prohibited": {
    "reasons": ["blocklist", "daily_limit_exceeded", "unknown_type", "injection_detected"],
    "prohibited_transaction_types": ["Clawback"]
  }
}
```

| Field | Type | Default | Security Impact |
|-------|------|---------|-----------------|
| `reasons` | array | See above | Documents why transactions are blocked. |
| `prohibited_transaction_types` | array | `["Clawback"]` | **Critical**: Types that are never allowed. |

**Standard Reasons:**
- `blocklist` - Destination is blocklisted
- `daily_limit_exceeded` - Would exceed daily volume limit
- `hourly_limit_exceeded` - Would exceed hourly transaction count
- `unknown_type` - Unrecognized transaction type
- `high_risk_type` - Transaction type flagged as high-risk
- `injection_detected` - Prompt injection pattern found
- `invalid_destination` - Destination failed validation
- `policy_disabled` - Policy is disabled

---

## 4. Rules System

Rules define how transactions are classified into tiers. Rules are evaluated in priority order (lower number = higher priority).

### Rule Structure

```json
{
  "id": "rule-001",
  "name": "blocklist-check",
  "description": "Block transactions to known bad addresses",
  "priority": 1,
  "enabled": true,
  "condition": { ... },
  "action": { ... }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier. Format: `rule-{identifier}` |
| `name` | string | Yes | Human-readable name for logging. |
| `description` | string | No | Explanation of rule purpose. |
| `priority` | integer | Yes | Evaluation order. 1-9999, lower = evaluated first. |
| `enabled` | boolean | No | Default true. Disabled rules are skipped. |
| `condition` | object | Yes | When this rule applies. |
| `action` | object | Yes | What tier to assign. |

### Conditions

#### Simple Condition

Compare a transaction field against a value.

```json
{
  "field": "amount_xrp",
  "operator": ">=",
  "value": 1000
}
```

**Available Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `destination` | string | Destination XRPL address |
| `amount_xrp` | number | Transaction amount in XRP |
| `amount_drops` | number | Transaction amount in drops |
| `transaction_type` | string | XRPL transaction type |
| `transaction_category` | string | Category (payments, dex, escrow, etc.) |
| `memo` | string | Transaction memo content |
| `memo_type` | string | Memo type field |
| `fee_drops` | number | Transaction fee |
| `destination_tag` | number | Destination tag |
| `source_tag` | number | Source tag |
| `daily_volume_xrp` | number | Today's cumulative volume |
| `hourly_count` | number | Transactions in last hour |
| `is_new_destination` | boolean | First transaction to this address |
| `currency` | string | Currency code (for tokens) |
| `issuer` | string | Token issuer address |

**Available Operators:**

| Operator | Description | Example |
|----------|-------------|---------|
| `==` | Equals | `{"field": "transaction_type", "operator": "==", "value": "Payment"}` |
| `!=` | Not equals | `{"field": "transaction_type", "operator": "!=", "value": "Clawback"}` |
| `>` | Greater than | `{"field": "amount_xrp", "operator": ">", "value": 100}` |
| `>=` | Greater or equal | `{"field": "amount_xrp", "operator": ">=", "value": 100}` |
| `<` | Less than | `{"field": "amount_xrp", "operator": "<", "value": 100}` |
| `<=` | Less or equal | `{"field": "amount_xrp", "operator": "<=", "value": 100}` |
| `in` | In array | `{"field": "destination", "operator": "in", "value": {"ref": "allowlist.addresses"}}` |
| `not_in` | Not in array | `{"field": "destination", "operator": "not_in", "value": {"ref": "blocklist.addresses"}}` |
| `matches` | Regex match | `{"field": "memo", "operator": "matches", "value": ".*INST.*"}` |
| `contains` | String contains | `{"field": "memo", "operator": "contains", "value": "urgent"}` |
| `starts_with` | String prefix | `{"field": "destination", "operator": "starts_with", "value": "rExchange"}` |
| `ends_with` | String suffix | `{"field": "memo_type", "operator": "ends_with", "value": "/json"}` |
| `in_category` | Transaction category | `{"field": "transaction_type", "operator": "in_category", "value": "account"}` |

**Value References:**

Instead of literal values, reference lists defined in the policy:

```json
{
  "field": "destination",
  "operator": "in",
  "value": { "ref": "blocklist.addresses" }
}
```

Available references:
- `blocklist.addresses`
- `blocklist.memo_patterns`
- `allowlist.addresses`
- `allowlist.trusted_tags`

#### Logical Conditions

Combine conditions with AND, OR, NOT.

**AND Condition:**
```json
{
  "and": [
    { "field": "amount_xrp", "operator": ">=", "value": 100 },
    { "field": "amount_xrp", "operator": "<", "value": 1000 }
  ]
}
```

**OR Condition:**
```json
{
  "or": [
    { "field": "transaction_type", "operator": "==", "value": "Payment" },
    { "field": "transaction_type", "operator": "==", "value": "EscrowFinish" }
  ]
}
```

**NOT Condition:**
```json
{
  "not": {
    "field": "destination",
    "operator": "in",
    "value": { "ref": "allowlist.addresses" }
  }
}
```

**Nested Conditions:**
```json
{
  "and": [
    { "field": "amount_xrp", "operator": ">=", "value": 1000 },
    {
      "or": [
        { "field": "is_new_destination", "operator": "==", "value": true },
        { "field": "transaction_type", "operator": "==", "value": "AccountSet" }
      ]
    }
  ]
}
```

#### Always Condition

Matches all transactions. Used for default/catch-all rules.

```json
{
  "always": true
}
```

### Actions

Define what happens when a rule matches.

```json
{
  "tier": "cosign",
  "reason": "High-value payment requires human approval",
  "override_delay_seconds": 600,
  "notify": true,
  "log_level": "warn"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tier` | enum | Yes | "autonomous", "delayed", "cosign", or "prohibited" |
| `reason` | string | No | Human-readable explanation (logged and returned) |
| `override_delay_seconds` | integer | No | Custom delay for delayed tier |
| `notify` | boolean | No | Send notification for this specific action |
| `log_level` | enum | No | "info", "warn", or "error" (default: "info") |

---

## 5. Lists (Blocklist/Allowlist)

### Blocklist

Addresses and patterns that are always blocked. Blocklist is checked before all other rules.

```json
{
  "blocklist": {
    "addresses": [
      "rScamAddress111111111111111111111",
      "rSanctionedAddress2222222222222222"
    ],
    "memo_patterns": [
      "ignore.*previous",
      "\\[INST\\]",
      "<<SYS>>",
      "system.*prompt",
      "admin.*override"
    ],
    "currency_issuers": [
      "rScamTokenIssuer333333333333333333"
    ]
  }
}
```

| Field | Type | Default | Max Items | Security Impact |
|-------|------|---------|-----------|-----------------|
| `addresses` | array | `[]` | 10,000 | **Critical**: Known bad destinations. Populate from scam/sanctions lists. |
| `memo_patterns` | array | See above | 100 | **Critical**: Regex patterns detecting prompt injection. |
| `currency_issuers` | array | `[]` | 1,000 | **High**: Blocked token issuers. |

**Default Memo Patterns:**

These patterns detect common prompt injection attempts:

| Pattern | Detects |
|---------|---------|
| `ignore.*previous` | "Ignore previous instructions" attacks |
| `\[INST\]` | Llama-style instruction markers |
| `<<SYS>>` | System prompt injection |
| `system.*prompt` | Attempts to override system prompts |
| `admin.*override` | Fake admin override commands |

### Allowlist

Pre-approved destinations that may receive favorable treatment.

```json
{
  "allowlist": {
    "addresses": [
      "rKnownGoodAddress11111111111111111",
      "rTreasuryWallet222222222222222222222"
    ],
    "trusted_tags": [
      123456,
      789012
    ],
    "auto_learn": false,
    "exchange_addresses": [
      {
        "address": "rBinance111111111111111111111111111",
        "name": "Binance Hot Wallet",
        "require_tag": true
      }
    ]
  }
}
```

| Field | Type | Default | Max Items | Security Impact |
|-------|------|---------|-----------|-----------------|
| `addresses` | array | `[]` | 1,000 | **Medium**: Pre-approved destinations. |
| `trusted_tags` | array | `[]` | 1,000 | **Medium**: Known-good destination tags. |
| `auto_learn` | boolean | false | - | **High**: If true, co-signed destinations are auto-added. Use with caution. |
| `exchange_addresses` | array | `[]` | 100 | **Medium**: Exchange addresses with special handling. |

---

## 6. Limits Configuration

Global hard limits that cannot be bypassed by rules.

```json
{
  "limits": {
    "daily_reset_utc_hour": 0,
    "max_transactions_per_hour": 100,
    "max_transactions_per_day": 1000,
    "max_unique_destinations_per_day": 50,
    "max_total_volume_xrp_per_day": 10000,
    "cooldown_after_high_value": {
      "enabled": false,
      "threshold_xrp": 1000,
      "cooldown_seconds": 300
    }
  }
}
```

| Field | Type | Default | Constraints | Security Impact |
|-------|------|---------|-------------|-----------------|
| `daily_reset_utc_hour` | integer | 0 | 0-23 | **Low**: When daily counters reset. |
| `max_transactions_per_hour` | integer | 100 | 1-10,000 | **High**: Hourly rate limit. Prevents rapid drain. |
| `max_transactions_per_day` | integer | 1000 | 1-100,000 | **High**: Daily transaction count cap. |
| `max_unique_destinations_per_day` | integer | 50 | 1-1,000 | **High**: Limits fund scattering to many addresses. |
| `max_total_volume_xrp_per_day` | number | 10000 | 0-100,000,000 | **Critical**: Absolute daily cap. Hard ceiling. |
| `cooldown_after_high_value` | object | disabled | - | **Medium**: Optional pause after large transactions. |

### Cooldown Configuration

```json
{
  "cooldown_after_high_value": {
    "enabled": true,
    "threshold_xrp": 1000,
    "cooldown_seconds": 300
  }
}
```

When enabled, after a transaction exceeding `threshold_xrp`, no new transactions are allowed for `cooldown_seconds`.

---

## 7. Transaction Type Configuration

Override defaults for specific XRPL transaction types.

```json
{
  "transaction_types": {
    "Payment": {
      "enabled": true,
      "default_tier": "autonomous"
    },
    "AccountSet": {
      "enabled": true,
      "default_tier": "cosign",
      "require_cosign": true
    },
    "Clawback": {
      "enabled": false
    }
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | true | Whether this type is allowed at all. |
| `default_tier` | enum | varies | Starting tier before rules apply. |
| `max_amount_xrp` | number | - | Type-specific amount limit. |
| `require_cosign` | boolean | false | Always require co-signature. |

### Transaction Type Categories

| Category | Types | Default Tier |
|----------|-------|--------------|
| `payments` | Payment | autonomous |
| `trustlines` | TrustSet | delayed |
| `dex` | OfferCreate, OfferCancel | delayed |
| `escrow` | EscrowCreate, EscrowFinish, EscrowCancel | delayed/autonomous |
| `paychan` | PaymentChannelCreate, PaymentChannelFund, PaymentChannelClaim | delayed |
| `account` | AccountSet, SetRegularKey, SignerListSet | **cosign** |
| `nft` | NFToken* | delayed |
| `amm` | AMM* | delayed/cosign |
| `checks` | Check* | autonomous/delayed |
| `tickets` | TicketCreate | delayed |
| `clawback` | Clawback | **prohibited** |
| `did` | DIDSet, DIDDelete | delayed |
| `oracle` | OracleSet, OracleDelete | delayed |

---

## 8. Escalation Configuration

Configure human escalation for approval workflows.

```json
{
  "escalation": {
    "webhook_url": "https://your-service.com/webhooks/wallet",
    "webhook_secret": "your-32-char-minimum-hmac-secret-here",
    "notification_channels": ["webhook", "email"],
    "escalation_contacts": [
      {
        "name": "Primary Admin",
        "type": "email",
        "address": "admin@example.com",
        "priority": 1
      },
      {
        "name": "Backup Admin",
        "type": "email",
        "address": "backup@example.com",
        "priority": 2
      }
    ],
    "auto_deny_on_timeout": true
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `webhook_url` | string | HTTPS endpoint for notifications. |
| `webhook_secret` | string | HMAC secret for webhook signatures (32+ chars). |
| `notification_channels` | array | "webhook", "email", "slack", "discord" |
| `escalation_contacts` | array | People to notify (ordered by priority). |
| `auto_deny_on_timeout` | boolean | If true, expired approvals are denied. |

**Security Note:** Store `webhook_secret` in a secure secrets manager, not in the policy file. Reference via environment variable.

---

## 9. Network-Specific Defaults

### Mainnet (Production)

**Philosophy:** Maximum security, conservative limits, assume hostile environment.

```json
{
  "version": "1.0",
  "name": "mainnet-conservative",
  "network": "mainnet",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 100,
      "daily_limit_xrp": 1000,
      "require_known_destination": true,
      "allowed_transaction_types": ["Payment", "EscrowFinish", "EscrowCancel"]
    },
    "delayed": {
      "max_amount_xrp": 1000,
      "daily_limit_xrp": 10000,
      "delay_seconds": 300,
      "veto_enabled": true
    },
    "cosign": {
      "min_amount_xrp": 1000,
      "new_destination_always": true,
      "signer_quorum": 2,
      "approval_timeout_hours": 24
    },
    "prohibited": {
      "prohibited_transaction_types": ["Clawback", "AccountSet", "SetRegularKey", "SignerListSet"]
    }
  },
  "limits": {
    "max_transactions_per_hour": 50,
    "max_transactions_per_day": 200,
    "max_unique_destinations_per_day": 20,
    "max_total_volume_xrp_per_day": 5000
  }
}
```

### Testnet (Testing)

**Philosophy:** Permissive for testing, still safe (test XRP has no value).

```json
{
  "version": "1.0",
  "name": "testnet-permissive",
  "network": "testnet",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 10000,
      "daily_limit_xrp": 100000,
      "require_known_destination": false,
      "allowed_transaction_types": ["Payment", "TrustSet", "OfferCreate", "OfferCancel", "EscrowCreate", "EscrowFinish", "EscrowCancel"]
    },
    "delayed": {
      "max_amount_xrp": 100000,
      "daily_limit_xrp": 1000000,
      "delay_seconds": 60,
      "veto_enabled": true
    },
    "cosign": {
      "min_amount_xrp": 100000,
      "new_destination_always": false,
      "signer_quorum": 1,
      "approval_timeout_hours": 1
    },
    "prohibited": {
      "prohibited_transaction_types": []
    }
  },
  "limits": {
    "max_transactions_per_hour": 1000,
    "max_transactions_per_day": 10000,
    "max_unique_destinations_per_day": 500,
    "max_total_volume_xrp_per_day": 10000000
  }
}
```

### Devnet (Development)

**Philosophy:** Maximum permissiveness for rapid development iteration.

```json
{
  "version": "1.0",
  "name": "devnet-development",
  "network": "devnet",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 1000000,
      "daily_limit_xrp": 10000000,
      "require_known_destination": false,
      "allowed_transaction_types": ["Payment", "TrustSet", "OfferCreate", "OfferCancel", "EscrowCreate", "EscrowFinish", "EscrowCancel", "AccountSet", "NFTokenMint", "AMMCreate"]
    },
    "delayed": {
      "max_amount_xrp": 10000000,
      "daily_limit_xrp": 100000000,
      "delay_seconds": 10,
      "veto_enabled": false
    },
    "cosign": {
      "min_amount_xrp": 10000000,
      "new_destination_always": false,
      "signer_quorum": 1,
      "approval_timeout_hours": 1
    },
    "prohibited": {
      "prohibited_transaction_types": []
    }
  },
  "limits": {
    "max_transactions_per_hour": 10000,
    "max_transactions_per_day": 100000,
    "max_unique_destinations_per_day": 10000,
    "max_total_volume_xrp_per_day": 100000000
  }
}
```

---

## 10. Policy Examples by Use Case

### 10.1 Trading Bot Policy

For a DEX trading agent that needs to manage offers.

```json
{
  "version": "1.0",
  "name": "trading-bot-policy",
  "network": "mainnet",
  "description": "Policy for automated DEX trading operations",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 500,
      "daily_limit_xrp": 5000,
      "require_known_destination": false,
      "allowed_transaction_types": ["OfferCreate", "OfferCancel", "TrustSet"]
    },
    "delayed": {
      "max_amount_xrp": 2000,
      "daily_limit_xrp": 20000,
      "delay_seconds": 180
    },
    "cosign": {
      "min_amount_xrp": 2000,
      "signer_quorum": 2
    },
    "prohibited": {
      "prohibited_transaction_types": ["Payment", "AccountSet", "SetRegularKey"]
    }
  },
  "rules": [
    {
      "id": "rule-allow-dex",
      "name": "allow-dex-operations",
      "priority": 10,
      "condition": {
        "field": "transaction_type",
        "operator": "in_category",
        "value": "dex"
      },
      "action": {
        "tier": "autonomous",
        "reason": "DEX operations allowed for trading"
      }
    },
    {
      "id": "rule-block-payments",
      "name": "block-all-payments",
      "priority": 5,
      "condition": {
        "field": "transaction_type",
        "operator": "==",
        "value": "Payment"
      },
      "action": {
        "tier": "prohibited",
        "reason": "Trading bot cannot make payments"
      }
    }
  ],
  "limits": {
    "max_transactions_per_hour": 200,
    "max_transactions_per_day": 2000,
    "max_unique_destinations_per_day": 10
  }
}
```

### 10.2 Escrow Service Policy

For an escrow management agent.

```json
{
  "version": "1.0",
  "name": "escrow-service-policy",
  "network": "mainnet",
  "description": "Policy for automated escrow management",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 1000,
      "daily_limit_xrp": 10000,
      "require_known_destination": true,
      "allowed_transaction_types": ["EscrowCreate", "EscrowFinish", "EscrowCancel"]
    },
    "delayed": {
      "max_amount_xrp": 10000,
      "daily_limit_xrp": 100000,
      "delay_seconds": 600
    },
    "cosign": {
      "min_amount_xrp": 10000,
      "signer_quorum": 2
    },
    "prohibited": {
      "prohibited_transaction_types": ["Payment", "OfferCreate", "TrustSet", "AccountSet"]
    }
  },
  "rules": [
    {
      "id": "rule-escrow-ops",
      "name": "allow-escrow-operations",
      "priority": 10,
      "condition": {
        "field": "transaction_type",
        "operator": "in_category",
        "value": "escrow"
      },
      "action": {
        "tier": "autonomous",
        "reason": "Escrow operations allowed"
      }
    },
    {
      "id": "rule-high-value-escrow",
      "name": "high-value-escrow-cosign",
      "priority": 5,
      "condition": {
        "and": [
          { "field": "transaction_type", "operator": "==", "value": "EscrowCreate" },
          { "field": "amount_xrp", "operator": ">=", "value": 5000 }
        ]
      },
      "action": {
        "tier": "cosign",
        "reason": "High-value escrow creation requires approval"
      }
    }
  ],
  "allowlist": {
    "addresses": [
      "rEscrowCounterparty1111111111111111"
    ]
  }
}
```

### 10.3 Treasury Management Policy

For controlled treasury operations with strict human oversight.

```json
{
  "version": "1.0",
  "name": "treasury-policy",
  "network": "mainnet",
  "description": "Strict policy for treasury wallet management",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 10,
      "daily_limit_xrp": 100,
      "require_known_destination": true,
      "allowed_transaction_types": ["Payment"]
    },
    "delayed": {
      "max_amount_xrp": 100,
      "daily_limit_xrp": 1000,
      "delay_seconds": 3600,
      "veto_enabled": true
    },
    "cosign": {
      "min_amount_xrp": 100,
      "new_destination_always": true,
      "signer_quorum": 3,
      "approval_timeout_hours": 48
    },
    "prohibited": {
      "prohibited_transaction_types": ["OfferCreate", "TrustSet", "AccountSet", "SetRegularKey", "SignerListSet", "AMMCreate"]
    }
  },
  "rules": [
    {
      "id": "rule-all-cosign",
      "name": "all-require-cosign",
      "priority": 1,
      "condition": { "always": true },
      "action": {
        "tier": "cosign",
        "reason": "All treasury operations require multi-sig approval"
      }
    }
  ],
  "limits": {
    "max_transactions_per_hour": 5,
    "max_transactions_per_day": 20,
    "max_unique_destinations_per_day": 5,
    "max_total_volume_xrp_per_day": 1000
  },
  "escalation": {
    "notification_channels": ["webhook", "email"],
    "auto_deny_on_timeout": true
  }
}
```

### 10.4 NFT Marketplace Agent Policy

For an agent managing NFT operations.

```json
{
  "version": "1.0",
  "name": "nft-marketplace-policy",
  "network": "mainnet",
  "description": "Policy for NFT marketplace operations",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 100,
      "daily_limit_xrp": 1000,
      "require_known_destination": false,
      "allowed_transaction_types": ["NFTokenMint", "NFTokenCreateOffer", "NFTokenAcceptOffer", "NFTokenCancelOffer", "NFTokenBurn"]
    },
    "delayed": {
      "max_amount_xrp": 500,
      "daily_limit_xrp": 5000,
      "delay_seconds": 300
    },
    "cosign": {
      "min_amount_xrp": 500,
      "signer_quorum": 2
    },
    "prohibited": {
      "prohibited_transaction_types": ["Payment", "AccountSet"]
    }
  },
  "transaction_types": {
    "NFTokenMint": {
      "enabled": true,
      "default_tier": "autonomous"
    },
    "NFTokenCreateOffer": {
      "enabled": true,
      "default_tier": "autonomous",
      "max_amount_xrp": 100
    }
  },
  "limits": {
    "max_transactions_per_hour": 100,
    "max_transactions_per_day": 500
  }
}
```

---

## 11. Security Considerations

### 11.1 Policy File Security

| Concern | Recommendation |
|---------|----------------|
| File permissions | Set to `0600` (owner read/write only) |
| Storage location | Use `~/.xrpl-wallet-mcp/{network}/` structure |
| Secrets in policy | Never store `webhook_secret` in policy file; use env vars |
| Version control | Track policy changes in git for audit trail |
| Backup | Maintain encrypted backups of policies |

### 11.2 Configuration Security Implications

| Setting | Security Impact | Recommendation |
|---------|-----------------|----------------|
| `max_amount_xrp` | Single transaction exposure | Keep < 1% of total wallet balance |
| `daily_limit_xrp` | Daily exposure | Keep < 10% of total wallet balance |
| `require_known_destination` | Exfiltration prevention | Enable for mainnet |
| `signer_quorum` | Approval robustness | Use 2+ for high-value wallets |
| `auto_learn` | Allowlist pollution | Disable for mainnet |
| `veto_enabled` | Human override capability | Always enable for mainnet |

### 11.3 Common Mistakes to Avoid

1. **High autonomous limits on mainnet**: Keep autonomous thresholds conservative
2. **Empty blocklist**: Populate with known scam addresses
3. **Disabled veto**: Always allow human override
4. **Missing default rule**: Include a catch-all rule as last priority
5. **No memo pattern filters**: Keep prompt injection detection patterns
6. **Single signer quorum**: Use 2+ signers for co-sign tier
7. **Auto-learn enabled on mainnet**: Can pollute allowlist via social engineering

### 11.4 Prompt Injection Defense

The policy schema includes multiple layers of defense:

1. **Memo pattern blocklist**: Rejects transactions with injection patterns
2. **Immutable policy**: Agents cannot modify policy at runtime
3. **Fail-secure defaults**: Unknown types are prohibited
4. **Human oversight tiers**: High-risk operations require approval

---

## 12. Migration Guide

### From Version 1.0 to Future Versions

When policy schema changes:

1. Check `version` field in existing policy
2. Run migration tool: `xrpl-wallet migrate-policy --from 1.0 --to 2.0`
3. Review and approve migrated policy
4. Test with `--dry-run` before applying

### Policy Validation

Validate policy before deployment:

```bash
# Validate against schema
xrpl-wallet validate-policy ./policy.json

# Test with sample transactions
xrpl-wallet test-policy ./policy.json --test-cases ./test-transactions.json
```

---

## Related Documents

- [ADR-003: Policy Engine Design](../architecture/09-decisions/ADR-003-policy-engine.md)
- [ADR-009: Transaction Scope](../architecture/09-decisions/ADR-009-transaction-scope.md)
- [ADR-010: Network Isolation](../architecture/09-decisions/ADR-010-network-isolation.md)
- [Security Requirements](../security/security-requirements.md)
- [Threat Model](../security/threat-model.md)

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Backend Engineer | Initial schema documentation |

---

*This document is part of the XRPL Agent Wallet MCP specification. The schema is defined in [policies/schema.json](../../policies/schema.json).*
