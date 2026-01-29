# XRPL Credentials Integration Research

**Document Type**: Research & Integration Analysis
**Date**: 2026-01-28
**Status**: Research Complete
**Author**: Claude Code (Opus 4.5)

---

## Executive Summary

XRPL Credentials (XLS-70) is a **live mainnet feature** (activated September 4, 2025) that enables on-chain verifiable credentials for identity, compliance, and authorization. This document explores how the xrpl-wallet-mcp can leverage Credentials for:

1. **Policy-based credential validation** before signing transactions
2. **Credential lifecycle management** (issue, accept, revoke) as wallet operations
3. **Credential-gated transaction signing** with automatic CredentialIDs injection
4. **Issuer reputation tracking** and trust verification
5. **Integration with xrpl-escrow-mcp** for compliant escrow workflows

### Key Opportunity

The wallet MCP is uniquely positioned to become a **Credential-aware signing service** that:
- Validates credentials before signing credential-gated transactions
- Manages an agent's credential portfolio
- Enforces issuer trust policies
- Audits all credential-related operations

---

## Table of Contents

1. [XRPL Credentials Overview](#1-xrpl-credentials-overview)
2. [Current Project State](#2-current-project-state)
3. [Integration Opportunities](#3-integration-opportunities)
4. [Proposed New MCP Tools](#4-proposed-new-mcp-tools)
5. [Policy Engine Extensions](#5-policy-engine-extensions)
6. [Schema Additions](#6-schema-additions)
7. [Security Considerations](#7-security-considerations)
8. [Implementation Phases](#8-implementation-phases)
9. [Architecture Decisions](#9-architecture-decisions)
10. [Integration with xrpl-escrow-mcp](#10-integration-with-xrpl-escrow-mcp)
11. [Future Considerations](#11-future-considerations)
12. [References](#12-references)

---

## 1. XRPL Credentials Overview

### What Are XRPL Credentials?

XRPL Credentials are **signed attestations stored on-chain** that prove facts about an account (KYC verification, accreditation status, sanctions clearance) without exposing personal information to the blockchain.

### Core Components

| Component | Description |
|-----------|-------------|
| **Issuer** | Trusted entity that vets and provisions credentials |
| **Subject** | XRPL account that owns the credential |
| **Verifier** | Service/protocol that checks credentials before allowing actions |
| **CredentialType** | Arbitrary hex-encoded identifier (e.g., "KYCVerified") |

### Transaction Types

| Transaction | Purpose | Who Submits |
|-------------|---------|-------------|
| `CredentialCreate` | Issue new credential | Issuer |
| `CredentialAccept` | Accept provisioned credential | Subject |
| `CredentialDelete` | Revoke/remove credential | Issuer or Subject |

### Credential Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                    CREDENTIAL LIFECYCLE                          │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ISSUANCE                ACCEPTANCE              VERIFICATION  │
│   ─────────              ───────────              ─────────────  │
│                                                                  │
│   ┌─────────┐           ┌───────────┐           ┌─────────────┐ │
│   │ Off-chain│           │Credential │           │ Subject     │ │
│   │   KYC   │────────▶  │ Create TX │────────▶  │ Accept TX   │ │
│   │ Process │           │ (Issuer)  │           │ (Subject)   │ │
│   └─────────┘           └───────────┘           └──────┬──────┘ │
│        │                      │                        │        │
│        ▼                      ▼                        ▼        │
│   ┌─────────┐           ┌───────────┐           ┌─────────────┐ │
│   │ Issuer  │           │Credential │           │ Credential  │ │
│   │validates│           │ on ledger │           │   VALID     │ │
│   │identity │           │(pending)  │           │ (accepted)  │ │
│   └─────────┘           └───────────┘           └──────┬──────┘ │
│                                                        │        │
│                              USAGE                     ▼        │
│                              ─────            ┌─────────────────┐│
│                                               │ Payment with    ││
│                                               │ CredentialIDs   ││
│                                               │ field validated ││
│                                               └─────────────────┘│
│                                                        │        │
│                           REVOCATION                   ▼        │
│                           ──────────          ┌─────────────────┐│
│                                               │CredentialDelete ││
│                                               │ (Issuer/Subject)││
│                                               └─────────────────┘│
└──────────────────────────────────────────────────────────────────┘
```

### Key Properties

- **Reserve**: 0.2 XRP (owned by issuer until accepted, then subject)
- **Privacy**: No PII on-chain, only type + metadata
- **Expiration**: Optional timestamp for automatic invalidation
- **URI**: Optional link to full W3C VC document off-chain
- **Revocation**: Issuer or subject can delete anytime

### Amendment Status

| Amendment | Status | Activation Date |
|-----------|--------|-----------------|
| Credentials (XLS-70) | ✅ **Live** | September 4, 2025 |
| PermissionedDomains (XLS-80) | 🗳️ Voting (~80%) | Expected Feb 4, 2026 |
| PermissionedDEX (XLS-81) | 🗳️ Voting (~53%) | TBD |

---

## 2. Current Project State

### Implementation Status

The xrpl-wallet-mcp project is **specification-complete** with only the schema layer implemented:

| Component | Status | Lines of Code |
|-----------|--------|---------------|
| Zod Schemas | ✅ Complete | 2,059 |
| Unit Tests | ✅ Complete | 1,191 |
| Documentation | ✅ Complete | 66 files |
| Core Business Logic | ❌ Not started | - |
| MCP Tool Handlers | ❌ Not started | - |

### Existing Transaction Type Support

The `TransactionTypeSchema` already includes **all 38 XRPL transaction types**, including:

```typescript
// From src/schemas/index.ts (lines 146-183)
export const TransactionTypeSchema = z.enum([
  // ... other types ...
  'CredentialAccept',
  'CredentialCreate',
  'CredentialDelete',
  // ... other types ...
]);
```

**Finding**: Credential transaction types are already defined in the schema layer.

### Policy Schema Review

Current policy structure supports:
- Transaction type allowlisting/blocking
- Amount-based tiering
- Destination controls
- Time-based restrictions

**Gap**: No credential-specific policy rules exist.

---

## 3. Integration Opportunities

### 3.1 Credential-Aware Transaction Signing

**Problem**: Agent needs to sign transactions that require credentials (payments to KYC-gated exchanges).

**Solution**: Wallet automatically validates and injects CredentialIDs before signing.

```
┌─────────────────────────────────────────────────────────────┐
│                 CREDENTIAL-AWARE SIGNING                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Agent Request        Wallet MCP              Signed TX    │
│   ─────────────        ──────────              ─────────    │
│                                                             │
│   ┌───────────┐       ┌─────────────────────┐              │
│   │ Payment   │       │ 1. Policy Check     │              │
│   │ to KYC    │──────▶│ 2. Check destination│              │
│   │ Exchange  │       │    requires creds   │              │
│   └───────────┘       │ 3. Find matching    │              │
│                       │    credentials      │              │
│                       │ 4. Validate creds   │              │
│                       │    (accepted,       │              │
│                       │    not expired)     │              │
│                       │ 5. Inject           │              │
│                       │    CredentialIDs    │              │
│                       │ 6. Sign transaction │              │
│                       └──────────┬──────────┘              │
│                                  │                         │
│                                  ▼                         │
│                       ┌─────────────────────┐              │
│                       │ Signed TX with      │              │
│                       │ CredentialIDs field │              │
│                       │ populated           │              │
│                       └─────────────────────┘              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Credential Lifecycle Management

**Problem**: Agent needs to manage its credential portfolio (accept new credentials, check status, revoke).

**Solution**: New MCP tools for credential operations.

| Operation | Tool | Description |
|-----------|------|-------------|
| List credentials | `credential_list` | Show all credentials for managed wallets |
| Accept credential | `credential_accept` | Accept a provisionally-issued credential |
| Check credential | `credential_check` | Validate credential status and expiration |
| Revoke credential | `credential_delete` | Remove credential (subject-initiated) |
| Issue credential | `credential_create` | Issue credential (if wallet is trusted issuer) |

### 3.3 Issuer Trust Management

**Problem**: Agent should only accept credentials from trusted issuers.

**Solution**: Policy-based issuer trust configuration.

```json
{
  "credential_policy": {
    "trusted_issuers": [
      {
        "address": "rBitstamp...",
        "credential_types": ["KYCVerified", "AMLCleared"],
        "trust_level": "high"
      },
      {
        "address": "rCircle...",
        "credential_types": ["*"],
        "trust_level": "medium"
      }
    ],
    "auto_accept_from_trusted": true,
    "block_unknown_issuers": false,
    "alert_on_new_credential": true
  }
}
```

### 3.4 Credential-Gated Policy Rules

**Problem**: Signing policy should consider credential requirements.

**Solution**: Extend policy engine to check credentials.

```json
{
  "rules": [
    {
      "id": "kyc-gated-payments",
      "description": "Payments to KYC-required destinations need credential",
      "conditions": {
        "transaction_type": "Payment",
        "destination_requires_credential": true
      },
      "action": "check_credentials",
      "fallback": "reject_with_reason"
    }
  ]
}
```

### 3.5 Credential Expiration Monitoring

**Problem**: Agent's credentials may expire, blocking operations.

**Solution**: Proactive expiration alerts and pre-signing validation.

```
┌─────────────────────────────────────────────────────────────┐
│              CREDENTIAL EXPIRATION MONITORING                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Background Service              Alerts                    │
│   ──────────────────              ──────                    │
│                                                             │
│   ┌─────────────────┐            ┌────────────────────┐    │
│   │ Check credential│            │ 30 days: INFO      │    │
│   │ expirations     │───────────▶│ 7 days: WARNING    │    │
│   │ (hourly)        │            │ 1 day: CRITICAL    │    │
│   └─────────────────┘            │ Expired: ERROR     │    │
│                                  └────────────────────┘    │
│                                                             │
│   Pre-Sign Check                  Rejection                 │
│   ──────────────                  ─────────                 │
│                                                             │
│   ┌─────────────────┐            ┌────────────────────┐    │
│   │ Credential      │            │ "Credential expired│    │
│   │ required but    │───────────▶│  on 2026-01-15.    │    │
│   │ expired         │            │  Contact issuer    │    │
│   └─────────────────┘            │  for renewal."     │    │
│                                  └────────────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Proposed New MCP Tools

### 4.1 credential_list

**Purpose**: List all credentials for managed wallet(s).

**Sensitivity**: LOW

```typescript
// Input
{
  wallet_address?: string;  // Optional: filter by wallet
  include_expired?: boolean; // Default: false
  include_pending?: boolean; // Default: true (not yet accepted)
}

// Output
{
  credentials: [
    {
      credential_id: string;        // Ledger object ID
      issuer: string;               // Issuer address
      subject: string;              // Subject address (wallet)
      credential_type: string;      // Hex-encoded type
      credential_type_decoded: string; // Human-readable
      status: 'pending' | 'accepted' | 'expired';
      accepted: boolean;
      expiration?: number;          // Unix timestamp
      expires_in_days?: number;     // Convenience field
      uri?: string;                 // Off-chain VC link
      created_at: number;           // Ledger timestamp
    }
  ],
  total_count: number;
  expired_count: number;
  pending_count: number;
}
```

### 4.2 credential_accept

**Purpose**: Accept a provisionally-issued credential.

**Sensitivity**: MEDIUM (low risk, but changes wallet state)

```typescript
// Input
{
  wallet_address: string;
  issuer: string;
  credential_type: string;  // Hex or human-readable
}

// Output
{
  success: boolean;
  transaction_hash?: string;
  credential_id?: string;
  error?: {
    code: string;
    message: string;
  };
}
```

### 4.3 credential_check

**Purpose**: Validate credential status and usability.

**Sensitivity**: LOW (read-only)

```typescript
// Input
{
  credential_id?: string;    // Direct ID lookup
  // OR
  subject?: string;          // Subject + issuer + type lookup
  issuer?: string;
  credential_type?: string;
}

// Output
{
  exists: boolean;
  valid: boolean;           // exists && accepted && !expired
  details?: {
    issuer: string;
    subject: string;
    credential_type: string;
    accepted: boolean;
    expiration?: number;
    expired: boolean;
    expires_in_seconds?: number;
    uri?: string;
  };
  usability: {
    can_use_for_payments: boolean;
    can_use_for_escrow: boolean;
    requires_renewal: boolean;
    renewal_urgency?: 'none' | 'low' | 'medium' | 'high' | 'critical';
  };
}
```

### 4.4 credential_delete

**Purpose**: Revoke/remove a credential (subject-initiated).

**Sensitivity**: HIGH (irreversible action)

```typescript
// Input
{
  wallet_address: string;
  issuer: string;
  credential_type: string;
  reason?: string;  // For audit log
}

// Output
{
  success: boolean;
  transaction_hash?: string;
  warning?: string;  // e.g., "This may affect your ability to..."
  error?: {
    code: string;
    message: string;
  };
}
```

### 4.5 credential_create

**Purpose**: Issue a credential (for issuer wallets).

**Sensitivity**: CRITICAL (creates obligations)

```typescript
// Input
{
  wallet_address: string;     // Issuer wallet (must be managed)
  subject: string;            // Recipient address
  credential_type: string;    // Hex or human-readable
  uri?: string;               // Link to full W3C VC
  expiration?: number;        // Unix timestamp
  expiration_days?: number;   // Convenience: days from now
}

// Output
{
  success: boolean;
  transaction_hash?: string;
  credential_id?: string;
  reserve_locked: string;     // "0.2 XRP"
  note: string;               // "Credential pending acceptance by subject"
  error?: {
    code: string;
    message: string;
  };
}
```

### 4.6 credential_verify_destination

**Purpose**: Check if a destination requires credentials and which ones.

**Sensitivity**: LOW (read-only, useful before payments)

```typescript
// Input
{
  destination: string;
  transaction_type?: 'Payment' | 'EscrowFinish' | 'PaymentChannelClaim';
}

// Output
{
  requires_credentials: boolean;
  deposit_auth_enabled: boolean;
  required_credentials?: [
    {
      issuer: string;
      credential_type: string;
      credential_type_decoded: string;
    }
  ];
  our_matching_credentials?: [
    {
      credential_id: string;
      wallet_address: string;
      status: 'valid' | 'expired' | 'pending';
    }
  ];
  can_transact: boolean;
  missing_credentials?: string[];  // What we need but don't have
}
```

---

## 5. Policy Engine Extensions

### 5.1 Credential Policy Section

Add new policy section for credential rules:

```json
{
  "credential_policy": {
    "trusted_issuers": {
      "addresses": ["rBitstamp...", "rCircle..."],
      "patterns": [],
      "trust_mode": "allowlist"
    },

    "auto_accept": {
      "enabled": true,
      "from_trusted_only": true,
      "require_expiration": true,
      "max_expiration_days": 365
    },

    "auto_inject": {
      "enabled": true,
      "prefer_newest": true,
      "prefer_longest_expiry": false
    },

    "validation": {
      "reject_if_expired": true,
      "warn_days_before_expiry": 30,
      "require_uri": false
    },

    "issuance": {
      "allowed": false,
      "require_approval_tier": 3,
      "allowed_types": []
    }
  }
}
```

### 5.2 Credential-Based Transaction Rules

Extend existing rule conditions:

```json
{
  "rules": [
    {
      "id": "credential-gated-high-value",
      "priority": 100,
      "conditions": {
        "transaction_type": "Payment",
        "amount_gte_drops": "100000000000",
        "requires_credential": true
      },
      "action": "require_cosign",
      "require_credential_check": true
    },
    {
      "id": "auto-approve-with-valid-credential",
      "priority": 200,
      "conditions": {
        "transaction_type": "Payment",
        "has_valid_credential": true,
        "destination_in_allowlist": true
      },
      "action": "approve",
      "tier": 1
    }
  ]
}
```

### 5.3 Issuer Trust Levels

```typescript
enum IssuerTrustLevel {
  UNTRUSTED = 0,      // Block all credentials from this issuer
  UNKNOWN = 1,        // Require manual approval
  LOW = 2,            // Allow but monitor
  MEDIUM = 3,         // Standard trust
  HIGH = 4,           // Full trust, auto-accept
  SELF = 5            // Our own issuance wallet
}
```

---

## 6. Schema Additions

### 6.1 Credential Schemas

```typescript
// Credential Type (hex-encoded string)
export const CredentialTypeSchema = z.string()
  .regex(/^[A-F0-9]+$/i)
  .min(2)
  .max(128)
  .transform(s => s.toUpperCase());

// Human-readable credential type
export const CredentialTypeHumanSchema = z.string()
  .min(1)
  .max(64)
  .regex(/^[a-zA-Z0-9_-]+$/);

// Credential ID (ledger object hash)
export const CredentialIdSchema = z.string()
  .regex(/^[A-F0-9]{64}$/i)
  .transform(s => s.toUpperCase());

// Credential status enum
export const CredentialStatusSchema = z.enum([
  'pending',    // Created but not accepted
  'accepted',   // Valid and usable
  'expired',    // Past expiration timestamp
  'revoked',    // Deleted by issuer
  'deleted'     // Deleted by subject
]);

// Issuer trust level
export const IssuerTrustLevelSchema = z.enum([
  'untrusted',
  'unknown',
  'low',
  'medium',
  'high',
  'self'
]);
```

### 6.2 Credential Object Schema

```typescript
export const CredentialObjectSchema = z.object({
  credential_id: CredentialIdSchema,
  issuer: XRPLAddressSchema,
  subject: XRPLAddressSchema,
  credential_type: CredentialTypeSchema,
  credential_type_decoded: z.string().optional(),
  accepted: z.boolean(),
  expiration: z.number().int().positive().optional(),
  uri: HexStringSchema.optional(),
  uri_decoded: z.string().url().optional(),
  flags: z.number().int().nonnegative(),
  created_ledger: z.number().int().positive(),
  previous_txn_id: TransactionHashSchema
});
```

### 6.3 Credential Policy Schema

```typescript
export const CredentialPolicySchema = z.object({
  trusted_issuers: z.object({
    addresses: z.array(XRPLAddressSchema).default([]),
    patterns: z.array(z.string().regex(/^r[a-zA-Z0-9*]+$/)).default([]),
    trust_mode: z.enum(['allowlist', 'blocklist', 'open']).default('allowlist')
  }).optional(),

  auto_accept: z.object({
    enabled: z.boolean().default(false),
    from_trusted_only: z.boolean().default(true),
    require_expiration: z.boolean().default(true),
    max_expiration_days: z.number().int().positive().max(3650).default(365)
  }).optional(),

  auto_inject: z.object({
    enabled: z.boolean().default(true),
    prefer_newest: z.boolean().default(false),
    prefer_longest_expiry: z.boolean().default(true)
  }).optional(),

  validation: z.object({
    reject_if_expired: z.boolean().default(true),
    warn_days_before_expiry: z.number().int().nonnegative().default(30),
    require_uri: z.boolean().default(false)
  }).optional(),

  issuance: z.object({
    allowed: z.boolean().default(false),
    require_approval_tier: z.number().int().min(1).max(4).default(3),
    allowed_types: z.array(CredentialTypeHumanSchema).default([])
  }).optional()
});
```

---

## 7. Security Considerations

### 7.1 Credential Validation Before Signing

**CRITICAL**: Always validate credentials before using them in transactions.

```typescript
interface CredentialValidationChecks {
  // Required checks
  exists(): Promise<boolean>;           // Credential on ledger
  accepted(): Promise<boolean>;         // lsfAccepted flag set
  notExpired(): Promise<boolean>;       // Current time < expiration
  subjectMatches(address: string): Promise<boolean>;  // Sender = subject

  // Optional checks
  issuerTrusted(): Promise<boolean>;    // Issuer in trust list
  uriAccessible(): Promise<boolean>;    // Off-chain VC reachable
  typeAllowed(): Promise<boolean>;      // Credential type permitted
}
```

### 7.2 Issuer Trust Model

**Trust Hierarchy**:
1. Self-issued credentials (our wallet is issuer)
2. Explicitly trusted issuers (in policy)
3. Community-recognized issuers (e.g., major exchanges)
4. Unknown issuers (require human approval)
5. Blocked issuers (reject all credentials)

**Attack Vector**: Malicious issuer could create fake KYC credentials.

**Mitigation**:
- Allowlist-based trust by default
- Policy immutability prevents agent self-modification
- Audit log all credential acceptance

### 7.3 Credential Injection Attacks

**Attack Vector**: Attacker tricks agent into using wrong credential or including extra CredentialIDs.

**Mitigation**:
- Only use credentials owned by signing wallet
- Validate subject field matches transaction sender
- Never inject credentials without policy approval

### 7.4 Expiration Race Conditions

**Attack Vector**: Credential expires between validation and transaction submission.

**Mitigation**:
- Check expiration with buffer (e.g., 5 minutes)
- Re-validate immediately before signing
- Include expiration in audit log

### 7.5 Privacy Considerations

**On-chain exposure**:
- Credential type visible (reveals what was verified)
- Issuer address visible (reveals who verified)
- Subject address visible (reveals holder)

**Mitigation**:
- Use generic credential types ("Verified" vs "KYCLevel3")
- Consider privacy-preserving issuers (Chainalysis vs named banks)
- Document privacy implications for users

### 7.6 Audit Trail Requirements

All credential operations MUST be logged:

```typescript
interface CredentialAuditEntry {
  event_type:
    | 'credential_accepted'
    | 'credential_rejected'
    | 'credential_used'
    | 'credential_expired'
    | 'credential_revoked'
    | 'credential_issued';

  credential_id: string;
  issuer: string;
  subject: string;
  credential_type: string;

  // Context
  transaction_hash?: string;
  policy_rule_id?: string;
  decision_reason?: string;

  // Chain integrity
  timestamp: number;
  prev_hash: string;
  hash: string;
}
```

---

## 8. Implementation Phases

### Phase 1: Schema & Types (Week 1)

**Deliverables**:
- [ ] Add credential schemas to `src/schemas/index.ts`
- [ ] Add credential policy schema
- [ ] Add credential-related error codes
- [ ] Add credential audit event types
- [ ] Unit tests for all new schemas

**Effort**: Low (schema-only, no business logic)

### Phase 2: Read-Only Tools (Week 2)

**Deliverables**:
- [ ] Implement `credential_list` tool
- [ ] Implement `credential_check` tool
- [ ] Implement `credential_verify_destination` tool
- [ ] XRPL client helper for credential queries
- [ ] Integration tests with testnet

**Effort**: Medium (XRPL integration required)

### Phase 3: Credential Lifecycle (Week 3)

**Deliverables**:
- [ ] Implement `credential_accept` tool
- [ ] Implement `credential_delete` tool
- [ ] Policy rule: auto-accept from trusted issuers
- [ ] Audit logging for credential operations
- [ ] E2E tests for lifecycle

**Effort**: Medium (transaction signing integration)

### Phase 4: Credential-Aware Signing (Week 4)

**Deliverables**:
- [ ] Modify `wallet_sign` to check destination requirements
- [ ] Auto-inject CredentialIDs when needed
- [ ] Policy conditions for credential requirements
- [ ] Expiration warning system
- [ ] E2E tests for credential-gated payments

**Effort**: High (core signing flow modification)

### Phase 5: Issuer Functionality (Week 5, Optional)

**Deliverables**:
- [ ] Implement `credential_create` tool
- [ ] Issuer policy configuration
- [ ] Credential issuance audit trail
- [ ] Documentation for issuer setup

**Effort**: Medium (optional for v1)

### Phase 6: Monitoring & Alerts (Week 6)

**Deliverables**:
- [ ] Background credential expiration checker
- [ ] Webhook notifications for expiring credentials
- [ ] Dashboard data for credential portfolio
- [ ] Integration with existing notification system

**Effort**: Medium (requires background service)

---

## 9. Architecture Decisions

### ADR-011: Credential Auto-Injection Strategy

**Status**: Proposed

**Context**: When signing transactions to credential-gated destinations, wallet must decide whether and which credentials to inject.

**Decision**: Auto-inject credentials when:
1. Destination has DepositPreauth with credential requirements
2. Wallet has matching valid credential(s)
3. Policy allows auto-injection
4. Credential is not expiring within 5 minutes

**Preference Order**:
1. Prefer credentials with longest remaining validity
2. If equal, prefer most recently accepted
3. If equal, prefer issuer with highest trust level

**Consequences**:
- Transactions succeed without explicit credential specification
- May reveal credential to destination (privacy consideration)
- Agent must be informed of injection in response

### ADR-012: Issuer Trust Storage

**Status**: Proposed

**Context**: Trusted issuers must be stored and queried efficiently.

**Decision**: Store issuer trust in policy file (not separate database).

**Format**:
```json
{
  "credential_policy": {
    "trusted_issuers": {
      "rBitstamp...": {"trust": "high", "types": ["*"]},
      "rCircle...": {"trust": "medium", "types": ["KYCVerified"]}
    }
  }
}
```

**Consequences**:
- Policy is single source of truth
- Policy immutability applies to trust config
- Easy to audit and backup
- Limited scalability (fine for agent use case)

### ADR-013: Credential Caching

**Status**: Proposed

**Context**: Credential validation requires XRPL queries which have latency.

**Decision**: Cache credential status with short TTL (60 seconds).

**Cache Keys**: `credential:{id}` → `{status, expiration, validated_at}`

**Invalidation**:
- On CredentialDelete transaction detected
- On any credential operation by wallet
- On TTL expiry

**Consequences**:
- Faster signing for repeat transactions
- Risk of stale data (acceptable with short TTL)
- Memory overhead (minimal for agent use case)

---

## 10. Integration with xrpl-escrow-mcp

### Current Flow (Without Credentials)

```
User: "Create escrow for 1000 XRP to rDestination..."
     │
     ▼
xrpl-escrow-mcp: Builds EscrowCreate transaction
     │
     ▼
xrpl-wallet-mcp: Signs transaction
     │
     ▼
xrpl-escrow-mcp: Submits to network
```

### Enhanced Flow (With Credentials)

```
User: "Create escrow for 1000 XRP to rKYCExchange..."
     │
     ▼
xrpl-escrow-mcp: Builds EscrowCreate transaction
     │
     ▼
xrpl-wallet-mcp:
  1. Check destination requirements
  2. Destination requires KYC credential
  3. Find matching credential for sender
  4. Inject CredentialIDs into transaction
  5. Sign transaction with credentials
     │
     ▼
xrpl-escrow-mcp: Submits credential-enriched transaction
```

### Credential Use Cases in Escrows

| Scenario | Transaction | Credential Requirement |
|----------|-------------|----------------------|
| Create escrow to KYC exchange | EscrowCreate | Sender needs KYC credential |
| Finish escrow to verified account | EscrowFinish | Finisher needs credential |
| Cancel escrow | EscrowCancel | May require credential if destination has requirements |

### API Contract

xrpl-escrow-mcp should expect these response fields from wallet_sign:

```typescript
// Extended wallet_sign response
{
  tier: 'approved' | 'pending_approval' | 'rejected',
  signed_tx?: string,
  tx_hash?: string,

  // New credential fields
  credentials_injected?: boolean,
  credential_ids_added?: string[],
  credential_warnings?: [
    {
      credential_id: string,
      warning: 'expiring_soon' | 'issuer_unknown',
      details: string
    }
  ]
}
```

---

## 11. Future Considerations

### 11.1 Permissioned Domains (XLS-80)

**Expected**: February 2026

**Impact**: Wallet will need to:
- Track permissioned domain membership
- Validate credentials match domain requirements
- Support PermissionedDomainSet transactions

**Preparation**: Design credential schemas to support domain-specific requirements.

### 11.2 Zero-Knowledge Credentials

**Potential**: Future XRPL amendment

**Impact**: Privacy-preserving credential verification without revealing type or issuer.

**Preparation**: Abstract credential validation interface to support multiple verification methods.

### 11.3 Cross-Chain Credentials

**Potential**: Axelar GMP for credential portability

**Impact**: Credentials from other chains could be recognized.

**Preparation**: Design issuer trust to support chain identifiers.

### 11.4 Credential Delegation

**Potential**: Temporary credential lending/borrowing

**Impact**: Agent could use delegated credentials from parent entity.

**Preparation**: Consider delegation model in policy design.

### 11.5 Multi-Credential Policies

**Potential**: Complex AND/OR logic for access control

**Example**: "Must have KYCVerified AND (AccreditedInvestor OR InstitutionalTrader)"

**Preparation**: Policy engine should support boolean expressions for credential conditions.

---

## 12. References

### XRPL Documentation
- [XRPL Credentials Concepts](https://xrpl.org/docs/concepts/decentralized-storage/credentials)
- [CredentialCreate Transaction](https://xrpl.org/docs/references/protocol/transactions/types/credentialcreate)
- [CredentialAccept Transaction](https://xrpl.org/docs/references/protocol/transactions/types/credentialaccept)
- [CredentialDelete Transaction](https://xrpl.org/docs/references/protocol/transactions/types/credentialdelete)
- [Credential Ledger Object](https://xrpl.org/docs/references/protocol/ledger-data/ledger-entry-types/credential)
- [DepositPreauth Transaction](https://xrpl.org/docs/references/protocol/transactions/types/depositpreauth)
- [Known Amendments](https://xrpl.org/resources/known-amendments)

### XLS Specifications
- [XLS-70d: Credentials](https://github.com/XRPLF/XRPL-Standards/tree/master/XLS-0070d-credentials)
- [XLS-80: Permissioned Domains](https://github.com/XRPLF/XRPL-Standards/tree/master/XLS-0080d-permissioned-domains)
- [XLS-81: Permissioned DEX](https://github.com/XRPLF/XRPL-Standards/tree/master/XLS-0081d-permissioned-dex)

### Tutorials
- [Build a Credential Issuing Service (Python)](https://xrpl.org/docs/tutorials/python/build-apps/credential-issuing-service)
- [Create Permissioned Domains (JavaScript)](https://xrpl.org/docs/tutorials/javascript/compliance/create-permissioned-domains)

### Articles
- [Credentials: Building a Compliant Identity Layer](https://dev.to/ripplexdev/credentials-building-a-compliant-identity-layer-for-the-xrp-ledger-155e)
- [Permissioned Domains: Compliance-Driven Finance](https://dev.to/ripplexdev/permissioned-domains-enabling-compliance-driven-onchain-finance-on-the-xrpl-29k2)
- [Introducing Permissioned DEX](https://ripple.com/insights/unlocking-institutional-access-to-defi-on-the-xrp-ledger/)

### Project Documentation
- [XRPL Wallet MCP CLAUDE.md](../../CLAUDE.md)
- [Architecture Overview](../architecture/01-introduction-and-goals.md)
- [Security Requirements](../security/security-requirements.md)
- [Threat Model](../security/threat-model.md)

---

## Appendix A: Credential Type Registry (Proposed Standards)

| Type (Human) | Type (Hex) | Description | Common Issuers |
|-------------|------------|-------------|----------------|
| `KYCVerified` | `4B59435665726966696564` | Basic identity verification | Exchanges, banks |
| `AMLCleared` | `414D4C436C6561726564` | Anti-money laundering check | Compliance providers |
| `AccreditedInvestor` | `41636372656469746564496E766573746F72` | Accredited investor status | Legal firms |
| `InstitutionalTrader` | `496E737469747574696F6E616C5472616465` | Institutional trading qualification | Regulators |
| `SanctionsCleared` | `53616E6374696F6E73436C6561726564` | OFAC/sanctions screening | Chainalysis, etc. |
| `USPerson` | `555350657273F6E` | US tax person status | Tax authorities |
| `NonUSPerson` | `4E6F6E555350657273F6E` | Non-US person status | Tax authorities |

---

## Appendix B: Error Codes

| Code | Description |
|------|-------------|
| `CREDENTIAL_NOT_FOUND` | Credential does not exist on ledger |
| `CREDENTIAL_NOT_ACCEPTED` | Credential exists but not accepted by subject |
| `CREDENTIAL_EXPIRED` | Credential past expiration timestamp |
| `CREDENTIAL_SUBJECT_MISMATCH` | Transaction sender ≠ credential subject |
| `CREDENTIAL_ISSUER_UNTRUSTED` | Issuer not in trusted list |
| `CREDENTIAL_TYPE_NOT_ALLOWED` | Credential type blocked by policy |
| `CREDENTIAL_INJECTION_DISABLED` | Auto-inject disabled in policy |
| `CREDENTIAL_ALREADY_EXISTS` | Duplicate credential for issuer+subject+type |
| `CREDENTIAL_ACCEPT_FAILED` | CredentialAccept transaction failed |
| `CREDENTIAL_DELETE_FAILED` | CredentialDelete transaction failed |
| `CREDENTIAL_CREATE_NOT_ALLOWED` | Issuance not permitted by policy |
| `NO_MATCHING_CREDENTIAL` | Destination requires credential we don't have |

---

*Document Version: 1.0.0*
*Research Completed: 2026-01-28*
*Next Review: After Phase 1 implementation*
