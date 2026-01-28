# 08 - Crosscutting Concepts

**Arc42 Section**: Crosscutting Concepts
**Version**: 1.0.0
**Date**: 2026-01-28
**Status**: Complete
**Author**: Security Specialist

---

## Table of Contents

1. [Overview](#1-overview)
2. [Security Concept](#2-security-concept)
3. [Logging and Monitoring](#3-logging-and-monitoring)
4. [Error Handling](#4-error-handling)
5. [Configuration Management](#5-configuration-management)
6. [Cryptographic Concepts](#6-cryptographic-concepts)
7. [Concurrency and Threading](#7-concurrency-and-threading)
8. [Testing Concepts](#8-testing-concepts)
9. [Internationalization](#9-internationalization)
10. [Related Documents](#10-related-documents)

---

## 1. Overview

This document describes the cross-cutting concepts that span multiple components of the XRPL Agent Wallet MCP server. These architectural patterns and design principles are applied consistently throughout the system to ensure security, maintainability, and operational excellence.

### Scope

Cross-cutting concerns covered in this document:

| Concern | Description | Primary Stakeholder |
|---------|-------------|---------------------|
| **Security** | Defense in depth, tiered access control | Security Team |
| **Logging** | Tamper-evident audit trails | Compliance, Operations |
| **Error Handling** | Fail-secure patterns | Developers |
| **Configuration** | Environment and policy management | Operations |
| **Cryptography** | Key management, encryption standards | Security Team |
| **Concurrency** | Thread safety, rate limiting | Developers |
| **Testing** | Test pyramid, security testing | QA Team |

### Principles

All cross-cutting concerns follow these principles:

1. **Security by Default**: Secure defaults, explicit opt-in for less secure options
2. **Fail-Secure**: On error, default to denying access
3. **Least Privilege**: Minimum necessary access for each operation
4. **Defense in Depth**: Multiple independent security layers
5. **Audit Everything**: Complete audit trail for security events

---

## 2. Security Concept

### 2.1 Defense in Depth Layers

The security architecture implements eight distinct defense layers. Each layer provides independent protection; failure of one layer does not compromise the entire system.

```
+-----------------------------------------------------------------------+
|  Layer 1: Transport Security                                           |
|  -------------------------                                             |
|  TLS 1.3 for all network communication                                |
|  Certificate validation enabled                                        |
|  No fallback to insecure protocols                                    |
+-----------------------------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|  Layer 2: Input Validation                                             |
|  -----------------------                                               |
|  Zod schema validation for all tool inputs                            |
|  XRPL address checksum verification                                    |
|  String sanitization (control characters, length limits)               |
|  Prompt injection pattern detection                                    |
+-----------------------------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|  Layer 3: Authentication                                               |
|  ----------------------                                                |
|  Argon2id key derivation (64MB, 3 iterations, parallelism 4)          |
|  Progressive lockout (5 attempts, 15 min window, doubling duration)   |
|  Session management (30 min idle, 8 hour absolute timeout)            |
+-----------------------------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|  Layer 4: Authorization                                                |
|  ---------------------                                                 |
|  Tool permission classification (READ_ONLY, SENSITIVE, DESTRUCTIVE)   |
|  Per-operation authorization checks                                    |
|  No privilege inheritance between operations                           |
+-----------------------------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|  Layer 5: Policy Enforcement                                           |
|  -------------------------                                             |
|  Immutable policy engine (LLM cannot modify at runtime)               |
|  Transaction limits (amount, rate, volume)                            |
|  Destination allowlists and blocklists                                |
+-----------------------------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|  Layer 6: Cryptographic Protection                                     |
|  -------------------------------                                       |
|  AES-256-GCM encryption at rest                                       |
|  Unique IV per encryption operation                                    |
|  Secure memory handling (SecureBuffer pattern)                        |
|  Key material zeroed immediately after use                            |
+-----------------------------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|  Layer 7: XRPL Native Security                                         |
|  ---------------------------                                           |
|  Regular key configuration (hot/cold separation)                      |
|  Multi-signature support (threshold signatures)                       |
|  Sequence number management (replay protection)                       |
+-----------------------------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|  Layer 8: Audit and Detection                                          |
|  ---------------------------                                           |
|  Hash-chained audit logs (HMAC-SHA256)                                |
|  Monotonic sequence numbers for tamper detection                      |
|  Security event alerting                                              |
+-----------------------------------------------------------------------+
```

### 2.2 Tiered Security Model

Transactions are classified into four approval tiers based on risk assessment.

#### Tier Classification

| Tier | Name | Criteria | Approval Process | Use Case |
|------|------|----------|------------------|----------|
| **Tier 1** | Autonomous | < 100 XRP AND known destination AND within daily limit | Automatic after policy check | Routine payments, micro-transactions |
| **Tier 2** | Delayed | 100-1,000 XRP OR new destination | 5-minute confirmation delay | Standard operations |
| **Tier 3** | Co-Sign | > 1,000 XRP OR elevated risk | Multi-signature required (2-of-3) | High-value transactions |
| **Tier 4** | Prohibited | Policy violation OR blocklisted | Rejected with audit log | Security threats |

#### Tier Classification Flow

```
                    +------------------+
                    |  Transaction     |
                    |  Received        |
                    +--------+---------+
                             |
                             v
                    +------------------+
                    |  Policy Check    |
                    +--------+---------+
                             |
              +--------------+--------------+
              |                             |
              v                             v
     +----------------+            +----------------+
     |  VIOLATION     |            |  PASSES        |
     +----------------+            +--------+-------+
              |                             |
              v                             v
     +----------------+            +----------------+
     |  TIER 4:       |            |  Amount Check  |
     |  Prohibited    |            +--------+-------+
     |  (Reject)      |                     |
     +----------------+         +-----------+-----------+
                                |           |           |
                                v           v           v
                        +-------+   +-------+   +-------+
                        |< 100  |   |100-   |   |>1000  |
                        | XRP   |   |1000   |   | XRP   |
                        +---+---+   +---+---+   +---+---+
                            |           |           |
                            v           v           v
                    +-------+   +-------+   +-------+
                    |Dest   |   |TIER 2:|   |TIER 3:|
                    |Check  |   |Delayed|   |Co-Sign|
                    +---+---+   +-------+   +-------+
                        |
           +------------+------------+
           |                         |
           v                         v
   +---------------+         +---------------+
   |  Known Dest   |         |  New Dest     |
   +-------+-------+         +-------+-------+
           |                         |
           v                         v
   +---------------+         +---------------+
   |  TIER 1:      |         |  TIER 2:      |
   |  Autonomous   |         |  Delayed      |
   +---------------+         +---------------+
```

#### Tier Configuration

```json
{
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 100,
      "daily_limit_xrp": 1000,
      "hourly_transaction_limit": 10,
      "requires_known_destination": true
    },
    "delayed": {
      "min_amount_xrp": 100,
      "max_amount_xrp": 1000,
      "delay_seconds": 300,
      "daily_limit_xrp": 10000,
      "cancellable": true
    },
    "cosign": {
      "min_amount_xrp": 1000,
      "signer_quorum": 2,
      "signer_count": 3,
      "timeout_hours": 24
    },
    "prohibited": {
      "blocklist_match": true,
      "policy_violation": true,
      "suspicious_memo": true
    }
  }
}
```

### 2.3 Security Boundaries

```
+--------------------------------------------------------------------+
|                        UNTRUSTED ZONE                               |
|                                                                     |
|   +------------------+                                              |
|   |   AI Agent       |                                              |
|   |   (MCP Client)   |                                              |
|   +--------+---------+                                              |
|            |                                                        |
+------------|--------------------------------------------------------+
             | MCP Protocol (JSON-RPC)
             | Input Validation Boundary
             v
+--------------------------------------------------------------------+
|                        INPUT VALIDATION ZONE                        |
|                                                                     |
|   +------------------+                                              |
|   |  Input Validator |  Zod schemas, sanitization, injection check |
|   +--------+---------+                                              |
|            |                                                        |
+------------|--------------------------------------------------------+
             | Validated Input
             | Policy Boundary
             v
+--------------------------------------------------------------------+
|                        POLICY ZONE                                  |
|                                                                     |
|   +------------------+    +------------------+                      |
|   |  Policy Engine   |    |  Rate Limiter    |                     |
|   +--------+---------+    +--------+---------+                     |
|            |                       |                                |
+------------|-------|---------------+--------------------------------+
             |       |
             | Approved Operations
             | Cryptographic Boundary
             v
+--------------------------------------------------------------------+
|                        TRUSTED ZONE                                 |
|                                                                     |
|   +------------------+    +------------------+                      |
|   |  Signing Service |    |  Keystore        |                     |
|   |  (Isolated)      |    |  (Encrypted)     |                     |
|   +--------+---------+    +------------------+                      |
|            |                                                        |
+------------|--------------------------------------------------------+
             | Signed Transactions
             v
+--------------------------------------------------------------------+
|                        NETWORK ZONE                                 |
|                                                                     |
|   +------------------+                                              |
|   |  XRPL Client     |  TLS 1.3, certificate validation            |
|   +--------+---------+                                              |
|            |                                                        |
+------------|--------------------------------------------------------+
             | WSS (Encrypted)
             v
+--------------------------------------------------------------------+
|                        EXTERNAL ZONE                                |
|                                                                     |
|   +------------------+                                              |
|   |  XRPL Network    |                                              |
|   +------------------+                                              |
|                                                                     |
+--------------------------------------------------------------------+
```

---

## 3. Logging and Monitoring

### 3.1 Audit Log Architecture

All security-relevant operations are recorded in a tamper-evident audit log with hash chain integrity.

#### Audit Log Entry Structure

```typescript
interface AuditLogEntry {
  // Identification
  id: string;                     // UUID v4, globally unique
  sequence: number;               // Monotonic sequence, gap detection
  timestamp: string;              // ISO 8601 with timezone (UTC)

  // Event Classification
  eventType: AuditEventType;      // Enumerated event type
  severity: 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL';
  category: EventCategory;        // Security, operation, system

  // Context
  toolName: string;               // MCP tool that triggered event
  correlationId: string;          // Request correlation ID
  sessionId?: string;             // Session identifier

  // Actor Information
  actor: {
    type: 'agent' | 'user' | 'system' | 'scheduled';
    id?: string;                  // Agent or user identifier
    ip?: string;                  // Only for compliance requirements
  };

  // Operation Details (sanitized)
  operation: {
    name: string;                 // Operation identifier
    parameters: Record<string, unknown>;  // Sanitized parameters
    result: 'success' | 'failure' | 'denied' | 'timeout';
    errorCode?: string;           // Error code if failed
    durationMs?: number;          // Operation duration
  };

  // Transaction Details (if applicable)
  transaction?: {
    type: string;                 // Payment, TrustSet, etc.
    hash?: string;                // Transaction hash
    destination?: string;         // Destination address (not full)
    amount?: string;              // Amount (XRP only, not tokens)
    tier: 1 | 2 | 3 | 4;         // Approval tier
    policyDecision: string;       // Policy evaluation result
  };

  // Integrity Fields
  previousHash: string;           // SHA-256 of previous entry
  hash: string;                   // HMAC-SHA256 of this entry
}

enum AuditEventType {
  // Authentication Events
  AUTH_ATTEMPT = 'auth.attempt',
  AUTH_SUCCESS = 'auth.success',
  AUTH_FAILURE = 'auth.failure',
  AUTH_LOCKOUT = 'auth.lockout',
  SESSION_START = 'session.start',
  SESSION_END = 'session.end',

  // Wallet Operations
  WALLET_CREATE = 'wallet.create',
  WALLET_IMPORT = 'wallet.import',
  WALLET_LIST = 'wallet.list',
  WALLET_DELETE = 'wallet.delete',

  // Transaction Operations
  TX_SIGN_REQUEST = 'transaction.sign.request',
  TX_SIGN_APPROVED = 'transaction.sign.approved',
  TX_SIGN_DENIED = 'transaction.sign.denied',
  TX_SUBMIT = 'transaction.submit',
  TX_CONFIRMED = 'transaction.confirmed',
  TX_FAILED = 'transaction.failed',

  // Policy Events
  POLICY_EVALUATION = 'policy.evaluation',
  POLICY_VIOLATION = 'policy.violation',
  POLICY_UPDATE = 'policy.update',
  LIMIT_EXCEEDED = 'limit.exceeded',
  LIMIT_WARNING = 'limit.warning',

  // Security Events
  INJECTION_DETECTED = 'security.injection_detected',
  RATE_LIMIT_TRIGGERED = 'security.rate_limit',
  SUSPICIOUS_ACTIVITY = 'security.suspicious',
  KEY_ACCESS = 'security.key_access',
  TAMPERING_DETECTED = 'security.tampering',

  // System Events
  SERVER_START = 'system.start',
  SERVER_STOP = 'system.stop',
  CONFIG_CHANGE = 'system.config_change',
  HEALTH_CHECK = 'system.health',
  ERROR = 'system.error'
}

type EventCategory = 'security' | 'operation' | 'transaction' | 'system';
```

### 3.2 What to Log vs. Never Log

#### ALWAYS Log

| Category | Fields | Example |
|----------|--------|---------|
| **Operation Metadata** | Tool name, operation type, timestamp | `sign_transaction`, `2026-01-28T14:30:00Z` |
| **Actor Information** | Actor type, session ID | `agent`, `sess_abc123` |
| **Results** | Success/failure, error codes, duration | `denied`, `POLICY_VIOLATION`, `45ms` |
| **Security Events** | Rate limits, injection attempts, lockouts | `rate_limit_exceeded`, `injection_pattern_detected` |
| **Policy Decisions** | Evaluation result, matched rules, tier | `allowed`, `tier_1_autonomous` |
| **Transaction Metadata** | Type, hash, tier, amount (XRP only) | `Payment`, `ABC123...`, `tier_1`, `50 XRP` |
| **Integrity Data** | Sequence, correlation ID, hashes | `12345`, `corr_xyz789` |

#### NEVER Log

| Category | Reason | Example of What NOT to Log |
|----------|--------|---------------------------|
| **Private Keys** | Complete security compromise | `sEdV...`, `ssec...` |
| **Seed Phrases** | Recovery phrase exposure | `abandon abandon ... zoo` |
| **Passwords** | Authentication secret | `MyP@ssw0rd!` |
| **Encryption Keys** | Breaks all encryption | `AES key bytes` |
| **Full Transaction Data** | May contain sensitive info | Complete tx JSON |
| **Decrypted Keystore** | Exposed key material | Decrypted wallet data |
| **Token Amounts** | Privacy for issued currencies | `1000 USD.rIssuer` |

#### Sanitization Examples

```typescript
// CORRECT: Log sanitized transaction metadata
auditLogger.log({
  eventType: AuditEventType.TX_SIGN_APPROVED,
  transaction: {
    type: 'Payment',
    hash: 'ABC123DEF456...',    // OK: Transaction hash
    destination: 'rDest...ABC', // OK: Partial address
    amount: '100 XRP',          // OK: XRP amount
    tier: 1                     // OK: Approval tier
  }
});

// INCORRECT: Never log like this
auditLogger.log({
  privateKey: wallet.privateKey,  // NEVER
  seedPhrase: importedSeed,       // NEVER
  password: userPassword,         // NEVER
  fullTransaction: txJson         // NEVER
});
```

### 3.3 Hash Chain Implementation

```typescript
class HashChainAuditLogger {
  private sequence: number = 0;
  private previousHash: string;
  private hmacKey: Buffer;

  constructor(hmacKey: Buffer) {
    this.hmacKey = hmacKey;
    // Genesis hash - known starting point
    this.previousHash = createHash('sha256')
      .update('XRPL_WALLET_MCP_AUDIT_GENESIS_V1')
      .digest('hex');
  }

  async log(event: Omit<AuditLogEntry, 'id' | 'sequence' | 'previousHash' | 'hash'>): Promise<AuditLogEntry> {
    const entry: AuditLogEntry = {
      ...event,
      id: randomUUID(),
      sequence: ++this.sequence,
      timestamp: new Date().toISOString(),
      previousHash: this.previousHash,
      hash: ''  // Calculated below
    };

    // Calculate HMAC excluding hash field
    const entryForHashing = { ...entry };
    delete (entryForHashing as any).hash;

    const hmac = createHmac('sha256', this.hmacKey);
    hmac.update(JSON.stringify(entryForHashing));
    entry.hash = hmac.digest('hex');

    // Persist entry (append-only)
    await this.persistEntry(entry);

    // Update chain
    this.previousHash = entry.hash;

    return entry;
  }

  async verifyChain(entries: AuditLogEntry[]): Promise<ChainVerificationResult> {
    let expectedPreviousHash = createHash('sha256')
      .update('XRPL_WALLET_MCP_AUDIT_GENESIS_V1')
      .digest('hex');

    const errors: string[] = [];
    let expectedSequence = 1;

    for (const entry of entries) {
      // Verify sequence
      if (entry.sequence !== expectedSequence) {
        errors.push(`Sequence gap: expected ${expectedSequence}, got ${entry.sequence}`);
      }

      // Verify previous hash link
      if (entry.previousHash !== expectedPreviousHash) {
        errors.push(`Chain break at sequence ${entry.sequence}: previousHash mismatch`);
      }

      // Verify entry hash
      const entryForHashing = { ...entry };
      delete (entryForHashing as any).hash;

      const hmac = createHmac('sha256', this.hmacKey);
      hmac.update(JSON.stringify(entryForHashing));
      const calculatedHash = hmac.digest('hex');

      if (calculatedHash !== entry.hash) {
        errors.push(`Tampering detected at sequence ${entry.sequence}: hash mismatch`);
      }

      expectedPreviousHash = entry.hash;
      expectedSequence++;
    }

    return {
      valid: errors.length === 0,
      entriesVerified: entries.length,
      errors
    };
  }
}
```

### 3.4 Log Retention and Compliance

| Requirement | Configuration | Rationale |
|-------------|---------------|-----------|
| **Retention Period** | 7 years minimum | Financial compliance (SOC 2, MiCA) |
| **Storage Type** | Append-only, encrypted at rest | Tamper prevention |
| **Access Control** | Read-only for auditors, no delete | Integrity protection |
| **Backup** | Daily encrypted backup, off-site | Disaster recovery |
| **Verification** | Hourly chain verification | Early tamper detection |
| **Rotation** | Daily file rotation, chain continues | Operational manageability |

---

## 4. Error Handling

### 4.1 Fail-Secure Principles

All error handling follows fail-secure design:

1. **Default Deny**: On any error, deny access
2. **No Information Leakage**: Never expose internal details in error responses
3. **Correlation for Debugging**: Include correlation ID for support lookup
4. **Complete Internal Logging**: Log full error details internally
5. **Sanitized External Response**: Return user-safe messages externally

### 4.2 Error Response Structure

```typescript
interface SecureError {
  error: true;
  code: ErrorCode;           // Machine-readable error code
  message: string;           // Human-readable, user-safe message
  correlationId: string;     // For support lookup
  retryable: boolean;        // Whether retry might succeed
  retryAfter?: number;       // Seconds to wait before retry
}

enum ErrorCode {
  // Validation Errors (4xx equivalent)
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  INVALID_ADDRESS = 'INVALID_ADDRESS',
  INVALID_AMOUNT = 'INVALID_AMOUNT',
  MISSING_PARAMETER = 'MISSING_PARAMETER',

  // Authentication Errors
  AUTH_REQUIRED = 'AUTH_REQUIRED',
  AUTH_FAILED = 'AUTH_FAILED',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  SESSION_EXPIRED = 'SESSION_EXPIRED',

  // Authorization Errors
  UNAUTHORIZED = 'UNAUTHORIZED',
  PERMISSION_DENIED = 'PERMISSION_DENIED',
  POLICY_VIOLATION = 'POLICY_VIOLATION',
  TIER_ESCALATION_REQUIRED = 'TIER_ESCALATION_REQUIRED',

  // Rate Limiting
  RATE_LIMITED = 'RATE_LIMITED',
  DAILY_LIMIT_EXCEEDED = 'DAILY_LIMIT_EXCEEDED',

  // Resource Errors
  WALLET_NOT_FOUND = 'WALLET_NOT_FOUND',
  TRANSACTION_NOT_FOUND = 'TRANSACTION_NOT_FOUND',

  // Security Errors
  INJECTION_DETECTED = 'INJECTION_DETECTED',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',

  // System Errors (5xx equivalent)
  INTERNAL_ERROR = 'INTERNAL_ERROR',
  SERVICE_UNAVAILABLE = 'SERVICE_UNAVAILABLE',
  NETWORK_ERROR = 'NETWORK_ERROR',
  TIMEOUT = 'TIMEOUT'
}
```

### 4.3 Error Handling Pattern

```typescript
async function handleToolRequest(
  request: MCPToolRequest,
  context: RequestContext
): Promise<MCPToolResponse> {
  const correlationId = generateCorrelationId();

  try {
    // Step 1: Validate input
    const validated = inputValidator.validate(request);
    if (!validated.success) {
      await auditLogger.log({
        eventType: AuditEventType.ERROR,
        severity: 'WARN',
        correlationId,
        operation: {
          name: request.tool,
          parameters: sanitizeForLog(request.params),
          result: 'failure',
          errorCode: 'VALIDATION_ERROR'
        }
      });

      return formatSecureError({
        code: ErrorCode.VALIDATION_ERROR,
        message: 'Invalid request parameters',
        correlationId,
        retryable: false
      });
    }

    // Step 2: Check rate limits
    const rateLimit = await rateLimiter.check(context.clientId, request.tool);
    if (!rateLimit.allowed) {
      await auditLogger.log({
        eventType: AuditEventType.RATE_LIMIT_TRIGGERED,
        severity: 'WARN',
        correlationId,
        operation: {
          name: request.tool,
          result: 'denied',
          errorCode: 'RATE_LIMITED'
        }
      });

      return formatSecureError({
        code: ErrorCode.RATE_LIMITED,
        message: 'Rate limit exceeded. Please try again later.',
        correlationId,
        retryable: true,
        retryAfter: rateLimit.retryAfter
      });
    }

    // Step 3: Execute operation
    const result = await executeOperation(validated.data, context);

    // Step 4: Log success
    await auditLogger.log({
      eventType: getEventType(request.tool),
      severity: 'INFO',
      correlationId,
      operation: {
        name: request.tool,
        parameters: sanitizeForLog(request.params),
        result: 'success',
        durationMs: Date.now() - context.startTime
      }
    });

    return formatSuccessResponse(result);

  } catch (error) {
    // Catch-all: Log full error internally, return sanitized response

    // Log complete error details internally
    logger.error('Operation failed', {
      correlationId,
      tool: request.tool,
      error: error.message,
      stack: error.stack,
      context: sanitizeForLog(context)
    });

    await auditLogger.log({
      eventType: AuditEventType.ERROR,
      severity: 'ERROR',
      correlationId,
      operation: {
        name: request.tool,
        result: 'failure',
        errorCode: 'INTERNAL_ERROR'
      }
    });

    // Return sanitized error - NEVER expose stack trace or internal details
    return formatSecureError({
      code: ErrorCode.INTERNAL_ERROR,
      message: 'An unexpected error occurred. Please contact support with the correlation ID.',
      correlationId,
      retryable: false
    });
  }
}
```

### 4.4 Error Response Examples

```typescript
// Example: Policy violation
{
  error: true,
  code: 'POLICY_VIOLATION',
  message: 'Transaction exceeds configured limits. Use a lower amount or request approval.',
  correlationId: 'corr_7f3d2a1b-4c5e-6789-abcd-ef0123456789',
  retryable: false
}

// Example: Rate limited
{
  error: true,
  code: 'RATE_LIMITED',
  message: 'Too many requests. Please wait before trying again.',
  correlationId: 'corr_8a4e3b2c-5d6f-7890-bcde-f01234567890',
  retryable: true,
  retryAfter: 60
}

// Example: Internal error (sanitized)
{
  error: true,
  code: 'INTERNAL_ERROR',
  message: 'An unexpected error occurred. Please contact support with the correlation ID.',
  correlationId: 'corr_9b5f4c3d-6e7g-8901-cdef-012345678901',
  retryable: false
}
```

---

## 5. Configuration Management

### 5.1 Configuration Hierarchy

Configuration is loaded in order of precedence (later overrides earlier):

```
1. Default Values (hardcoded)
        |
        v
2. Configuration Files (server.json, networks.json, policy.json)
        |
        v
3. Environment Variables (XRPL_* prefix)
        |
        v
4. Runtime Parameters (CLI flags)
```

### 5.2 Environment Variables

#### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `XRPL_NETWORK` | Target network | `mainnet`, `testnet`, `devnet` |
| `XRPL_WALLET_KEYSTORE_PATH` | Keystore directory | `~/.xrpl-wallet-mcp/mainnet/keystore` |

#### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `XRPL_LOG_LEVEL` | `info` | Logging level (debug, info, warn, error) |
| `XRPL_RATE_LIMIT_STANDARD` | `100` | Requests per minute for standard ops |
| `XRPL_RATE_LIMIT_STRICT` | `20` | Requests per minute for sensitive ops |
| `XRPL_RATE_LIMIT_CRITICAL` | `5` | Requests per 5 minutes for critical ops |
| `XRPL_SESSION_TIMEOUT` | `1800` | Session idle timeout in seconds |
| `XRPL_SESSION_MAX_AGE` | `28800` | Session absolute timeout in seconds |
| `XRPL_METRICS_ENABLED` | `false` | Enable Prometheus metrics |
| `XRPL_HEALTH_PORT` | `9090` | Health check endpoint port |

### 5.3 Policy Files

Policy files are JSON format with JSON Schema validation.

#### Policy File Structure

```json
{
  "$schema": "https://xrpl-wallet-mcp.io/schemas/policy-v1.json",
  "version": "1.0",
  "network": "mainnet",
  "created": "2026-01-28T00:00:00Z",
  "modified": "2026-01-28T00:00:00Z",

  "tiers": {
    "autonomous": {
      "max_amount_xrp": 100,
      "daily_limit_xrp": 1000,
      "hourly_transaction_limit": 10,
      "requires_known_destination": true
    },
    "delayed": {
      "min_amount_xrp": 100,
      "max_amount_xrp": 1000,
      "delay_seconds": 300,
      "daily_limit_xrp": 10000,
      "cancellable": true
    },
    "cosign": {
      "min_amount_xrp": 1000,
      "signer_quorum": 2,
      "signer_count": 3,
      "timeout_hours": 24
    }
  },

  "allowlist": {
    "addresses": [
      {
        "address": "rKnownExchange...",
        "tag": "trusted_exchange",
        "added": "2026-01-28T00:00:00Z"
      }
    ],
    "trusted_tags": ["trusted_exchange", "internal_wallet"]
  },

  "blocklist": {
    "addresses": [
      {
        "address": "rSuspicious...",
        "reason": "known_scam",
        "added": "2026-01-28T00:00:00Z"
      }
    ],
    "memo_patterns": [
      "(?i)send.*seed",
      "(?i)urgent.*transfer",
      "(?i)ignore.*previous"
    ]
  },

  "transaction_types": {
    "allowed": ["Payment", "TrustSet", "AccountSet"],
    "restricted": ["SignerListSet", "RegularKeySet"],
    "prohibited": ["AccountDelete"]
  },

  "fee_limits": {
    "max_fee_drops": 1000000,
    "warn_fee_drops": 100000
  }
}
```

#### File Organization

```
~/.xrpl-wallet-mcp/
|-- config/
|   |-- server.json           # Server configuration
|   `-- networks.json         # Network endpoints
|-- mainnet/
|   |-- keystore/             # Encrypted wallets
|   |   |-- agent-wallet-001.enc
|   |   `-- agent-wallet-002.enc
|   |-- policies/             # Network-specific policies
|   |   `-- default.json
|   `-- audit/                # Audit logs
|       |-- audit-2026-01-28.jsonl
|       `-- hmac-key.enc      # Encrypted HMAC key
|-- testnet/
|   |-- keystore/
|   |-- policies/
|   `-- audit/
`-- devnet/
    |-- keystore/
    |-- policies/
    `-- audit/
```

### 5.4 Configuration Validation

```typescript
// Configuration is validated on startup using Zod schemas
const ServerConfigSchema = z.object({
  transport: z.enum(['stdio', 'sse']).default('stdio'),
  logLevel: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  metricsEnabled: z.boolean().default(false),
  healthPort: z.number().int().min(1024).max(65535).default(9090)
});

const SecurityConfigSchema = z.object({
  rateLimitStandard: z.number().int().positive().default(100),
  rateLimitStrict: z.number().int().positive().default(20),
  rateLimitCritical: z.number().int().positive().default(5),
  sessionTimeout: z.number().int().positive().default(1800),
  sessionMaxAge: z.number().int().positive().default(28800),
  maxRequestSize: z.number().int().positive().default(1048576)
});

const PolicySchema = z.object({
  version: z.string(),
  network: z.enum(['mainnet', 'testnet', 'devnet']),
  tiers: TiersSchema,
  allowlist: AllowlistSchema,
  blocklist: BlocklistSchema,
  transactionTypes: TransactionTypesSchema,
  feeLimits: FeeLimitsSchema
});

// Validate on load, fail fast if invalid
function loadConfiguration(): Configuration {
  const serverConfig = ServerConfigSchema.parse(loadServerJson());
  const securityConfig = SecurityConfigSchema.parse(loadFromEnv());
  const policy = PolicySchema.parse(loadPolicyJson());

  // Verify policy file integrity
  verifyPolicySignature(policy);

  return { server: serverConfig, security: securityConfig, policy };
}
```

---

## 6. Cryptographic Concepts

### 6.1 Key Storage

All private keys are encrypted at rest using AES-256-GCM with keys derived via Argon2id.

#### Encryption Flow

```
                    +------------------+
                    |  User Password   |
                    +--------+---------+
                             |
                             v
+------------------+    +------------------+
|  Random Salt     |--->|    Argon2id      |
|  (32 bytes)      |    |  Key Derivation  |
+------------------+    |                  |
                        |  Memory: 64 MB   |
                        |  Iterations: 3   |
                        |  Parallelism: 4  |
                        +--------+---------+
                                 |
                                 v
                        +------------------+
                        |  Derived Key     |
                        |  (256 bits)      |
                        +--------+---------+
                                 |
                                 v
+------------------+    +------------------+
|  Random IV       |--->|   AES-256-GCM    |
|  (12 bytes)      |    |   Encryption     |
+------------------+    +--------+---------+
                                 |
                        +--------+--------+
                        |                 |
                        v                 v
               +----------------+  +----------------+
               |  Ciphertext    |  |  Auth Tag      |
               |  (encrypted    |  |  (16 bytes)    |
               |   private key) |  |                |
               +----------------+  +----------------+
```

#### Keystore File Format

```json
{
  "version": 1,
  "wallet_id": "agent-wallet-001",
  "address": "rAddress...",
  "algorithm": "ed25519",
  "encryption": {
    "algorithm": "aes-256-gcm",
    "kdf": {
      "algorithm": "argon2id",
      "memory_cost": 65536,
      "time_cost": 3,
      "parallelism": 4,
      "salt": "base64-encoded-salt-32-bytes"
    },
    "iv": "base64-encoded-iv-12-bytes",
    "auth_tag": "base64-encoded-tag-16-bytes"
  },
  "encrypted_data": "base64-encoded-ciphertext",
  "metadata": {
    "created_at": "2026-01-28T00:00:00Z",
    "modified_at": "2026-01-28T00:00:00Z",
    "network": "mainnet"
  }
}
```

### 6.2 Cryptographic Parameters

| Parameter | Value | Reference |
|-----------|-------|-----------|
| **Encryption Algorithm** | AES-256-GCM | NIST SP 800-38D |
| **IV Length** | 12 bytes (96 bits) | NIST recommendation for GCM |
| **Auth Tag Length** | 16 bytes (128 bits) | Maximum security |
| **KDF Algorithm** | Argon2id | RFC 9106 |
| **KDF Memory** | 64 MB (65,536 KB) | OWASP recommendation |
| **KDF Iterations** | 3 | Balances security and performance |
| **KDF Parallelism** | 4 | Typical CPU core count |
| **Salt Length** | 32 bytes | Per-wallet uniqueness |
| **Key Length** | 32 bytes (256 bits) | AES-256 requirement |

### 6.3 Memory Safety

Private keys must be handled with extreme care to minimize exposure.

#### SecureBuffer Pattern

```typescript
class SecureBuffer {
  private buffer: Buffer;
  private isZeroed: boolean = false;
  private createdAt: number = Date.now();

  private constructor(size: number) {
    this.buffer = Buffer.allocUnsafe(size);
  }

  static allocate(size: number): SecureBuffer {
    return new SecureBuffer(size);
  }

  static from(data: Buffer | Uint8Array): SecureBuffer {
    const secureBuffer = new SecureBuffer(data.length);
    Buffer.from(data).copy(secureBuffer.buffer);
    return secureBuffer;
  }

  getBuffer(): Buffer {
    if (this.isZeroed) {
      throw new Error('SecureBuffer has been zeroed and cannot be read');
    }
    return this.buffer;
  }

  zero(): void {
    if (!this.isZeroed) {
      // Overwrite with zeros
      this.buffer.fill(0);
      this.isZeroed = true;
    }
  }

  get age(): number {
    return Date.now() - this.createdAt;
  }

  // Prevent JSON serialization
  toJSON(): never {
    throw new Error('SecureBuffer cannot be serialized');
  }

  // Prevent string conversion
  toString(): never {
    throw new Error('SecureBuffer cannot be converted to string');
  }

  // Static helper for scoped operations
  static async withSecureBuffer<T>(
    data: Buffer,
    operation: (buffer: Buffer) => Promise<T>
  ): Promise<T> {
    const secureBuffer = SecureBuffer.from(data);
    try {
      return await operation(secureBuffer.getBuffer());
    } finally {
      secureBuffer.zero();
    }
  }
}
```

#### Memory Safety Rules

| Rule | Implementation |
|------|----------------|
| **Minimize Lifetime** | Keys in memory < 100ms during signing |
| **Avoid String Conversion** | Never use `key.toString()` or `Buffer.toString()` on keys |
| **Immediate Zeroing** | Call `SecureBuffer.zero()` in `finally` blocks |
| **No Logging** | Never pass key buffers to logging functions |
| **No Serialization** | Override `toJSON()` to throw errors |
| **Core Dumps Disabled** | Set `ulimit -c 0` at startup |

### 6.4 HMAC for Audit Log Integrity

```typescript
// Audit log HMAC configuration
const HMAC_ALGORITHM = 'sha256';
const HMAC_KEY_LENGTH = 32;  // 256 bits

// HMAC key stored encrypted, separate from logs
interface HMACKeyStorage {
  encrypted_key: string;  // AES-256-GCM encrypted
  iv: string;
  auth_tag: string;
  created_at: string;
}

// Key derivation for HMAC key encryption
// Uses separate password from wallet passwords
async function deriveHMACEncryptionKey(adminPassword: string, salt: Buffer): Promise<Buffer> {
  return argon2.hash(adminPassword, {
    type: argon2.argon2id,
    salt,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
    hashLength: 32,
    raw: true
  });
}
```

---

## 7. Concurrency and Threading

### 7.1 Thread Safety

Node.js operates on a single-threaded event loop, which simplifies concurrency but requires careful handling of asynchronous operations.

#### Concurrency Model

```
+------------------------------------------------------------------+
|                        Node.js Process                            |
|                                                                   |
|  +------------------------------------------------------------+  |
|  |                    Event Loop (Single Thread)               |  |
|  |                                                             |  |
|  |  +---------------+  +---------------+  +---------------+   |  |
|  |  | MCP Request 1 |  | MCP Request 2 |  | MCP Request 3 |   |  |
|  |  |   (async)     |  |   (async)     |  |   (async)     |   |  |
|  |  +-------+-------+  +-------+-------+  +-------+-------+   |  |
|  |          |                  |                  |           |  |
|  |          v                  v                  v           |  |
|  |  +----------------------------------------------------+   |  |
|  |  |              Shared State (with locks)              |   |  |
|  |  |  - Rate limit counters                              |   |  |
|  |  |  - Limit tracker state                              |   |  |
|  |  |  - Audit log sequence                               |   |  |
|  |  +----------------------------------------------------+   |  |
|  |                                                             |  |
|  +------------------------------------------------------------+  |
|                                                                   |
|  +------------------------------------------------------------+  |
|  |                    Worker Pool (libuv)                      |  |
|  |  - File I/O (keystore reads/writes)                        |  |
|  |  - Crypto operations (Argon2id)                            |  |
|  |  - DNS resolution                                          |  |
|  +------------------------------------------------------------+  |
|                                                                   |
+------------------------------------------------------------------+
```

### 7.2 Atomic File Operations

Keystore writes must be atomic to prevent corruption.

```typescript
async function atomicWriteKeystore(
  filepath: string,
  data: Buffer
): Promise<void> {
  const tempPath = `${filepath}.tmp.${Date.now()}.${randomBytes(4).toString('hex')}`;
  const backupPath = `${filepath}.bak`;

  try {
    // Step 1: Write to temporary file
    await fs.writeFile(tempPath, data, { mode: 0o600 });

    // Step 2: Verify written data
    const written = await fs.readFile(tempPath);
    if (!written.equals(data)) {
      throw new Error('Written data verification failed');
    }

    // Step 3: Backup existing file (if exists)
    try {
      await fs.access(filepath);
      await fs.copyFile(filepath, backupPath);
    } catch {
      // No existing file to backup
    }

    // Step 4: Atomic rename
    await fs.rename(tempPath, filepath);

    // Step 5: Verify permissions
    await fs.chmod(filepath, 0o600);

  } catch (error) {
    // Cleanup on error
    try {
      await fs.unlink(tempPath);
    } catch {
      // Ignore cleanup errors
    }
    throw error;
  }
}
```

### 7.3 Rate Limiting

Rate limiting uses token bucket with sliding window for smooth enforcement.

#### Rate Limit Tiers

| Tier | Window | Max Requests | Burst | Use Case |
|------|--------|--------------|-------|----------|
| **Standard** | 60 seconds | 100 | 10 | Read operations (get_balance, list_wallets) |
| **Strict** | 60 seconds | 20 | 2 | Write operations (sign_transaction) |
| **Critical** | 300 seconds | 5 | 0 | Sensitive operations (import_wallet, delete_wallet) |
| **Auth** | 900 seconds | 5 | 0 | Authentication attempts per account |
| **Auth (IP)** | 3600 seconds | 10 | 0 | Authentication attempts per IP |

#### Token Bucket Implementation

```typescript
class TokenBucketRateLimiter {
  private buckets: Map<string, TokenBucket> = new Map();

  constructor(private config: RateLimitConfig) {}

  check(clientId: string, tier: RateLimitTier): RateLimitResult {
    const key = `${clientId}:${tier}`;
    let bucket = this.buckets.get(key);

    if (!bucket) {
      bucket = new TokenBucket(this.config.tiers[tier]);
      this.buckets.set(key, bucket);
    }

    return bucket.tryConsume();
  }
}

class TokenBucket {
  private tokens: number;
  private lastRefill: number;

  constructor(private config: TierConfig) {
    this.tokens = config.maxTokens;
    this.lastRefill = Date.now();
  }

  tryConsume(): RateLimitResult {
    this.refill();

    if (this.tokens >= 1) {
      this.tokens -= 1;
      return {
        allowed: true,
        remaining: Math.floor(this.tokens),
        resetAt: this.calculateResetTime()
      };
    }

    return {
      allowed: false,
      remaining: 0,
      resetAt: this.calculateResetTime(),
      retryAfter: this.calculateRetryAfter()
    };
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    const tokensToAdd = (elapsed / 1000) * this.config.refillRate;

    this.tokens = Math.min(
      this.config.maxTokens,
      this.tokens + tokensToAdd
    );
    this.lastRefill = now;
  }

  private calculateResetTime(): number {
    const tokensNeeded = this.config.maxTokens - this.tokens;
    const secondsToFull = tokensNeeded / this.config.refillRate;
    return Math.ceil(Date.now() / 1000) + Math.ceil(secondsToFull);
  }

  private calculateRetryAfter(): number {
    return Math.ceil(1 / this.config.refillRate);
  }
}
```

---

## 8. Testing Concepts

### 8.1 Testing Pyramid

```
                    +-------------------+
                   /                     \
                  /    E2E Tests (10%)    \
                 /   Full wallet lifecycle \
                /    with XRPL testnet      \
               +---------------------------+
              /                             \
             /    Integration Tests (30%)    \
            /   MCP tool flows, component     \
           /    interactions, policy engine   \
          +-----------------------------------+
         /                                     \
        /         Unit Tests (60%)              \
       /   Keystore, validators, policy rules,   \
      /    cryptographic operations, utilities    \
     +-----------------------------------------+
```

### 8.2 Test Categories

| Category | Description | Coverage Target |
|----------|-------------|-----------------|
| **Unit Tests** | Individual functions and classes | >= 80% line coverage |
| **Integration Tests** | Component interactions | All critical paths |
| **E2E Tests** | Full system with testnet | Happy paths + error cases |
| **Security Tests** | Attack simulations | All threat vectors |
| **Performance Tests** | Load and stress testing | Rate limit validation |

### 8.3 Test Environment

```
+------------------------------------------------------------------+
|                        Test Environment                           |
|                                                                   |
|  +---------------------------+  +---------------------------+    |
|  |      Unit Tests           |  |   Integration Tests       |    |
|  |                           |  |                           |    |
|  |  - Mock XRPL client       |  |  - In-memory keystore     |    |
|  |  - Fixture policy files   |  |  - Test policy files      |    |
|  |  - No network calls       |  |  - Mock XRPL responses    |    |
|  |  - Isolated components    |  |  - Full MCP tool flows    |    |
|  +---------------------------+  +---------------------------+    |
|                                                                   |
|  +---------------------------+  +---------------------------+    |
|  |      E2E Tests            |  |   Security Tests          |    |
|  |                           |  |                           |    |
|  |  - XRPL Testnet/Devnet    |  |  - Injection attempts     |    |
|  |  - Real transactions      |  |  - Bypass attempts        |    |
|  |  - Funded test wallets    |  |  - Brute force tests      |    |
|  |  - Full lifecycle         |  |  - Fuzzing                |    |
|  +---------------------------+  +---------------------------+    |
|                                                                   |
+------------------------------------------------------------------+
```

### 8.4 Security Test Cases

| Test Category | Test Cases |
|---------------|------------|
| **Input Validation** | Malformed JSON, oversized inputs, invalid addresses, bad checksums |
| **Prompt Injection** | `[INST]` patterns, `<<SYS>>` markers, "ignore previous" phrases |
| **Authentication** | Brute force, lockout bypass, session hijacking, timing attacks |
| **Authorization** | Privilege escalation, policy bypass, tier manipulation |
| **Cryptographic** | IV reuse detection, weak key detection, auth tag tampering |
| **Rate Limiting** | Burst attacks, distributed attacks, rate limit bypass |
| **Audit Logging** | Log tampering, chain verification, sequence gap detection |

### 8.5 Test Data and Fixtures

```
tests/
|-- fixtures/
|   |-- policies/
|   |   |-- permissive.json       # Allow most transactions
|   |   |-- restrictive.json      # Strict limits
|   |   `-- blocklist-test.json   # Test blocklist functionality
|   |-- keystores/
|   |   |-- test-wallet.enc       # Pre-encrypted test wallet
|   |   `-- corrupted-wallet.enc  # For error handling tests
|   |-- transactions/
|   |   |-- valid-payment.json
|   |   |-- invalid-destination.json
|   |   `-- injection-memo.json
|   `-- audit-logs/
|       |-- valid-chain.jsonl
|       `-- tampered-chain.jsonl
|-- unit/
|-- integration/
|-- e2e/
`-- security/
```

---

## 9. Internationalization

### Current Status

Internationalization is **not applicable** for the MVP release. All user-facing messages are in English.

### Future Considerations

If internationalization is required in future versions:

| Consideration | Approach |
|---------------|----------|
| **Message Externalization** | Use i18n library (e.g., `i18next`) |
| **Error Messages** | Map error codes to localized strings |
| **Audit Logs** | Keep in English for compliance |
| **Date/Time** | Use ISO 8601 format universally |
| **Currency** | Display XRP with proper decimal formatting |

---

## 10. Related Documents

### Security Documentation

- [Security Architecture](../security/SECURITY-ARCHITECTURE.md) - Complete security design
- [Security Requirements](../security/security-requirements.md) - Formal requirements specification
- [Threat Model](../security/threat-model.md) - Threat analysis and mitigations

### Architecture Documentation

- [01 - Introduction](./01-introduction.md) - Project overview
- [02 - Constraints](./02-constraints.md) - Architectural constraints
- [03 - Context](./03-context.md) - System context
- [04 - Solution Strategy](./04-solution-strategy.md) - Technical approach
- [05 - Building Blocks](./05-building-blocks.md) - Component decomposition

### C4 Diagrams

- [Context Diagram](../c4-diagrams/context.md) - Level 1 system context
- [Container Diagram](../c4-diagrams/containers.md) - Level 2 containers
- [Component Diagram](../c4-diagrams/components.md) - Level 3 components

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Security Specialist | Initial cross-cutting concepts document |

**Next Review Date:** 2026-04-28

**Classification:** Internal/Public

---

*Arc42 Template - Section 08: Crosscutting Concepts*
