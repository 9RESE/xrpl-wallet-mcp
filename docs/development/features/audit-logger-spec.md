# Audit Logger Implementation Specification

**Version:** 1.0.0
**Date:** 2026-01-28
**Status:** Draft
**Author:** Backend Engineer

---

## Table of Contents

1. [Overview](#1-overview)
2. [AuditLogger Class Interface](#2-auditlogger-class-interface)
3. [Log Entry Structure](#3-log-entry-structure)
4. [HMAC Hash Chain Implementation](#4-hmac-hash-chain-implementation)
5. [Event Types Enumeration](#5-event-types-enumeration)
6. [Storage Backend Interface](#6-storage-backend-interface)
7. [Log Rotation Configuration](#7-log-rotation-configuration)
8. [Compliance Queries](#8-compliance-queries)
9. [Tamper Detection and Alerting](#9-tamper-detection-and-alerting)
10. [Performance Considerations](#10-performance-considerations)
11. [Test Patterns](#11-test-patterns)
12. [Implementation Checklist](#12-implementation-checklist)

---

## 1. Overview

### Purpose

The AuditLogger provides tamper-evident logging for all security-relevant operations in the XRPL Agent Wallet MCP server. It implements an HMAC-SHA256 hash chain that enables detection of:

- Log entry modifications (tampering)
- Log entry deletions (sequence gaps)
- Log insertion attacks (chain breaks)

### Design Goals

| Goal | Description | Metric |
|------|-------------|--------|
| **Tamper Evidence** | Any modification detectable | 100% detection rate |
| **Non-Repudiation** | Cryptographic proof of events | HMAC-SHA256 signatures |
| **Compliance Ready** | SOC 2 / MiCA compatible | 7+ year retention |
| **High Performance** | Minimal latency impact | < 5ms per log entry |
| **Queryable** | Efficient compliance queries | < 100ms for date range |

### Dependencies

```typescript
// Required packages
import { createHmac, randomUUID, createHash } from 'crypto';
import { EventEmitter } from 'events';
import { z } from 'zod';
```

### References

- [ADR-005: Audit Logging](../../architecture/09-decisions/ADR-005-audit-logging.md)
- [08-Crosscutting Concepts](../../architecture/08-crosscutting.md)
- Security Requirements: AUDIT-001 through AUDIT-007

---

## 2. AuditLogger Class Interface

### Main Interface

```typescript
/**
 * AuditLogger - Tamper-evident audit logging with HMAC hash chains
 *
 * @example
 * const logger = await AuditLogger.create({
 *   hmacKeyProvider: keyProvider,
 *   storageBackend: fileStorage,
 *   onTamperDetected: async (event) => alerting.send(event)
 * });
 *
 * await logger.log({
 *   eventType: AuditEventType.TX_SIGN_SUCCESS,
 *   correlationId: 'corr_abc123',
 *   actor: { type: 'agent', id: 'agent_001' },
 *   operation: {
 *     name: 'sign_transaction',
 *     parameters: { wallet: 'rAddress...' },
 *     result: 'success'
 *   }
 * });
 */
export interface IAuditLogger {
  /**
   * Log an audit event
   * @param event - Event data (without integrity fields)
   * @returns Complete log entry with integrity fields
   * @throws AuditLogError if storage fails
   */
  log(event: AuditLogInput): Promise<AuditLogEntry>;

  /**
   * Verify hash chain integrity
   * @param options - Verification options (date range, full/partial)
   * @returns Verification result with any detected errors
   */
  verifyChain(options?: VerificationOptions): Promise<ChainVerificationResult>;

  /**
   * Query logs by criteria
   * @param query - Query parameters
   * @returns Matching log entries
   */
  query(query: AuditLogQuery): Promise<AuditLogEntry[]>;

  /**
   * Export logs for compliance
   * @param options - Export parameters (date range, format)
   * @returns Signed compliance export
   */
  export(options: ExportOptions): Promise<ComplianceExport>;

  /**
   * Get current chain state
   * @returns Current sequence number and hash
   */
  getChainState(): ChainState;

  /**
   * Graceful shutdown
   * @param timeout - Max wait time for pending writes
   */
  shutdown(timeout?: number): Promise<void>;
}
```

### Factory Method

```typescript
export class AuditLogger extends EventEmitter implements IAuditLogger {
  private constructor(
    private readonly hmacKey: Buffer,
    private readonly storage: IStorageBackend,
    private readonly config: AuditLoggerConfig,
    private chainState: ChainState
  ) {
    super();
  }

  /**
   * Create AuditLogger instance
   *
   * Factory method ensures proper initialization:
   * 1. Loads/creates HMAC key
   * 2. Initializes storage backend
   * 3. Restores chain state from storage
   * 4. Verifies chain integrity on startup
   *
   * @param options - Configuration options
   * @returns Initialized AuditLogger
   * @throws AuditLogError if initialization fails
   */
  static async create(options: AuditLoggerOptions): Promise<AuditLogger> {
    // 1. Get HMAC key
    const hmacKey = await options.hmacKeyProvider.getKey();
    if (hmacKey.length !== 32) {
      throw new AuditLogError('HMAC key must be 256 bits', 'INVALID_HMAC_KEY');
    }

    // 2. Initialize storage
    const storage = options.storageBackend;
    await storage.initialize();

    // 3. Restore chain state
    const lastEntry = await storage.getLastEntry();
    const chainState: ChainState = lastEntry
      ? { sequence: lastEntry.sequence, previousHash: lastEntry.hash }
      : { sequence: 0, previousHash: AuditLogger.computeGenesisHash(hmacKey) };

    // 4. Create instance
    const logger = new AuditLogger(hmacKey, storage, options.config ?? DEFAULT_CONFIG, chainState);

    // 5. Optional startup verification
    if (options.verifyOnStartup !== false) {
      const result = await logger.verifyChain({ fullChain: false, recentEntries: 1000 });
      if (!result.valid) {
        logger.emit('tamper_detected', result);
        if (options.onTamperDetected) {
          await options.onTamperDetected(result);
        }
      }
    }

    return logger;
  }

  private static computeGenesisHash(hmacKey: Buffer): string {
    const hmac = createHmac('sha256', hmacKey);
    hmac.update('XRPL-WALLET-MCP-GENESIS-V1');
    return hmac.digest('hex');
  }
}
```

### Configuration

```typescript
export interface AuditLoggerOptions {
  /** Provider for HMAC key (encrypted storage) */
  hmacKeyProvider: IHmacKeyProvider;

  /** Storage backend implementation */
  storageBackend: IStorageBackend;

  /** Logger configuration */
  config?: Partial<AuditLoggerConfig>;

  /** Verify chain integrity on startup */
  verifyOnStartup?: boolean;

  /** Callback when tampering detected */
  onTamperDetected?: (event: ChainVerificationResult) => Promise<void>;
}

export interface AuditLoggerConfig {
  /** Maximum entries to buffer before flush */
  bufferSize: number;

  /** Maximum time (ms) to buffer before flush */
  flushIntervalMs: number;

  /** Enable synchronous writes (slower but safer) */
  syncWrites: boolean;

  /** Maximum query result size */
  maxQueryResults: number;

  /** Periodic verification interval (0 = disabled) */
  verificationIntervalMs: number;

  /** Number of recent entries to verify periodically */
  verificationSampleSize: number;
}

export const DEFAULT_CONFIG: AuditLoggerConfig = {
  bufferSize: 100,
  flushIntervalMs: 1000,
  syncWrites: true, // For security, default to sync
  maxQueryResults: 10000,
  verificationIntervalMs: 3600000, // 1 hour
  verificationSampleSize: 1000
};
```

---

## 3. Log Entry Structure

### Complete Entry Schema

```typescript
/**
 * Complete audit log entry with all fields
 */
export interface AuditLogEntry {
  // === Identification ===
  /** UUID v4, globally unique */
  id: string;

  /** Monotonic sequence number (1-based) */
  sequence: number;

  /** ISO 8601 timestamp with timezone (UTC) */
  timestamp: string;

  // === Event Classification ===
  /** Enumerated event type */
  eventType: AuditEventType;

  /** Severity level */
  severity: AuditSeverity;

  /** Event category */
  category: EventCategory;

  // === Context ===
  /** MCP tool that triggered event */
  toolName?: string;

  /** Request correlation ID for tracing */
  correlationId: string;

  /** Session identifier */
  sessionId?: string;

  // === Actor Information ===
  actor: {
    /** Actor type */
    type: ActorType;
    /** Actor identifier */
    id?: string;
  };

  // === Operation Details ===
  operation: {
    /** Operation identifier */
    name: string;
    /** Sanitized parameters (no secrets) */
    parameters: Record<string, unknown>;
    /** Operation result */
    result: OperationResult;
    /** Error code if failed */
    errorCode?: string;
    /** Error message (sanitized) */
    errorMessage?: string;
    /** Operation duration in milliseconds */
    durationMs?: number;
  };

  // === Transaction Context (optional) ===
  transaction?: {
    /** Transaction type */
    type: string;
    /** Transaction hash */
    hash?: string;
    /** Destination address */
    destination?: string;
    /** Amount (XRP only, not tokens) */
    amount?: string;
    /** Approval tier */
    tier: 1 | 2 | 3 | 4;
    /** Policy decision */
    policyDecision: string;
  };

  // === Network Context ===
  context: {
    /** XRPL network */
    network: XRPLNetwork;
    /** Wallet address */
    walletAddress?: string;
    /** Policy version */
    policyVersion?: string;
  };

  // === Integrity Fields ===
  /** HMAC-SHA256 of previous entry */
  previousHash: string;

  /** HMAC-SHA256 of this entry */
  hash: string;
}

// Supporting types
export type AuditSeverity = 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL';
export type EventCategory = 'security' | 'operation' | 'transaction' | 'system';
export type ActorType = 'agent' | 'system' | 'human' | 'scheduled';
export type OperationResult = 'success' | 'failure' | 'denied' | 'timeout';
export type XRPLNetwork = 'mainnet' | 'testnet' | 'devnet';
```

### Input Schema (For Logging)

```typescript
/**
 * Input for log() method - integrity fields computed automatically
 */
export type AuditLogInput = Omit<
  AuditLogEntry,
  'id' | 'sequence' | 'timestamp' | 'previousHash' | 'hash'
>;
```

### Zod Validation Schemas

```typescript
export const AuditLogInputSchema = z.object({
  eventType: z.nativeEnum(AuditEventType),
  severity: z.enum(['INFO', 'WARN', 'ERROR', 'CRITICAL']),
  category: z.enum(['security', 'operation', 'transaction', 'system']),
  toolName: z.string().max(100).optional(),
  correlationId: z.string().uuid(),
  sessionId: z.string().max(100).optional(),
  actor: z.object({
    type: z.enum(['agent', 'system', 'human', 'scheduled']),
    id: z.string().max(100).optional()
  }),
  operation: z.object({
    name: z.string().max(100),
    parameters: z.record(z.unknown()),
    result: z.enum(['success', 'failure', 'denied', 'timeout']),
    errorCode: z.string().max(50).optional(),
    errorMessage: z.string().max(500).optional(),
    durationMs: z.number().int().nonnegative().optional()
  }),
  transaction: z
    .object({
      type: z.string().max(50),
      hash: z.string().length(64).regex(/^[A-F0-9]+$/i).optional(),
      destination: z.string().max(50).optional(),
      amount: z.string().max(50).optional(),
      tier: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4)]),
      policyDecision: z.string().max(100)
    })
    .optional(),
  context: z.object({
    network: z.enum(['mainnet', 'testnet', 'devnet']),
    walletAddress: z.string().max(50).optional(),
    policyVersion: z.string().max(20).optional()
  })
});
```

### Sensitive Data Sanitization

```typescript
/**
 * Fields that must NEVER appear in audit logs
 */
const REDACTED_FIELDS = new Set([
  'password',
  'seed',
  'secret',
  'privatekey',
  'private_key',
  'mnemonic',
  'passphrase',
  'encryptionkey',
  'hmackey',
  'masterkey',
  'master_key',
  'secretkey',
  'secret_key',
  'apikey',
  'api_key',
  'token',
  'bearer'
]);

/**
 * Patterns that indicate sensitive data
 */
const SENSITIVE_PATTERNS = [
  /^s[a-zA-Z0-9]{28}$/, // XRPL seed
  /^[a-f0-9]{64}$/i, // 256-bit hex (private key)
  /^[a-f0-9]{128}$/i, // 512-bit hex
  /^(abandon\s+){11}(abandon|about|above|absent)\b/i // BIP39 mnemonic start
];

/**
 * Sanitize object for logging - removes all sensitive data
 *
 * @param obj - Object to sanitize
 * @param depth - Current recursion depth
 * @returns Sanitized copy of object
 */
export function sanitizeForLogging(obj: unknown, depth = 0): unknown {
  // Prevent infinite recursion
  if (depth > 10) return '[MAX_DEPTH]';

  // Handle null/undefined
  if (obj === null || obj === undefined) return obj;

  // Handle strings
  if (typeof obj === 'string') {
    // Check patterns
    for (const pattern of SENSITIVE_PATTERNS) {
      if (pattern.test(obj)) return '[REDACTED]';
    }
    // Truncate long strings
    return obj.length > 1000 ? obj.slice(0, 100) + '...[TRUNCATED]' : obj;
  }

  // Handle primitives
  if (typeof obj !== 'object') return obj;

  // Handle arrays
  if (Array.isArray(obj)) {
    return obj.map((item) => sanitizeForLogging(item, depth + 1));
  }

  // Handle objects
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase().replace(/[-_]/g, '');
    if (REDACTED_FIELDS.has(lowerKey)) {
      result[key] = '[REDACTED]';
    } else {
      result[key] = sanitizeForLogging(value, depth + 1);
    }
  }
  return result;
}
```

---

## 4. HMAC Hash Chain Implementation

### Genesis Entry

The genesis entry establishes the chain's starting point with a well-known constant.

```typescript
/**
 * Genesis hash computation
 *
 * The genesis hash is computed from a constant string using HMAC-SHA256.
 * This provides a verifiable starting point for the chain that can be
 * independently computed by any party with the HMAC key.
 *
 * @param hmacKey - 256-bit HMAC key
 * @returns Hex-encoded genesis hash
 */
function computeGenesisHash(hmacKey: Buffer): string {
  const hmac = createHmac('sha256', hmacKey);
  hmac.update('XRPL-WALLET-MCP-GENESIS-V1');
  return hmac.digest('hex');
}

/**
 * Create the first entry in a new chain (sequence = 1)
 */
async function createFirstEntry(
  event: AuditLogInput,
  hmacKey: Buffer
): Promise<AuditLogEntry> {
  const entry: AuditLogEntry = {
    ...event,
    id: randomUUID(),
    sequence: 1,
    timestamp: new Date().toISOString(),
    previousHash: computeGenesisHash(hmacKey),
    hash: '' // Computed below
  };

  entry.hash = computeEntryHash(entry, hmacKey);
  return entry;
}
```

### Chain Continuation

```typescript
/**
 * Compute HMAC-SHA256 hash of an entry
 *
 * The hash includes ALL fields except 'hash' itself. Fields are
 * sorted alphabetically for deterministic serialization.
 *
 * @param entry - Log entry (hash field will be ignored)
 * @param hmacKey - 256-bit HMAC key
 * @returns Hex-encoded hash
 */
function computeEntryHash(entry: AuditLogEntry, hmacKey: Buffer): string {
  // Create copy without hash field
  const entryForHashing: Partial<AuditLogEntry> = { ...entry };
  delete entryForHashing.hash;

  // Sort keys for deterministic serialization
  const sortedJson = JSON.stringify(entryForHashing, Object.keys(entryForHashing).sort());

  // Compute HMAC
  const hmac = createHmac('sha256', hmacKey);
  hmac.update(sortedJson);
  return hmac.digest('hex');
}

/**
 * Main logging implementation
 */
async log(event: AuditLogInput): Promise<AuditLogEntry> {
  // 1. Validate input
  const validated = AuditLogInputSchema.parse(event);

  // 2. Acquire write lock (for thread safety)
  await this.writeLock.acquire();

  try {
    // 3. Create entry with integrity fields
    const entry: AuditLogEntry = {
      ...validated,
      id: randomUUID(),
      sequence: this.chainState.sequence + 1,
      timestamp: new Date().toISOString(),
      previousHash: this.chainState.previousHash,
      hash: ''
    };

    // 4. Compute hash
    entry.hash = computeEntryHash(entry, this.hmacKey);

    // 5. Persist to storage
    await this.storage.append(entry);

    // 6. Update chain state
    this.chainState = {
      sequence: entry.sequence,
      previousHash: entry.hash
    };

    // 7. Emit event
    this.emit('entry_logged', { sequence: entry.sequence, eventType: entry.eventType });

    return entry;

  } finally {
    this.writeLock.release();
  }
}
```

### Verification Algorithm

```typescript
/**
 * Result of chain verification
 */
export interface ChainVerificationResult {
  /** Overall validity */
  valid: boolean;

  /** Number of entries verified */
  entriesVerified: number;

  /** First sequence number verified */
  startSequence: number;

  /** Last sequence number verified */
  endSequence: number;

  /** Verification duration (ms) */
  durationMs: number;

  /** List of detected errors */
  errors: ChainError[];
}

export interface ChainError {
  /** Error type */
  type: 'sequence_gap' | 'chain_break' | 'tampered_entry' | 'invalid_timestamp';

  /** Sequence number where error detected */
  sequence: number;

  /** Expected value */
  expected: string | number;

  /** Actual value found */
  actual: string | number;

  /** Error description */
  description: string;
}

/**
 * Verify chain integrity
 *
 * Verification checks:
 * 1. Sequence numbers are monotonic without gaps
 * 2. Each entry's previousHash matches prior entry's hash
 * 3. Each entry's hash can be recomputed correctly
 * 4. Timestamps are monotonically increasing
 *
 * @param options - Verification options
 * @returns Verification result
 */
async verifyChain(options: VerificationOptions = {}): Promise<ChainVerificationResult> {
  const startTime = Date.now();
  const errors: ChainError[] = [];

  // Determine range to verify
  let entries: AuditLogEntry[];
  if (options.fullChain) {
    entries = await this.storage.getAllEntries();
  } else if (options.startSequence && options.endSequence) {
    entries = await this.storage.getEntriesBySequenceRange(
      options.startSequence,
      options.endSequence
    );
  } else {
    // Default: verify recent entries
    const recentCount = options.recentEntries ?? 1000;
    entries = await this.storage.getRecentEntries(recentCount);
  }

  if (entries.length === 0) {
    return {
      valid: true,
      entriesVerified: 0,
      startSequence: 0,
      endSequence: 0,
      durationMs: Date.now() - startTime,
      errors: []
    };
  }

  // Determine expected previous hash for first entry
  let expectedPrevHash: string;
  if (entries[0].sequence === 1) {
    expectedPrevHash = computeGenesisHash(this.hmacKey);
  } else {
    // Need to fetch the entry before our range
    const priorEntry = await this.storage.getEntryBySequence(entries[0].sequence - 1);
    if (!priorEntry) {
      errors.push({
        type: 'sequence_gap',
        sequence: entries[0].sequence,
        expected: entries[0].sequence - 1,
        actual: 'missing',
        description: `Entry before sequence ${entries[0].sequence} not found`
      });
      expectedPrevHash = entries[0].previousHash; // Continue with claimed hash
    } else {
      expectedPrevHash = priorEntry.hash;
    }
  }

  let expectedSequence = entries[0].sequence;
  let lastTimestamp = new Date(0);

  for (const entry of entries) {
    // Check 1: Sequence continuity
    if (entry.sequence !== expectedSequence) {
      errors.push({
        type: 'sequence_gap',
        sequence: entry.sequence,
        expected: expectedSequence,
        actual: entry.sequence,
        description: `Expected sequence ${expectedSequence}, got ${entry.sequence}`
      });
    }

    // Check 2: Previous hash chain
    if (entry.previousHash !== expectedPrevHash) {
      errors.push({
        type: 'chain_break',
        sequence: entry.sequence,
        expected: expectedPrevHash,
        actual: entry.previousHash,
        description: `Chain break: previousHash does not match prior entry's hash`
      });
    }

    // Check 3: Entry hash integrity
    const computedHash = computeEntryHash(entry, this.hmacKey);
    if (computedHash !== entry.hash) {
      errors.push({
        type: 'tampered_entry',
        sequence: entry.sequence,
        expected: computedHash,
        actual: entry.hash,
        description: `Entry hash mismatch: entry may have been tampered with`
      });
    }

    // Check 4: Timestamp ordering
    const entryTime = new Date(entry.timestamp);
    if (entryTime < lastTimestamp) {
      errors.push({
        type: 'invalid_timestamp',
        sequence: entry.sequence,
        expected: lastTimestamp.toISOString(),
        actual: entry.timestamp,
        description: `Timestamp is earlier than previous entry`
      });
    }
    lastTimestamp = entryTime;

    // Update expectations for next iteration
    expectedPrevHash = entry.hash;
    expectedSequence = entry.sequence + 1;
  }

  const result: ChainVerificationResult = {
    valid: errors.length === 0,
    entriesVerified: entries.length,
    startSequence: entries[0].sequence,
    endSequence: entries[entries.length - 1].sequence,
    durationMs: Date.now() - startTime,
    errors
  };

  // Emit tampering event if errors found
  if (!result.valid) {
    this.emit('tamper_detected', result);
  }

  return result;
}
```

### Verification Options

```typescript
export interface VerificationOptions {
  /** Verify entire chain from genesis */
  fullChain?: boolean;

  /** Start sequence for range verification */
  startSequence?: number;

  /** End sequence for range verification */
  endSequence?: number;

  /** Number of recent entries to verify (default: 1000) */
  recentEntries?: number;

  /** Continue verification after finding errors */
  continueOnError?: boolean;
}
```

---

## 5. Event Types Enumeration

### Complete Event Type Enumeration

```typescript
/**
 * Audit event types - comprehensive enumeration of all loggable events
 */
export enum AuditEventType {
  // === Authentication Events ===
  /** Successful unlock attempt */
  AUTH_UNLOCK_SUCCESS = 'auth.unlock.success',
  /** Failed unlock attempt */
  AUTH_UNLOCK_FAILURE = 'auth.unlock.failure',
  /** Wallet locked */
  AUTH_LOCK = 'auth.lock',
  /** Account lockout triggered */
  AUTH_LOCKOUT = 'auth.lockout',
  /** Lockout expired */
  AUTH_LOCKOUT_EXPIRED = 'auth.lockout.expired',

  // === Session Events ===
  /** Session started */
  SESSION_START = 'session.start',
  /** Session ended */
  SESSION_END = 'session.end',
  /** Session expired */
  SESSION_EXPIRED = 'session.expired',

  // === Wallet Operations ===
  /** New wallet created */
  WALLET_CREATE = 'wallet.create',
  /** Wallet imported from seed */
  WALLET_IMPORT = 'wallet.import',
  /** Wallet list retrieved */
  WALLET_LIST = 'wallet.list',
  /** Wallet balance checked */
  WALLET_BALANCE = 'wallet.balance',
  /** Wallet deleted */
  WALLET_DELETE = 'wallet.delete',

  // === Key Operations ===
  /** Regular key set on account */
  KEY_REGULAR_SET = 'key.regular.set',
  /** Key rotation performed */
  KEY_ROTATE = 'key.rotate',
  /** Key export requested */
  KEY_EXPORT = 'key.export',
  /** Multi-sig configured */
  MULTISIG_SETUP = 'multisig.setup',
  /** Signer added to multi-sig */
  MULTISIG_SIGNER_ADD = 'multisig.signer.add',
  /** Signer removed from multi-sig */
  MULTISIG_SIGNER_REMOVE = 'multisig.signer.remove',

  // === Transaction Operations ===
  /** Transaction sign requested */
  TX_SIGN_REQUEST = 'tx.sign.request',
  /** Transaction signed successfully */
  TX_SIGN_SUCCESS = 'tx.sign.success',
  /** Transaction sign denied (policy) */
  TX_SIGN_DENIED = 'tx.sign.denied',
  /** Transaction sign failed (error) */
  TX_SIGN_FAILURE = 'tx.sign.failure',
  /** Transaction submitted to network */
  TX_SUBMIT = 'tx.submit',
  /** Transaction confirmed on ledger */
  TX_CONFIRMED = 'tx.confirmed',
  /** Transaction failed on ledger */
  TX_FAILED = 'tx.failed',
  /** Transaction queued for delay */
  TX_QUEUED = 'tx.queued',
  /** Queued transaction cancelled */
  TX_CANCELLED = 'tx.cancelled',

  // === Policy Operations ===
  /** Policy evaluated for operation */
  POLICY_EVALUATE = 'policy.evaluate',
  /** Policy violation detected */
  POLICY_VIOLATION = 'policy.violation',
  /** Policy reloaded from disk */
  POLICY_RELOAD = 'policy.reload',
  /** Policy updated */
  POLICY_UPDATE = 'policy.update',
  /** Daily limit warning (approaching) */
  LIMIT_WARNING = 'limit.warning',
  /** Daily limit exceeded */
  LIMIT_EXCEEDED = 'limit.exceeded',

  // === Security Events ===
  /** Rate limit triggered */
  SECURITY_RATE_LIMIT = 'security.rate_limit',
  /** Invalid input detected */
  SECURITY_INVALID_INPUT = 'security.invalid_input',
  /** Prompt injection detected */
  SECURITY_PROMPT_INJECTION = 'security.prompt_injection',
  /** Blocklist match */
  SECURITY_BLOCKLIST_MATCH = 'security.blocklist_match',
  /** Suspicious activity detected */
  SECURITY_SUSPICIOUS = 'security.suspicious',
  /** Chain tamper detected */
  SECURITY_TAMPER_DETECTED = 'security.tamper_detected',
  /** Invalid signature */
  SECURITY_INVALID_SIGNATURE = 'security.invalid_signature',

  // === System Events ===
  /** Server startup */
  SYSTEM_STARTUP = 'system.startup',
  /** Server shutdown */
  SYSTEM_SHUTDOWN = 'system.shutdown',
  /** Configuration changed */
  SYSTEM_CONFIG_CHANGE = 'system.config_change',
  /** System error occurred */
  SYSTEM_ERROR = 'system.error',
  /** Health check performed */
  SYSTEM_HEALTH_CHECK = 'system.health_check',
  /** Backup completed */
  SYSTEM_BACKUP = 'system.backup',
  /** Log rotation occurred */
  SYSTEM_LOG_ROTATE = 'system.log_rotate'
}
```

### Event Category Mapping

```typescript
/**
 * Map event types to categories for filtering
 */
export const EVENT_CATEGORY_MAP: Record<AuditEventType, EventCategory> = {
  // Authentication - security
  [AuditEventType.AUTH_UNLOCK_SUCCESS]: 'security',
  [AuditEventType.AUTH_UNLOCK_FAILURE]: 'security',
  [AuditEventType.AUTH_LOCK]: 'security',
  [AuditEventType.AUTH_LOCKOUT]: 'security',
  [AuditEventType.AUTH_LOCKOUT_EXPIRED]: 'security',
  [AuditEventType.SESSION_START]: 'security',
  [AuditEventType.SESSION_END]: 'security',
  [AuditEventType.SESSION_EXPIRED]: 'security',

  // Wallet - operation
  [AuditEventType.WALLET_CREATE]: 'operation',
  [AuditEventType.WALLET_IMPORT]: 'operation',
  [AuditEventType.WALLET_LIST]: 'operation',
  [AuditEventType.WALLET_BALANCE]: 'operation',
  [AuditEventType.WALLET_DELETE]: 'operation',

  // Key - security
  [AuditEventType.KEY_REGULAR_SET]: 'security',
  [AuditEventType.KEY_ROTATE]: 'security',
  [AuditEventType.KEY_EXPORT]: 'security',
  [AuditEventType.MULTISIG_SETUP]: 'security',
  [AuditEventType.MULTISIG_SIGNER_ADD]: 'security',
  [AuditEventType.MULTISIG_SIGNER_REMOVE]: 'security',

  // Transaction - transaction
  [AuditEventType.TX_SIGN_REQUEST]: 'transaction',
  [AuditEventType.TX_SIGN_SUCCESS]: 'transaction',
  [AuditEventType.TX_SIGN_DENIED]: 'transaction',
  [AuditEventType.TX_SIGN_FAILURE]: 'transaction',
  [AuditEventType.TX_SUBMIT]: 'transaction',
  [AuditEventType.TX_CONFIRMED]: 'transaction',
  [AuditEventType.TX_FAILED]: 'transaction',
  [AuditEventType.TX_QUEUED]: 'transaction',
  [AuditEventType.TX_CANCELLED]: 'transaction',

  // Policy - security
  [AuditEventType.POLICY_EVALUATE]: 'security',
  [AuditEventType.POLICY_VIOLATION]: 'security',
  [AuditEventType.POLICY_RELOAD]: 'security',
  [AuditEventType.POLICY_UPDATE]: 'security',
  [AuditEventType.LIMIT_WARNING]: 'security',
  [AuditEventType.LIMIT_EXCEEDED]: 'security',

  // Security - security
  [AuditEventType.SECURITY_RATE_LIMIT]: 'security',
  [AuditEventType.SECURITY_INVALID_INPUT]: 'security',
  [AuditEventType.SECURITY_PROMPT_INJECTION]: 'security',
  [AuditEventType.SECURITY_BLOCKLIST_MATCH]: 'security',
  [AuditEventType.SECURITY_SUSPICIOUS]: 'security',
  [AuditEventType.SECURITY_TAMPER_DETECTED]: 'security',
  [AuditEventType.SECURITY_INVALID_SIGNATURE]: 'security',

  // System - system
  [AuditEventType.SYSTEM_STARTUP]: 'system',
  [AuditEventType.SYSTEM_SHUTDOWN]: 'system',
  [AuditEventType.SYSTEM_CONFIG_CHANGE]: 'system',
  [AuditEventType.SYSTEM_ERROR]: 'system',
  [AuditEventType.SYSTEM_HEALTH_CHECK]: 'system',
  [AuditEventType.SYSTEM_BACKUP]: 'system',
  [AuditEventType.SYSTEM_LOG_ROTATE]: 'system'
};
```

### Severity Mapping

```typescript
/**
 * Default severity for each event type
 */
export const EVENT_SEVERITY_MAP: Record<AuditEventType, AuditSeverity> = {
  // Authentication
  [AuditEventType.AUTH_UNLOCK_SUCCESS]: 'INFO',
  [AuditEventType.AUTH_UNLOCK_FAILURE]: 'WARN',
  [AuditEventType.AUTH_LOCK]: 'INFO',
  [AuditEventType.AUTH_LOCKOUT]: 'ERROR',
  [AuditEventType.AUTH_LOCKOUT_EXPIRED]: 'INFO',
  [AuditEventType.SESSION_START]: 'INFO',
  [AuditEventType.SESSION_END]: 'INFO',
  [AuditEventType.SESSION_EXPIRED]: 'INFO',

  // Wallet
  [AuditEventType.WALLET_CREATE]: 'INFO',
  [AuditEventType.WALLET_IMPORT]: 'INFO',
  [AuditEventType.WALLET_LIST]: 'INFO',
  [AuditEventType.WALLET_BALANCE]: 'INFO',
  [AuditEventType.WALLET_DELETE]: 'WARN',

  // Key
  [AuditEventType.KEY_REGULAR_SET]: 'WARN',
  [AuditEventType.KEY_ROTATE]: 'WARN',
  [AuditEventType.KEY_EXPORT]: 'WARN',
  [AuditEventType.MULTISIG_SETUP]: 'WARN',
  [AuditEventType.MULTISIG_SIGNER_ADD]: 'WARN',
  [AuditEventType.MULTISIG_SIGNER_REMOVE]: 'WARN',

  // Transaction
  [AuditEventType.TX_SIGN_REQUEST]: 'INFO',
  [AuditEventType.TX_SIGN_SUCCESS]: 'INFO',
  [AuditEventType.TX_SIGN_DENIED]: 'WARN',
  [AuditEventType.TX_SIGN_FAILURE]: 'ERROR',
  [AuditEventType.TX_SUBMIT]: 'INFO',
  [AuditEventType.TX_CONFIRMED]: 'INFO',
  [AuditEventType.TX_FAILED]: 'ERROR',
  [AuditEventType.TX_QUEUED]: 'INFO',
  [AuditEventType.TX_CANCELLED]: 'INFO',

  // Policy
  [AuditEventType.POLICY_EVALUATE]: 'INFO',
  [AuditEventType.POLICY_VIOLATION]: 'WARN',
  [AuditEventType.POLICY_RELOAD]: 'INFO',
  [AuditEventType.POLICY_UPDATE]: 'WARN',
  [AuditEventType.LIMIT_WARNING]: 'WARN',
  [AuditEventType.LIMIT_EXCEEDED]: 'ERROR',

  // Security
  [AuditEventType.SECURITY_RATE_LIMIT]: 'WARN',
  [AuditEventType.SECURITY_INVALID_INPUT]: 'WARN',
  [AuditEventType.SECURITY_PROMPT_INJECTION]: 'CRITICAL',
  [AuditEventType.SECURITY_BLOCKLIST_MATCH]: 'WARN',
  [AuditEventType.SECURITY_SUSPICIOUS]: 'WARN',
  [AuditEventType.SECURITY_TAMPER_DETECTED]: 'CRITICAL',
  [AuditEventType.SECURITY_INVALID_SIGNATURE]: 'ERROR',

  // System
  [AuditEventType.SYSTEM_STARTUP]: 'INFO',
  [AuditEventType.SYSTEM_SHUTDOWN]: 'INFO',
  [AuditEventType.SYSTEM_CONFIG_CHANGE]: 'WARN',
  [AuditEventType.SYSTEM_ERROR]: 'ERROR',
  [AuditEventType.SYSTEM_HEALTH_CHECK]: 'INFO',
  [AuditEventType.SYSTEM_BACKUP]: 'INFO',
  [AuditEventType.SYSTEM_LOG_ROTATE]: 'INFO'
};
```

---

## 6. Storage Backend Interface

### Interface Definition

```typescript
/**
 * Storage backend interface for audit logs
 *
 * Implementations must ensure:
 * 1. Append-only semantics (no modification/deletion)
 * 2. Crash consistency (fsync on write)
 * 3. Atomic operations (no partial writes)
 */
export interface IStorageBackend {
  /**
   * Initialize storage (create directories, open connections)
   */
  initialize(): Promise<void>;

  /**
   * Append entry to storage
   * @param entry - Complete log entry with hash
   * @throws StorageError if write fails
   */
  append(entry: AuditLogEntry): Promise<void>;

  /**
   * Get last entry in storage (for chain continuation)
   * @returns Last entry or null if empty
   */
  getLastEntry(): Promise<AuditLogEntry | null>;

  /**
   * Get entry by sequence number
   * @param sequence - Sequence number to retrieve
   * @returns Entry or null if not found
   */
  getEntryBySequence(sequence: number): Promise<AuditLogEntry | null>;

  /**
   * Get entries by sequence range (inclusive)
   * @param startSequence - Start of range
   * @param endSequence - End of range
   * @returns Array of entries
   */
  getEntriesBySequenceRange(
    startSequence: number,
    endSequence: number
  ): Promise<AuditLogEntry[]>;

  /**
   * Get recent entries
   * @param count - Number of entries to retrieve
   * @returns Array of entries (most recent first)
   */
  getRecentEntries(count: number): Promise<AuditLogEntry[]>;

  /**
   * Get all entries (use with caution for large logs)
   * @returns All entries in sequence order
   */
  getAllEntries(): Promise<AuditLogEntry[]>;

  /**
   * Query entries by criteria
   * @param query - Query parameters
   * @returns Matching entries
   */
  query(query: AuditLogQuery): Promise<AuditLogEntry[]>;

  /**
   * Rotate current log file (for file backend)
   * @returns Path to rotated file
   */
  rotate(): Promise<string>;

  /**
   * Get storage statistics
   * @returns Storage statistics
   */
  getStats(): Promise<StorageStats>;

  /**
   * Close storage (cleanup resources)
   */
  close(): Promise<void>;
}

export interface StorageStats {
  /** Total entries stored */
  totalEntries: number;
  /** Current file size (bytes) */
  currentFileSize: number;
  /** Total size of all files (bytes) */
  totalSize: number;
  /** Number of rotated files */
  rotatedFiles: number;
  /** Oldest entry timestamp */
  oldestEntry?: string;
  /** Newest entry timestamp */
  newestEntry?: string;
}
```

### File Storage Implementation

```typescript
/**
 * File-based storage backend using JSON Lines format
 *
 * File format: One JSON object per line (JSONL)
 * File naming: audit-YYYY-MM-DD.jsonl
 *
 * Features:
 * - Append-only with fsync
 * - Automatic rotation by size/date
 * - Compression of rotated files
 * - Sequence-based indexing for fast lookups
 */
export class FileStorageBackend implements IStorageBackend {
  private currentFile: FileHandle | null = null;
  private currentPath: string = '';
  private currentSize: number = 0;
  private sequenceIndex: Map<number, { file: string; offset: number }> = new Map();
  private writeLock = new Mutex();

  constructor(private readonly config: FileStorageConfig) {}

  async initialize(): Promise<void> {
    // Create directory if needed
    await fs.mkdir(this.config.directory, { recursive: true, mode: 0o700 });

    // Open current file
    const today = new Date().toISOString().split('T')[0];
    this.currentPath = path.join(this.config.directory, `audit-${today}.jsonl`);

    // Check if file exists and get size
    try {
      const stats = await fs.stat(this.currentPath);
      this.currentSize = stats.size;
    } catch {
      this.currentSize = 0;
    }

    // Open in append mode
    this.currentFile = await fs.open(this.currentPath, 'a', 0o600);

    // Build sequence index from existing files
    await this.buildSequenceIndex();
  }

  async append(entry: AuditLogEntry): Promise<void> {
    await this.writeLock.acquire();

    try {
      // Check if rotation needed
      const line = JSON.stringify(entry) + '\n';
      const lineBytes = Buffer.byteLength(line);

      if (this.currentSize + lineBytes > this.config.maxFileSize) {
        await this.rotateInternal();
      }

      // Check if date changed
      const today = new Date().toISOString().split('T')[0];
      const expectedPath = path.join(this.config.directory, `audit-${today}.jsonl`);
      if (this.currentPath !== expectedPath) {
        await this.rotateInternal();
      }

      // Get current position for index
      const offset = this.currentSize;

      // Write entry
      await this.currentFile!.write(line);

      // Sync to disk if configured
      if (this.config.syncWrites) {
        await this.currentFile!.sync();
      }

      // Update state
      this.currentSize += lineBytes;
      this.sequenceIndex.set(entry.sequence, { file: this.currentPath, offset });

    } finally {
      this.writeLock.release();
    }
  }

  async getLastEntry(): Promise<AuditLogEntry | null> {
    // Find highest sequence in index
    if (this.sequenceIndex.size === 0) {
      return null;
    }

    const maxSequence = Math.max(...this.sequenceIndex.keys());
    return this.getEntryBySequence(maxSequence);
  }

  async getEntryBySequence(sequence: number): Promise<AuditLogEntry | null> {
    const location = this.sequenceIndex.get(sequence);
    if (!location) {
      return null;
    }

    // Read from file at offset
    const fileHandle = await fs.open(location.file, 'r');
    try {
      // Read line at offset
      const buffer = Buffer.alloc(1024 * 1024); // 1MB max line
      const { bytesRead } = await fileHandle.read(buffer, 0, buffer.length, location.offset);

      // Find end of line
      const lineEnd = buffer.indexOf('\n');
      const line = buffer.slice(0, lineEnd).toString();

      return JSON.parse(line);
    } finally {
      await fileHandle.close();
    }
  }

  async query(query: AuditLogQuery): Promise<AuditLogEntry[]> {
    const results: AuditLogEntry[] = [];
    const files = await this.getFilesInDateRange(query.startDate, query.endDate);

    for (const file of files) {
      const entries = await this.readEntriesFromFile(file);

      for (const entry of entries) {
        if (this.matchesQuery(entry, query)) {
          results.push(entry);

          if (results.length >= (query.limit ?? this.config.maxQueryResults)) {
            return results;
          }
        }
      }
    }

    return results;
  }

  private async rotateInternal(): Promise<string> {
    // Close current file
    if (this.currentFile) {
      await this.currentFile.close();
    }

    const rotatedPath = this.currentPath;

    // Compress if configured
    if (this.config.compressionEnabled) {
      await this.compressFile(rotatedPath);
    }

    // Open new file
    const today = new Date().toISOString().split('T')[0];
    const timestamp = Date.now();
    this.currentPath = path.join(
      this.config.directory,
      `audit-${today}-${timestamp}.jsonl`
    );

    this.currentFile = await fs.open(this.currentPath, 'a', 0o600);
    this.currentSize = 0;

    // Cleanup old files
    await this.cleanupOldFiles();

    return rotatedPath;
  }

  private async cleanupOldFiles(): Promise<void> {
    const files = await fs.readdir(this.config.directory);
    const auditFiles = files
      .filter((f) => f.startsWith('audit-'))
      .sort()
      .reverse();

    // Keep only configured number of files
    const toDelete = auditFiles.slice(this.config.maxFiles);

    for (const file of toDelete) {
      const filePath = path.join(this.config.directory, file);
      await fs.unlink(filePath);
    }
  }
}

export interface FileStorageConfig {
  /** Directory for log files */
  directory: string;

  /** Maximum file size before rotation (bytes) */
  maxFileSize: number;

  /** Maximum number of files to retain */
  maxFiles: number;

  /** Enable compression of rotated files */
  compressionEnabled: boolean;

  /** Sync each write to disk */
  syncWrites: boolean;

  /** Maximum query results */
  maxQueryResults: number;
}

export const DEFAULT_FILE_STORAGE_CONFIG: FileStorageConfig = {
  directory: '~/.xrpl-wallet-mcp/mainnet/audit',
  maxFileSize: 100 * 1024 * 1024, // 100MB
  maxFiles: 365, // ~1 year at 1 file/day
  compressionEnabled: true,
  syncWrites: true,
  maxQueryResults: 10000
};
```

### Database Storage Implementation (SQLite)

```typescript
/**
 * SQLite-based storage backend
 *
 * Suitable for:
 * - Environments where file system access is limited
 * - Need for complex queries
 * - Atomic transactions
 *
 * Schema:
 * - audit_entries table with indexes on sequence, timestamp, eventType
 */
export class SQLiteStorageBackend implements IStorageBackend {
  private db: Database | null = null;

  constructor(private readonly config: SQLiteStorageConfig) {}

  async initialize(): Promise<void> {
    // Open database
    this.db = new Database(this.config.databasePath);

    // Create table if needed
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_entries (
        sequence INTEGER PRIMARY KEY,
        id TEXT UNIQUE NOT NULL,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        correlation_id TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        hash TEXT NOT NULL,
        entry_json TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_entries(timestamp);
      CREATE INDEX IF NOT EXISTS idx_event_type ON audit_entries(event_type);
      CREATE INDEX IF NOT EXISTS idx_correlation_id ON audit_entries(correlation_id);
      CREATE INDEX IF NOT EXISTS idx_severity ON audit_entries(severity);
    `);

    // Enable WAL mode for better concurrency
    this.db.exec('PRAGMA journal_mode=WAL');
    this.db.exec('PRAGMA synchronous=FULL');
  }

  async append(entry: AuditLogEntry): Promise<void> {
    const stmt = this.db!.prepare(`
      INSERT INTO audit_entries
        (sequence, id, timestamp, event_type, severity, category,
         correlation_id, previous_hash, hash, entry_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      entry.sequence,
      entry.id,
      entry.timestamp,
      entry.eventType,
      entry.severity,
      entry.category,
      entry.correlationId,
      entry.previousHash,
      entry.hash,
      JSON.stringify(entry)
    );
  }

  async getLastEntry(): Promise<AuditLogEntry | null> {
    const row = this.db!.prepare(
      'SELECT entry_json FROM audit_entries ORDER BY sequence DESC LIMIT 1'
    ).get() as { entry_json: string } | undefined;

    return row ? JSON.parse(row.entry_json) : null;
  }

  async query(query: AuditLogQuery): Promise<AuditLogEntry[]> {
    let sql = 'SELECT entry_json FROM audit_entries WHERE 1=1';
    const params: unknown[] = [];

    if (query.startDate) {
      sql += ' AND timestamp >= ?';
      params.push(query.startDate.toISOString());
    }

    if (query.endDate) {
      sql += ' AND timestamp <= ?';
      params.push(query.endDate.toISOString());
    }

    if (query.eventTypes?.length) {
      sql += ` AND event_type IN (${query.eventTypes.map(() => '?').join(',')})`;
      params.push(...query.eventTypes);
    }

    if (query.severity) {
      sql += ' AND severity = ?';
      params.push(query.severity);
    }

    if (query.correlationId) {
      sql += ' AND correlation_id = ?';
      params.push(query.correlationId);
    }

    sql += ' ORDER BY sequence ASC';
    sql += ` LIMIT ${query.limit ?? 10000}`;

    const rows = this.db!.prepare(sql).all(...params) as { entry_json: string }[];
    return rows.map((row) => JSON.parse(row.entry_json));
  }
}
```

---

## 7. Log Rotation Configuration

### Rotation Strategy

```typescript
/**
 * Log rotation configuration
 */
export interface LogRotationConfig {
  /** Maximum file size before rotation (bytes) */
  maxFileSize: number;

  /** Rotate at midnight UTC regardless of size */
  rotateDaily: boolean;

  /** Maximum number of files to retain */
  maxFiles: number;

  /** Compress rotated files with gzip */
  compressionEnabled: boolean;

  /** Minimum free space before triggering cleanup (bytes) */
  minFreeSpace: number;

  /** Archive old files to external storage */
  archiveEnabled: boolean;

  /** Archive destination (S3 bucket, GCS bucket, etc.) */
  archiveDestination?: string;
}

export const DEFAULT_ROTATION_CONFIG: LogRotationConfig = {
  maxFileSize: 100 * 1024 * 1024, // 100MB
  rotateDaily: true,
  maxFiles: 365, // ~1 year
  compressionEnabled: true,
  minFreeSpace: 1024 * 1024 * 1024, // 1GB
  archiveEnabled: false
};
```

### Rotation Implementation

```typescript
/**
 * Log rotation manager
 */
export class LogRotationManager {
  constructor(
    private readonly storage: FileStorageBackend,
    private readonly config: LogRotationConfig
  ) {}

  /**
   * Check if rotation is needed
   */
  async shouldRotate(): Promise<boolean> {
    const stats = await this.storage.getStats();

    // Size-based rotation
    if (stats.currentFileSize >= this.config.maxFileSize) {
      return true;
    }

    // Time-based rotation (daily at midnight UTC)
    if (this.config.rotateDaily) {
      const lastRotation = await this.getLastRotationTime();
      const now = new Date();
      const today = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));

      if (lastRotation < today) {
        return true;
      }
    }

    return false;
  }

  /**
   * Perform rotation with chain continuation
   */
  async rotate(): Promise<RotationResult> {
    const rotatedFile = await this.storage.rotate();

    // Compress if enabled
    if (this.config.compressionEnabled) {
      await this.compress(rotatedFile);
    }

    // Archive if enabled
    if (this.config.archiveEnabled && this.config.archiveDestination) {
      await this.archive(rotatedFile);
    }

    // Cleanup old files
    await this.cleanup();

    return {
      rotatedFile,
      compressed: this.config.compressionEnabled,
      archived: this.config.archiveEnabled
    };
  }

  /**
   * Cleanup old files based on retention policy
   */
  async cleanup(): Promise<CleanupResult> {
    const files = await this.getRotatedFiles();
    const toDelete: string[] = [];

    // Keep only maxFiles
    if (files.length > this.config.maxFiles) {
      toDelete.push(...files.slice(0, files.length - this.config.maxFiles));
    }

    // Check free space
    const freeSpace = await this.getFreeSpace();
    if (freeSpace < this.config.minFreeSpace) {
      // Delete oldest files until we have enough space
      for (const file of files) {
        if (!toDelete.includes(file)) {
          toDelete.push(file);
          const newFreeSpace = await this.getFreeSpace();
          if (newFreeSpace >= this.config.minFreeSpace) {
            break;
          }
        }
      }
    }

    // Delete files
    let deletedBytes = 0;
    for (const file of toDelete) {
      const stats = await fs.stat(file);
      await fs.unlink(file);
      deletedBytes += stats.size;
    }

    return {
      filesDeleted: toDelete.length,
      bytesReclaimed: deletedBytes
    };
  }

  private async compress(filePath: string): Promise<void> {
    const gzipPath = filePath + '.gz';

    await pipeline(
      createReadStream(filePath),
      createGzip({ level: 9 }),
      createWriteStream(gzipPath)
    );

    // Remove original after successful compression
    await fs.unlink(filePath);
  }
}
```

### File Naming Convention

```
~/.xrpl-wallet-mcp/mainnet/audit/
  audit-2026-01-28.jsonl              # Current day's file
  audit-2026-01-27.jsonl.gz           # Compressed previous day
  audit-2026-01-26.jsonl.gz
  ...
  audit-2025-01-28.jsonl.gz           # Oldest retained file (1 year ago)
```

---

## 8. Compliance Queries

### Query Interface

```typescript
/**
 * Query parameters for audit log searches
 */
export interface AuditLogQuery {
  /** Start date (inclusive) */
  startDate?: Date;

  /** End date (inclusive) */
  endDate?: Date;

  /** Filter by event types */
  eventTypes?: AuditEventType[];

  /** Filter by severity */
  severity?: AuditSeverity;

  /** Filter by category */
  category?: EventCategory;

  /** Filter by correlation ID */
  correlationId?: string;

  /** Filter by session ID */
  sessionId?: string;

  /** Filter by actor type */
  actorType?: ActorType;

  /** Filter by actor ID */
  actorId?: string;

  /** Filter by operation name */
  operationName?: string;

  /** Filter by operation result */
  operationResult?: OperationResult;

  /** Filter by wallet address */
  walletAddress?: string;

  /** Filter by transaction hash */
  transactionHash?: string;

  /** Filter by network */
  network?: XRPLNetwork;

  /** Text search in parameters */
  textSearch?: string;

  /** Maximum results to return */
  limit?: number;

  /** Offset for pagination */
  offset?: number;

  /** Sort order */
  sortOrder?: 'asc' | 'desc';
}
```

### Common Query Methods

```typescript
/**
 * Pre-built compliance queries
 */
export class ComplianceQueries {
  constructor(private readonly logger: IAuditLogger) {}

  /**
   * Get all authentication failures in date range
   */
  async getAuthFailures(startDate: Date, endDate: Date): Promise<AuditLogEntry[]> {
    return this.logger.query({
      startDate,
      endDate,
      eventTypes: [
        AuditEventType.AUTH_UNLOCK_FAILURE,
        AuditEventType.AUTH_LOCKOUT
      ]
    });
  }

  /**
   * Get all transactions for a wallet
   */
  async getWalletTransactions(
    walletAddress: string,
    startDate?: Date,
    endDate?: Date
  ): Promise<AuditLogEntry[]> {
    return this.logger.query({
      startDate,
      endDate,
      walletAddress,
      eventTypes: [
        AuditEventType.TX_SIGN_SUCCESS,
        AuditEventType.TX_SUBMIT,
        AuditEventType.TX_CONFIRMED,
        AuditEventType.TX_FAILED
      ]
    });
  }

  /**
   * Get all policy violations
   */
  async getPolicyViolations(startDate: Date, endDate: Date): Promise<AuditLogEntry[]> {
    return this.logger.query({
      startDate,
      endDate,
      eventTypes: [
        AuditEventType.POLICY_VIOLATION,
        AuditEventType.SECURITY_BLOCKLIST_MATCH,
        AuditEventType.LIMIT_EXCEEDED
      ]
    });
  }

  /**
   * Get all security events
   */
  async getSecurityEvents(startDate: Date, endDate: Date): Promise<AuditLogEntry[]> {
    return this.logger.query({
      startDate,
      endDate,
      category: 'security',
      severity: 'WARN' // WARN or higher
    });
  }

  /**
   * Get daily activity summary
   */
  async getDailyActivitySummary(date: Date): Promise<ActivitySummary> {
    const startOfDay = new Date(Date.UTC(
      date.getUTCFullYear(),
      date.getUTCMonth(),
      date.getUTCDate()
    ));
    const endOfDay = new Date(startOfDay.getTime() + 86400000 - 1);

    const entries = await this.logger.query({ startDate: startOfDay, endDate: endOfDay });

    return {
      date: startOfDay.toISOString().split('T')[0],
      totalEvents: entries.length,
      byEventType: this.groupBy(entries, 'eventType'),
      bySeverity: this.groupBy(entries, 'severity'),
      byCategory: this.groupBy(entries, 'category'),
      uniqueWallets: new Set(
        entries.filter(e => e.context.walletAddress).map(e => e.context.walletAddress)
      ).size,
      totalTransactions: entries.filter(
        e => e.eventType === AuditEventType.TX_SIGN_SUCCESS
      ).length,
      securityIncidents: entries.filter(
        e => e.severity === 'CRITICAL' || e.severity === 'ERROR'
      ).length
    };
  }

  /**
   * Trace all events for a correlation ID
   */
  async traceByCorrelationId(correlationId: string): Promise<AuditLogEntry[]> {
    return this.logger.query({
      correlationId,
      sortOrder: 'asc'
    });
  }

  private groupBy<T extends AuditLogEntry>(
    entries: T[],
    key: keyof T
  ): Record<string, number> {
    return entries.reduce((acc, entry) => {
      const value = String(entry[key]);
      acc[value] = (acc[value] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
  }
}
```

### Compliance Export

```typescript
/**
 * Compliance export format
 */
export interface ComplianceExport {
  /** Export metadata */
  metadata: {
    /** Export generation timestamp */
    exportDate: string;
    /** Export format version */
    version: string;
    /** Exporter identity */
    exportedBy: string;
    /** Start of date range */
    startDate: string;
    /** End of date range */
    endDate: string;
    /** First sequence included */
    startSequence: number;
    /** Last sequence included */
    endSequence: number;
    /** Total entries in export */
    entryCount: number;
    /** SHA-256 hash of entries array */
    entriesHash: string;
  };

  /** Chain verification result */
  chainVerification: ChainVerificationResult;

  /** Audit log entries */
  entries: AuditLogEntry[];

  /** Digital signature of entire export */
  signature: string;
}

/**
 * Export options
 */
export interface ExportOptions {
  /** Start date for export */
  startDate: Date;

  /** End date for export */
  endDate: Date;

  /** Export format */
  format: 'json' | 'csv' | 'jsonl';

  /** Include chain verification */
  includeVerification: boolean;

  /** Sign the export */
  signExport: boolean;

  /** Signing key provider */
  signingKeyProvider?: ISigningKeyProvider;
}

/**
 * Export implementation
 */
async export(options: ExportOptions): Promise<ComplianceExport> {
  // 1. Query entries
  const entries = await this.query({
    startDate: options.startDate,
    endDate: options.endDate,
    sortOrder: 'asc'
  });

  if (entries.length === 0) {
    throw new AuditLogError('No entries found in date range', 'NO_ENTRIES');
  }

  // 2. Verify chain
  let verification: ChainVerificationResult;
  if (options.includeVerification) {
    verification = await this.verifyChain({
      startSequence: entries[0].sequence,
      endSequence: entries[entries.length - 1].sequence
    });
  } else {
    verification = {
      valid: true,
      entriesVerified: 0,
      startSequence: entries[0].sequence,
      endSequence: entries[entries.length - 1].sequence,
      durationMs: 0,
      errors: []
    };
  }

  // 3. Compute entries hash
  const entriesJson = JSON.stringify(entries);
  const entriesHash = createHash('sha256').update(entriesJson).digest('hex');

  // 4. Build export
  const complianceExport: ComplianceExport = {
    metadata: {
      exportDate: new Date().toISOString(),
      version: '1.0',
      exportedBy: 'AuditLogger',
      startDate: options.startDate.toISOString(),
      endDate: options.endDate.toISOString(),
      startSequence: entries[0].sequence,
      endSequence: entries[entries.length - 1].sequence,
      entryCount: entries.length,
      entriesHash
    },
    chainVerification: verification,
    entries,
    signature: ''
  };

  // 5. Sign if requested
  if (options.signExport && options.signingKeyProvider) {
    const exportWithoutSig = { ...complianceExport, signature: '' };
    const dataToSign = JSON.stringify(exportWithoutSig);
    complianceExport.signature = await options.signingKeyProvider.sign(dataToSign);
  }

  return complianceExport;
}
```

---

## 9. Tamper Detection and Alerting

### Detection Events

```typescript
/**
 * Tamper detection events
 */
export enum TamperEventType {
  /** Entry hash does not match computed hash */
  HASH_MISMATCH = 'hash_mismatch',

  /** Previous hash does not link to prior entry */
  CHAIN_BREAK = 'chain_break',

  /** Sequence numbers not contiguous */
  SEQUENCE_GAP = 'sequence_gap',

  /** Timestamps not monotonically increasing */
  TIMESTAMP_ANOMALY = 'timestamp_anomaly',

  /** Entry missing from expected position */
  ENTRY_MISSING = 'entry_missing',

  /** Duplicate sequence number detected */
  DUPLICATE_SEQUENCE = 'duplicate_sequence'
}

export interface TamperEvent {
  /** Event type */
  type: TamperEventType;

  /** When detected */
  detectedAt: string;

  /** Sequence number affected */
  affectedSequence: number;

  /** Expected value */
  expected: string;

  /** Actual value found */
  actual: string;

  /** Human-readable description */
  description: string;

  /** Severity assessment */
  severity: 'low' | 'medium' | 'high' | 'critical';
}
```

### Alerting Interface

```typescript
/**
 * Alerting interface for tamper events
 */
export interface IAlerter {
  /**
   * Send alert for tamper detection
   * @param event - Tamper event details
   */
  alert(event: TamperEvent): Promise<void>;

  /**
   * Send batch of alerts
   * @param events - Multiple tamper events
   */
  alertBatch(events: TamperEvent[]): Promise<void>;
}

/**
 * Webhook alerter implementation
 */
export class WebhookAlerter implements IAlerter {
  constructor(private readonly config: WebhookAlerterConfig) {}

  async alert(event: TamperEvent): Promise<void> {
    const payload = {
      type: 'AUDIT_TAMPER_DETECTED',
      timestamp: new Date().toISOString(),
      event,
      source: 'xrpl-wallet-mcp',
      severity: event.severity
    };

    const response = await fetch(this.config.webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Webhook-Secret': this.config.webhookSecret
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      // Log failure but don't throw - alerting should not disrupt operation
      console.error(`Alert webhook failed: ${response.status}`);
    }
  }

  async alertBatch(events: TamperEvent[]): Promise<void> {
    // Send individual alerts to avoid payload size issues
    for (const event of events) {
      await this.alert(event);
    }
  }
}

/**
 * Console alerter for development
 */
export class ConsoleAlerter implements IAlerter {
  async alert(event: TamperEvent): Promise<void> {
    console.error(`[TAMPER DETECTED] ${event.type} at sequence ${event.affectedSequence}`);
    console.error(`  Expected: ${event.expected}`);
    console.error(`  Actual: ${event.actual}`);
    console.error(`  Description: ${event.description}`);
  }

  async alertBatch(events: TamperEvent[]): Promise<void> {
    console.error(`[TAMPER DETECTED] ${events.length} anomalies found:`);
    for (const event of events) {
      await this.alert(event);
    }
  }
}
```

### Periodic Verification

```typescript
/**
 * Periodic verification scheduler
 */
export class VerificationScheduler {
  private intervalHandle: NodeJS.Timeout | null = null;

  constructor(
    private readonly logger: IAuditLogger,
    private readonly alerter: IAlerter,
    private readonly config: VerificationSchedulerConfig
  ) {}

  /**
   * Start periodic verification
   */
  start(): void {
    if (this.intervalHandle) {
      return; // Already running
    }

    this.intervalHandle = setInterval(
      () => this.runVerification(),
      this.config.intervalMs
    );

    // Run immediately on start
    this.runVerification();
  }

  /**
   * Stop periodic verification
   */
  stop(): void {
    if (this.intervalHandle) {
      clearInterval(this.intervalHandle);
      this.intervalHandle = null;
    }
  }

  private async runVerification(): Promise<void> {
    try {
      const result = await this.logger.verifyChain({
        recentEntries: this.config.sampleSize
      });

      if (!result.valid) {
        // Convert verification errors to tamper events
        const tamperEvents: TamperEvent[] = result.errors.map((error) => ({
          type: this.mapErrorType(error.type),
          detectedAt: new Date().toISOString(),
          affectedSequence: error.sequence,
          expected: String(error.expected),
          actual: String(error.actual),
          description: error.description,
          severity: this.assessSeverity(error.type)
        }));

        await this.alerter.alertBatch(tamperEvents);
      }

    } catch (error) {
      console.error('Verification failed:', error);
      // Alert on verification failure itself
      await this.alerter.alert({
        type: TamperEventType.CHAIN_BREAK,
        detectedAt: new Date().toISOString(),
        affectedSequence: 0,
        expected: 'successful verification',
        actual: String(error),
        description: 'Verification process failed',
        severity: 'high'
      });
    }
  }

  private mapErrorType(type: string): TamperEventType {
    switch (type) {
      case 'tampered_entry': return TamperEventType.HASH_MISMATCH;
      case 'chain_break': return TamperEventType.CHAIN_BREAK;
      case 'sequence_gap': return TamperEventType.SEQUENCE_GAP;
      case 'invalid_timestamp': return TamperEventType.TIMESTAMP_ANOMALY;
      default: return TamperEventType.CHAIN_BREAK;
    }
  }

  private assessSeverity(type: string): 'low' | 'medium' | 'high' | 'critical' {
    switch (type) {
      case 'tampered_entry': return 'critical';
      case 'chain_break': return 'critical';
      case 'sequence_gap': return 'high';
      case 'invalid_timestamp': return 'medium';
      default: return 'high';
    }
  }
}

export interface VerificationSchedulerConfig {
  /** Interval between verifications (ms) */
  intervalMs: number;

  /** Number of recent entries to verify */
  sampleSize: number;
}

export const DEFAULT_VERIFICATION_SCHEDULER_CONFIG: VerificationSchedulerConfig = {
  intervalMs: 3600000, // 1 hour
  sampleSize: 1000
};
```

---

## 10. Performance Considerations

### Benchmarks

| Operation | Target Latency | Throughput |
|-----------|---------------|------------|
| log() | < 5ms | > 1000/sec |
| verifyChain(1000 entries) | < 100ms | N/A |
| query(date range, 1 day) | < 100ms | N/A |
| rotate() | < 1s | N/A |
| export(1 month) | < 10s | N/A |

### Optimization Strategies

```typescript
/**
 * Performance optimizations
 */

// 1. Write buffering (trade durability for throughput)
export class BufferedAuditLogger extends AuditLogger {
  private buffer: AuditLogEntry[] = [];
  private flushTimeout: NodeJS.Timeout | null = null;

  override async log(event: AuditLogInput): Promise<AuditLogEntry> {
    const entry = await this.createEntry(event);
    this.buffer.push(entry);

    // Flush if buffer full
    if (this.buffer.length >= this.config.bufferSize) {
      await this.flush();
    }

    // Set flush timer if not set
    if (!this.flushTimeout) {
      this.flushTimeout = setTimeout(
        () => this.flush(),
        this.config.flushIntervalMs
      );
    }

    return entry;
  }

  private async flush(): Promise<void> {
    if (this.buffer.length === 0) return;

    const toFlush = [...this.buffer];
    this.buffer = [];

    if (this.flushTimeout) {
      clearTimeout(this.flushTimeout);
      this.flushTimeout = null;
    }

    await this.storage.appendBatch(toFlush);
  }
}

// 2. In-memory index for fast lookups
export class IndexedStorage implements IStorageBackend {
  private sequenceIndex = new Map<number, AuditLogEntry>();
  private timestampIndex = new Map<string, number[]>();
  private eventTypeIndex = new Map<AuditEventType, number[]>();

  async append(entry: AuditLogEntry): Promise<void> {
    // Persist to underlying storage
    await this.backend.append(entry);

    // Update indexes
    this.sequenceIndex.set(entry.sequence, entry);

    const dateKey = entry.timestamp.split('T')[0];
    if (!this.timestampIndex.has(dateKey)) {
      this.timestampIndex.set(dateKey, []);
    }
    this.timestampIndex.get(dateKey)!.push(entry.sequence);

    if (!this.eventTypeIndex.has(entry.eventType)) {
      this.eventTypeIndex.set(entry.eventType, []);
    }
    this.eventTypeIndex.get(entry.eventType)!.push(entry.sequence);
  }

  async getEntryBySequence(sequence: number): Promise<AuditLogEntry | null> {
    // Check memory first
    if (this.sequenceIndex.has(sequence)) {
      return this.sequenceIndex.get(sequence)!;
    }
    // Fall back to storage
    return this.backend.getEntryBySequence(sequence);
  }
}

// 3. Lazy hash computation for bulk operations
export class LazyVerifier {
  async verifyChainLazy(entries: AsyncIterable<AuditLogEntry>): Promise<ChainVerificationResult> {
    const errors: ChainError[] = [];
    let count = 0;
    let expectedPrevHash: string | null = null;
    let expectedSequence = 1;
    let startSequence = 0;
    let endSequence = 0;

    for await (const entry of entries) {
      if (count === 0) {
        startSequence = entry.sequence;
        expectedSequence = entry.sequence;
        expectedPrevHash = entry.sequence === 1
          ? this.computeGenesisHash()
          : null; // Will be validated against prior entry
      }

      if (expectedPrevHash && entry.previousHash !== expectedPrevHash) {
        errors.push({
          type: 'chain_break',
          sequence: entry.sequence,
          expected: expectedPrevHash,
          actual: entry.previousHash,
          description: 'Chain break detected'
        });
      }

      // Update for next iteration
      expectedPrevHash = entry.hash;
      expectedSequence = entry.sequence + 1;
      endSequence = entry.sequence;
      count++;
    }

    return {
      valid: errors.length === 0,
      entriesVerified: count,
      startSequence,
      endSequence,
      durationMs: 0,
      errors
    };
  }
}
```

### Memory Management

```typescript
/**
 * Memory-efficient streaming for large queries
 */
export async function* streamEntries(
  storage: IStorageBackend,
  query: AuditLogQuery
): AsyncGenerator<AuditLogEntry> {
  const batchSize = 1000;
  let offset = 0;

  while (true) {
    const batch = await storage.query({
      ...query,
      limit: batchSize,
      offset
    });

    if (batch.length === 0) {
      break;
    }

    for (const entry of batch) {
      yield entry;
    }

    offset += batch.length;

    if (batch.length < batchSize) {
      break; // Last batch
    }
  }
}

// Usage
async function processLargeExport(storage: IStorageBackend): Promise<void> {
  const stream = streamEntries(storage, {
    startDate: new Date('2026-01-01'),
    endDate: new Date('2026-01-31')
  });

  for await (const entry of stream) {
    // Process one entry at a time
    await processEntry(entry);
  }
}
```

---

## 11. Test Patterns

### Unit Test Patterns

```typescript
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

describe('AuditLogger', () => {
  let logger: AuditLogger;
  let mockStorage: IStorageBackend;
  let hmacKey: Buffer;

  beforeEach(async () => {
    hmacKey = Buffer.from('0'.repeat(64), 'hex'); // 256-bit test key
    mockStorage = {
      initialize: vi.fn(),
      append: vi.fn(),
      getLastEntry: vi.fn().mockResolvedValue(null),
      getEntryBySequence: vi.fn(),
      getEntriesBySequenceRange: vi.fn(),
      getRecentEntries: vi.fn().mockResolvedValue([]),
      getAllEntries: vi.fn().mockResolvedValue([]),
      query: vi.fn(),
      rotate: vi.fn(),
      getStats: vi.fn(),
      close: vi.fn()
    };

    logger = await AuditLogger.create({
      hmacKeyProvider: { getKey: async () => hmacKey },
      storageBackend: mockStorage,
      verifyOnStartup: false
    });
  });

  afterEach(async () => {
    await logger.shutdown();
  });

  describe('log()', () => {
    it('should create entry with correct sequence', async () => {
      const entry = await logger.log({
        eventType: AuditEventType.AUTH_UNLOCK_SUCCESS,
        severity: 'INFO',
        category: 'security',
        correlationId: '550e8400-e29b-41d4-a716-446655440000',
        actor: { type: 'agent', id: 'agent_001' },
        operation: { name: 'unlock', parameters: {}, result: 'success' },
        context: { network: 'testnet' }
      });

      expect(entry.sequence).toBe(1);
      expect(entry.id).toMatch(/^[0-9a-f-]{36}$/);
      expect(entry.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    });

    it('should compute correct genesis hash for first entry', async () => {
      const entry = await logger.log({
        eventType: AuditEventType.SYSTEM_STARTUP,
        severity: 'INFO',
        category: 'system',
        correlationId: '550e8400-e29b-41d4-a716-446655440000',
        actor: { type: 'system' },
        operation: { name: 'startup', parameters: {}, result: 'success' },
        context: { network: 'testnet' }
      });

      const expectedGenesis = createHmac('sha256', hmacKey)
        .update('XRPL-WALLET-MCP-GENESIS-V1')
        .digest('hex');

      expect(entry.previousHash).toBe(expectedGenesis);
    });

    it('should link entries via hash chain', async () => {
      const entry1 = await logger.log({
        eventType: AuditEventType.AUTH_UNLOCK_SUCCESS,
        severity: 'INFO',
        category: 'security',
        correlationId: '550e8400-e29b-41d4-a716-446655440001',
        actor: { type: 'agent' },
        operation: { name: 'unlock', parameters: {}, result: 'success' },
        context: { network: 'testnet' }
      });

      const entry2 = await logger.log({
        eventType: AuditEventType.WALLET_LIST,
        severity: 'INFO',
        category: 'operation',
        correlationId: '550e8400-e29b-41d4-a716-446655440002',
        actor: { type: 'agent' },
        operation: { name: 'list', parameters: {}, result: 'success' },
        context: { network: 'testnet' }
      });

      expect(entry2.previousHash).toBe(entry1.hash);
      expect(entry2.sequence).toBe(2);
    });

    it('should persist entry to storage', async () => {
      const entry = await logger.log({
        eventType: AuditEventType.TX_SIGN_SUCCESS,
        severity: 'INFO',
        category: 'transaction',
        correlationId: '550e8400-e29b-41d4-a716-446655440003',
        actor: { type: 'agent' },
        operation: { name: 'sign', parameters: {}, result: 'success' },
        context: { network: 'testnet' }
      });

      expect(mockStorage.append).toHaveBeenCalledWith(entry);
    });
  });

  describe('verifyChain()', () => {
    it('should detect tampered entry', async () => {
      const entries: AuditLogEntry[] = [
        createValidEntry(1),
        createValidEntry(2),
        { ...createValidEntry(3), hash: 'tampered_hash' }
      ];

      mockStorage.getRecentEntries = vi.fn().mockResolvedValue(entries);

      const result = await logger.verifyChain({ recentEntries: 10 });

      expect(result.valid).toBe(false);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].type).toBe('tampered_entry');
    });

    it('should detect sequence gap', async () => {
      const entries: AuditLogEntry[] = [
        createValidEntry(1),
        createValidEntry(2),
        createValidEntry(5) // Gap: 3, 4 missing
      ];

      mockStorage.getRecentEntries = vi.fn().mockResolvedValue(entries);

      const result = await logger.verifyChain({ recentEntries: 10 });

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.type === 'sequence_gap')).toBe(true);
    });

    it('should detect chain break', async () => {
      const entry1 = createValidEntry(1);
      const entry2 = { ...createValidEntry(2), previousHash: 'wrong_hash' };

      mockStorage.getRecentEntries = vi.fn().mockResolvedValue([entry1, entry2]);

      const result = await logger.verifyChain({ recentEntries: 10 });

      expect(result.valid).toBe(false);
      expect(result.errors[0].type).toBe('chain_break');
    });

    it('should pass valid chain', async () => {
      const entries = createValidChain(10);
      mockStorage.getRecentEntries = vi.fn().mockResolvedValue(entries);

      const result = await logger.verifyChain({ recentEntries: 10 });

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
  });
});
```

### Integration Test Patterns

```typescript
describe('AuditLogger Integration', () => {
  let logger: AuditLogger;
  let storage: FileStorageBackend;
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'audit-test-'));
    storage = new FileStorageBackend({
      directory: tempDir,
      maxFileSize: 1024 * 1024,
      maxFiles: 10,
      compressionEnabled: false,
      syncWrites: true,
      maxQueryResults: 1000
    });

    logger = await AuditLogger.create({
      hmacKeyProvider: { getKey: async () => Buffer.from('0'.repeat(64), 'hex') },
      storageBackend: storage
    });
  });

  afterEach(async () => {
    await logger.shutdown();
    await fs.rm(tempDir, { recursive: true });
  });

  it('should persist and reload chain state', async () => {
    // Log some entries
    for (let i = 0; i < 10; i++) {
      await logger.log({
        eventType: AuditEventType.WALLET_BALANCE,
        severity: 'INFO',
        category: 'operation',
        correlationId: randomUUID(),
        actor: { type: 'agent' },
        operation: { name: 'balance', parameters: {}, result: 'success' },
        context: { network: 'testnet' }
      });
    }

    // Shutdown and recreate
    await logger.shutdown();

    const newLogger = await AuditLogger.create({
      hmacKeyProvider: { getKey: async () => Buffer.from('0'.repeat(64), 'hex') },
      storageBackend: storage
    });

    // Next entry should have correct sequence
    const entry = await newLogger.log({
      eventType: AuditEventType.WALLET_BALANCE,
      severity: 'INFO',
      category: 'operation',
      correlationId: randomUUID(),
      actor: { type: 'agent' },
      operation: { name: 'balance', parameters: {}, result: 'success' },
      context: { network: 'testnet' }
    });

    expect(entry.sequence).toBe(11);

    await newLogger.shutdown();
  });

  it('should handle log rotation', async () => {
    // Create small file limit for testing
    const smallStorage = new FileStorageBackend({
      directory: tempDir,
      maxFileSize: 1000, // Very small
      maxFiles: 5,
      compressionEnabled: false,
      syncWrites: true,
      maxQueryResults: 1000
    });

    const rotatingLogger = await AuditLogger.create({
      hmacKeyProvider: { getKey: async () => Buffer.from('0'.repeat(64), 'hex') },
      storageBackend: smallStorage
    });

    // Log enough to trigger rotation
    for (let i = 0; i < 50; i++) {
      await rotatingLogger.log({
        eventType: AuditEventType.WALLET_BALANCE,
        severity: 'INFO',
        category: 'operation',
        correlationId: randomUUID(),
        actor: { type: 'agent' },
        operation: {
          name: 'balance',
          parameters: { index: i },
          result: 'success'
        },
        context: { network: 'testnet' }
      });
    }

    // Verify chain across rotations
    const result = await rotatingLogger.verifyChain({ fullChain: true });
    expect(result.valid).toBe(true);

    await rotatingLogger.shutdown();
  });
});
```

### Test Fixtures

```typescript
/**
 * Test fixture helpers
 */
export function createValidEntry(sequence: number): AuditLogEntry {
  // Create deterministic entry for testing
  return {
    id: `test-${sequence}`,
    sequence,
    timestamp: new Date(Date.UTC(2026, 0, 28, 0, 0, sequence)).toISOString(),
    eventType: AuditEventType.WALLET_BALANCE,
    severity: 'INFO',
    category: 'operation',
    correlationId: `corr-${sequence}`,
    actor: { type: 'agent', id: 'test-agent' },
    operation: { name: 'balance', parameters: {}, result: 'success' },
    context: { network: 'testnet' },
    previousHash: sequence === 1 ? 'genesis' : `hash-${sequence - 1}`,
    hash: `hash-${sequence}`
  };
}

export function createValidChain(length: number, hmacKey: Buffer): AuditLogEntry[] {
  const entries: AuditLogEntry[] = [];
  let prevHash = createHmac('sha256', hmacKey)
    .update('XRPL-WALLET-MCP-GENESIS-V1')
    .digest('hex');

  for (let i = 1; i <= length; i++) {
    const entry: AuditLogEntry = {
      id: randomUUID(),
      sequence: i,
      timestamp: new Date(Date.UTC(2026, 0, 28, 0, 0, i)).toISOString(),
      eventType: AuditEventType.WALLET_BALANCE,
      severity: 'INFO',
      category: 'operation',
      correlationId: randomUUID(),
      actor: { type: 'agent' },
      operation: { name: 'balance', parameters: {}, result: 'success' },
      context: { network: 'testnet' },
      previousHash: prevHash,
      hash: ''
    };

    // Compute hash
    const entryForHashing = { ...entry };
    delete (entryForHashing as any).hash;
    entry.hash = createHmac('sha256', hmacKey)
      .update(JSON.stringify(entryForHashing, Object.keys(entryForHashing).sort()))
      .digest('hex');

    entries.push(entry);
    prevHash = entry.hash;
  }

  return entries;
}

export function createTamperedChain(
  validChain: AuditLogEntry[],
  tamperIndex: number
): AuditLogEntry[] {
  const tampered = [...validChain];
  tampered[tamperIndex] = {
    ...tampered[tamperIndex],
    operation: {
      ...tampered[tamperIndex].operation,
      parameters: { tampered: true }
    }
    // Hash not recomputed - will fail verification
  };
  return tampered;
}
```

---

## 12. Implementation Checklist

### Phase 1: Core Implementation

- [ ] **AuditLogEntry types** - Complete type definitions
- [ ] **AuditEventType enum** - All event types defined
- [ ] **sanitizeForLogging()** - Sensitive data redaction
- [ ] **computeGenesisHash()** - Genesis hash computation
- [ ] **computeEntryHash()** - Entry hash computation
- [ ] **AuditLogger.create()** - Factory method
- [ ] **AuditLogger.log()** - Main logging method
- [ ] **AuditLogger.verifyChain()** - Chain verification
- [ ] **AuditLogger.getChainState()** - State accessor
- [ ] **AuditLogger.shutdown()** - Graceful shutdown

### Phase 2: Storage Backends

- [ ] **IStorageBackend interface** - Complete interface
- [ ] **FileStorageBackend** - JSONL file storage
- [ ] **SQLiteStorageBackend** - SQLite storage (optional)
- [ ] **Sequence indexing** - Fast lookups
- [ ] **Atomic file writes** - Crash safety
- [ ] **Compression** - gzip for rotated files

### Phase 3: Log Rotation

- [ ] **LogRotationConfig** - Configuration
- [ ] **LogRotationManager** - Rotation logic
- [ ] **Size-based rotation** - Max file size
- [ ] **Time-based rotation** - Daily rotation
- [ ] **Retention cleanup** - Max files limit
- [ ] **Free space monitoring** - Min free space

### Phase 4: Compliance

- [ ] **AuditLogQuery interface** - Query parameters
- [ ] **ComplianceQueries class** - Pre-built queries
- [ ] **ComplianceExport interface** - Export format
- [ ] **export() method** - Export implementation
- [ ] **Streaming queries** - Memory-efficient

### Phase 5: Alerting

- [ ] **TamperEvent types** - Event definitions
- [ ] **IAlerter interface** - Alert interface
- [ ] **WebhookAlerter** - Webhook implementation
- [ ] **ConsoleAlerter** - Development alerter
- [ ] **VerificationScheduler** - Periodic verification
- [ ] **Event emission** - EventEmitter integration

### Phase 6: Testing

- [ ] **Unit tests** - All methods covered
- [ ] **Integration tests** - Storage backends
- [ ] **Security tests** - Tamper detection
- [ ] **Performance tests** - Benchmarks met
- [ ] **Test fixtures** - Helper functions

---

## References

- [ADR-005: Audit Logging](../../architecture/09-decisions/ADR-005-audit-logging.md)
- [08-Crosscutting Concepts](../../architecture/08-crosscutting.md)
- [NIST SP 800-92: Guide to Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [RFC 5424: Syslog Protocol](https://datatracker.ietf.org/doc/html/rfc5424)
- [SOC 2 Trust Services Criteria](https://www.aicpa.org/soc2)

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Backend Engineer | Initial specification |

---

*Implementation Specification - Audit Logger*
*XRPL Agent Wallet MCP Server*
