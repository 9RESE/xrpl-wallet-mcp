# Security Architecture Recommendations for XRPL Wallet MCP Server

**Version:** 1.0.0
**Date:** 2026-01-28
**Author:** Security Specialist
**Classification:** Internal/Public

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [MCP Server Security](#mcp-server-security)
3. [Cryptographic Best Practices](#cryptographic-best-practices)
4. [Private Key Security](#private-key-security)
5. [Audit Logging](#audit-logging)
6. [Defense in Depth](#defense-in-depth)
7. [Open Source Security](#open-source-security)
8. [Implementation Checklist](#implementation-checklist)
9. [References](#references)

---

## Executive Summary

This document outlines security architecture recommendations for the XRPL Wallet MCP (Model Context Protocol) server. Given the sensitive nature of cryptocurrency wallet operations, this implementation must prioritize security at every layer while maintaining usability.

### Key Security Principles

1. **Never expose private keys** - Keys should never leave secure storage unencrypted
2. **Defense in depth** - Multiple layers of security controls
3. **Fail-secure design** - Default to denying access on errors
4. **Minimal attack surface** - Expose only necessary functionality
5. **Audit everything** - Log all sensitive operations (but never secrets)

---

## MCP Server Security

### 1. Input Validation

All MCP tool inputs must be rigorously validated before processing.

#### Validation Requirements

```typescript
// Schema validation using zod for all tool inputs
import { z } from 'zod';

// Example: Address validation
const XRPLAddressSchema = z.string()
  .regex(/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/, 'Invalid XRPL address format')
  .refine(isValidXRPLChecksum, 'Invalid XRPL address checksum');

// Example: Amount validation
const XRPAmountSchema = z.string()
  .regex(/^\d+(\.\d{1,6})?$/, 'Invalid XRP amount format')
  .refine((val) => {
    const drops = parseFloat(val) * 1_000_000;
    return drops >= 1 && drops <= 100_000_000_000_000_000;
  }, 'Amount out of valid range');

// Sanitize all string inputs
function sanitizeInput(input: string): string {
  return input
    .replace(/[\x00-\x1f\x7f]/g, '') // Remove control characters
    .trim()
    .slice(0, MAX_INPUT_LENGTH);
}
```

#### Validation Layers

| Layer | Validation Type | Purpose |
|-------|----------------|---------|
| Schema | Zod schemas | Type and format validation |
| Business | Custom validators | Domain-specific rules |
| Cryptographic | Checksum verification | Address/key integrity |

### 2. Tool Authorization Model

Implement fine-grained access control for MCP tools based on sensitivity.

#### Tool Classification

```typescript
enum ToolSensitivity {
  READ_ONLY = 'read_only',      // Account info, balance queries
  SENSITIVE = 'sensitive',       // Transaction signing, key operations
  DESTRUCTIVE = 'destructive'    // Key deletion, wallet reset
}

interface ToolDefinition {
  name: string;
  sensitivity: ToolSensitivity;
  requiresConfirmation: boolean;
  rateLimitTier: RateLimitTier;
}

const TOOL_DEFINITIONS: ToolDefinition[] = [
  { name: 'get_balance', sensitivity: ToolSensitivity.READ_ONLY, requiresConfirmation: false, rateLimitTier: 'standard' },
  { name: 'sign_transaction', sensitivity: ToolSensitivity.SENSITIVE, requiresConfirmation: true, rateLimitTier: 'strict' },
  { name: 'export_wallet', sensitivity: ToolSensitivity.SENSITIVE, requiresConfirmation: true, rateLimitTier: 'strict' },
  { name: 'delete_wallet', sensitivity: ToolSensitivity.DESTRUCTIVE, requiresConfirmation: true, rateLimitTier: 'critical' },
];
```

#### Authorization Flow

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   MCP Client    │────▶│  Input Validator │────▶│ Authorization   │
└─────────────────┘     └──────────────────┘     │    Check        │
                                                  └────────┬────────┘
                                                           │
                        ┌──────────────────┐               │
                        │  Tool Executor   │◀──────────────┘
                        └────────┬─────────┘
                                 │
                        ┌────────▼─────────┐
                        │   Audit Logger   │
                        └──────────────────┘
```

### 3. Sandboxing MCP Tool Execution

#### Process Isolation

```typescript
// Each tool execution should be isolated
interface ExecutionContext {
  toolName: string;
  correlationId: string;
  timeout: number;
  memoryLimit: number;
  permissions: Permission[];
}

// Implement timeouts for all operations
async function executeWithTimeout<T>(
  operation: () => Promise<T>,
  timeoutMs: number,
  context: ExecutionContext
): Promise<T> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await operation();
  } finally {
    clearTimeout(timeoutId);
  }
}
```

#### Resource Limits

| Resource | Limit | Rationale |
|----------|-------|-----------|
| Execution timeout | 30 seconds | Prevent hung operations |
| Memory per operation | 50MB | Prevent memory exhaustion |
| Concurrent operations | 10 | Prevent resource starvation |
| Request size | 1MB | Prevent large payload attacks |

### 4. MCP-Specific Security Considerations

Based on [OWASP GenAI Security guidance](https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers-1-0/), address these MCP-specific threats:

#### Tool Poisoning Prevention
- Validate tool outputs before returning to client
- Sanitize data to prevent prompt injection
- Never include executable code in responses

#### Prompt Injection Defense
- Escape special characters in user-provided data
- Separate data from instructions in responses
- Implement output encoding

```typescript
function sanitizeToolOutput(output: unknown): string {
  const stringOutput = JSON.stringify(output);
  // Remove potential instruction patterns
  return stringOutput
    .replace(/\[INST\]/gi, '[DATA]')
    .replace(/<<SYS>>/gi, '<<DATA>>')
    .replace(/```/g, '\\`\\`\\`');
}
```

---

## Cryptographic Best Practices

### 1. AES-256-GCM Implementation

AES-256-GCM is the recommended encryption algorithm for wallet data at rest.

#### Implementation Requirements

```typescript
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

interface EncryptionResult {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
  salt: Buffer;
}

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;  // 96 bits - NIST recommended for GCM
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 32;

async function encrypt(
  plaintext: Buffer,
  masterKey: Buffer
): Promise<EncryptionResult> {
  // Generate unique IV for each encryption
  const iv = randomBytes(IV_LENGTH);
  const salt = randomBytes(SALT_LENGTH);

  // Derive encryption key from master key
  const encryptionKey = await deriveKey(masterKey, salt);

  const cipher = createCipheriv(ALGORITHM, encryptionKey, iv, {
    authTagLength: AUTH_TAG_LENGTH
  });

  const ciphertext = Buffer.concat([
    cipher.update(plaintext),
    cipher.final()
  ]);

  const authTag = cipher.getAuthTag();

  // Zero sensitive data from memory
  encryptionKey.fill(0);

  return { ciphertext, iv, authTag, salt };
}

async function decrypt(
  encrypted: EncryptionResult,
  masterKey: Buffer
): Promise<Buffer> {
  const encryptionKey = await deriveKey(masterKey, encrypted.salt);

  const decipher = createDecipheriv(ALGORITHM, encryptionKey, encrypted.iv, {
    authTagLength: AUTH_TAG_LENGTH
  });

  decipher.setAuthTag(encrypted.authTag);

  try {
    const plaintext = Buffer.concat([
      decipher.update(encrypted.ciphertext),
      decipher.final()
    ]);
    return plaintext;
  } finally {
    encryptionKey.fill(0);
  }
}
```

#### Critical Requirements

| Requirement | Value | Reference |
|-------------|-------|-----------|
| IV Length | 12 bytes (96 bits) | NIST SP 800-38D |
| IV Uniqueness | Unique per encryption | Never reuse IV with same key |
| Key Rotation | After 2^32 encryptions | NIST recommendation |
| Auth Tag | Always verify | Provides integrity check |

### 2. Key Derivation

#### Argon2id (Recommended)

[Argon2id](https://en.wikipedia.org/wiki/Argon2) is the winner of the Password Hashing Competition and provides resistance against both side-channel and GPU attacks.

```typescript
import argon2 from 'argon2';

interface KeyDerivationOptions {
  memoryCost: number;    // Memory in KB
  timeCost: number;      // Iterations
  parallelism: number;   // Threads
  hashLength: number;    // Output key length
}

const ARGON2_OPTIONS: KeyDerivationOptions = {
  memoryCost: 65536,     // 64 MB (adjust based on available memory)
  timeCost: 3,           // 3 iterations
  parallelism: 4,        // 4 parallel threads
  hashLength: 32         // 256-bit key
};

async function deriveKeyFromPassword(
  password: string,
  salt: Buffer
): Promise<Buffer> {
  return argon2.hash(password, {
    type: argon2.argon2id,  // Hybrid mode - best overall security
    salt,
    memoryCost: ARGON2_OPTIONS.memoryCost,
    timeCost: ARGON2_OPTIONS.timeCost,
    parallelism: ARGON2_OPTIONS.parallelism,
    hashLength: ARGON2_OPTIONS.hashLength,
    raw: true  // Return raw bytes, not encoded string
  });
}
```

#### PBKDF2 (Alternative for FIPS Compliance)

```typescript
import { pbkdf2 } from 'crypto';
import { promisify } from 'util';

const pbkdf2Async = promisify(pbkdf2);

const PBKDF2_ITERATIONS = 600_000;  // OWASP 2023 recommendation
const KEY_LENGTH = 32;

async function deriveKeyPBKDF2(
  password: string,
  salt: Buffer
): Promise<Buffer> {
  return pbkdf2Async(
    password,
    salt,
    PBKDF2_ITERATIONS,
    KEY_LENGTH,
    'sha256'
  );
}
```

#### Comparison

| Algorithm | GPU Resistance | Memory Hard | FIPS Compliant | Recommended For |
|-----------|---------------|-------------|----------------|-----------------|
| Argon2id | Excellent | Yes | No | Default choice |
| PBKDF2 | Fair | No | Yes | Compliance requirements |

### 3. Secure Random Generation

```typescript
import { randomBytes, randomInt } from 'crypto';

// Generate cryptographically secure random bytes
function generateSecureRandom(length: number): Buffer {
  return randomBytes(length);
}

// Generate secure random integer in range
function generateSecureRandomInt(min: number, max: number): number {
  return randomInt(min, max);
}

// Generate secure random hex string
function generateSecureRandomHex(byteLength: number): string {
  return randomBytes(byteLength).toString('hex');
}
```

### 4. Memory-Safe Key Handling

#### Challenges in JavaScript/Node.js

JavaScript's garbage collector makes true secure memory handling difficult. Keys may persist in memory longer than expected.

#### Mitigation Strategies

```typescript
import { Buffer } from 'buffer';

class SecureBuffer {
  private buffer: Buffer;
  private isZeroed: boolean = false;

  constructor(size: number) {
    this.buffer = Buffer.allocUnsafe(size);
  }

  static from(data: string | Buffer, encoding?: BufferEncoding): SecureBuffer {
    const secureBuffer = new SecureBuffer(
      typeof data === 'string' ? Buffer.byteLength(data, encoding) : data.length
    );
    if (typeof data === 'string') {
      secureBuffer.buffer.write(data, encoding);
    } else {
      data.copy(secureBuffer.buffer);
    }
    return secureBuffer;
  }

  getBuffer(): Buffer {
    if (this.isZeroed) {
      throw new Error('Buffer has been zeroed');
    }
    return this.buffer;
  }

  zero(): void {
    if (!this.isZeroed) {
      this.buffer.fill(0);
      this.isZeroed = true;
    }
  }

  // Use with try-finally to ensure cleanup
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

// Example usage
async function signTransaction(privateKey: Buffer, transaction: object): Promise<string> {
  return SecureBuffer.withSecureBuffer(privateKey, async (key) => {
    // Perform signing
    const signature = await performSigning(key, transaction);
    return signature;
  });
  // Key is automatically zeroed after operation
}
```

#### Best Practices

1. **Minimize key lifetime** - Load keys only when needed, zero immediately after
2. **Avoid string conversion** - Keep keys as Buffers, not strings
3. **Use dedicated key storage** - Consider Node.js secure heap for sensitive operations
4. **Avoid logging** - Never log key material or related data
5. **Consider native modules** - For critical operations, use Rust/C++ native modules

---

## Private Key Security

### 1. Key Storage Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    User Password                             │
└──────────────────────────┬──────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │   Argon2id  │
                    │   KDF       │
                    └──────┬──────┘
                           │
              ┌────────────▼────────────┐
              │    Master Key (256-bit) │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │   AES-256-GCM Encrypt   │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │   Encrypted Wallet      │
              │   (Private Keys)        │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │   File System Storage   │
              │   (with OS permissions) │
              └─────────────────────────┘
```

### 2. Wallet File Format

```typescript
interface EncryptedWallet {
  version: 1;
  encryption: {
    algorithm: 'aes-256-gcm';
    kdf: 'argon2id';
    kdfParams: {
      memoryCost: number;
      timeCost: number;
      parallelism: number;
      salt: string;  // Base64 encoded
    };
  };
  data: {
    iv: string;       // Base64 encoded
    authTag: string;  // Base64 encoded
    ciphertext: string;  // Base64 encoded
  };
  metadata: {
    created: string;  // ISO 8601
    modified: string;
    keyCount: number;
    // Never include addresses or any derivable information
  };
}
```

### 3. File System Security

```typescript
import { promises as fs } from 'fs';
import { platform } from 'os';

const SECURE_FILE_MODE = 0o600;  // Owner read/write only
const SECURE_DIR_MODE = 0o700;   // Owner read/write/execute only

async function secureWriteFile(
  filepath: string,
  data: Buffer
): Promise<void> {
  // Write to temp file first
  const tempPath = `${filepath}.tmp.${Date.now()}`;

  try {
    await fs.writeFile(tempPath, data, { mode: SECURE_FILE_MODE });

    // Atomic rename
    await fs.rename(tempPath, filepath);

    // Verify permissions on non-Windows
    if (platform() !== 'win32') {
      await fs.chmod(filepath, SECURE_FILE_MODE);
    }
  } catch (error) {
    // Clean up temp file on error
    try {
      await fs.unlink(tempPath);
    } catch {
      // Ignore cleanup errors
    }
    throw error;
  }
}

async function secureReadFile(filepath: string): Promise<Buffer> {
  // Verify permissions before reading
  const stats = await fs.stat(filepath);

  if (platform() !== 'win32') {
    const mode = stats.mode & 0o777;
    if (mode !== SECURE_FILE_MODE) {
      throw new Error(`Insecure file permissions: ${mode.toString(8)}`);
    }
  }

  return fs.readFile(filepath);
}
```

### 4. Seed Phrase Handling

```typescript
// NEVER store seed phrases in plain text
// NEVER log seed phrases
// NEVER transmit seed phrases over network

interface SeedPhraseInput {
  // Accept array to avoid string memory issues
  words: string[];
}

function validateSeedPhrase(input: SeedPhraseInput): boolean {
  const { words } = input;

  // Validate word count (12, 15, 18, 21, or 24)
  if (![12, 15, 18, 21, 24].includes(words.length)) {
    return false;
  }

  // Validate against BIP-39 wordlist
  const isValid = words.every(word => BIP39_WORDLIST.includes(word.toLowerCase()));

  // Validate checksum
  return isValid && validateBIP39Checksum(words);
}

// Zero seed phrase from memory immediately after use
function processSeedPhrase(words: string[]): Buffer {
  try {
    const entropy = mnemonicToEntropy(words);
    const seed = entropyToSeed(entropy);
    return seed;
  } finally {
    // Overwrite input array
    words.fill('');
    words.length = 0;
  }
}
```

---

## Audit Logging

### 1. Tamper-Evident Logging Architecture

Based on [Cossack Labs audit log security](https://www.cossacklabs.com/blog/audit-logs-security/) best practices.

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Operation     │────▶│   Log Entry      │────▶│  Hash Chain     │
└─────────────────┘     │   Generator      │     │  (HMAC)         │
                        └──────────────────┘     └────────┬────────┘
                                                          │
                        ┌──────────────────┐              │
                        │  Secure Storage  │◀─────────────┘
                        └──────────────────┘
```

### 2. Log Entry Structure

```typescript
interface AuditLogEntry {
  // Identification
  id: string;                    // UUID v4
  sequence: number;              // Monotonic sequence number
  timestamp: string;             // ISO 8601 with timezone

  // Event details
  eventType: AuditEventType;
  toolName: string;
  correlationId: string;         // Links related operations

  // Actor
  actor: {
    type: 'user' | 'system' | 'scheduled';
    id?: string;
  };

  // Operation details (NEVER include secrets)
  operation: {
    name: string;
    parameters: Record<string, unknown>;  // Sanitized
    result: 'success' | 'failure' | 'denied';
    errorCode?: string;
  };

  // Integrity
  previousHash: string;          // SHA-256 of previous entry
  hash: string;                  // SHA-256 of this entry (excluding hash field)
}

enum AuditEventType {
  // Wallet operations
  WALLET_CREATE = 'wallet.create',
  WALLET_IMPORT = 'wallet.import',
  WALLET_EXPORT = 'wallet.export',
  WALLET_DELETE = 'wallet.delete',

  // Key operations
  KEY_GENERATE = 'key.generate',
  KEY_DERIVE = 'key.derive',

  // Transaction operations
  TRANSACTION_SIGN = 'transaction.sign',
  TRANSACTION_SUBMIT = 'transaction.submit',

  // Authentication
  AUTH_SUCCESS = 'auth.success',
  AUTH_FAILURE = 'auth.failure',
  AUTH_LOCKOUT = 'auth.lockout',

  // Security events
  SECURITY_RATE_LIMIT = 'security.rate_limit',
  SECURITY_INVALID_INPUT = 'security.invalid_input',
  SECURITY_SUSPICIOUS = 'security.suspicious'
}
```

### 3. What to Log vs What NOT to Log

#### ALWAYS LOG

| Category | Fields |
|----------|--------|
| Operation | Tool name, operation type, timestamp |
| Actor | Actor type, correlation ID |
| Result | Success/failure, error codes |
| Context | Sequence number, previous hash |
| Security | Rate limit triggers, auth failures |

#### NEVER LOG

| Category | Reason |
|----------|--------|
| Private keys | Obvious security risk |
| Seed phrases | Recovery phrase exposure |
| Passwords | Authentication secret |
| Full transaction data | May contain sensitive info |
| Encryption keys | Security breach risk |
| IP addresses | Privacy (unless required for compliance) |

### 4. Hash Chain Implementation

```typescript
import { createHmac, createHash } from 'crypto';

class AuditLogger {
  private sequence: number = 0;
  private previousHash: string = '';
  private hmacKey: Buffer;

  constructor(hmacKey: Buffer) {
    this.hmacKey = hmacKey;
    // Initialize with known genesis hash
    this.previousHash = createHash('sha256')
      .update('GENESIS')
      .digest('hex');
  }

  async log(event: Omit<AuditLogEntry, 'id' | 'sequence' | 'previousHash' | 'hash'>): Promise<AuditLogEntry> {
    const entry: AuditLogEntry = {
      ...event,
      id: generateUUID(),
      sequence: ++this.sequence,
      previousHash: this.previousHash,
      hash: ''  // Placeholder
    };

    // Calculate hash (excluding hash field)
    const entryForHashing = { ...entry };
    delete (entryForHashing as any).hash;

    const hmac = createHmac('sha256', this.hmacKey);
    hmac.update(JSON.stringify(entryForHashing));
    entry.hash = hmac.digest('hex');

    // Store entry
    await this.persistEntry(entry);

    // Update chain
    this.previousHash = entry.hash;

    return entry;
  }

  async verifyChain(entries: AuditLogEntry[]): Promise<boolean> {
    let expectedPreviousHash = createHash('sha256')
      .update('GENESIS')
      .digest('hex');

    for (const entry of entries) {
      // Verify previous hash links
      if (entry.previousHash !== expectedPreviousHash) {
        return false;
      }

      // Verify entry hash
      const entryForHashing = { ...entry };
      delete (entryForHashing as any).hash;

      const hmac = createHmac('sha256', this.hmacKey);
      hmac.update(JSON.stringify(entryForHashing));
      const calculatedHash = hmac.digest('hex');

      if (calculatedHash !== entry.hash) {
        return false;
      }

      expectedPreviousHash = entry.hash;
    }

    return true;
  }

  private async persistEntry(entry: AuditLogEntry): Promise<void> {
    // Implement append-only storage
    // Consider WORM (Write Once Read Many) storage
  }
}
```

### 5. Log Retention and Compliance

| Requirement | Recommendation |
|-------------|----------------|
| Retention Period | Minimum 7 years for financial compliance |
| Storage | Append-only, encrypted at rest |
| Access Control | Read-only for auditors, no delete capability |
| Backup | Encrypted off-site backup |
| Verification | Weekly automated chain verification |

---

## Defense in Depth

### 1. Multiple Validation Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                        Layer 1: Transport                        │
│                 (TLS 1.3, Certificate Pinning)                   │
├─────────────────────────────────────────────────────────────────┤
│                        Layer 2: Input                            │
│              (Schema validation, Sanitization)                   │
├─────────────────────────────────────────────────────────────────┤
│                        Layer 3: Authentication                   │
│              (Password verification, Rate limiting)              │
├─────────────────────────────────────────────────────────────────┤
│                        Layer 4: Authorization                    │
│              (Tool permissions, Sensitivity checks)              │
├─────────────────────────────────────────────────────────────────┤
│                        Layer 5: Business Logic                   │
│              (Domain validation, Sanity checks)                  │
├─────────────────────────────────────────────────────────────────┤
│                        Layer 6: Data                             │
│              (Encryption at rest, Integrity checks)              │
└─────────────────────────────────────────────────────────────────┘
```

### 2. Fail-Secure Design Patterns

```typescript
// Always default to deny
async function authorizeOperation(
  operation: string,
  context: SecurityContext
): Promise<AuthorizationResult> {
  try {
    // Check all authorization rules
    const checks = [
      checkRateLimit(context),
      checkAuthenticationValid(context),
      checkOperationPermitted(operation, context),
      checkInputValid(context.input)
    ];

    const results = await Promise.all(checks);

    // All checks must pass
    if (results.some(r => !r.passed)) {
      return { allowed: false, reason: getFirstFailure(results) };
    }

    return { allowed: true };
  } catch (error) {
    // On ANY error, deny access
    await logSecurityEvent('authorization_error', { error, context });
    return { allowed: false, reason: 'Internal error - access denied' };
  }
}

// Secure error handling - never expose internal details
function createSecureError(
  internalError: Error,
  publicMessage: string
): SecureError {
  // Log full error internally
  logger.error('Internal error', {
    message: internalError.message,
    stack: internalError.stack,
    correlationId: getCurrentCorrelationId()
  });

  // Return sanitized error to client
  return new SecureError(publicMessage, getCurrentCorrelationId());
}
```

### 3. Rate Limiting Strategy

Based on [Zuplo rate limiting best practices](https://zuplo.com/learning-center/10-best-practices-for-api-rate-limiting-in-2025).

```typescript
interface RateLimitConfig {
  tier: RateLimitTier;
  window: number;      // Seconds
  maxRequests: number;
  burstAllowance: number;
}

enum RateLimitTier {
  STANDARD = 'standard',    // Read operations
  STRICT = 'strict',        // Write operations
  CRITICAL = 'critical'     // Sensitive operations
}

const RATE_LIMITS: Record<RateLimitTier, RateLimitConfig> = {
  [RateLimitTier.STANDARD]: {
    tier: RateLimitTier.STANDARD,
    window: 60,
    maxRequests: 100,
    burstAllowance: 10
  },
  [RateLimitTier.STRICT]: {
    tier: RateLimitTier.STRICT,
    window: 60,
    maxRequests: 20,
    burstAllowance: 2
  },
  [RateLimitTier.CRITICAL]: {
    tier: RateLimitTier.CRITICAL,
    window: 300,
    maxRequests: 5,
    burstAllowance: 0
  }
};

// Implement sliding window with token bucket
class RateLimiter {
  private buckets: Map<string, TokenBucket> = new Map();

  async checkLimit(
    identifier: string,
    tier: RateLimitTier
  ): Promise<RateLimitResult> {
    const config = RATE_LIMITS[tier];
    const bucket = this.getOrCreateBucket(identifier, config);

    if (bucket.tryConsume()) {
      return {
        allowed: true,
        remaining: bucket.getRemaining(),
        resetAt: bucket.getResetTime()
      };
    }

    await this.logRateLimitExceeded(identifier, tier);

    return {
      allowed: false,
      remaining: 0,
      resetAt: bucket.getResetTime(),
      retryAfter: bucket.getRetryAfter()
    };
  }
}
```

#### Rate Limit Response Headers

```typescript
// Always include rate limit headers in responses
function addRateLimitHeaders(
  response: Response,
  result: RateLimitResult
): void {
  response.setHeader('X-RateLimit-Limit', result.limit);
  response.setHeader('X-RateLimit-Remaining', result.remaining);
  response.setHeader('X-RateLimit-Reset', result.resetAt);

  if (!result.allowed) {
    response.setHeader('Retry-After', result.retryAfter);
  }
}
```

### 4. Authentication Lockout

```typescript
interface LockoutConfig {
  maxAttempts: number;
  windowSeconds: number;
  lockoutDurationSeconds: number;
  progressiveLockout: boolean;
}

const LOCKOUT_CONFIG: LockoutConfig = {
  maxAttempts: 5,
  windowSeconds: 900,          // 15 minutes
  lockoutDurationSeconds: 1800, // 30 minutes
  progressiveLockout: true      // Doubles each time
};

class AuthenticationLockout {
  async recordAttempt(
    identifier: string,
    success: boolean
  ): Promise<void> {
    if (success) {
      await this.clearAttempts(identifier);
      return;
    }

    const attempts = await this.incrementAttempts(identifier);

    if (attempts >= LOCKOUT_CONFIG.maxAttempts) {
      const lockoutDuration = this.calculateLockoutDuration(identifier);
      await this.setLockout(identifier, lockoutDuration);
      await this.logLockout(identifier, lockoutDuration);
    }
  }

  private calculateLockoutDuration(identifier: string): number {
    if (!LOCKOUT_CONFIG.progressiveLockout) {
      return LOCKOUT_CONFIG.lockoutDurationSeconds;
    }

    const previousLockouts = this.getPreviousLockoutCount(identifier);
    return LOCKOUT_CONFIG.lockoutDurationSeconds * Math.pow(2, previousLockouts);
  }
}
```

---

## Open Source Security

### 1. SECURITY.md Best Practices

Based on [OpenSSF Security Baseline](https://baseline.openssf.org/versions/2025-10-10.html).

```markdown
# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

1. **DO NOT** create a public GitHub issue
2. Email security@yourproject.org with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: 90 days

### Safe Harbor

We support safe harbor for security researchers who:
- Make good faith efforts to avoid privacy violations
- Avoid destruction of data
- Do not exploit issues beyond demonstration
- Give us reasonable time to respond

## Security Update Policy

- Security patches are released as soon as possible
- CVEs are requested for significant vulnerabilities
- Security advisories are published on GitHub

## Security Best Practices for Users

1. Always use the latest version
2. Enable all security features
3. Use strong, unique passwords
4. Keep your system updated
5. Review dependencies regularly
```

### 2. Vulnerability Disclosure Process

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Researcher    │────▶│   Security Team  │────▶│   Assessment    │
│   Reports       │     │   Receives       │     │   & Triage      │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
        ┌──────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Develop Fix   │────▶│   Security       │────▶│   Public        │
│   & Test        │     │   Advisory       │     │   Disclosure    │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

### 3. Dependency Security

Based on learnings from the [2025 npm supply chain attacks](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem).

#### Package Management Security

```json
// package.json security configuration
{
  "scripts": {
    "preinstall": "npx only-allow pnpm",
    "audit": "pnpm audit --audit-level=moderate",
    "audit:fix": "pnpm audit --fix",
    "deps:check": "npx npm-check-updates -u --target minor"
  },
  "engines": {
    "node": ">=20.0.0",
    "pnpm": ">=9.0.0"
  }
}
```

#### .npmrc Security Settings

```ini
# .npmrc - Security hardened configuration

# Disable lifecycle scripts by default
ignore-scripts=true

# Require lockfile
package-lock=true

# Strict SSL
strict-ssl=true

# Audit on install
audit=true

# Prevent version resolution attacks
save-exact=true

# Use specific registry
registry=https://registry.npmjs.org/
```

#### CI/CD Security Pipeline

```yaml
# .github/workflows/security.yml
name: Security Checks

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * *'  # Daily

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install with audit
        run: |
          npm ci --ignore-scripts
          npm audit --audit-level=high

      - name: Run Snyk
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}

      - name: Run CodeQL
        uses: github/codeql-action/analyze@v3

      - name: Check for secrets
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./

      - name: Generate SBOM
        run: npx @cyclonedx/cyclonedx-npm --output-file sbom.json

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.json
```

### 4. Supply Chain Attack Prevention

| Control | Implementation |
|---------|----------------|
| Lockfile enforcement | Always use `npm ci` in CI |
| Version pinning | Use exact versions, not ranges |
| Integrity verification | Enable `package-lock.json` integrity |
| Script disabling | Set `ignore-scripts=true` |
| Provenance verification | Use npm trusted publishing |
| SBOM generation | Generate on each release |
| Regular audits | Daily automated scans |
| Dependency review | Manual review for new deps |

---

## Implementation Checklist

### Phase 1: Foundation (Week 1-2)

- [ ] Set up secure development environment
- [ ] Implement input validation framework with zod
- [ ] Create AES-256-GCM encryption module
- [ ] Implement Argon2id key derivation
- [ ] Set up secure file storage with proper permissions

### Phase 2: Core Security (Week 3-4)

- [ ] Implement tool authorization model
- [ ] Create audit logging system with hash chains
- [ ] Implement rate limiting
- [ ] Add authentication lockout
- [ ] Create SecureBuffer for key handling

### Phase 3: Hardening (Week 5-6)

- [ ] Implement defense in depth layers
- [ ] Add comprehensive error handling
- [ ] Create security event monitoring
- [ ] Implement log verification system
- [ ] Add security headers and protections

### Phase 4: Open Source Readiness (Week 7-8)

- [ ] Create SECURITY.md
- [ ] Set up vulnerability disclosure process
- [ ] Configure CI/CD security pipeline
- [ ] Implement dependency scanning
- [ ] Generate initial SBOM
- [ ] Security audit and penetration testing

---

## References

### MCP Security
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
- [OWASP Guide for MCP Servers](https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers-1-0/)
- [Red Hat MCP Security Analysis](https://www.redhat.com/en/blog/model-context-protocol-mcp-understanding-security-risks-and-controls)
- [WorkOS MCP Security Guide](https://workos.com/blog/mcp-security-risks-best-practices)

### Cryptography
- [AES-GCM Implementation Examples](https://gist.github.com/rjz/15baffeab434b8125ca4d783f4116d81)
- [Node.js Crypto Documentation](https://nodejs.org/api/crypto.html)
- [Argon2 Wikipedia](https://en.wikipedia.org/wiki/Argon2)
- [Password Hashing Guide 2025](https://guptadeepak.com/the-complete-guide-to-password-hashing-argon2-vs-bcrypt-vs-scrypt-vs-pbkdf2-2026/)
- [Key Derivation Functions - Python Cryptography](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/)

### Audit Logging
- [Cossack Labs Audit Log Security](https://www.cossacklabs.com/blog/audit-logs-security/)
- [Pangea Tamperproof Logging](https://pangea.cloud/blog/a-tamperproof-logging-implementation)
- [Immutable Audit Logs Guide](https://www.hubifi.com/blog/immutable-audit-log-guide)

### Rate Limiting
- [Zuplo Rate Limiting Best Practices 2025](https://zuplo.com/learning-center/10-best-practices-for-api-rate-limiting-in-2025)
- [Cloudflare Rate Limiting](https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/)
- [APIsec Rate Limiting Strategies](https://www.apisec.ai/blog/api-rate-limiting-strategies-preventing)

### Open Source Security
- [OpenSSF Security Baseline 2025](https://baseline.openssf.org/versions/2025-10-10.html)
- [Google OSS Vulnerability Guide](https://github.com/google/oss-vulnerability-guide/blob/main/guide.md)
- [disclose.io Project](https://disclose.io/)

### Supply Chain Security
- [CISA npm Supply Chain Alert](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)
- [Snyk npm Security Best Practices](https://snyk.io/articles/npm-security-best-practices-shai-hulud-attack/)
- [pnpm Supply Chain Security](https://pnpm.io/blog/2025/12/05/newsroom-npm-supply-chain-security)
- [GitHub npm Supply Chain Plan](https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/)

### Cryptocurrency Wallet Security
- [Ledger Security Checklist 2025](https://www.ledger.com/academy/topics/security/crypto-wallet-security-checklist-2025-protect-crypto-with-ledger)
- [OSL Private Key Storage](https://www.osl.com/hk-en/academy/article/how-to-securely-store-your-private-keys-best-practices)
- [Bitcoin Wallet Security](https://bitcoin.org/en/secure-your-wallet)

---

*Document generated: 2026-01-28*
*Next review date: 2026-04-28*
*Classification: Internal/Public*
