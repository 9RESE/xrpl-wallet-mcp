# ADR-005: Audit Logging

**Status:** Accepted
**Date:** 2026-01-28
**Decision Makers:** Tech Lead, Security Specialist

---

## Context

The XRPL Agent Wallet MCP server handles high-value financial operations that require complete, tamper-evident audit trails. Audit logs serve multiple purposes:

1. **Security Forensics**: Investigate incidents and compromises
2. **Compliance**: Meet regulatory requirements (SOC 2, MiCA)
3. **Non-Repudiation**: Prove what operations occurred and when
4. **Operational Monitoring**: Detect anomalies and suspicious patterns
5. **Debugging**: Understand system behavior during issues

Key requirements:
- **Tamper Evidence**: Detect if logs have been modified or deleted
- **Completeness**: Log all security-relevant events
- **Confidentiality**: Never log secrets (keys, passwords, seeds)
- **Queryability**: Support efficient searching and analysis
- **Retention**: Meet compliance retention requirements (7+ years)

The threat model identifies audit log tampering (T-012) and non-repudiation failures (R-001) as significant risks.

## Decision

**We will implement HMAC-SHA256 hash chains with tamper detection for all audit logs.**

### Hash Chain Architecture

```
+-------------+     +-------------+     +-------------+     +-------------+
|  Entry 1    |     |  Entry 2    |     |  Entry 3    |     |  Entry N    |
|             |     |             |     |             |     |             |
| sequence: 1 |     | sequence: 2 |     | sequence: 3 |     | sequence: N |
| prevHash:   |---->| prevHash:   |---->| prevHash:   |---->| prevHash:   |
|  GENESIS    |     |  hash(E1)   |     |  hash(E2)   |     | hash(E(N-1))|
| hash: H1    |     | hash: H2    |     | hash: H3    |     | hash: HN    |
+-------------+     +-------------+     +-------------+     +-------------+
```

### Log Entry Structure

```typescript
interface AuditLogEntry {
  // Identification
  id: string;                    // UUID v4
  sequence: number;              // Monotonic sequence number
  timestamp: string;             // ISO 8601 with timezone (UTC)

  // Event details
  eventType: AuditEventType;
  toolName?: string;
  correlationId: string;         // Links related operations

  // Actor
  actor: {
    type: 'agent' | 'system' | 'human' | 'scheduled';
    id?: string;
  };

  // Operation details (sanitized - no secrets)
  operation: {
    name: string;
    parameters: Record<string, unknown>;  // Redacted sensitive fields
    result: 'success' | 'failure' | 'denied';
    errorCode?: string;
    errorMessage?: string;
  };

  // Context
  context: {
    network: 'mainnet' | 'testnet' | 'devnet';
    walletAddress?: string;
    transactionHash?: string;
    policyVersion?: string;
  };

  // Integrity
  previousHash: string;          // HMAC-SHA256 of previous entry
  hash: string;                  // HMAC-SHA256 of this entry
}
```

### Event Types

```typescript
enum AuditEventType {
  // Authentication
  AUTH_UNLOCK_SUCCESS = 'auth.unlock.success',
  AUTH_UNLOCK_FAILURE = 'auth.unlock.failure',
  AUTH_LOCK = 'auth.lock',
  AUTH_LOCKOUT = 'auth.lockout',

  // Wallet Operations
  WALLET_CREATE = 'wallet.create',
  WALLET_IMPORT = 'wallet.import',
  WALLET_LIST = 'wallet.list',
  WALLET_BALANCE = 'wallet.balance',

  // Key Operations
  KEY_REGULAR_SET = 'key.regular.set',
  KEY_ROTATE = 'key.rotate',
  KEY_EXPORT = 'key.export',
  MULTISIG_SETUP = 'multisig.setup',

  // Transaction Operations
  TX_SIGN_REQUEST = 'tx.sign.request',
  TX_SIGN_SUCCESS = 'tx.sign.success',
  TX_SIGN_DENIED = 'tx.sign.denied',
  TX_SIGN_FAILURE = 'tx.sign.failure',
  TX_SUBMIT = 'tx.submit',
  TX_CONFIRMED = 'tx.confirmed',
  TX_FAILED = 'tx.failed',

  // Policy Operations
  POLICY_EVALUATE = 'policy.evaluate',
  POLICY_VIOLATION = 'policy.violation',
  POLICY_RELOAD = 'policy.reload',

  // Security Events
  SECURITY_RATE_LIMIT = 'security.rate_limit',
  SECURITY_INVALID_INPUT = 'security.invalid_input',
  SECURITY_PROMPT_INJECTION = 'security.prompt_injection',
  SECURITY_BLOCKLIST_MATCH = 'security.blocklist_match',
  SECURITY_SUSPICIOUS = 'security.suspicious',

  // System Events
  SYSTEM_STARTUP = 'system.startup',
  SYSTEM_SHUTDOWN = 'system.shutdown',
  SYSTEM_CONFIG_CHANGE = 'system.config_change',
  SYSTEM_ERROR = 'system.error'
}
```

### Implementation

```typescript
import { createHmac, randomUUID } from 'crypto';

class AuditLogger {
  private sequence: number = 0;
  private previousHash: string;
  private hmacKey: Buffer;
  private logWriter: LogWriter;

  constructor(hmacKey: Buffer, logWriter: LogWriter) {
    this.hmacKey = hmacKey;
    this.logWriter = logWriter;
    // Genesis hash is well-known constant
    this.previousHash = this.computeGenesisHash();
  }

  private computeGenesisHash(): string {
    const hmac = createHmac('sha256', this.hmacKey);
    hmac.update('XRPL-WALLET-MCP-GENESIS-V1');
    return hmac.digest('hex');
  }

  async log(event: Omit<AuditLogEntry, 'id' | 'sequence' | 'timestamp' | 'previousHash' | 'hash'>): Promise<AuditLogEntry> {
    const entry: AuditLogEntry = {
      ...event,
      id: randomUUID(),
      sequence: ++this.sequence,
      timestamp: new Date().toISOString(),
      previousHash: this.previousHash,
      hash: ''  // Computed below
    };

    // Compute hash of entry (excluding hash field itself)
    entry.hash = this.computeEntryHash(entry);

    // Persist entry
    await this.logWriter.append(entry);

    // Update chain
    this.previousHash = entry.hash;

    return entry;
  }

  private computeEntryHash(entry: AuditLogEntry): string {
    const hmac = createHmac('sha256', this.hmacKey);
    const entryForHashing = { ...entry, hash: undefined };
    hmac.update(JSON.stringify(entryForHashing, Object.keys(entryForHashing).sort()));
    return hmac.digest('hex');
  }

  async verifyChain(entries: AuditLogEntry[]): Promise<ChainVerificationResult> {
    let expectedPrevHash = this.computeGenesisHash();
    const errors: ChainError[] = [];

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];

      // Check sequence
      if (entry.sequence !== i + 1) {
        errors.push({
          type: 'sequence_gap',
          sequence: entry.sequence,
          expected: i + 1
        });
      }

      // Check previous hash link
      if (entry.previousHash !== expectedPrevHash) {
        errors.push({
          type: 'chain_break',
          sequence: entry.sequence,
          expected: expectedPrevHash,
          actual: entry.previousHash
        });
      }

      // Verify entry hash
      const computedHash = this.computeEntryHash(entry);
      if (computedHash !== entry.hash) {
        errors.push({
          type: 'tampered_entry',
          sequence: entry.sequence,
          expected: computedHash,
          actual: entry.hash
        });
      }

      expectedPrevHash = entry.hash;
    }

    return {
      valid: errors.length === 0,
      entriesVerified: entries.length,
      errors
    };
  }
}
```

### Sensitive Data Redaction

```typescript
const REDACTED_FIELDS = new Set([
  'password', 'seed', 'secret', 'privateKey', 'private_key',
  'mnemonic', 'passphrase', 'encryptionKey', 'hmacKey'
]);

function sanitizeForLogging(obj: unknown, depth = 0): unknown {
  if (depth > 10) return '[MAX_DEPTH]';
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') {
    // Detect potential secrets by pattern
    if (obj.length === 64 && /^[a-f0-9]+$/i.test(obj)) return '[REDACTED_HEX]';
    if (/^s[a-zA-Z0-9]{28}$/.test(obj)) return '[REDACTED_SEED]';
    return obj.length > 1000 ? obj.slice(0, 100) + '...[TRUNCATED]' : obj;
  }
  if (typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(item => sanitizeForLogging(item, depth + 1));

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (REDACTED_FIELDS.has(key.toLowerCase())) {
      result[key] = '[REDACTED]';
    } else {
      result[key] = sanitizeForLogging(value, depth + 1);
    }
  }
  return result;
}
```

## Consequences

### Positive

- **Tamper Detection**: Any modification breaks the hash chain
- **Deletion Detection**: Sequence gaps reveal deleted entries
- **Cryptographic Proof**: HMAC-SHA256 provides strong integrity guarantee
- **Compliance Ready**: Meets SOC 2 and financial audit requirements
- **Forensic Value**: Complete trail for incident investigation
- **Non-Repudiation**: Cannot deny logged actions occurred
- **Standard Format**: JSON logs work with existing SIEM tools

### Negative

- **HMAC Key Management**: Requires secure storage of separate HMAC key
- **Write Performance**: Each write computes HMAC (minimal overhead)
- **Storage Growth**: Complete logs can grow large over time
- **Verification Cost**: Full chain verification is O(n)
- **Cannot Delete**: By design, problematic if sensitive data accidentally logged

### Neutral

- Logs are append-only (feature, not bug)
- Requires rotation strategy for very long-running systems
- HMAC key compromise allows future tampering (but not retroactive)

## Alternatives Considered

| Option | Pros | Cons | Why Not Chosen |
|--------|------|------|----------------|
| **Plain JSON Logs** | Simple, standard | No tamper detection | Insufficient for compliance |
| **Database with Triggers** | Query flexibility | Complex, mutation possible | Doesn't guarantee immutability |
| **Blockchain Anchoring** | Maximum tamper-evidence | Complex, costly, latency | Overkill for Phase 1 |
| **SHA256 (No HMAC)** | Simpler | Anyone can recompute valid hashes | HMAC provides authentication |
| **Merkle Trees** | Efficient proofs | More complex, not needed for single-writer | Hash chain sufficient |

## Implementation Notes

### Log File Management

```typescript
interface LogWriterConfig {
  directory: string;
  maxFileSize: number;      // Bytes before rotation
  maxFiles: number;         // Files to retain
  compressionEnabled: boolean;
}

class FileLogWriter implements LogWriter {
  private currentFile: string;
  private currentSize: number = 0;

  async append(entry: AuditLogEntry): Promise<void> {
    const line = JSON.stringify(entry) + '\n';
    const lineSize = Buffer.byteLength(line);

    if (this.currentSize + lineSize > this.config.maxFileSize) {
      await this.rotateFile();
    }

    await fs.appendFile(this.currentFile, line, { mode: 0o600 });
    this.currentSize += lineSize;
  }

  private async rotateFile(): Promise<void> {
    // Create new file with timestamp
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const newFile = path.join(this.config.directory, `audit-${timestamp}.log`);

    // Optionally compress old file
    if (this.config.compressionEnabled) {
      await this.compressFile(this.currentFile);
    }

    this.currentFile = newFile;
    this.currentSize = 0;

    // Cleanup old files beyond retention limit
    await this.cleanupOldFiles();
  }
}
```

### HMAC Key Storage

The HMAC key must be stored separately from logs:

```typescript
// HMAC key stored in separate encrypted file
const HMAC_KEY_FILE = '~/.xrpl-wallet-mcp/audit-hmac.key.enc';

async function loadOrCreateHmacKey(password: string): Promise<Buffer> {
  if (await fileExists(HMAC_KEY_FILE)) {
    return decryptHmacKey(HMAC_KEY_FILE, password);
  }

  // Generate new HMAC key
  const hmacKey = crypto.randomBytes(32);
  await encryptAndSaveHmacKey(hmacKey, HMAC_KEY_FILE, password);
  return hmacKey;
}
```

### Compliance Export

```typescript
interface ComplianceExport {
  exportDate: string;
  startSequence: number;
  endSequence: number;
  entries: AuditLogEntry[];
  chainVerification: ChainVerificationResult;
  signature: string;  // Signed by export key
}

async function exportForCompliance(
  startDate: Date,
  endDate: Date
): Promise<ComplianceExport> {
  const entries = await queryLogsByDateRange(startDate, endDate);
  const verification = await auditLogger.verifyChain(entries);

  const export_: ComplianceExport = {
    exportDate: new Date().toISOString(),
    startSequence: entries[0]?.sequence ?? 0,
    endSequence: entries[entries.length - 1]?.sequence ?? 0,
    entries,
    chainVerification: verification,
    signature: ''
  };

  export_.signature = await signExport(export_);
  return export_;
}
```

## Security Considerations

### What to Log

| Category | Fields to Log |
|----------|---------------|
| Transaction | Type, destination (address only), amount, hash |
| Authentication | Event type, success/failure, lockout status |
| Policy | Decision, matched rule, tier |
| System | Config changes, startup/shutdown |

### What NOT to Log

| Category | Reason |
|----------|--------|
| Private keys | Direct fund theft risk |
| Seeds/mnemonics | Recovery phrase exposure |
| Passwords | Credential theft |
| Full transaction blobs | May contain sensitive memos |
| HMAC key | Would allow tampering |

### Compliance Mapping

| Requirement | Implementation |
|-------------|----------------|
| AUDIT-001 | HMAC-SHA256 hash chain |
| AUDIT-002 | All required events logged |
| AUDIT-003 | Sensitive data never logged |
| AUDIT-004 | Monotonic sequence numbers |
| AUDIT-005 | ISO 8601 timestamps in hash |
| AUDIT-006 | Correlation ID in all entries |
| AUDIT-007 | Append-only file storage |

## References

- [Cossack Labs - Audit Log Security](https://www.cossacklabs.com/blog/audit-logs-security/)
- [Pangea - Tamperproof Logging](https://pangea.cloud/blog/a-tamperproof-logging-implementation)
- [SOC 2 Trust Services Criteria](https://www.aicpa.org/soc2)
- Security Requirements: AUDIT-001 through AUDIT-007

## Related ADRs

- [ADR-001: Key Storage](ADR-001-key-storage.md) - HMAC key encrypted alongside keystore
- [ADR-003: Policy Engine](ADR-003-policy-engine.md) - Policy decisions logged
- [ADR-007: Rate Limiting](ADR-007-rate-limiting.md) - Rate limit events logged

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Tech Lead | Initial ADR |
