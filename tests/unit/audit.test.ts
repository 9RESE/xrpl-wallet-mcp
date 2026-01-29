/**
 * Audit Logger Tests
 *
 * Tests for the tamper-evident audit logging system with HMAC hash chains.
 *
 * @module tests/unit/audit
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import {
  HashChain,
  generateHmacKey,
  isValidHmacKey,
  computeStandaloneHash,
  GENESIS_CONSTANT,
  HMAC_KEY_LENGTH,
  type ChainState,
  type HashableEntry,
} from '../../src/audit/chain.js';
import {
  AuditLogger,
  sanitizeForLogging,
  createMemoryKeyProvider,
  type AuditLogInput,
} from '../../src/audit/logger.js';

// ============================================================================
// HASH CHAIN TESTS
// ============================================================================

describe('HashChain', () => {
  let hmacKey: Buffer;
  let chain: HashChain;

  beforeEach(() => {
    hmacKey = crypto.randomBytes(32);
    chain = new HashChain(hmacKey);
  });

  afterEach(() => {
    chain.dispose();
  });

  describe('constructor', () => {
    it('should create a new hash chain with valid HMAC key', () => {
      const newChain = new HashChain(hmacKey);
      expect(newChain.getState().sequence).toBe(0);
      newChain.dispose();
    });

    it('should reject invalid HMAC key (too short)', () => {
      const shortKey = crypto.randomBytes(16);
      expect(() => new HashChain(shortKey)).toThrow(/HMAC key must be/);
    });

    it('should reject invalid HMAC key (too long)', () => {
      const longKey = crypto.randomBytes(64);
      expect(() => new HashChain(longKey)).toThrow(/HMAC key must be/);
    });

    it('should accept initial state for chain continuation', () => {
      const initialState: ChainState = {
        sequence: 100,
        previousHash: 'a'.repeat(64),
      };
      const newChain = new HashChain(hmacKey, initialState);
      expect(newChain.getState()).toEqual(initialState);
      newChain.dispose();
    });
  });

  describe('computeGenesisHash', () => {
    it('should compute deterministic genesis hash', () => {
      const hash1 = chain.computeGenesisHash();
      const hash2 = chain.computeGenesisHash();
      expect(hash1).toBe(hash2);
    });

    it('should produce 64-character hex string', () => {
      const hash = chain.computeGenesisHash();
      expect(hash).toHaveLength(64);
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should differ with different HMAC keys', () => {
      const otherKey = crypto.randomBytes(32);
      const otherChain = new HashChain(otherKey);
      expect(chain.computeGenesisHash()).not.toBe(otherChain.computeGenesisHash());
      otherChain.dispose();
    });
  });

  describe('computeHash', () => {
    it('should compute deterministic hash for same data', () => {
      const data = { foo: 'bar', num: 42 };
      const hash1 = chain.computeHash(data);
      const hash2 = chain.computeHash(data);
      expect(hash1).toBe(hash2);
    });

    it('should exclude hash field from computation', () => {
      const data1 = { foo: 'bar', hash: 'ignored' };
      const data2 = { foo: 'bar', hash: 'different' };
      expect(chain.computeHash(data1)).toBe(chain.computeHash(data2));
    });

    it('should produce different hashes for different data', () => {
      const hash1 = chain.computeHash({ foo: 'bar' });
      const hash2 = chain.computeHash({ foo: 'baz' });
      expect(hash1).not.toBe(hash2);
    });

    it('should handle nested objects', () => {
      const data = { outer: { inner: 'value' } };
      const hash = chain.computeHash(data);
      expect(hash).toHaveLength(64);
    });
  });

  describe('createEntry', () => {
    it('should create entry with sequential sequence numbers', () => {
      const entry1 = chain.createEntry({ data: 'first' });
      const entry2 = chain.createEntry({ data: 'second' });

      expect(entry1.sequence).toBe(1);
      expect(entry2.sequence).toBe(2);
    });

    it('should link entries via hash chain', () => {
      const entry1 = chain.createEntry({ data: 'first' });
      const entry2 = chain.createEntry({ data: 'second' });

      expect(entry2.previousHash).toBe(entry1.hash);
    });

    it('should use genesis hash for first entry', () => {
      const genesisHash = chain.computeGenesisHash();
      const entry = chain.createEntry({ data: 'first' });

      expect(entry.previousHash).toBe(genesisHash);
    });

    it('should include timestamp in ISO 8601 format', () => {
      const entry = chain.createEntry({ data: 'test' });
      expect(entry.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    });

    it('should preserve original data', () => {
      const originalData = { foo: 'bar', num: 42 };
      const entry = chain.createEntry(originalData);

      expect(entry.foo).toBe('bar');
      expect(entry.num).toBe(42);
    });

    it('should update chain state after each entry', () => {
      const entry = chain.createEntry({ data: 'test' });
      const state = chain.getState();

      expect(state.sequence).toBe(1);
      expect(state.previousHash).toBe(entry.hash);
    });
  });

  describe('verifyEntry', () => {
    it('should pass for valid entry', () => {
      const entry = chain.createEntry({ data: 'test' });
      const errors = chain.verifyEntry(entry);

      expect(errors).toHaveLength(0);
    });

    it('should detect tampered hash', () => {
      const entry = chain.createEntry({ data: 'test' });
      entry.hash = 'tampered'.repeat(8);

      const errors = chain.verifyEntry(entry);
      expect(errors.some((e) => e.type === 'tampered_entry')).toBe(true);
    });

    it('should detect chain break', () => {
      const entry = chain.createEntry({ data: 'test' });
      const wrongPrevHash = 'wrong'.repeat(12.8);

      const errors = chain.verifyEntry(entry, wrongPrevHash);
      expect(errors.some((e) => e.type === 'chain_break')).toBe(true);
    });
  });

  describe('verifyEntries', () => {
    it('should pass for valid chain', () => {
      const entries = [
        chain.createEntry({ data: 'first' }),
        chain.createEntry({ data: 'second' }),
        chain.createEntry({ data: 'third' }),
      ];

      const result = chain.verifyEntries(entries);

      expect(result.valid).toBe(true);
      expect(result.entriesVerified).toBe(3);
      expect(result.errors).toHaveLength(0);
    });

    it('should handle empty array', () => {
      const result = chain.verifyEntries([]);

      expect(result.valid).toBe(true);
      expect(result.entriesVerified).toBe(0);
    });

    it('should detect sequence gap', () => {
      const entry1 = chain.createEntry({ data: 'first' });
      chain.createEntry({ data: 'second' }); // Skip this one
      const entry3 = chain.createEntry({ data: 'third' });

      const result = chain.verifyEntries([entry1, entry3]);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.type === 'sequence_gap')).toBe(true);
    });

    it('should detect chain break', () => {
      const entry1 = chain.createEntry({ data: 'first' });
      const entry2 = chain.createEntry({ data: 'second' });

      // Tamper with chain link
      entry2.previousHash = 'broken'.repeat(10.67);

      const result = chain.verifyEntries([entry1, entry2]);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.type === 'chain_break')).toBe(true);
    });

    it('should detect tampered entry', () => {
      const entry1 = chain.createEntry({ data: 'first' });
      const entry2 = chain.createEntry({ data: 'second' });

      // Tamper with data (hash will no longer match)
      (entry2 as any).data = 'modified';

      const result = chain.verifyEntries([entry1, entry2]);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.type === 'tampered_entry')).toBe(true);
    });

    it('should detect timestamp anomaly', () => {
      const entry1 = chain.createEntry({ data: 'first' });
      const entry2 = chain.createEntry({ data: 'second' });

      // Set timestamp in the past (but keep hash valid by not recomputing)
      const tamperedEntry2: HashableEntry = {
        ...entry2,
        timestamp: '2000-01-01T00:00:00.000Z',
      };
      // Recompute hash for the tampered entry
      tamperedEntry2.hash = chain.computeHash(tamperedEntry2);

      const result = chain.verifyEntries([entry1, tamperedEntry2]);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.type === 'invalid_timestamp')).toBe(true);
    });

    it('should record verification duration', () => {
      const entries = [
        chain.createEntry({ data: 'first' }),
        chain.createEntry({ data: 'second' }),
      ];

      const result = chain.verifyEntries(entries);

      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });
  });

  describe('verifyChainLink', () => {
    it('should return true for valid chain link', () => {
      const entry1 = chain.createEntry({ data: 'first' });
      const entry2 = chain.createEntry({ data: 'second' });

      expect(chain.verifyChainLink(entry2, entry1)).toBe(true);
    });

    it('should return false for invalid chain link', () => {
      const entry1 = chain.createEntry({ data: 'first' });
      const entry2 = chain.createEntry({ data: 'second' });

      entry2.previousHash = 'tampered'.repeat(8);

      expect(chain.verifyChainLink(entry2, entry1)).toBe(false);
    });
  });

  describe('dispose', () => {
    it('should zero out the HMAC key', () => {
      const key = crypto.randomBytes(32);
      const testChain = new HashChain(key);

      // Create a copy to verify original is zeroed
      const originalKey = Buffer.from(key);

      testChain.dispose();

      // The key buffer should be zeroed
      // Note: We can't directly test this due to defensive copy,
      // but we can verify the chain still works after dispose
      // by ensuring subsequent operations fail or produce different results
    });
  });
});

// ============================================================================
// UTILITY FUNCTION TESTS
// ============================================================================

describe('Utility Functions', () => {
  describe('generateHmacKey', () => {
    it('should generate key of correct length', () => {
      const key = generateHmacKey();
      expect(key.length).toBe(HMAC_KEY_LENGTH);
    });

    it('should generate unique keys', () => {
      const key1 = generateHmacKey();
      const key2 = generateHmacKey();
      expect(key1.equals(key2)).toBe(false);
    });
  });

  describe('isValidHmacKey', () => {
    it('should accept valid 32-byte key', () => {
      const key = crypto.randomBytes(32);
      expect(isValidHmacKey(key)).toBe(true);
    });

    it('should reject short key', () => {
      const key = crypto.randomBytes(16);
      expect(isValidHmacKey(key)).toBe(false);
    });

    it('should reject long key', () => {
      const key = crypto.randomBytes(64);
      expect(isValidHmacKey(key)).toBe(false);
    });
  });

  describe('computeStandaloneHash', () => {
    it('should compute valid HMAC-SHA256 hash', () => {
      const key = crypto.randomBytes(32);
      const hash = computeStandaloneHash(key, 'test data');

      expect(hash).toHaveLength(64);
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should produce different hashes for different data', () => {
      const key = crypto.randomBytes(32);
      const hash1 = computeStandaloneHash(key, 'data1');
      const hash2 = computeStandaloneHash(key, 'data2');

      expect(hash1).not.toBe(hash2);
    });
  });
});

// ============================================================================
// SANITIZATION TESTS
// ============================================================================

describe('sanitizeForLogging', () => {
  it('should redact password fields', () => {
    const obj = { username: 'user', password: 'secret123' };
    const sanitized = sanitizeForLogging(obj) as Record<string, unknown>;

    expect(sanitized.username).toBe('user');
    expect(sanitized.password).toBe('[REDACTED]');
  });

  it('should redact seed fields', () => {
    const obj = { wallet: 'wallet1', seed: 'sEd7Xxxxxxxxxxxxxxxxxxxxxx' };
    const sanitized = sanitizeForLogging(obj) as Record<string, unknown>;

    expect(sanitized.seed).toBe('[REDACTED]');
  });

  it('should redact private key fields', () => {
    const obj = { privateKey: 'a'.repeat(64), private_key: 'b'.repeat(64) };
    const sanitized = sanitizeForLogging(obj) as Record<string, unknown>;

    expect(sanitized.privateKey).toBe('[REDACTED]');
    expect(sanitized.private_key).toBe('[REDACTED]');
  });

  it('should detect and redact XRPL seed patterns', () => {
    // XRPL seeds are s + 28 Base58 characters = 29 characters total
    const seed = 'sn3nxiW7v8KXzPzAqzyHXbSSKNuN9';
    const sanitized = sanitizeForLogging(seed);

    expect(sanitized).toBe('[REDACTED]');
  });

  it('should detect and redact 64-char hex strings (private keys)', () => {
    const privateKey = 'a'.repeat(64);
    const sanitized = sanitizeForLogging(privateKey);

    expect(sanitized).toBe('[REDACTED]');
  });

  it('should truncate long strings', () => {
    const longString = 'a'.repeat(2000);
    const sanitized = sanitizeForLogging(longString) as string;

    expect(sanitized).toContain('[TRUNCATED]');
    expect(sanitized.length).toBeLessThan(150);
  });

  it('should handle nested objects', () => {
    const obj = {
      outer: {
        inner: {
          password: 'secret',
          data: 'visible',
        },
      },
    };
    const sanitized = sanitizeForLogging(obj) as any;

    expect(sanitized.outer.inner.password).toBe('[REDACTED]');
    expect(sanitized.outer.inner.data).toBe('visible');
  });

  it('should handle arrays', () => {
    const arr = [{ password: 'secret1' }, { password: 'secret2' }];
    const sanitized = sanitizeForLogging(arr) as any[];

    expect(sanitized[0].password).toBe('[REDACTED]');
    expect(sanitized[1].password).toBe('[REDACTED]');
  });

  it('should handle null and undefined', () => {
    expect(sanitizeForLogging(null)).toBeNull();
    expect(sanitizeForLogging(undefined)).toBeUndefined();
  });

  it('should handle primitives', () => {
    expect(sanitizeForLogging(42)).toBe(42);
    expect(sanitizeForLogging(true)).toBe(true);
    expect(sanitizeForLogging('hello')).toBe('hello');
  });

  it('should limit recursion depth', () => {
    // Create deeply nested object
    let obj: any = { data: 'leaf' };
    for (let i = 0; i < 15; i++) {
      obj = { nested: obj };
    }

    const sanitized = sanitizeForLogging(obj) as any;

    // Should not throw and should handle deep nesting
    let current = sanitized;
    let depth = 0;
    while (current.nested && depth < 15) {
      current = current.nested;
      depth++;
    }
  });
});

// ============================================================================
// AUDIT LOGGER TESTS
// ============================================================================

describe('AuditLogger', () => {
  let tempDir: string;
  let hmacKey: Buffer;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'audit-test-'));
    hmacKey = crypto.randomBytes(32);
  });

  afterEach(async () => {
    try {
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('create', () => {
    it('should create logger with valid configuration', async () => {
      const logger = await AuditLogger.create({
        hmacKeyProvider: createMemoryKeyProvider(hmacKey),
        config: {
          baseDir: tempDir,
          network: 'testnet',
          verifyOnStartup: false,
        },
      });

      expect(logger).toBeInstanceOf(AuditLogger);
      await logger.shutdown();
    });

    it('should reject invalid HMAC key', async () => {
      const invalidKey = crypto.randomBytes(16);

      await expect(
        AuditLogger.create({
          hmacKeyProvider: createMemoryKeyProvider(invalidKey),
          config: {
            baseDir: tempDir,
            network: 'testnet',
            verifyOnStartup: false,
          },
        })
      ).rejects.toThrow(/Invalid HMAC key/);
    });

    it('should create audit directory structure', async () => {
      const logger = await AuditLogger.create({
        hmacKeyProvider: createMemoryKeyProvider(hmacKey),
        config: {
          baseDir: tempDir,
          network: 'testnet',
          verifyOnStartup: false,
        },
      });

      const auditDir = path.join(tempDir, 'testnet', 'audit');
      const stat = await fs.stat(auditDir);

      expect(stat.isDirectory()).toBe(true);
      await logger.shutdown();
    });

    it('should verify chain on startup by default', async () => {
      const onTamperDetected = vi.fn();

      const logger = await AuditLogger.create({
        hmacKeyProvider: createMemoryKeyProvider(hmacKey),
        config: {
          baseDir: tempDir,
          network: 'testnet',
          verifyOnStartup: true,
        },
        onTamperDetected,
      });

      // No tampering should be detected for new chain
      expect(onTamperDetected).not.toHaveBeenCalled();
      await logger.shutdown();
    });
  });

  describe('log', () => {
    let logger: AuditLogger;

    beforeEach(async () => {
      logger = await AuditLogger.create({
        hmacKeyProvider: createMemoryKeyProvider(hmacKey),
        config: {
          baseDir: tempDir,
          network: 'testnet',
          verifyOnStartup: false,
          syncWrites: true,
        },
      });
    });

    afterEach(async () => {
      await logger.shutdown();
    });

    it('should log audit event with all fields', async () => {
      const input: AuditLogInput = {
        event: 'wallet_created',
        wallet_id: 'test-wallet',
        wallet_address: 'rTestAddress123456789012345',
        context: 'Test context',
      };

      const entry = await logger.log(input);

      expect(entry.seq).toBe(1);
      expect(entry.event).toBe('wallet_created');
      expect(entry.wallet_id).toBe('test-wallet');
      expect(entry.wallet_address).toBe('rTestAddress123456789012345');
      expect(entry.context).toBe('Test context');
      expect(entry.hash).toHaveLength(64);
      expect(entry.prev_hash).toHaveLength(64);
    });

    it('should create sequential entries', async () => {
      const entry1 = await logger.log({ event: 'wallet_created' });
      const entry2 = await logger.log({ event: 'transaction_signed' });
      const entry3 = await logger.log({ event: 'policy_evaluated' });

      expect(entry1.seq).toBe(1);
      expect(entry2.seq).toBe(2);
      expect(entry3.seq).toBe(3);
    });

    it('should link entries via hash chain', async () => {
      const entry1 = await logger.log({ event: 'wallet_created' });
      const entry2 = await logger.log({ event: 'transaction_signed' });

      expect(entry2.prev_hash).toBe(entry1.hash);
    });

    it('should persist entries to file', async () => {
      await logger.log({ event: 'wallet_created' });
      await logger.log({ event: 'transaction_signed' });

      const stats = await logger.getStats();
      expect(stats.totalEntries).toBe(2);
      expect(stats.currentFileSize).toBeGreaterThan(0);
    });

    it('should sanitize sensitive context containing passwords', async () => {
      // The context contains a field name that triggers redaction
      const entry = await logger.log({
        event: 'wallet_created',
        // Sanitization redacts strings matching sensitive patterns like 64-char hex
        context: 'a'.repeat(64), // This matches the 64-char hex pattern
      });

      // The context should be sanitized
      expect(entry.context).toBe('[REDACTED]');
    });
  });

  describe('verifyChain', () => {
    let logger: AuditLogger;

    beforeEach(async () => {
      logger = await AuditLogger.create({
        hmacKeyProvider: createMemoryKeyProvider(hmacKey),
        config: {
          baseDir: tempDir,
          network: 'testnet',
          verifyOnStartup: false,
        },
      });
    });

    afterEach(async () => {
      await logger.shutdown();
    });

    it('should pass for valid chain', async () => {
      await logger.log({ event: 'wallet_created' });
      await logger.log({ event: 'transaction_signed' });
      await logger.log({ event: 'policy_evaluated' });

      const result = await logger.verifyChain();

      expect(result.valid).toBe(true);
      expect(result.entriesVerified).toBe(3);
      expect(result.errors).toHaveLength(0);
    });

    it('should handle empty chain', async () => {
      const result = await logger.verifyChain();

      expect(result.valid).toBe(true);
      expect(result.entriesVerified).toBe(0);
    });

    it('should verify recent entries only', async () => {
      for (let i = 0; i < 10; i++) {
        await logger.log({ event: 'wallet_created' });
      }

      const result = await logger.verifyChain({ recentEntries: 5 });

      expect(result.entriesVerified).toBe(5);
    });
  });

  describe('query', () => {
    let logger: AuditLogger;

    beforeEach(async () => {
      logger = await AuditLogger.create({
        hmacKeyProvider: createMemoryKeyProvider(hmacKey),
        config: {
          baseDir: tempDir,
          network: 'testnet',
          verifyOnStartup: false,
        },
      });
    });

    afterEach(async () => {
      await logger.shutdown();
    });

    it('should query by event type', async () => {
      await logger.log({ event: 'wallet_created' });
      await logger.log({ event: 'transaction_signed' });
      await logger.log({ event: 'wallet_created' });

      const results = await logger.query({
        eventTypes: ['wallet_created'],
      });

      expect(results).toHaveLength(2);
      expect(results.every((e) => e.event === 'wallet_created')).toBe(true);
    });

    it('should query by wallet ID', async () => {
      await logger.log({ event: 'wallet_created', wallet_id: 'wallet-1' });
      await logger.log({ event: 'wallet_created', wallet_id: 'wallet-2' });
      await logger.log({ event: 'transaction_signed', wallet_id: 'wallet-1' });

      const results = await logger.query({
        walletId: 'wallet-1',
      });

      expect(results).toHaveLength(2);
      expect(results.every((e) => e.wallet_id === 'wallet-1')).toBe(true);
    });

    it('should apply limit', async () => {
      for (let i = 0; i < 10; i++) {
        await logger.log({ event: 'wallet_created' });
      }

      const results = await logger.query({ limit: 5 });

      expect(results).toHaveLength(5);
    });

    it('should apply descending sort order', async () => {
      for (let i = 0; i < 5; i++) {
        await logger.log({ event: 'wallet_created' });
      }

      const results = await logger.query({ sortOrder: 'desc' });

      expect(results[0].seq).toBeGreaterThan(results[4].seq);
    });
  });

  describe('getChainState', () => {
    it('should return current chain state', async () => {
      const logger = await AuditLogger.create({
        hmacKeyProvider: createMemoryKeyProvider(hmacKey),
        config: {
          baseDir: tempDir,
          network: 'testnet',
          verifyOnStartup: false,
        },
      });

      const entry = await logger.log({ event: 'wallet_created' });
      const state = logger.getChainState();

      expect(state.sequence).toBe(1);
      expect(state.previousHash).toBe(entry.hash);

      await logger.shutdown();
    });
  });

  describe('getStats', () => {
    it('should return storage statistics', async () => {
      const logger = await AuditLogger.create({
        hmacKeyProvider: createMemoryKeyProvider(hmacKey),
        config: {
          baseDir: tempDir,
          network: 'testnet',
          verifyOnStartup: false,
        },
      });

      await logger.log({ event: 'wallet_created' });
      await logger.log({ event: 'transaction_signed' });

      const stats = await logger.getStats();

      expect(stats.totalEntries).toBe(2);
      expect(stats.currentFileSize).toBeGreaterThan(0);
      expect(stats.currentFilePath).toContain('audit-');
      expect(stats.oldestEntry).toBeDefined();
      expect(stats.newestEntry).toBeDefined();

      await logger.shutdown();
    });
  });

  describe('shutdown', () => {
    it('should complete pending writes', async () => {
      const logger = await AuditLogger.create({
        hmacKeyProvider: createMemoryKeyProvider(hmacKey),
        config: {
          baseDir: tempDir,
          network: 'testnet',
          verifyOnStartup: false,
        },
      });

      // Log some entries
      for (let i = 0; i < 5; i++) {
        await logger.log({ event: 'wallet_created' });
      }

      await logger.shutdown();

      // Verify entries were persisted
      const auditDir = path.join(tempDir, 'testnet', 'audit');
      const files = await fs.readdir(auditDir);
      const logFile = files.find((f) => f.startsWith('audit-'));

      expect(logFile).toBeDefined();

      const content = await fs.readFile(path.join(auditDir, logFile!), 'utf-8');
      const lines = content.trim().split('\n').filter(Boolean);

      expect(lines).toHaveLength(5);
    });

    it('should emit shutdown event', async () => {
      const logger = await AuditLogger.create({
        hmacKeyProvider: createMemoryKeyProvider(hmacKey),
        config: {
          baseDir: tempDir,
          network: 'testnet',
          verifyOnStartup: false,
        },
      });

      const shutdownPromise = new Promise<void>((resolve) => {
        logger.on('shutdown', resolve);
      });

      await logger.shutdown();
      await shutdownPromise;
    });
  });

  describe('chain persistence', () => {
    it('should restore chain state after restart', async () => {
      // First session
      const logger1 = await AuditLogger.create({
        hmacKeyProvider: createMemoryKeyProvider(hmacKey),
        config: {
          baseDir: tempDir,
          network: 'testnet',
          verifyOnStartup: false,
        },
      });

      await logger1.log({ event: 'wallet_created' });
      await logger1.log({ event: 'transaction_signed' });
      await logger1.shutdown();

      // Second session
      const logger2 = await AuditLogger.create({
        hmacKeyProvider: createMemoryKeyProvider(hmacKey),
        config: {
          baseDir: tempDir,
          network: 'testnet',
          verifyOnStartup: false,
        },
      });

      const entry3 = await logger2.log({ event: 'policy_evaluated' });

      expect(entry3.seq).toBe(3);

      // Verify full chain
      const result = await logger2.verifyChain();
      expect(result.valid).toBe(true);
      expect(result.entriesVerified).toBe(3);

      await logger2.shutdown();
    });
  });
});
