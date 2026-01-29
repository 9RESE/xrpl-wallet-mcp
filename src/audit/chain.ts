/**
 * Hash Chain Implementation for Audit Logging
 *
 * Implements HMAC-SHA256 hash chain for tamper-evident audit logs.
 * Formula: hash(N) = HMAC-SHA256(data_N || prev_hash)
 *
 * @module audit/chain
 * @version 1.0.0
 * @since 2026-01-28
 */

import { createHmac } from 'crypto';
import { z } from 'zod';

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * Genesis constant used to compute the starting hash of a new chain
 */
const GENESIS_CONSTANT = 'XRPL-WALLET-MCP-GENESIS-V1';

/**
 * HMAC algorithm used for hash chain
 */
const HMAC_ALGORITHM = 'sha256';

/**
 * Required HMAC key length in bytes (256 bits)
 */
const HMAC_KEY_LENGTH = 32;

// ============================================================================
// TYPES
// ============================================================================

/**
 * Current state of the hash chain
 */
export interface ChainState {
  /** Current sequence number (0 if no entries) */
  sequence: number;

  /** Hash of the previous entry (or genesis hash if sequence is 0) */
  previousHash: string;
}

/**
 * Error types that can occur during chain verification
 */
export type ChainErrorType =
  | 'sequence_gap'
  | 'chain_break'
  | 'tampered_entry'
  | 'invalid_timestamp';

/**
 * Represents an error found during chain verification
 */
export interface ChainError {
  /** Type of error detected */
  type: ChainErrorType;

  /** Sequence number where error was detected */
  sequence: number;

  /** Expected value */
  expected: string | number;

  /** Actual value found */
  actual: string | number;

  /** Human-readable description */
  description: string;
}

/**
 * Result of chain verification
 */
export interface ChainVerificationResult {
  /** Whether the chain is valid */
  valid: boolean;

  /** Number of entries verified */
  entriesVerified: number;

  /** First sequence number verified */
  startSequence: number;

  /** Last sequence number verified */
  endSequence: number;

  /** Verification duration in milliseconds */
  durationMs: number;

  /** List of detected errors */
  errors: ChainError[];
}

/**
 * Options for chain verification
 */
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

/**
 * Data structure that can be hashed (must be JSON serializable)
 */
export interface HashableEntry {
  /** Sequence number */
  sequence: number;

  /** Entry timestamp */
  timestamp: string;

  /** Hash of previous entry */
  previousHash: string;

  /** This entry's hash (excluded from hash computation) */
  hash: string;

  /** Any additional data */
  [key: string]: unknown;
}

// ============================================================================
// SCHEMAS
// ============================================================================

/**
 * Schema for HMAC key validation
 */
export const HmacKeySchema = z
  .instanceof(Buffer)
  .refine(
    (buf) => buf.length === HMAC_KEY_LENGTH,
    `HMAC key must be exactly ${HMAC_KEY_LENGTH} bytes (${HMAC_KEY_LENGTH * 8} bits)`
  );

/**
 * Schema for chain state
 */
export const ChainStateSchema = z.object({
  sequence: z.number().int().min(0),
  previousHash: z.string().length(64).regex(/^[a-f0-9]{64}$/i),
});

/**
 * Schema for verification options
 */
export const VerificationOptionsSchema = z.object({
  fullChain: z.boolean().optional(),
  startSequence: z.number().int().positive().optional(),
  endSequence: z.number().int().positive().optional(),
  recentEntries: z.number().int().positive().optional(),
  continueOnError: z.boolean().optional(),
});

// ============================================================================
// HASH CHAIN CLASS
// ============================================================================

/**
 * HashChain - Manages HMAC-SHA256 hash chain for tamper-evident logging
 *
 * The hash chain provides:
 * - Tamper detection: Any modification breaks the chain
 * - Deletion detection: Sequence gaps reveal deleted entries
 * - Cryptographic proof: HMAC-SHA256 provides strong integrity guarantee
 *
 * @example
 * ```typescript
 * const hmacKey = crypto.randomBytes(32);
 * const chain = new HashChain(hmacKey);
 *
 * const entry = chain.createEntry({ event: 'test', data: 'value' });
 * console.log(entry.hash); // HMAC-SHA256 hash
 *
 * // Later, verify entries
 * const result = chain.verifyEntries(entries);
 * if (!result.valid) {
 *   console.error('Chain tampering detected!', result.errors);
 * }
 * ```
 */
export class HashChain {
  private readonly hmacKey: Buffer;
  private state: ChainState;

  /**
   * Create a new HashChain instance
   *
   * @param hmacKey - 256-bit HMAC key (32 bytes)
   * @param initialState - Optional initial chain state (for resuming)
   * @throws Error if HMAC key is invalid
   */
  constructor(hmacKey: Buffer, initialState?: ChainState) {
    // Validate HMAC key
    const keyResult = HmacKeySchema.safeParse(hmacKey);
    if (!keyResult.success) {
      throw new Error(`Invalid HMAC key: ${keyResult.error.message}`);
    }

    this.hmacKey = Buffer.from(hmacKey); // Create defensive copy
    this.state = initialState ?? {
      sequence: 0,
      previousHash: this.computeGenesisHash(),
    };
  }

  /**
   * Compute the genesis hash for a new chain
   *
   * The genesis hash is a well-known constant computed from the
   * GENESIS_CONSTANT using the HMAC key. This provides a verifiable
   * starting point for the chain.
   *
   * @returns Hex-encoded genesis hash
   */
  computeGenesisHash(): string {
    const hmac = createHmac(HMAC_ALGORITHM, this.hmacKey);
    hmac.update(GENESIS_CONSTANT);
    return hmac.digest('hex');
  }

  /**
   * Compute HMAC-SHA256 hash of entry data
   *
   * The hash includes all fields except 'hash' itself. Fields are
   * sorted alphabetically for deterministic serialization.
   *
   * @param data - Entry data (hash field will be ignored)
   * @returns Hex-encoded HMAC-SHA256 hash
   */
  computeHash(data: Record<string, unknown>): string {
    // Create copy without hash field for hashing
    const dataForHashing: Record<string, unknown> = {};
    for (const key of Object.keys(data).sort()) {
      if (key !== 'hash') {
        dataForHashing[key] = data[key];
      }
    }

    // Serialize with sorted keys for determinism
    const serialized = JSON.stringify(dataForHashing, Object.keys(dataForHashing).sort());

    // Compute HMAC
    const hmac = createHmac(HMAC_ALGORITHM, this.hmacKey);
    hmac.update(serialized);
    return hmac.digest('hex');
  }

  /**
   * Get the current chain state
   *
   * @returns Current sequence number and previous hash
   */
  getState(): ChainState {
    return { ...this.state };
  }

  /**
   * Set the chain state (for resuming from storage)
   *
   * @param state - Chain state to restore
   */
  setState(state: ChainState): void {
    const result = ChainStateSchema.safeParse(state);
    if (!result.success) {
      throw new Error(`Invalid chain state: ${result.error.message}`);
    }
    this.state = { ...state };
  }

  /**
   * Create the next entry in the chain
   *
   * Adds integrity fields (sequence, timestamp, previousHash, hash)
   * to the provided data and updates the chain state.
   *
   * @param data - Entry data (without integrity fields)
   * @returns Complete entry with hash chain fields
   */
  createEntry<T extends Record<string, unknown>>(data: T): T & HashableEntry {
    const sequence = this.state.sequence + 1;
    const timestamp = new Date().toISOString();
    const previousHash = this.state.previousHash;

    // Create entry with all fields
    const entry = {
      ...data,
      sequence,
      timestamp,
      previousHash,
      hash: '',
    } as T & HashableEntry;

    // Compute and set hash
    entry.hash = this.computeHash(entry);

    // Update chain state
    this.state = {
      sequence,
      previousHash: entry.hash,
    };

    return entry;
  }

  /**
   * Verify hash integrity of a single entry
   *
   * @param entry - Entry to verify
   * @param expectedPrevHash - Expected previous hash (from prior entry or genesis)
   * @returns Array of errors found (empty if valid)
   */
  verifyEntry(entry: HashableEntry, expectedPrevHash?: string): ChainError[] {
    const errors: ChainError[] = [];

    // Check previous hash chain
    if (expectedPrevHash !== undefined && entry.previousHash !== expectedPrevHash) {
      errors.push({
        type: 'chain_break',
        sequence: entry.sequence,
        expected: expectedPrevHash,
        actual: entry.previousHash,
        description: `Chain break: previousHash does not match prior entry's hash`,
      });
    }

    // Verify entry hash
    const computedHash = this.computeHash(entry);
    if (computedHash !== entry.hash) {
      errors.push({
        type: 'tampered_entry',
        sequence: entry.sequence,
        expected: computedHash,
        actual: entry.hash,
        description: `Entry hash mismatch: entry may have been tampered with`,
      });
    }

    return errors;
  }

  /**
   * Verify a sequence of entries
   *
   * Checks:
   * 1. Sequence numbers are monotonic without gaps
   * 2. Each entry's previousHash matches prior entry's hash
   * 3. Each entry's hash can be recomputed correctly
   * 4. Timestamps are monotonically increasing
   *
   * @param entries - Array of entries to verify (must be in sequence order)
   * @param options - Verification options
   * @returns Verification result with any detected errors
   */
  verifyEntries(
    entries: HashableEntry[],
    options: VerificationOptions = {}
  ): ChainVerificationResult {
    const startTime = Date.now();
    const errors: ChainError[] = [];

    if (entries.length === 0) {
      return {
        valid: true,
        entriesVerified: 0,
        startSequence: 0,
        endSequence: 0,
        durationMs: Date.now() - startTime,
        errors: [],
      };
    }

    // Get first and last entries (safe after length check)
    const firstEntry = entries[0]!;
    const lastEntry = entries[entries.length - 1]!;

    // Determine expected previous hash for first entry
    let expectedPrevHash: string;
    if (firstEntry.sequence === 1) {
      expectedPrevHash = this.computeGenesisHash();
    } else {
      // For partial verification, we trust the first entry's previousHash
      // unless we have explicit starting state
      expectedPrevHash = firstEntry.previousHash;
    }

    let expectedSequence = firstEntry.sequence;
    let lastTimestamp = new Date(0);

    for (const entry of entries) {
      // Check 1: Sequence continuity
      if (entry.sequence !== expectedSequence) {
        errors.push({
          type: 'sequence_gap',
          sequence: entry.sequence,
          expected: expectedSequence,
          actual: entry.sequence,
          description: `Expected sequence ${expectedSequence}, got ${entry.sequence}`,
        });

        if (!options.continueOnError) {
          // Adjust expected for subsequent checks
          expectedSequence = entry.sequence;
        }
      }

      // Check 2: Previous hash chain
      if (entry.previousHash !== expectedPrevHash) {
        errors.push({
          type: 'chain_break',
          sequence: entry.sequence,
          expected: expectedPrevHash,
          actual: entry.previousHash,
          description: `Chain break: previousHash does not match prior entry's hash`,
        });
      }

      // Check 3: Entry hash integrity
      const computedHash = this.computeHash(entry);
      if (computedHash !== entry.hash) {
        errors.push({
          type: 'tampered_entry',
          sequence: entry.sequence,
          expected: computedHash,
          actual: entry.hash,
          description: `Entry hash mismatch: entry may have been tampered with`,
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
          description: `Timestamp is earlier than previous entry`,
        });
      }
      lastTimestamp = entryTime;

      // Update expectations for next iteration
      expectedPrevHash = entry.hash;
      expectedSequence = entry.sequence + 1;
    }

    return {
      valid: errors.length === 0,
      entriesVerified: entries.length,
      startSequence: firstEntry.sequence,
      endSequence: lastEntry.sequence,
      durationMs: Date.now() - startTime,
      errors,
    };
  }

  /**
   * Verify that an entry correctly links to a previous entry
   *
   * @param current - Current entry to verify
   * @param previous - Previous entry in the chain
   * @returns True if chain link is valid
   */
  verifyChainLink(current: HashableEntry, previous: HashableEntry): boolean {
    return current.previousHash === previous.hash;
  }

  /**
   * Dispose of the hash chain and zero out the HMAC key
   *
   * Should be called when the chain is no longer needed to
   * prevent key material from remaining in memory.
   */
  dispose(): void {
    this.hmacKey.fill(0);
  }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Validate that an HMAC key meets requirements
 *
 * @param key - Buffer to validate
 * @returns True if key is valid
 */
export function isValidHmacKey(key: Buffer): boolean {
  return HmacKeySchema.safeParse(key).success;
}

/**
 * Generate a cryptographically secure HMAC key
 *
 * @returns 256-bit HMAC key
 */
export function generateHmacKey(): Buffer {
  // Use Node.js crypto for secure random generation
  // This is imported at the top but we reference it dynamically
  // to allow for easy mocking in tests
  const crypto = require('crypto');
  return crypto.randomBytes(HMAC_KEY_LENGTH);
}

/**
 * Compute a standalone HMAC-SHA256 hash (without chain state)
 *
 * @param key - HMAC key
 * @param data - Data to hash
 * @returns Hex-encoded hash
 */
export function computeStandaloneHash(key: Buffer, data: string): string {
  const hmac = createHmac(HMAC_ALGORITHM, key);
  hmac.update(data);
  return hmac.digest('hex');
}

// ============================================================================
// EXPORTS
// ============================================================================

export { GENESIS_CONSTANT, HMAC_ALGORITHM, HMAC_KEY_LENGTH };
