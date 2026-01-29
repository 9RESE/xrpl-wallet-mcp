/**
 * Audit Logger Implementation
 *
 * Tamper-evident audit logging with HMAC-SHA256 hash chains.
 * Stores logs in JSON Lines format with automatic integrity verification.
 *
 * @module audit/logger
 * @version 1.0.0
 * @since 2026-01-28
 */

import { createHmac, randomUUID } from 'crypto';
import { EventEmitter } from 'events';
import * as fs from 'fs/promises';
import * as path from 'path';
import { z } from 'zod';
import {
  HashChain,
  isValidHmacKey,
  type ChainState,
  type ChainVerificationResult,
  type ChainError,
  type VerificationOptions,
  type HashableEntry,
} from './chain.js';
import {
  AuditEventTypeSchema,
  AuditLogEntrySchema,
  NetworkSchema,
  TransactionTypeSchema,
  type AuditEventType,
  type AuditLogEntry,
  type Network,
  type TransactionType,
} from '../schemas/index.js';

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * Default audit log directory relative to home
 */
const DEFAULT_BASE_DIR = '.xrpl-wallet-mcp';

/**
 * Audit subdirectory name
 */
const AUDIT_SUBDIR = 'audit';

/**
 * Log file prefix
 */
const LOG_FILE_PREFIX = 'audit-';

/**
 * Log file extension (JSON Lines format)
 */
const LOG_FILE_EXTENSION = '.jsonl';

/**
 * File permissions for audit logs (owner read/write only)
 */
const LOG_FILE_MODE = 0o600;

/**
 * Directory permissions (owner read/write/execute only)
 */
const DIR_MODE = 0o700;

// ============================================================================
// TYPES
// ============================================================================

/**
 * Severity levels for audit events
 */
export type AuditSeverity = 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL';

/**
 * Event categories for filtering and analysis
 */
export type EventCategory = 'security' | 'operation' | 'transaction' | 'system';

/**
 * Actor types that can trigger events
 */
export type ActorType = 'agent' | 'system' | 'human' | 'scheduled';

/**
 * Operation result status
 */
export type OperationResult = 'success' | 'failure' | 'denied' | 'timeout';

/**
 * Input for logging an audit event (without auto-generated fields)
 */
export interface AuditLogInput {
  /** Event type from schema */
  event: AuditEventType;

  /** Wallet ID (if applicable) */
  wallet_id?: string;

  /** Wallet address (if applicable) */
  wallet_address?: string;

  /** Transaction type (if applicable) */
  transaction_type?: TransactionType;

  /** Amount in XRP (if applicable) */
  amount_xrp?: string;

  /** Destination address (if applicable) */
  destination?: string;

  /** Policy tier (if applicable) */
  tier?: 1 | 2 | 3 | 4;

  /** Policy decision */
  policy_decision?: 'allowed' | 'denied' | 'pending';

  /** Transaction hash (if applicable) */
  tx_hash?: string;

  /** Context from agent */
  context?: string;
}

/**
 * Configuration for the AuditLogger
 */
export interface AuditLoggerConfig {
  /** Base directory for audit logs */
  baseDir: string;

  /** Network (determines subdirectory) */
  network: Network;

  /** Enable synchronous writes (safer but slower) */
  syncWrites: boolean;

  /** Verify chain integrity on startup */
  verifyOnStartup: boolean;

  /** Number of recent entries to verify on startup */
  startupVerificationEntries: number;
}

/**
 * Default configuration
 */
export const DEFAULT_AUDIT_LOGGER_CONFIG: AuditLoggerConfig = {
  baseDir: path.join(process.env['HOME'] || '~', DEFAULT_BASE_DIR),
  network: 'testnet',
  syncWrites: true,
  verifyOnStartup: true,
  startupVerificationEntries: 1000,
};

/**
 * Provider interface for HMAC key
 */
export interface IHmacKeyProvider {
  /** Get the HMAC key for audit logging */
  getKey(): Promise<Buffer>;
}

/**
 * Options for creating an AuditLogger
 */
export interface AuditLoggerOptions {
  /** Provider for HMAC key */
  hmacKeyProvider: IHmacKeyProvider;

  /** Configuration overrides */
  config?: Partial<AuditLoggerConfig>;

  /** Callback when tampering is detected */
  onTamperDetected?: (result: ChainVerificationResult) => Promise<void>;
}

/**
 * Query parameters for searching audit logs
 */
export interface AuditLogQuery {
  /** Start date (inclusive) */
  startDate?: Date;

  /** End date (inclusive) */
  endDate?: Date;

  /** Filter by event types */
  eventTypes?: AuditEventType[];

  /** Filter by wallet ID */
  walletId?: string;

  /** Filter by wallet address */
  walletAddress?: string;

  /** Filter by transaction hash */
  txHash?: string;

  /** Maximum results to return */
  limit?: number;

  /** Sort order */
  sortOrder?: 'asc' | 'desc';
}

/**
 * Storage statistics
 */
export interface AuditStorageStats {
  /** Total entries in current file */
  totalEntries: number;

  /** Current file size in bytes */
  currentFileSize: number;

  /** Path to current log file */
  currentFilePath: string;

  /** Oldest entry timestamp */
  oldestEntry?: string;

  /** Newest entry timestamp */
  newestEntry?: string;
}

// ============================================================================
// SCHEMAS
// ============================================================================

/**
 * Schema for audit log input validation
 */
export const AuditLogInputSchema = z.object({
  event: AuditEventTypeSchema,
  wallet_id: z.string().optional(),
  wallet_address: z.string().optional(),
  transaction_type: TransactionTypeSchema.optional(),
  amount_xrp: z.string().optional(),
  destination: z.string().optional(),
  tier: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4)]).optional(),
  policy_decision: z.enum(['allowed', 'denied', 'pending']).optional(),
  tx_hash: z.string().optional(),
  context: z.string().optional(),
});

// ============================================================================
// SENSITIVE DATA SANITIZATION
// ============================================================================

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
  'bearer',
]);

/**
 * Patterns that indicate sensitive data
 */
const SENSITIVE_PATTERNS = [
  /^s[a-zA-Z0-9]{28}$/, // XRPL seed
  /^[a-f0-9]{64}$/i, // 256-bit hex (private key)
  /^[a-f0-9]{128}$/i, // 512-bit hex
  /^(abandon\s+){11}(abandon|about|above|absent)\b/i, // BIP39 mnemonic start
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
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    const lowerKey = key.toLowerCase().replace(/[-_]/g, '');
    if (REDACTED_FIELDS.has(lowerKey)) {
      result[key] = '[REDACTED]';
    } else {
      result[key] = sanitizeForLogging(value, depth + 1);
    }
  }
  return result;
}

// ============================================================================
// AUDIT LOGGER CLASS
// ============================================================================

/**
 * AuditLogger - Tamper-evident audit logging with HMAC hash chains
 *
 * Features:
 * - HMAC-SHA256 hash chain for tamper detection
 * - JSON Lines format for append-only storage
 * - Automatic integrity verification
 * - Network-isolated log directories
 * - Sensitive data sanitization
 *
 * @example
 * ```typescript
 * const logger = await AuditLogger.create({
 *   hmacKeyProvider: { getKey: async () => myHmacKey },
 *   config: { network: 'testnet' }
 * });
 *
 * await logger.log({
 *   event: 'wallet_created',
 *   wallet_id: 'wallet-123',
 *   wallet_address: 'rAddress...'
 * });
 *
 * const result = await logger.verifyChain();
 * if (!result.valid) {
 *   console.error('Tampering detected!');
 * }
 *
 * await logger.shutdown();
 * ```
 */
export class AuditLogger extends EventEmitter {
  private readonly config: AuditLoggerConfig;
  private readonly chain: HashChain;
  private readonly logDir: string;
  private currentLogPath: string;
  private isInitialized: boolean = false;
  private writeLock: Promise<void> = Promise.resolve();

  /**
   * Private constructor - use AuditLogger.create() factory method
   */
  private constructor(
    hmacKey: Buffer,
    config: AuditLoggerConfig,
    chainState?: ChainState
  ) {
    super();
    this.config = config;
    this.chain = new HashChain(hmacKey, chainState);
    this.logDir = path.join(config.baseDir, config.network, AUDIT_SUBDIR);
    this.currentLogPath = this.getLogFilePath(new Date());
  }

  /**
   * Create and initialize an AuditLogger instance
   *
   * Factory method ensures proper initialization:
   * 1. Loads HMAC key from provider
   * 2. Creates audit directory if needed
   * 3. Restores chain state from existing logs
   * 4. Optionally verifies chain integrity on startup
   *
   * @param options - Configuration options
   * @returns Initialized AuditLogger
   * @throws Error if initialization fails
   */
  static async create(options: AuditLoggerOptions): Promise<AuditLogger> {
    // 1. Get HMAC key
    const hmacKey = await options.hmacKeyProvider.getKey();
    if (!isValidHmacKey(hmacKey)) {
      throw new Error('Invalid HMAC key: must be 32 bytes (256 bits)');
    }

    // 2. Build config
    const config: AuditLoggerConfig = {
      ...DEFAULT_AUDIT_LOGGER_CONFIG,
      ...options.config,
    };

    // 3. Create instance
    const logger = new AuditLogger(hmacKey, config);

    // 4. Initialize storage
    await logger.initialize();

    // 5. Restore chain state from existing logs
    await logger.restoreChainState();

    // 6. Optional startup verification
    if (config.verifyOnStartup) {
      const result = await logger.verifyChain({
        recentEntries: config.startupVerificationEntries,
      });

      if (!result.valid) {
        logger.emit('tamper_detected', result);
        if (options.onTamperDetected) {
          await options.onTamperDetected(result);
        }
      }
    }

    return logger;
  }

  /**
   * Initialize the audit log storage
   */
  private async initialize(): Promise<void> {
    // Create directory structure
    await fs.mkdir(this.logDir, { recursive: true, mode: DIR_MODE });

    // Ensure current log file exists
    try {
      await fs.access(this.currentLogPath);
    } catch {
      // Create empty file with proper permissions
      await fs.writeFile(this.currentLogPath, '', { mode: LOG_FILE_MODE });
    }

    this.isInitialized = true;
  }

  /**
   * Restore chain state from existing log files
   */
  private async restoreChainState(): Promise<void> {
    const lastEntry = await this.getLastEntry();

    if (lastEntry) {
      this.chain.setState({
        sequence: lastEntry.seq,
        previousHash: lastEntry.hash,
      });
    }
  }

  /**
   * Get the log file path for a given date
   */
  private getLogFilePath(date: Date): string {
    const dateStr = date.toISOString().split('T')[0]; // YYYY-MM-DD
    return path.join(this.logDir, `${LOG_FILE_PREFIX}${dateStr}${LOG_FILE_EXTENSION}`);
  }

  /**
   * Get the last entry from the current log file
   */
  private async getLastEntry(): Promise<AuditLogEntry | null> {
    try {
      const content = await fs.readFile(this.currentLogPath, 'utf-8');
      const lines = content.trim().split('\n').filter(Boolean);

      if (lines.length === 0) {
        return null;
      }

      const lastLine = lines[lines.length - 1]!;
      return JSON.parse(lastLine) as AuditLogEntry;
    } catch {
      return null;
    }
  }

  /**
   * Log an audit event
   *
   * @param input - Event data
   * @returns Complete log entry with integrity fields
   * @throws Error if logging fails
   */
  async log(input: AuditLogInput): Promise<AuditLogEntry> {
    if (!this.isInitialized) {
      throw new Error('AuditLogger not initialized. Use AuditLogger.create()');
    }

    // Validate input
    const validated = AuditLogInputSchema.parse(input);

    // Sanitize context if provided
    const sanitizedContext = validated.context
      ? (sanitizeForLogging(validated.context) as string)
      : undefined;

    // Serialize write operations to maintain chain integrity
    const writePromise = this.writeLock.then(async () => {
      // Check if we need to rotate to a new day's file
      const today = new Date();
      const newLogPath = this.getLogFilePath(today);
      if (newLogPath !== this.currentLogPath) {
        this.currentLogPath = newLogPath;
        try {
          await fs.access(this.currentLogPath);
        } catch {
          await fs.writeFile(this.currentLogPath, '', { mode: LOG_FILE_MODE });
        }
      }

      // Build entry data (without hash chain fields)
      const entryData = {
        event: validated.event,
        wallet_id: validated.wallet_id,
        wallet_address: validated.wallet_address,
        transaction_type: validated.transaction_type,
        amount_xrp: validated.amount_xrp,
        destination: validated.destination,
        tier: validated.tier,
        policy_decision: validated.policy_decision,
        tx_hash: validated.tx_hash,
        context: sanitizedContext,
      };

      // Create entry with hash chain (adds seq, timestamp, prev_hash, hash)
      const chainEntry = this.chain.createEntry(entryData);

      // Map to AuditLogEntry schema (seq instead of sequence)
      const entry: AuditLogEntry = {
        seq: chainEntry.sequence,
        timestamp: chainEntry.timestamp,
        event: chainEntry.event,
        wallet_id: chainEntry.wallet_id,
        wallet_address: chainEntry.wallet_address,
        transaction_type: chainEntry.transaction_type,
        amount_xrp: chainEntry.amount_xrp,
        destination: chainEntry.destination,
        tier: chainEntry.tier,
        policy_decision: chainEntry.policy_decision,
        tx_hash: chainEntry.tx_hash,
        context: chainEntry.context,
        prev_hash: chainEntry.previousHash,
        hash: chainEntry.hash,
      };

      // Append to log file
      const line = JSON.stringify(entry) + '\n';

      if (this.config.syncWrites) {
        // Use synchronous write for safety
        const handle = await fs.open(this.currentLogPath, 'a');
        try {
          await handle.write(line);
          await handle.sync();
        } finally {
          await handle.close();
        }
      } else {
        await fs.appendFile(this.currentLogPath, line);
      }

      // Emit event
      this.emit('entry_logged', { seq: entry.seq, event: entry.event });

      return entry;
    });

    this.writeLock = writePromise.then(() => {});
    return writePromise;
  }

  /**
   * Verify hash chain integrity
   *
   * @param options - Verification options
   * @returns Verification result with any detected errors
   */
  async verifyChain(options: VerificationOptions = {}): Promise<ChainVerificationResult> {
    const entries = await this.loadEntries(options);

    if (entries.length === 0) {
      return {
        valid: true,
        entriesVerified: 0,
        startSequence: 0,
        endSequence: 0,
        durationMs: 0,
        errors: [],
      };
    }

    // Convert AuditLogEntry to HashableEntry format
    const hashableEntries: HashableEntry[] = entries.map((e) => ({
      sequence: e.seq,
      timestamp: e.timestamp,
      previousHash: e.prev_hash,
      hash: e.hash,
      event: e.event,
      wallet_id: e.wallet_id,
      wallet_address: e.wallet_address,
      transaction_type: e.transaction_type,
      amount_xrp: e.amount_xrp,
      destination: e.destination,
      tier: e.tier,
      policy_decision: e.policy_decision,
      tx_hash: e.tx_hash,
      context: e.context,
    }));

    const result = this.chain.verifyEntries(hashableEntries, options);

    if (!result.valid) {
      this.emit('tamper_detected', result);
    }

    return result;
  }

  /**
   * Load entries for verification/querying
   */
  private async loadEntries(options: VerificationOptions = {}): Promise<AuditLogEntry[]> {
    const entries: AuditLogEntry[] = [];

    try {
      const content = await fs.readFile(this.currentLogPath, 'utf-8');
      const lines = content.trim().split('\n').filter(Boolean);

      for (const line of lines) {
        try {
          const entry = JSON.parse(line) as AuditLogEntry;
          entries.push(entry);
        } catch {
          // Skip malformed lines
          continue;
        }
      }
    } catch {
      // File doesn't exist or can't be read
      return [];
    }

    // Apply options
    let result = entries;

    if (options.startSequence !== undefined || options.endSequence !== undefined) {
      result = result.filter((e) => {
        if (options.startSequence !== undefined && e.seq < options.startSequence) {
          return false;
        }
        if (options.endSequence !== undefined && e.seq > options.endSequence) {
          return false;
        }
        return true;
      });
    }

    if (options.recentEntries !== undefined) {
      result = result.slice(-options.recentEntries);
    }

    return result;
  }

  /**
   * Query logs by criteria
   *
   * @param query - Query parameters
   * @returns Matching log entries
   */
  async query(query: AuditLogQuery): Promise<AuditLogEntry[]> {
    const allEntries = await this.loadEntries({});

    let filtered = allEntries;

    // Apply filters
    if (query.startDate) {
      filtered = filtered.filter((e) => new Date(e.timestamp) >= query.startDate!);
    }

    if (query.endDate) {
      filtered = filtered.filter((e) => new Date(e.timestamp) <= query.endDate!);
    }

    if (query.eventTypes && query.eventTypes.length > 0) {
      const eventSet = new Set(query.eventTypes);
      filtered = filtered.filter((e) => eventSet.has(e.event));
    }

    if (query.walletId) {
      filtered = filtered.filter((e) => e.wallet_id === query.walletId);
    }

    if (query.walletAddress) {
      filtered = filtered.filter((e) => e.wallet_address === query.walletAddress);
    }

    if (query.txHash) {
      filtered = filtered.filter((e) => e.tx_hash === query.txHash);
    }

    // Apply sort order
    if (query.sortOrder === 'desc') {
      filtered = filtered.reverse();
    }

    // Apply limit
    if (query.limit && query.limit > 0) {
      filtered = filtered.slice(0, query.limit);
    }

    return filtered;
  }

  /**
   * Get current chain state
   *
   * @returns Current sequence number and previous hash
   */
  getChainState(): ChainState {
    return this.chain.getState();
  }

  /**
   * Get storage statistics
   *
   * @returns Storage statistics
   */
  async getStats(): Promise<AuditStorageStats> {
    const entries = await this.loadEntries({});

    let fileSize = 0;
    try {
      const stat = await fs.stat(this.currentLogPath);
      fileSize = stat.size;
    } catch {
      // File doesn't exist
    }

    const stats: AuditStorageStats = {
      totalEntries: entries.length,
      currentFileSize: fileSize,
      currentFilePath: this.currentLogPath,
    };

    if (entries.length > 0) {
      const firstEntry = entries[0]!;
      const lastEntry = entries[entries.length - 1]!;
      stats.oldestEntry = firstEntry.timestamp;
      stats.newestEntry = lastEntry.timestamp;
    }

    return stats;
  }

  /**
   * Graceful shutdown
   *
   * Ensures all pending writes complete and disposes of the hash chain.
   *
   * @param timeout - Maximum wait time for pending writes (ms)
   */
  async shutdown(timeout = 5000): Promise<void> {
    // Wait for pending writes
    const timeoutPromise = new Promise<void>((_, reject) => {
      setTimeout(() => reject(new Error('Shutdown timeout')), timeout);
    });

    try {
      await Promise.race([this.writeLock, timeoutPromise]);
    } catch {
      // Timeout or error - continue with shutdown
    }

    // Dispose of hash chain (zeros HMAC key)
    this.chain.dispose();

    // Emit shutdown event
    this.emit('shutdown');
  }
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/**
 * Create an in-memory HMAC key provider for testing
 *
 * @param key - HMAC key buffer
 * @returns HMAC key provider
 */
export function createMemoryKeyProvider(key: Buffer): IHmacKeyProvider {
  return {
    getKey: async () => key,
  };
}

/**
 * Get the default audit log directory for a network
 *
 * @param network - XRPL network
 * @returns Directory path
 */
export function getDefaultAuditDir(network: Network): string {
  const baseDir = path.join(process.env['HOME'] || '~', DEFAULT_BASE_DIR);
  return path.join(baseDir, network, AUDIT_SUBDIR);
}
