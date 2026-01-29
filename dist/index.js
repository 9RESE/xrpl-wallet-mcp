#!/usr/bin/env node
import { AuditEventTypeSchema, TransactionTypeSchema, __require, InputSchemas } from './chunk-WARGRSMR.js';
export { AgentWalletPolicySchema, ApprovalTierSchema, AuditEventTypeSchema, AuditLogEntrySchema, DecodedTransactionSchema, DestinationModeSchema, DropsAmountOptionalZeroSchema, DropsAmountSchema, ErrorCodeSchema, ErrorResponseSchema, HexStringRawSchema, HexStringSchema, InputSchemas, LedgerIndexSchema, LimitStatusSchema, NetworkConfigInputSchema, NetworkConfigOutputSchema, NetworkSchema, NotificationEventSchema, OutputSchemas, PaginationMarkerSchema, PolicyDestinationsSchema, PolicyEscalationSchema, PolicyLimitsSchema, PolicyNotificationsSchema, PolicySetInputSchema, PolicySetOutputSchema, PolicyTimeControlsSchema, PolicyTransactionTypesSchema, PolicyViolationSchema, PublicKeySchema, RemainingLimitsSchema, SequenceNumberSchema, SignedTransactionBlobSchema, SignerEntrySchema, TimestampSchema, TransactionHashSchema, TransactionHistoryEntrySchema, TransactionResultSchema, TransactionTypeSchema, TxDecodeInputSchema, TxDecodeOutputSchema, TxSubmitInputSchema, TxSubmitOutputSchema, UnsignedTransactionBlobSchema, WalletBalanceInputSchema, WalletBalanceOutputSchema, WalletCreateInputSchema, WalletCreateOutputSchema, WalletFundInputSchema, WalletFundOutputSchema, WalletHistoryInputSchema, WalletHistoryOutputSchema, WalletIdSchema, WalletListEntrySchema, WalletListInputSchema, WalletListOutputSchema, WalletNameSchema, WalletPolicyCheckInputSchema, WalletPolicyCheckOutputSchema, WalletRotateInputSchema, WalletRotateOutputSchema, WalletSignApprovedOutputSchema, WalletSignInputSchema, WalletSignOutputSchema, WalletSignPendingOutputSchema, WalletSignRejectedOutputSchema, XRPLAddressSchema } from './chunk-WARGRSMR.js';
import * as crypto from 'crypto';
import { createHmac, createHash, randomUUID } from 'crypto';
import { z } from 'zod';
import { EventEmitter } from 'events';
import * as fs from 'fs/promises';
import * as path2 from 'path';
import { promises } from 'fs';
import * as argon2 from 'argon2';
import { ECDSA, Wallet, Client, decode, encode, multisign, hashes, dropsToXrp as dropsToXrp$1 } from 'xrpl';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';

var GENESIS_CONSTANT = "XRPL-WALLET-MCP-GENESIS-V1";
var HMAC_ALGORITHM = "sha256";
var HMAC_KEY_LENGTH = 32;
var HmacKeySchema = z.instanceof(Buffer).refine(
  (buf) => buf.length === HMAC_KEY_LENGTH,
  `HMAC key must be exactly ${HMAC_KEY_LENGTH} bytes (${HMAC_KEY_LENGTH * 8} bits)`
);
var ChainStateSchema = z.object({
  sequence: z.number().int().min(0),
  previousHash: z.string().length(64).regex(/^[a-f0-9]{64}$/i)
});
var VerificationOptionsSchema = z.object({
  fullChain: z.boolean().optional(),
  startSequence: z.number().int().positive().optional(),
  endSequence: z.number().int().positive().optional(),
  recentEntries: z.number().int().positive().optional(),
  continueOnError: z.boolean().optional()
});
var HashChain = class {
  hmacKey;
  state;
  /**
   * Create a new HashChain instance
   *
   * @param hmacKey - 256-bit HMAC key (32 bytes)
   * @param initialState - Optional initial chain state (for resuming)
   * @throws Error if HMAC key is invalid
   */
  constructor(hmacKey, initialState) {
    const keyResult = HmacKeySchema.safeParse(hmacKey);
    if (!keyResult.success) {
      throw new Error(`Invalid HMAC key: ${keyResult.error.message}`);
    }
    this.hmacKey = Buffer.from(hmacKey);
    this.state = initialState ?? {
      sequence: 0,
      previousHash: this.computeGenesisHash()
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
  computeGenesisHash() {
    const hmac = createHmac(HMAC_ALGORITHM, this.hmacKey);
    hmac.update(GENESIS_CONSTANT);
    return hmac.digest("hex");
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
  computeHash(data) {
    const dataForHashing = {};
    for (const key of Object.keys(data).sort()) {
      if (key !== "hash") {
        dataForHashing[key] = data[key];
      }
    }
    const serialized = JSON.stringify(dataForHashing, Object.keys(dataForHashing).sort());
    const hmac = createHmac(HMAC_ALGORITHM, this.hmacKey);
    hmac.update(serialized);
    return hmac.digest("hex");
  }
  /**
   * Get the current chain state
   *
   * @returns Current sequence number and previous hash
   */
  getState() {
    return { ...this.state };
  }
  /**
   * Set the chain state (for resuming from storage)
   *
   * @param state - Chain state to restore
   */
  setState(state) {
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
  createEntry(data) {
    const sequence = this.state.sequence + 1;
    const timestamp = (/* @__PURE__ */ new Date()).toISOString();
    const previousHash = this.state.previousHash;
    const entry = {
      ...data,
      sequence,
      timestamp,
      previousHash,
      hash: ""
    };
    entry.hash = this.computeHash(entry);
    this.state = {
      sequence,
      previousHash: entry.hash
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
  verifyEntry(entry, expectedPrevHash) {
    const errors = [];
    if (expectedPrevHash !== void 0 && entry.previousHash !== expectedPrevHash) {
      errors.push({
        type: "chain_break",
        sequence: entry.sequence,
        expected: expectedPrevHash,
        actual: entry.previousHash,
        description: `Chain break: previousHash does not match prior entry's hash`
      });
    }
    const computedHash = this.computeHash(entry);
    if (computedHash !== entry.hash) {
      errors.push({
        type: "tampered_entry",
        sequence: entry.sequence,
        expected: computedHash,
        actual: entry.hash,
        description: `Entry hash mismatch: entry may have been tampered with`
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
  verifyEntries(entries, options = {}) {
    const startTime = Date.now();
    const errors = [];
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
    const firstEntry = entries[0];
    const lastEntry = entries[entries.length - 1];
    let expectedPrevHash;
    if (firstEntry.sequence === 1) {
      expectedPrevHash = this.computeGenesisHash();
    } else {
      expectedPrevHash = firstEntry.previousHash;
    }
    let expectedSequence = firstEntry.sequence;
    let lastTimestamp = /* @__PURE__ */ new Date(0);
    for (const entry of entries) {
      if (entry.sequence !== expectedSequence) {
        errors.push({
          type: "sequence_gap",
          sequence: entry.sequence,
          expected: expectedSequence,
          actual: entry.sequence,
          description: `Expected sequence ${expectedSequence}, got ${entry.sequence}`
        });
        if (!options.continueOnError) {
          expectedSequence = entry.sequence;
        }
      }
      if (entry.previousHash !== expectedPrevHash) {
        errors.push({
          type: "chain_break",
          sequence: entry.sequence,
          expected: expectedPrevHash,
          actual: entry.previousHash,
          description: `Chain break: previousHash does not match prior entry's hash`
        });
      }
      const computedHash = this.computeHash(entry);
      if (computedHash !== entry.hash) {
        errors.push({
          type: "tampered_entry",
          sequence: entry.sequence,
          expected: computedHash,
          actual: entry.hash,
          description: `Entry hash mismatch: entry may have been tampered with`
        });
      }
      const entryTime = new Date(entry.timestamp);
      if (entryTime < lastTimestamp) {
        errors.push({
          type: "invalid_timestamp",
          sequence: entry.sequence,
          expected: lastTimestamp.toISOString(),
          actual: entry.timestamp,
          description: `Timestamp is earlier than previous entry`
        });
      }
      lastTimestamp = entryTime;
      expectedPrevHash = entry.hash;
      expectedSequence = entry.sequence + 1;
    }
    return {
      valid: errors.length === 0,
      entriesVerified: entries.length,
      startSequence: firstEntry.sequence,
      endSequence: lastEntry.sequence,
      durationMs: Date.now() - startTime,
      errors
    };
  }
  /**
   * Verify that an entry correctly links to a previous entry
   *
   * @param current - Current entry to verify
   * @param previous - Previous entry in the chain
   * @returns True if chain link is valid
   */
  verifyChainLink(current, previous) {
    return current.previousHash === previous.hash;
  }
  /**
   * Dispose of the hash chain and zero out the HMAC key
   *
   * Should be called when the chain is no longer needed to
   * prevent key material from remaining in memory.
   */
  dispose() {
    this.hmacKey.fill(0);
  }
};
function isValidHmacKey(key) {
  return HmacKeySchema.safeParse(key).success;
}
function generateHmacKey() {
  const crypto2 = __require("crypto");
  return crypto2.randomBytes(HMAC_KEY_LENGTH);
}
function computeStandaloneHash(key, data) {
  const hmac = createHmac(HMAC_ALGORITHM, key);
  hmac.update(data);
  return hmac.digest("hex");
}
var DEFAULT_BASE_DIR = ".xrpl-wallet-mcp";
var AUDIT_SUBDIR = "audit";
var LOG_FILE_PREFIX = "audit-";
var LOG_FILE_EXTENSION = ".jsonl";
var LOG_FILE_MODE = 384;
var DIR_MODE = 448;
var DEFAULT_AUDIT_LOGGER_CONFIG = {
  baseDir: path2.join(process.env["HOME"] || "~", DEFAULT_BASE_DIR),
  network: "testnet",
  syncWrites: true,
  verifyOnStartup: true,
  startupVerificationEntries: 1e3
};
var AuditLogInputSchema = z.object({
  event: AuditEventTypeSchema,
  wallet_id: z.string().optional(),
  wallet_address: z.string().optional(),
  transaction_type: TransactionTypeSchema.optional(),
  amount_xrp: z.string().optional(),
  destination: z.string().optional(),
  tier: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4)]).optional(),
  policy_decision: z.enum(["allowed", "denied", "pending"]).optional(),
  tx_hash: z.string().optional(),
  context: z.string().optional()
});
var REDACTED_FIELDS = /* @__PURE__ */ new Set([
  "password",
  "seed",
  "secret",
  "privatekey",
  "private_key",
  "mnemonic",
  "passphrase",
  "encryptionkey",
  "hmackey",
  "masterkey",
  "master_key",
  "secretkey",
  "secret_key",
  "apikey",
  "api_key",
  "token",
  "bearer"
]);
var SENSITIVE_PATTERNS = [
  /^s[a-zA-Z0-9]{28}$/,
  // XRPL seed
  /^[a-f0-9]{64}$/i,
  // 256-bit hex (private key)
  /^[a-f0-9]{128}$/i,
  // 512-bit hex
  /^(abandon\s+){11}(abandon|about|above|absent)\b/i
  // BIP39 mnemonic start
];
function sanitizeForLogging(obj, depth = 0) {
  if (depth > 10) return "[MAX_DEPTH]";
  if (obj === null || obj === void 0) return obj;
  if (typeof obj === "string") {
    for (const pattern of SENSITIVE_PATTERNS) {
      if (pattern.test(obj)) return "[REDACTED]";
    }
    return obj.length > 1e3 ? obj.slice(0, 100) + "...[TRUNCATED]" : obj;
  }
  if (typeof obj !== "object") return obj;
  if (Array.isArray(obj)) {
    return obj.map((item) => sanitizeForLogging(item, depth + 1));
  }
  const result = {};
  for (const [key, value] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase().replace(/[-_]/g, "");
    if (REDACTED_FIELDS.has(lowerKey)) {
      result[key] = "[REDACTED]";
    } else {
      result[key] = sanitizeForLogging(value, depth + 1);
    }
  }
  return result;
}
var AuditLogger = class _AuditLogger extends EventEmitter {
  config;
  chain;
  logDir;
  currentLogPath;
  isInitialized = false;
  writeLock = Promise.resolve();
  /**
   * Private constructor - use AuditLogger.create() factory method
   */
  constructor(hmacKey, config, chainState) {
    super();
    this.config = config;
    this.chain = new HashChain(hmacKey, chainState);
    this.logDir = path2.join(config.baseDir, config.network, AUDIT_SUBDIR);
    this.currentLogPath = this.getLogFilePath(/* @__PURE__ */ new Date());
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
  static async create(options) {
    const hmacKey = await options.hmacKeyProvider.getKey();
    if (!isValidHmacKey(hmacKey)) {
      throw new Error("Invalid HMAC key: must be 32 bytes (256 bits)");
    }
    const config = {
      ...DEFAULT_AUDIT_LOGGER_CONFIG,
      ...options.config
    };
    const logger = new _AuditLogger(hmacKey, config);
    await logger.initialize();
    await logger.restoreChainState();
    if (config.verifyOnStartup) {
      const result = await logger.verifyChain({
        recentEntries: config.startupVerificationEntries
      });
      if (!result.valid) {
        logger.emit("tamper_detected", result);
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
  async initialize() {
    await fs.mkdir(this.logDir, { recursive: true, mode: DIR_MODE });
    try {
      await fs.access(this.currentLogPath);
    } catch {
      await fs.writeFile(this.currentLogPath, "", { mode: LOG_FILE_MODE });
    }
    this.isInitialized = true;
  }
  /**
   * Restore chain state from existing log files
   */
  async restoreChainState() {
    const lastEntry = await this.getLastEntry();
    if (lastEntry) {
      this.chain.setState({
        sequence: lastEntry.seq,
        previousHash: lastEntry.hash
      });
    }
  }
  /**
   * Get the log file path for a given date
   */
  getLogFilePath(date) {
    const dateStr = date.toISOString().split("T")[0];
    return path2.join(this.logDir, `${LOG_FILE_PREFIX}${dateStr}${LOG_FILE_EXTENSION}`);
  }
  /**
   * Get the last entry from the current log file
   */
  async getLastEntry() {
    try {
      const content = await fs.readFile(this.currentLogPath, "utf-8");
      const lines = content.trim().split("\n").filter(Boolean);
      if (lines.length === 0) {
        return null;
      }
      const lastLine = lines[lines.length - 1];
      return JSON.parse(lastLine);
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
  async log(input) {
    if (!this.isInitialized) {
      throw new Error("AuditLogger not initialized. Use AuditLogger.create()");
    }
    const validated = AuditLogInputSchema.parse(input);
    const sanitizedContext = validated.context ? sanitizeForLogging(validated.context) : void 0;
    const writePromise = this.writeLock.then(async () => {
      const today = /* @__PURE__ */ new Date();
      const newLogPath = this.getLogFilePath(today);
      if (newLogPath !== this.currentLogPath) {
        this.currentLogPath = newLogPath;
        try {
          await fs.access(this.currentLogPath);
        } catch {
          await fs.writeFile(this.currentLogPath, "", { mode: LOG_FILE_MODE });
        }
      }
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
        context: sanitizedContext
      };
      const chainEntry = this.chain.createEntry(entryData);
      const entry = {
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
        hash: chainEntry.hash
      };
      const line = JSON.stringify(entry) + "\n";
      if (this.config.syncWrites) {
        const handle = await fs.open(this.currentLogPath, "a");
        try {
          await handle.write(line);
          await handle.sync();
        } finally {
          await handle.close();
        }
      } else {
        await fs.appendFile(this.currentLogPath, line);
      }
      this.emit("entry_logged", { seq: entry.seq, event: entry.event });
      return entry;
    });
    this.writeLock = writePromise.then(() => {
    });
    return writePromise;
  }
  /**
   * Verify hash chain integrity
   *
   * @param options - Verification options
   * @returns Verification result with any detected errors
   */
  async verifyChain(options = {}) {
    const entries = await this.loadEntries(options);
    if (entries.length === 0) {
      return {
        valid: true,
        entriesVerified: 0,
        startSequence: 0,
        endSequence: 0,
        durationMs: 0,
        errors: []
      };
    }
    const hashableEntries = entries.map((e) => ({
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
      context: e.context
    }));
    const result = this.chain.verifyEntries(hashableEntries, options);
    if (!result.valid) {
      this.emit("tamper_detected", result);
    }
    return result;
  }
  /**
   * Load entries for verification/querying
   */
  async loadEntries(options = {}) {
    const entries = [];
    try {
      const content = await fs.readFile(this.currentLogPath, "utf-8");
      const lines = content.trim().split("\n").filter(Boolean);
      for (const line of lines) {
        try {
          const entry = JSON.parse(line);
          entries.push(entry);
        } catch {
          continue;
        }
      }
    } catch {
      return [];
    }
    let result = entries;
    if (options.startSequence !== void 0 || options.endSequence !== void 0) {
      result = result.filter((e) => {
        if (options.startSequence !== void 0 && e.seq < options.startSequence) {
          return false;
        }
        if (options.endSequence !== void 0 && e.seq > options.endSequence) {
          return false;
        }
        return true;
      });
    }
    if (options.recentEntries !== void 0) {
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
  async query(query) {
    const allEntries = await this.loadEntries({});
    let filtered = allEntries;
    if (query.startDate) {
      filtered = filtered.filter((e) => new Date(e.timestamp) >= query.startDate);
    }
    if (query.endDate) {
      filtered = filtered.filter((e) => new Date(e.timestamp) <= query.endDate);
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
    if (query.sortOrder === "desc") {
      filtered = filtered.reverse();
    }
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
  getChainState() {
    return this.chain.getState();
  }
  /**
   * Get storage statistics
   *
   * @returns Storage statistics
   */
  async getStats() {
    const entries = await this.loadEntries({});
    let fileSize = 0;
    try {
      const stat2 = await fs.stat(this.currentLogPath);
      fileSize = stat2.size;
    } catch {
    }
    const stats = {
      totalEntries: entries.length,
      currentFileSize: fileSize,
      currentFilePath: this.currentLogPath
    };
    if (entries.length > 0) {
      const firstEntry = entries[0];
      const lastEntry = entries[entries.length - 1];
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
  async shutdown(timeout = 5e3) {
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error("Shutdown timeout")), timeout);
    });
    try {
      await Promise.race([this.writeLock, timeoutPromise]);
    } catch {
    }
    this.chain.dispose();
    this.emit("shutdown");
  }
};
function createMemoryKeyProvider(key) {
  return {
    getKey: async () => key
  };
}
function getDefaultAuditDir(network) {
  const baseDir = path2.join(process.env["HOME"] || "~", DEFAULT_BASE_DIR);
  return path2.join(baseDir, network, AUDIT_SUBDIR);
}
function tierToNumeric(tier) {
  const map = {
    autonomous: 1,
    delayed: 2,
    cosign: 3,
    prohibited: 4
  };
  return map[tier];
}
function numericToTier(tier) {
  const map = {
    1: "autonomous",
    2: "delayed",
    3: "cosign",
    4: "prohibited"
  };
  return map[tier];
}
var PolicyError = class extends Error {
  constructor(message, code, recoverable = false) {
    super(message);
    this.code = code;
    this.recoverable = recoverable;
    this.name = "PolicyError";
  }
  toJSON() {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      recoverable: this.recoverable
    };
  }
};
var PolicyLoadError = class extends PolicyError {
  constructor(message) {
    super(message, "POLICY_LOAD_ERROR", false);
    this.name = "PolicyLoadError";
  }
};
var PolicyValidationError = class extends PolicyError {
  constructor(message, issues) {
    super(message, "POLICY_VALIDATION_ERROR", false);
    this.issues = issues;
    this.name = "PolicyValidationError";
  }
};
var PolicyEvaluationError = class extends PolicyError {
  constructor(message) {
    super(message, "POLICY_EVALUATION_ERROR", true);
    this.name = "PolicyEvaluationError";
  }
};
var PolicyIntegrityError = class extends PolicyError {
  constructor() {
    super("Policy integrity verification failed", "POLICY_INTEGRITY_ERROR", false);
    this.name = "PolicyIntegrityError";
  }
};
var LimitExceededError = class extends PolicyError {
  constructor(message, limitType, currentValue, limitValue) {
    super(message, "LIMIT_EXCEEDED", true);
    this.limitType = limitType;
    this.currentValue = currentValue;
    this.limitValue = limitValue;
    this.name = "LimitExceededError";
  }
};

// src/policy/evaluator.ts
var TRANSACTION_CATEGORIES = {
  // Payments
  Payment: "payments",
  // Trustlines
  TrustSet: "trustlines",
  // DEX
  OfferCreate: "dex",
  OfferCancel: "dex",
  // Escrow
  EscrowCreate: "escrow",
  EscrowFinish: "escrow",
  EscrowCancel: "escrow",
  // Payment Channels
  PaymentChannelCreate: "paychan",
  PaymentChannelFund: "paychan",
  PaymentChannelClaim: "paychan",
  // Account
  AccountSet: "account",
  AccountDelete: "account",
  SetRegularKey: "account",
  SignerListSet: "account",
  DepositPreauth: "account",
  // NFT
  NFTokenMint: "nft",
  NFTokenBurn: "nft",
  NFTokenCreateOffer: "nft",
  NFTokenCancelOffer: "nft",
  NFTokenAcceptOffer: "nft",
  // AMM
  AMMCreate: "amm",
  AMMDeposit: "amm",
  AMMWithdraw: "amm",
  AMMVote: "amm",
  AMMBid: "amm",
  AMMDelete: "amm",
  // Checks
  CheckCreate: "checks",
  CheckCash: "checks",
  CheckCancel: "checks",
  // Tickets
  TicketCreate: "tickets",
  // Clawback
  Clawback: "clawback",
  // DID
  DIDSet: "did",
  DIDDelete: "did",
  // Cross-chain
  XChainAccountCreateCommit: "xchain",
  XChainAddClaimAttestation: "xchain",
  XChainClaim: "xchain",
  XChainCommit: "xchain",
  XChainCreateBridge: "xchain",
  XChainCreateClaimID: "xchain",
  XChainModifyBridge: "xchain"
};
function getTransactionCategory(type) {
  return TRANSACTION_CATEGORIES[type] ?? "unknown";
}
var RuleEvaluator = class {
  compiledRules = /* @__PURE__ */ new Map();
  regexCache = /* @__PURE__ */ new Map();
  options;
  constructor(options) {
    this.options = {
      regexTimeoutMs: options?.regexTimeoutMs ?? 100,
      maxRegexInputLength: options?.maxRegexInputLength ?? 1e4
    };
  }
  /**
   * Compile rules for efficient evaluation.
   * Rules are sorted by priority (lower = higher priority).
   */
  compileRules(rules) {
    this.compiledRules.clear();
    const enabledRules = rules.filter((rule) => rule.enabled !== false).sort((a, b) => a.priority - b.priority);
    for (const rule of enabledRules) {
      const compiled = this.compileRule(rule);
      this.compiledRules.set(rule.id, compiled);
    }
  }
  /**
   * Compile a single rule.
   */
  compileRule(rule) {
    return {
      id: rule.id,
      name: rule.name,
      priority: rule.priority,
      evaluator: this.compileCondition(rule.condition),
      action: rule.action
    };
  }
  /**
   * Compile a condition into an evaluator function.
   */
  compileCondition(condition) {
    if (this.isAlwaysCondition(condition)) {
      return () => true;
    }
    if (this.isAndCondition(condition)) {
      const subEvaluators = condition.and.map((c) => this.compileCondition(c));
      return (ctx, policy) => subEvaluators.every((evaluator) => evaluator(ctx, policy));
    }
    if (this.isOrCondition(condition)) {
      const subEvaluators = condition.or.map((c) => this.compileCondition(c));
      return (ctx, policy) => subEvaluators.some((evaluator) => evaluator(ctx, policy));
    }
    if (this.isNotCondition(condition)) {
      const subEvaluator = this.compileCondition(condition.not);
      return (ctx, policy) => !subEvaluator(ctx, policy);
    }
    if (this.isFieldCondition(condition)) {
      return this.compileFieldCondition(condition);
    }
    throw new PolicyEvaluationError(
      `Unknown condition type: ${JSON.stringify(condition)}`
    );
  }
  /**
   * Compile a field condition.
   */
  compileFieldCondition(condition) {
    const { field, operator, value } = condition;
    return (context, policy) => {
      const fieldValue = this.extractFieldValue(field, context, policy);
      const compareValue = this.resolveValue(value, policy);
      return this.evaluateOperator(operator, fieldValue, compareValue);
    };
  }
  /**
   * Extract a field value from the policy context.
   */
  extractFieldValue(field, context, policy) {
    switch (field) {
      // Transaction fields
      case "destination":
        return context.transaction.destination;
      case "amount_xrp":
        return context.transaction.amount_xrp ?? 0;
      case "amount_drops":
        return context.transaction.amount_drops ?? 0n;
      case "transaction_type":
        return context.transaction.type;
      case "transaction_category":
        return getTransactionCategory(context.transaction.type);
      case "memo":
        return context.transaction.memo ?? "";
      case "memo_type":
        return context.transaction.memo_type ?? "";
      case "fee_drops":
        return context.transaction.fee_drops ?? 0;
      case "destination_tag":
        return context.transaction.destination_tag;
      case "source_tag":
        return context.transaction.source_tag;
      case "currency":
        return context.transaction.currency;
      case "issuer":
        return context.transaction.issuer;
      // Wallet fields
      case "wallet_address":
        return context.wallet.address;
      case "network":
        return context.wallet.network;
      // Derived fields
      case "is_new_destination":
        if (!context.transaction.destination) return false;
        const allowlist = policy.allowlist?.addresses ?? [];
        return !allowlist.includes(context.transaction.destination);
      default:
        throw new PolicyEvaluationError(`Unknown field: ${field}`);
    }
  }
  /**
   * Resolve a value (may be a reference to policy lists).
   */
  resolveValue(value, policy) {
    if (this.isValueReference(value)) {
      return this.resolveReference(value.ref, policy);
    }
    return value;
  }
  /**
   * Resolve a reference to a policy list.
   */
  resolveReference(ref, policy) {
    switch (ref) {
      case "blocklist.addresses":
        return policy.blocklist?.addresses ?? [];
      case "blocklist.memo_patterns":
        return policy.blocklist?.memo_patterns ?? [];
      case "blocklist.currency_issuers":
        return policy.blocklist?.currency_issuers ?? [];
      case "allowlist.addresses":
        return policy.allowlist?.addresses ?? [];
      case "allowlist.trusted_tags":
        return policy.allowlist?.trusted_tags ?? [];
      default:
        throw new PolicyEvaluationError(`Unknown reference: ${ref}`);
    }
  }
  /**
   * Evaluate an operator.
   */
  evaluateOperator(operator, fieldValue, compareValue) {
    switch (operator) {
      // Equality operators
      case "==":
        return fieldValue === compareValue;
      case "!=":
        return fieldValue !== compareValue;
      // Numeric comparison operators
      case ">":
        return this.asNumber(fieldValue) > this.asNumber(compareValue);
      case ">=":
        return this.asNumber(fieldValue) >= this.asNumber(compareValue);
      case "<":
        return this.asNumber(fieldValue) < this.asNumber(compareValue);
      case "<=":
        return this.asNumber(fieldValue) <= this.asNumber(compareValue);
      // Array operators
      case "in":
        return this.asArray(compareValue).includes(fieldValue);
      case "not_in":
        return !this.asArray(compareValue).includes(fieldValue);
      // String operators
      case "matches":
        return this.matchesRegex(this.asString(fieldValue), this.asString(compareValue));
      case "contains":
        return this.asString(fieldValue).includes(this.asString(compareValue));
      case "starts_with":
        return this.asString(fieldValue).startsWith(this.asString(compareValue));
      case "ends_with":
        return this.asString(fieldValue).endsWith(this.asString(compareValue));
      // Category operator
      case "in_category":
        return this.isInCategory(this.asString(fieldValue), this.asString(compareValue));
      default:
        throw new PolicyEvaluationError(`Unknown operator: ${operator}`);
    }
  }
  /**
   * Match a value against a regex pattern.
   */
  matchesRegex(value, pattern) {
    let regex = this.regexCache.get(pattern);
    if (!regex) {
      try {
        regex = new RegExp(pattern, "i");
        this.regexCache.set(pattern, regex);
      } catch (error) {
        throw new PolicyEvaluationError(`Invalid regex pattern: ${pattern}`);
      }
    }
    const truncatedValue = value.length > this.options.maxRegexInputLength ? value.slice(0, this.options.maxRegexInputLength) : value;
    return regex.test(truncatedValue);
  }
  /**
   * Check if a transaction type is in a category.
   */
  isInCategory(txType, category) {
    return getTransactionCategory(txType) === category;
  }
  // ============================================================================
  // TYPE GUARDS
  // ============================================================================
  isAlwaysCondition(condition) {
    return "always" in condition && condition.always === true;
  }
  isAndCondition(condition) {
    return "and" in condition;
  }
  isOrCondition(condition) {
    return "or" in condition;
  }
  isNotCondition(condition) {
    return "not" in condition;
  }
  isFieldCondition(condition) {
    return "field" in condition;
  }
  isValueReference(value) {
    return typeof value === "object" && value !== null && "ref" in value && typeof value.ref === "string";
  }
  // ============================================================================
  // TYPE CONVERSIONS
  // ============================================================================
  asNumber(value) {
    if (typeof value === "number") return value;
    if (typeof value === "bigint") return Number(value);
    if (typeof value === "string") {
      const parsed = parseFloat(value);
      if (isNaN(parsed)) {
        throw new PolicyEvaluationError(`Cannot convert "${value}" to number`);
      }
      return parsed;
    }
    throw new PolicyEvaluationError(`Cannot convert ${typeof value} to number`);
  }
  asString(value) {
    if (typeof value === "string") return value;
    if (value === null || value === void 0) return "";
    return String(value);
  }
  asArray(value) {
    if (Array.isArray(value)) return value;
    throw new PolicyEvaluationError(`Expected array, got ${typeof value}`);
  }
  // ============================================================================
  // PUBLIC EVALUATION METHODS
  // ============================================================================
  /**
   * Evaluate rules against a context.
   * Returns the first matching rule's result.
   */
  evaluate(context, policy) {
    for (const [ruleId, compiled] of this.compiledRules) {
      try {
        const matches = compiled.evaluator(context, policy);
        if (matches) {
          return {
            matched: true,
            ruleId: compiled.id,
            ruleName: compiled.name,
            tier: compiled.action.tier,
            reason: compiled.action.reason ?? `Matched rule: ${compiled.name}`,
            overrideDelaySeconds: compiled.action.override_delay_seconds,
            notify: compiled.action.notify,
            logLevel: compiled.action.log_level
          };
        }
      } catch (error) {
        console.error(`Rule evaluation error for ${ruleId}:`, error);
      }
    }
    return {
      matched: false,
      ruleId: "default-deny",
      ruleName: "No matching rule",
      tier: "prohibited",
      reason: "No matching rule (default deny)"
    };
  }
  /**
   * Get the number of compiled rules.
   */
  getRuleCount() {
    return this.compiledRules.size;
  }
  /**
   * Clear compiled rules and caches.
   */
  clear() {
    this.compiledRules.clear();
    this.regexCache.clear();
  }
};
function checkBlocklist(context, policy, regexCache) {
  const blocklist = policy.blocklist;
  if (!blocklist) {
    return { blocked: false };
  }
  if (context.transaction.destination && blocklist.addresses?.includes(context.transaction.destination)) {
    return {
      blocked: true,
      reason: "Destination address is blocklisted",
      matchedRule: "blocklist-address"
    };
  }
  if (context.transaction.issuer && blocklist.currency_issuers?.includes(context.transaction.issuer)) {
    return {
      blocked: true,
      reason: "Token issuer is blocklisted",
      matchedRule: "blocklist-issuer"
    };
  }
  if (context.transaction.memo && blocklist.memo_patterns?.length) {
    const cache = regexCache ?? /* @__PURE__ */ new Map();
    for (const pattern of blocklist.memo_patterns) {
      let regex = cache.get(pattern);
      if (!regex) {
        try {
          regex = new RegExp(pattern, "i");
          cache.set(pattern, regex);
        } catch {
          continue;
        }
      }
      const memo = context.transaction.memo.length > 1e4 ? context.transaction.memo.slice(0, 1e4) : context.transaction.memo;
      if (regex.test(memo)) {
        return {
          blocked: true,
          reason: "Memo contains blocked pattern (potential injection)",
          matchedRule: "blocklist-memo-pattern",
          injectionDetected: true
        };
      }
    }
  }
  return { blocked: false };
}
function isInAllowlist(context, policy) {
  const allowlist = policy.allowlist;
  if (!allowlist) return false;
  if (context.transaction.destination && allowlist.addresses?.includes(context.transaction.destination)) {
    return true;
  }
  if (context.transaction.destination && allowlist.exchange_addresses) {
    const exchange = allowlist.exchange_addresses.find(
      (ex) => ex.address === context.transaction.destination
    );
    if (exchange) {
      if (exchange.require_tag && !context.transaction.destination_tag) {
        return false;
      }
      return true;
    }
  }
  if (context.transaction.destination_tag !== void 0 && allowlist.trusted_tags?.includes(context.transaction.destination_tag)) {
    return true;
  }
  return false;
}

// src/policy/limits.ts
var LimitTracker = class {
  state;
  config;
  persistencePath;
  clock;
  resetInterval;
  constructor(options) {
    this.config = options.config;
    this.persistencePath = options.persistencePath;
    this.clock = options.clock ?? (() => /* @__PURE__ */ new Date());
    this.state = this.createFreshState();
    this.schedulePeriodicCheck();
  }
  /**
   * Create fresh limit state.
   */
  createFreshState() {
    const now = this.clock();
    return {
      daily: {
        date: this.getDateString(now),
        transactionCount: 0,
        totalVolumeXrp: 0,
        uniqueDestinations: /* @__PURE__ */ new Set(),
        lastTransactionTime: null
      },
      hourly: {
        transactions: []
      },
      cooldown: {
        active: false,
        reason: null,
        expiresAt: null,
        triggeredBy: null
      }
    };
  }
  /**
   * Check if a transaction would exceed any limits.
   * Does NOT record the transaction - call recordTransaction after successful signing.
   */
  checkLimits(context) {
    const now = this.clock();
    this.maybeResetDaily(now);
    this.pruneHourlyWindow(now);
    if (this.state.cooldown.active) {
      if (this.state.cooldown.expiresAt && now < this.state.cooldown.expiresAt) {
        return {
          exceeded: true,
          reason: `Cooldown active: ${this.state.cooldown.reason}`,
          limitType: "cooldown",
          currentValue: 0,
          limitValue: 0,
          expiresAt: this.state.cooldown.expiresAt
        };
      } else {
        this.clearCooldown();
      }
    }
    const txAmountXrp = context.transaction.amount_xrp ?? 0;
    if (this.config.maxAmountPerTxXrp !== void 0 && txAmountXrp > this.config.maxAmountPerTxXrp) {
      return {
        exceeded: true,
        reason: `Transaction amount ${txAmountXrp} XRP exceeds per-tx limit of ${this.config.maxAmountPerTxXrp} XRP`,
        limitType: "per_tx_amount",
        currentValue: txAmountXrp,
        limitValue: this.config.maxAmountPerTxXrp
      };
    }
    if (this.state.daily.transactionCount >= this.config.maxTransactionsPerDay) {
      return {
        exceeded: true,
        reason: `Daily transaction count limit (${this.config.maxTransactionsPerDay}) exceeded`,
        limitType: "daily_count",
        currentValue: this.state.daily.transactionCount,
        limitValue: this.config.maxTransactionsPerDay
      };
    }
    const hourlyCount = this.state.hourly.transactions.length;
    if (hourlyCount >= this.config.maxTransactionsPerHour) {
      return {
        exceeded: true,
        reason: `Hourly transaction count limit (${this.config.maxTransactionsPerHour}) exceeded`,
        limitType: "hourly_count",
        currentValue: hourlyCount,
        limitValue: this.config.maxTransactionsPerHour
      };
    }
    const projectedVolume = this.state.daily.totalVolumeXrp + txAmountXrp;
    if (projectedVolume > this.config.maxTotalVolumeXrpPerDay) {
      return {
        exceeded: true,
        reason: `Daily XRP volume limit (${this.config.maxTotalVolumeXrpPerDay} XRP) would be exceeded`,
        limitType: "daily_volume",
        currentValue: this.state.daily.totalVolumeXrp,
        limitValue: this.config.maxTotalVolumeXrpPerDay,
        requestedAmount: txAmountXrp
      };
    }
    const destination = context.transaction.destination;
    if (this.config.maxUniqueDestinationsPerDay !== void 0 && destination && !this.state.daily.uniqueDestinations.has(destination) && this.state.daily.uniqueDestinations.size >= this.config.maxUniqueDestinationsPerDay) {
      return {
        exceeded: true,
        reason: `Daily unique destination limit (${this.config.maxUniqueDestinationsPerDay}) exceeded`,
        limitType: "unique_destinations",
        currentValue: this.state.daily.uniqueDestinations.size,
        limitValue: this.config.maxUniqueDestinationsPerDay
      };
    }
    return { exceeded: false };
  }
  /**
   * Record a successfully signed transaction.
   * Call this AFTER signing succeeds, not before.
   */
  recordTransaction(context) {
    const now = this.clock();
    this.maybeResetDaily(now);
    this.pruneHourlyWindow(now);
    const txAmountXrp = context.transaction.amount_xrp ?? 0;
    const destination = context.transaction.destination;
    this.state.daily.transactionCount++;
    this.state.daily.totalVolumeXrp += txAmountXrp;
    this.state.daily.lastTransactionTime = now;
    if (destination) {
      this.state.daily.uniqueDestinations.add(destination);
    }
    this.state.hourly.transactions.push({
      timestamp: now,
      amountXrp: txAmountXrp,
      destination: destination ?? ""
    });
    const cooldownConfig = this.config.cooldownAfterHighValue;
    if (cooldownConfig?.enabled && txAmountXrp >= cooldownConfig.thresholdXrp) {
      this.activateCooldown(
        `High-value transaction (${txAmountXrp} XRP)`,
        cooldownConfig.cooldownSeconds,
        context.transaction.type
      );
    }
  }
  /**
   * Check if daily reset should happen.
   */
  maybeResetDaily(now) {
    const currentDate = this.getDateString(now);
    const currentHour = now.getUTCHours();
    const shouldReset = this.state.daily.date !== currentDate || this.state.daily.date === currentDate && currentHour >= this.config.dailyResetHour && this.state.daily.lastTransactionTime && this.state.daily.lastTransactionTime.getUTCHours() < this.config.dailyResetHour;
    if (shouldReset) {
      this.state.daily = {
        date: currentDate,
        transactionCount: 0,
        totalVolumeXrp: 0,
        uniqueDestinations: /* @__PURE__ */ new Set(),
        lastTransactionTime: null
      };
    }
  }
  /**
   * Remove transactions older than 1 hour from sliding window.
   */
  pruneHourlyWindow(now) {
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1e3);
    this.state.hourly.transactions = this.state.hourly.transactions.filter(
      (tx) => tx.timestamp > oneHourAgo
    );
  }
  /**
   * Activate cooldown period.
   */
  activateCooldown(reason, durationSeconds, triggeredBy) {
    const now = this.clock();
    this.state.cooldown = {
      active: true,
      reason,
      expiresAt: new Date(now.getTime() + durationSeconds * 1e3),
      triggeredBy
    };
  }
  /**
   * Clear active cooldown.
   */
  clearCooldown() {
    this.state.cooldown = {
      active: false,
      reason: null,
      expiresAt: null,
      triggeredBy: null
    };
  }
  /**
   * Schedule periodic check for daily reset.
   */
  schedulePeriodicCheck() {
    this.resetInterval = setInterval(() => {
      this.maybeResetDaily(this.clock());
    }, 60 * 1e3);
  }
  /**
   * Stop periodic checks (for cleanup).
   */
  dispose() {
    if (this.resetInterval) {
      clearInterval(this.resetInterval);
      this.resetInterval = void 0;
    }
  }
  // ============================================================================
  // GETTERS FOR RULE EVALUATION
  // ============================================================================
  /**
   * Get current daily XRP volume.
   */
  getDailyVolumeXrp() {
    this.maybeResetDaily(this.clock());
    return this.state.daily.totalVolumeXrp;
  }
  /**
   * Get transactions in the last hour.
   */
  getHourlyCount() {
    const now = this.clock();
    this.pruneHourlyWindow(now);
    return this.state.hourly.transactions.length;
  }
  /**
   * Get daily transaction count.
   */
  getDailyCount() {
    this.maybeResetDaily(this.clock());
    return this.state.daily.transactionCount;
  }
  /**
   * Get unique destination count for today.
   */
  getUniqueDestinationCount() {
    this.maybeResetDaily(this.clock());
    return this.state.daily.uniqueDestinations.size;
  }
  /**
   * Check if a destination has been used before today.
   */
  isDestinationKnown(destination) {
    this.maybeResetDaily(this.clock());
    return this.state.daily.uniqueDestinations.has(destination);
  }
  /**
   * Get complete limit state (copy for safety).
   */
  getState() {
    const now = this.clock();
    this.maybeResetDaily(now);
    this.pruneHourlyWindow(now);
    return {
      daily: {
        ...this.state.daily,
        uniqueDestinations: new Set(this.state.daily.uniqueDestinations)
      },
      hourly: {
        transactions: [...this.state.hourly.transactions]
      },
      cooldown: { ...this.state.cooldown }
    };
  }
  /**
   * Get remaining limits for current period.
   */
  getRemainingLimits() {
    const now = this.clock();
    this.maybeResetDaily(now);
    this.pruneHourlyWindow(now);
    return {
      dailyTxRemaining: Math.max(
        0,
        this.config.maxTransactionsPerDay - this.state.daily.transactionCount
      ),
      hourlyTxRemaining: Math.max(
        0,
        this.config.maxTransactionsPerHour - this.state.hourly.transactions.length
      ),
      dailyVolumeRemainingXrp: Math.max(
        0,
        this.config.maxTotalVolumeXrpPerDay - this.state.daily.totalVolumeXrp
      ),
      uniqueDestinationsRemaining: Math.max(
        0,
        (this.config.maxUniqueDestinationsPerDay ?? Infinity) - this.state.daily.uniqueDestinations.size
      )
    };
  }
  /**
   * Reset all limits. Requires confirmation string for safety.
   */
  reset(confirmation) {
    if (confirmation !== "CONFIRM_LIMIT_RESET") {
      throw new Error("Invalid confirmation string for limit reset");
    }
    this.state = this.createFreshState();
  }
  /**
   * Get date string in YYYY-MM-DD format.
   */
  getDateString(date) {
    return date.toISOString().split("T")[0];
  }
};
function createLimitTracker(limits, options) {
  const dropsToXrp3 = (drops) => {
    return Number(BigInt(drops)) / 1e6;
  };
  const config = {
    dailyResetHour: options?.dailyResetHour ?? 0,
    maxTransactionsPerHour: limits.max_tx_per_hour,
    maxTransactionsPerDay: limits.max_tx_per_day,
    maxTotalVolumeXrpPerDay: dropsToXrp3(limits.max_daily_volume_drops),
    maxAmountPerTxXrp: dropsToXrp3(limits.max_amount_per_tx_drops),
    maxUniqueDestinationsPerDay: options?.maxUniqueDestinationsPerDay,
    cooldownAfterHighValue: options?.cooldownAfterHighValue
  };
  const trackerOptions = {
    config
  };
  if (options?.clock) {
    trackerOptions.clock = options.clock;
  }
  return new LimitTracker(trackerOptions);
}

// src/policy/engine.ts
var PolicyEngine = class {
  /** Frozen policy data */
  policy;
  /** SHA-256 hash of serialized policy */
  policyHash;
  /** When policy was loaded */
  loadedAt;
  /** Rule evaluator */
  ruleEvaluator;
  /** Limit tracker */
  limitTracker;
  /** Custom clock for testing */
  clock;
  /** Regex cache for blocklist patterns */
  regexCache = /* @__PURE__ */ new Map();
  constructor(policy, options) {
    this.clock = options?.clock ?? (() => /* @__PURE__ */ new Date());
    this.loadedAt = this.clock();
    this.policyHash = this.computeHash(policy);
    this.policy = this.deepFreeze(policy);
    const evaluatorOptions = {};
    if (options?.regexTimeoutMs !== void 0) {
      evaluatorOptions.regexTimeoutMs = options.regexTimeoutMs;
    }
    this.ruleEvaluator = new RuleEvaluator(evaluatorOptions);
    this.ruleEvaluator.compileRules(this.policy.rules);
    const limitTrackerOptions = {
      config: {
        dailyResetHour: this.policy.limits.daily_reset_utc_hour ?? 0,
        maxTransactionsPerHour: this.policy.limits.max_transactions_per_hour,
        maxTransactionsPerDay: this.policy.limits.max_transactions_per_day,
        maxTotalVolumeXrpPerDay: this.policy.limits.max_total_volume_xrp_per_day,
        maxUniqueDestinationsPerDay: this.policy.limits.max_unique_destinations_per_day,
        cooldownAfterHighValue: this.policy.limits.cooldown_after_high_value ? {
          enabled: this.policy.limits.cooldown_after_high_value.enabled,
          thresholdXrp: this.policy.limits.cooldown_after_high_value.threshold_xrp,
          cooldownSeconds: this.policy.limits.cooldown_after_high_value.cooldown_seconds
        } : void 0
      },
      clock: this.clock
    };
    this.limitTracker = new LimitTracker(limitTrackerOptions);
  }
  /**
   * Evaluate a transaction against the loaded policy.
   */
  evaluate(context) {
    const startTime = performance.now();
    try {
      if (!this.verifyIntegrity()) {
        return this.createProhibitedResult(
          "Policy integrity check failed",
          "integrity-check",
          startTime
        );
      }
      if (this.policy.enabled === false) {
        return this.createProhibitedResult(
          "Policy is disabled",
          "policy-disabled",
          startTime
        );
      }
      const limitResult = this.checkGlobalLimits(context);
      if (limitResult) {
        return {
          ...limitResult,
          evaluationTimeMs: performance.now() - startTime
        };
      }
      const blocklistResult = checkBlocklist(context, this.policy, this.regexCache);
      if (blocklistResult.blocked) {
        return this.createProhibitedResult(
          blocklistResult.reason,
          blocklistResult.matchedRule,
          startTime,
          blocklistResult.injectionDetected
        );
      }
      const typeResult = this.checkTransactionType(context);
      if (typeResult) {
        return {
          ...typeResult,
          evaluationTimeMs: performance.now() - startTime
        };
      }
      const ruleResult = this.ruleEvaluator.evaluate(context, this.policy);
      const finalResult = this.applyTierConstraints(ruleResult, context);
      return {
        ...finalResult,
        evaluationTimeMs: performance.now() - startTime
      };
    } catch (error) {
      console.error("Policy evaluation error:", {
        correlationId: context.correlationId,
        error,
        transactionType: context.transaction.type
      });
      if (error instanceof PolicyError) {
        return this.createProhibitedResult(
          `Policy error: ${error.code}`,
          "error-handler",
          startTime
        );
      }
      return this.createProhibitedResult(
        "Internal policy engine error",
        "error-handler",
        startTime
      );
    }
  }
  /**
   * Check global limits.
   */
  checkGlobalLimits(context) {
    const limitCheck = this.limitTracker.checkLimits(context);
    if (limitCheck.exceeded) {
      return {
        allowed: false,
        tier: "prohibited",
        tierNumeric: 4,
        reason: limitCheck.reason,
        matchedRule: `limit-${limitCheck.limitType}`,
        factors: [
          {
            source: "limit_exceeded",
            tier: "prohibited",
            reason: limitCheck.reason
          }
        ]
      };
    }
    return null;
  }
  /**
   * Check transaction type restrictions.
   */
  checkTransactionType(context) {
    const txType = context.transaction.type;
    const prohibitedTypes = this.policy.tiers.prohibited?.prohibited_transaction_types ?? [];
    if (prohibitedTypes.includes(txType)) {
      return {
        allowed: false,
        tier: "prohibited",
        tierNumeric: 4,
        reason: `Transaction type ${txType} is prohibited`,
        matchedRule: "prohibited-type",
        factors: [
          {
            source: "prohibited_type",
            tier: "prohibited",
            reason: `Transaction type ${txType} is prohibited`
          }
        ]
      };
    }
    const typeConfig = this.policy.transaction_types?.[txType];
    if (typeConfig?.enabled === false) {
      return {
        allowed: false,
        tier: "prohibited",
        tierNumeric: 4,
        reason: `Transaction type ${txType} is disabled`,
        matchedRule: "type-disabled",
        factors: [
          {
            source: "transaction_type",
            tier: "prohibited",
            reason: `Transaction type ${txType} is disabled`
          }
        ]
      };
    }
    return null;
  }
  /**
   * Apply tier-specific constraints and amount escalation.
   */
  applyTierConstraints(ruleResult, context) {
    let tier = ruleResult.tier;
    const factors = [
      {
        source: "rule",
        tier: ruleResult.tier,
        reason: ruleResult.reason
      }
    ];
    const typeConfig = this.policy.transaction_types?.[context.transaction.type];
    if (typeConfig?.require_cosign && tier !== "prohibited") {
      tier = this.compareTiers("cosign", tier);
      if (tier === "cosign") {
        factors.push({
          source: "transaction_type",
          tier: "cosign",
          reason: `Type ${context.transaction.type} requires co-sign`
        });
      }
    }
    tier = this.applyAmountEscalation(tier, context, factors);
    tier = this.applyNewDestinationEscalation(tier, context, factors);
    const result = {
      allowed: tier !== "prohibited",
      tier,
      tierNumeric: tierToNumeric(tier),
      reason: factors.find((f) => f.tier === tier)?.reason ?? ruleResult.reason,
      matchedRule: ruleResult.ruleId,
      factors
    };
    switch (tier) {
      case "delayed":
        result.delaySeconds = ruleResult.overrideDelaySeconds ?? this.policy.tiers.delayed?.delay_seconds ?? 300;
        result.vetoEnabled = this.policy.tiers.delayed?.veto_enabled ?? true;
        result.notify = ruleResult.notify ?? this.policy.tiers.delayed?.notify_on_queue ?? true;
        break;
      case "cosign":
        result.signerQuorum = this.policy.tiers.cosign?.signer_quorum ?? 2;
        result.approvalTimeoutHours = this.policy.tiers.cosign?.approval_timeout_hours ?? 24;
        result.signerAddresses = this.policy.tiers.cosign?.signer_addresses ?? [];
        result.notify = ruleResult.notify ?? true;
        break;
      case "autonomous":
        result.notify = ruleResult.notify ?? false;
        break;
    }
    return result;
  }
  /**
   * Apply amount-based tier escalation.
   */
  applyAmountEscalation(currentTier, context, factors) {
    const amountXrp = context.transaction.amount_xrp ?? 0;
    const tiers = this.policy.tiers;
    if (tiers.delayed?.max_amount_xrp !== void 0 && amountXrp > tiers.delayed.max_amount_xrp) {
      if (currentTier === "autonomous" || currentTier === "delayed") {
        factors.push({
          source: "amount_limit",
          tier: "cosign",
          reason: `Amount ${amountXrp} XRP exceeds delayed tier max (${tiers.delayed.max_amount_xrp})`
        });
        return "cosign";
      }
    }
    if (tiers.autonomous?.max_amount_xrp !== void 0 && amountXrp > tiers.autonomous.max_amount_xrp) {
      if (currentTier === "autonomous") {
        if (tiers.delayed?.max_amount_xrp === void 0 || amountXrp <= tiers.delayed.max_amount_xrp) {
          factors.push({
            source: "amount_limit",
            tier: "delayed",
            reason: `Amount ${amountXrp} XRP exceeds autonomous tier max (${tiers.autonomous.max_amount_xrp})`
          });
          return "delayed";
        }
      }
    }
    const typeConfig = this.policy.transaction_types?.[context.transaction.type];
    if (typeConfig?.max_amount_xrp !== void 0 && amountXrp > typeConfig.max_amount_xrp) {
      if (currentTier === "autonomous") {
        factors.push({
          source: "amount_limit",
          tier: "delayed",
          reason: `Amount ${amountXrp} XRP exceeds ${context.transaction.type} limit (${typeConfig.max_amount_xrp})`
        });
        return "delayed";
      }
    }
    return currentTier;
  }
  /**
   * Apply new destination escalation.
   */
  applyNewDestinationEscalation(currentTier, context, factors) {
    if (!context.transaction.destination || currentTier === "prohibited") {
      return currentTier;
    }
    if (isInAllowlist(context, this.policy)) {
      return currentTier;
    }
    let resultTier = currentTier;
    if (resultTier === "autonomous" && this.policy.tiers.autonomous?.require_known_destination) {
      factors.push({
        source: "new_destination",
        tier: "delayed",
        reason: "Destination not in allowlist (require_known_destination enabled)"
      });
      resultTier = "delayed";
    }
    if (this.policy.tiers.cosign?.new_destination_always) {
      const isKnown = this.limitTracker.isDestinationKnown(
        context.transaction.destination
      );
      if (!isKnown) {
        const newTier = this.compareTiers("cosign", resultTier);
        if (newTier === "cosign" && resultTier !== "cosign") {
          factors.push({
            source: "new_destination",
            tier: "cosign",
            reason: "First transaction to new destination"
          });
          resultTier = "cosign";
        }
      }
    }
    return resultTier;
  }
  /**
   * Compare two tiers and return the more restrictive one.
   */
  compareTiers(tier1, tier2) {
    const tierOrder = {
      autonomous: 1,
      delayed: 2,
      cosign: 3,
      prohibited: 4
    };
    return tierOrder[tier1] > tierOrder[tier2] ? tier1 : tier2;
  }
  /**
   * Create a prohibited result.
   */
  createProhibitedResult(reason, matchedRule, startTime, injectionDetected) {
    const result = {
      allowed: false,
      tier: "prohibited",
      tierNumeric: 4,
      reason,
      matchedRule,
      evaluationTimeMs: performance.now() - startTime
    };
    if (injectionDetected !== void 0) {
      result.injectionDetected = injectionDetected;
    }
    return result;
  }
  // ============================================================================
  // PUBLIC METHODS
  // ============================================================================
  /**
   * Get policy hash.
   */
  getPolicyHash() {
    return this.policyHash;
  }
  /**
   * Get policy info.
   */
  getPolicyInfo() {
    const info = {
      name: this.policy.name,
      version: this.policy.version,
      network: this.policy.network,
      enabled: this.policy.enabled,
      loadedAt: this.loadedAt,
      hash: this.policyHash.slice(0, 16),
      ruleCount: this.policy.rules.length,
      enabledRuleCount: this.ruleEvaluator.getRuleCount()
    };
    if (this.policy.description !== void 0) {
      info.description = this.policy.description;
    }
    return info;
  }
  /**
   * Verify policy integrity.
   */
  verifyIntegrity() {
    const currentHash = this.computeHash(this.policy);
    return currentHash === this.policyHash;
  }
  /**
   * Get limit state.
   */
  getLimitState() {
    return this.limitTracker.getState();
  }
  /**
   * Reset limits.
   */
  resetLimits(confirmation) {
    this.limitTracker.reset(confirmation);
  }
  /**
   * Record a successful transaction.
   */
  recordTransaction(context) {
    this.limitTracker.recordTransaction(context);
  }
  /**
   * Dispose of resources.
   */
  dispose() {
    this.limitTracker.dispose();
  }
  // ============================================================================
  // PRIVATE HELPERS
  // ============================================================================
  /**
   * Compute SHA-256 hash of policy.
   */
  computeHash(policy) {
    const content = JSON.stringify(policy);
    return createHash("sha256").update(content).digest("hex");
  }
  /**
   * Deep freeze an object.
   */
  deepFreeze(obj) {
    const propNames = Object.getOwnPropertyNames(obj);
    for (const name of propNames) {
      const value = obj[name];
      if (value && typeof value === "object") {
        this.deepFreeze(value);
      }
    }
    return Object.freeze(obj);
  }
};
function createPolicyEngine(policy, options) {
  const internalPolicy = {
    version: policy.policy_version,
    name: policy.policy_id,
    network: "mainnet",
    // Default, should be provided externally
    enabled: true,
    tiers: {
      autonomous: {
        max_amount_xrp: dropsToXrp(policy.limits.max_amount_per_tx_drops),
        daily_limit_xrp: dropsToXrp(policy.limits.max_daily_volume_drops),
        require_known_destination: policy.destinations.mode === "allowlist" || !policy.destinations.allow_new_destinations,
        allowed_transaction_types: policy.transaction_types.allowed
      },
      delayed: {
        max_amount_xrp: dropsToXrp(policy.escalation.amount_threshold_drops),
        delay_seconds: policy.escalation.delay_seconds ?? 300,
        veto_enabled: true,
        notify_on_queue: true
      },
      cosign: {
        signer_quorum: 2,
        new_destination_always: policy.escalation.new_destination === 3,
        approval_timeout_hours: 24
      },
      prohibited: {
        prohibited_transaction_types: policy.transaction_types.blocked ?? []
      }
    },
    rules: buildRulesFromPolicy(policy),
    blocklist: {
      addresses: policy.destinations.blocklist ?? []
    },
    allowlist: {
      addresses: policy.destinations.mode === "allowlist" ? policy.destinations.allowlist ?? [] : []
    },
    limits: {
      daily_reset_utc_hour: 0,
      max_transactions_per_hour: policy.limits.max_tx_per_hour,
      max_transactions_per_day: policy.limits.max_tx_per_day,
      max_total_volume_xrp_per_day: dropsToXrp(policy.limits.max_daily_volume_drops)
    }
  };
  return new PolicyEngine(internalPolicy, options);
}
function dropsToXrp(drops) {
  return Number(BigInt(drops)) / 1e6;
}
function buildRulesFromPolicy(policy) {
  const rules = [];
  let priority = 1;
  if (policy.destinations.blocklist && policy.destinations.blocklist.length > 0) {
    rules.push({
      id: "blocklist-check",
      name: "Blocklist Check",
      priority: priority++,
      condition: {
        field: "destination",
        operator: "in",
        value: { ref: "blocklist.addresses" }
      },
      action: {
        tier: "prohibited",
        reason: "Destination is blocklisted"
      }
    });
  }
  if (policy.transaction_types.blocked && policy.transaction_types.blocked.length > 0) {
    for (const txType of policy.transaction_types.blocked) {
      rules.push({
        id: `block-${txType.toLowerCase()}`,
        name: `Block ${txType}`,
        priority: priority++,
        condition: {
          field: "transaction_type",
          operator: "==",
          value: txType
        },
        action: {
          tier: "prohibited",
          reason: `Transaction type ${txType} is not allowed`
        }
      });
    }
  }
  if (policy.transaction_types.require_approval && policy.transaction_types.require_approval.length > 0) {
    for (const txType of policy.transaction_types.require_approval) {
      rules.push({
        id: `require-approval-${txType.toLowerCase()}`,
        name: `Require Approval for ${txType}`,
        priority: priority++,
        condition: {
          field: "transaction_type",
          operator: "==",
          value: txType
        },
        action: {
          tier: "cosign",
          reason: `Transaction type ${txType} requires approval`
        }
      });
    }
  }
  const thresholdXrp = dropsToXrp(policy.escalation.amount_threshold_drops);
  rules.push({
    id: "high-value-cosign",
    name: "High Value Transaction",
    priority: priority++,
    condition: {
      field: "amount_xrp",
      operator: ">=",
      value: thresholdXrp
    },
    action: {
      tier: policy.escalation.new_destination === 3 ? "cosign" : "delayed",
      reason: `Amount exceeds ${thresholdXrp} XRP threshold`
    }
  });
  if (policy.destinations.mode === "allowlist" || !policy.destinations.allow_new_destinations) {
    rules.push({
      id: "new-destination-check",
      name: "New Destination Check",
      priority: priority++,
      condition: {
        not: {
          field: "destination",
          operator: "in",
          value: { ref: "allowlist.addresses" }
        }
      },
      action: {
        tier: policy.destinations.new_destination_tier === 3 ? "cosign" : policy.destinations.new_destination_tier === 2 ? "delayed" : "prohibited",
        reason: "Destination not in allowlist"
      }
    });
  }
  rules.push({
    id: "default-allow",
    name: "Default Allow",
    priority: 999,
    condition: {
      always: true
    },
    action: {
      tier: "autonomous",
      reason: "Transaction within policy limits"
    }
  });
  return rules;
}
function createTestPolicy(network = "testnet", overrides) {
  const basePolicy = {
    version: "1.0",
    name: `${network}-test-policy`,
    description: "Test policy for development",
    network,
    enabled: true,
    tiers: {
      autonomous: {
        max_amount_xrp: network === "mainnet" ? 100 : 1e4,
        daily_limit_xrp: network === "mainnet" ? 1e3 : 1e5,
        require_known_destination: network === "mainnet",
        allowed_transaction_types: ["Payment", "EscrowFinish", "EscrowCancel"]
      },
      delayed: {
        max_amount_xrp: network === "mainnet" ? 1e3 : 1e5,
        delay_seconds: network === "mainnet" ? 300 : 60,
        veto_enabled: true,
        notify_on_queue: true
      },
      cosign: {
        signer_quorum: 2,
        new_destination_always: network === "mainnet",
        approval_timeout_hours: 24
      },
      prohibited: {
        prohibited_transaction_types: ["Clawback"]
      }
    },
    rules: [
      {
        id: "default-allow",
        name: "Default Allow",
        priority: 999,
        condition: { always: true },
        action: { tier: "autonomous", reason: "Within policy limits" }
      }
    ],
    blocklist: {
      addresses: [],
      memo_patterns: ["ignore.*previous", "\\[INST\\]", "<<SYS>>"]
    },
    allowlist: {
      addresses: []
    },
    limits: {
      daily_reset_utc_hour: 0,
      max_transactions_per_hour: network === "mainnet" ? 50 : 1e3,
      max_transactions_per_day: network === "mainnet" ? 200 : 1e4,
      max_unique_destinations_per_day: network === "mainnet" ? 20 : 500,
      max_total_volume_xrp_per_day: network === "mainnet" ? 5e3 : 1e7
    }
  };
  if (overrides) {
    return deepMerge(basePolicy, overrides);
  }
  return basePolicy;
}
function deepMerge(target, source) {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    const sourceValue = source[key];
    const targetValue = target[key];
    if (sourceValue !== void 0 && typeof sourceValue === "object" && sourceValue !== null && !Array.isArray(sourceValue) && typeof targetValue === "object" && targetValue !== null && !Array.isArray(targetValue)) {
      result[key] = deepMerge(
        targetValue,
        sourceValue
      );
    } else if (sourceValue !== void 0) {
      result[key] = sourceValue;
    }
  }
  return result;
}

// src/keystore/secure-buffer.ts
var SecureBuffer = class _SecureBuffer {
  buffer;
  isDisposed = false;
  /**
   * Private constructor - use static factory methods.
   */
  constructor(size) {
    this.buffer = Buffer.allocUnsafe(size);
  }
  /**
   * Creates a new SecureBuffer with uninitialized content of specified size.
   *
   * @param size - Size in bytes
   * @returns New SecureBuffer instance
   */
  static alloc(size) {
    if (size <= 0) {
      throw new Error("SecureBuffer size must be positive");
    }
    const secure = new _SecureBuffer(size);
    secure.buffer.fill(0);
    return secure;
  }
  /**
   * Creates a SecureBuffer from existing data.
   *
   * IMPORTANT: The source buffer is zeroed immediately after copying
   * to prevent the original data from remaining in memory.
   *
   * @param data - Source buffer (will be zeroed)
   * @returns New SecureBuffer containing the copied data
   */
  static from(data) {
    if (!Buffer.isBuffer(data)) {
      throw new Error("SecureBuffer.from requires a Buffer");
    }
    if (data.length === 0) {
      throw new Error("SecureBuffer cannot be empty");
    }
    const secure = new _SecureBuffer(data.length);
    data.copy(secure.buffer);
    data.fill(0);
    return secure;
  }
  /**
   * Gets the buffer contents for use in cryptographic operations.
   *
   * @returns The internal Buffer
   * @throws Error if buffer has been disposed
   */
  getBuffer() {
    if (this.isDisposed) {
      throw new Error("SecureBuffer has been disposed");
    }
    return this.buffer;
  }
  /**
   * Disposes the buffer by securely zeroing its contents.
   *
   * This operation is irreversible. Multiple overwrite passes are used
   * to help prevent data recovery.
   */
  dispose() {
    if (!this.isDisposed) {
      this.buffer.fill(0);
      this.buffer.fill(255);
      this.buffer.fill(0);
      this.isDisposed = true;
    }
  }
  /**
   * Alias for dispose() - matches common naming conventions.
   */
  zero() {
    this.dispose();
  }
  /**
   * Returns whether the buffer has been disposed.
   */
  get disposed() {
    return this.isDisposed;
  }
  /**
   * Alias for disposed getter - matches spec naming.
   */
  get zeroed() {
    return this.isDisposed;
  }
  /**
   * Buffer length in bytes.
   */
  get length() {
    return this.buffer.length;
  }
  /**
   * Executes an operation with the buffer and ensures cleanup on completion.
   *
   * The SecureBuffer is automatically disposed after the operation,
   * regardless of success or failure.
   *
   * @param secure - SecureBuffer to use
   * @param operation - Async operation that uses the buffer
   * @returns Result of the operation
   */
  static async withSecure(secure, operation) {
    try {
      return await operation(secure.getBuffer());
    } finally {
      secure.dispose();
    }
  }
  /**
   * Creates a SecureBuffer, executes an operation, and disposes it.
   *
   * @param data - Source buffer (will be zeroed)
   * @param operation - Async operation that uses the buffer
   * @returns Result of the operation
   */
  static async withSecureBuffer(data, operation) {
    const secure = _SecureBuffer.from(data);
    try {
      return await operation(secure.getBuffer());
    } finally {
      secure.dispose();
    }
  }
  // ========================================================================
  // Serialization Prevention
  // ========================================================================
  /**
   * Prevents JSON serialization of sensitive data.
   * @throws Error always
   */
  toJSON() {
    throw new Error("SecureBuffer cannot be serialized to JSON");
  }
  /**
   * Returns a placeholder string instead of buffer contents.
   */
  toString() {
    return "[SecureBuffer]";
  }
  /**
   * Custom Node.js inspection - prevents accidental logging of contents.
   */
  [/* @__PURE__ */ Symbol.for("nodejs.util.inspect.custom")]() {
    return `[SecureBuffer length=${this.length} disposed=${this.isDisposed}]`;
  }
  /**
   * Prevents spreading/iteration of buffer contents.
   */
  [Symbol.iterator]() {
    throw new Error("SecureBuffer cannot be iterated");
  }
};

// src/keystore/errors.ts
var KeystoreError = class extends Error {
  constructor(message, details) {
    super(message);
    this.details = details;
    this.name = this.constructor.name;
    this.timestamp = (/* @__PURE__ */ new Date()).toISOString();
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
  /** Timestamp when error occurred */
  timestamp;
  /** Correlation ID for tracking */
  correlationId;
  /**
   * Convert to safe JSON representation (excludes sensitive data).
   */
  toSafeJSON() {
    return {
      code: this.code,
      message: this.message,
      recoverable: this.recoverable,
      timestamp: this.timestamp,
      correlationId: this.correlationId
    };
  }
};
var KeystoreInitializationError = class extends KeystoreError {
  code = "KEYSTORE_INIT_ERROR";
  recoverable = false;
  originalCause;
  constructor(message, originalCause) {
    super(message, { cause: originalCause?.message });
    this.originalCause = originalCause;
  }
};
var WalletNotFoundError = class extends KeystoreError {
  constructor(walletId) {
    super(`Wallet not found: ${walletId}`, { walletId });
    this.walletId = walletId;
  }
  code = "WALLET_NOT_FOUND";
  recoverable = false;
};
var WalletExistsError = class extends KeystoreError {
  constructor(walletId, existingAddress) {
    super(`Wallet already exists: ${walletId}`, { walletId, existingAddress });
    this.walletId = walletId;
    this.existingAddress = existingAddress;
  }
  code = "WALLET_EXISTS";
  recoverable = false;
};
var AuthenticationError = class extends KeystoreError {
  code = "AUTHENTICATION_ERROR";
  recoverable = true;
  constructor() {
    super("Authentication failed");
  }
};
var WeakPasswordError = class extends KeystoreError {
  constructor(requirements) {
    super("Password does not meet security requirements", { requirements });
    this.requirements = requirements;
  }
  code = "WEAK_PASSWORD";
  recoverable = true;
};
var KeyDecryptionError = class extends KeystoreError {
  code = "KEY_DECRYPTION_ERROR";
  recoverable = false;
  constructor(message = "Key decryption failed") {
    super(message);
  }
};
var KeyEncryptionError = class extends KeystoreError {
  code = "KEY_ENCRYPTION_ERROR";
  recoverable = false;
  constructor(message = "Key encryption failed") {
    super(message);
  }
};
var InvalidKeyError = class extends KeystoreError {
  constructor(reason, expectedFormat) {
    super(`Invalid key format: ${reason}`, { reason, expectedFormat });
    this.reason = reason;
    this.expectedFormat = expectedFormat;
  }
  code = "INVALID_KEY_FORMAT";
  recoverable = false;
};
var KeystoreWriteError = class extends KeystoreError {
  constructor(message, operation) {
    super(message, { operation });
    this.operation = operation;
  }
  code = "KEYSTORE_WRITE_ERROR";
  recoverable = true;
};
var KeystoreReadError = class extends KeystoreError {
  code = "KEYSTORE_READ_ERROR";
  recoverable = true;
  constructor(message) {
    super(message);
  }
};
var KeystoreCapacityError = class extends KeystoreError {
  constructor(network, currentCount, maxCount) {
    super(`Keystore capacity exceeded for ${network}`, {
      network,
      currentCount,
      maxCount
    });
    this.network = network;
    this.currentCount = currentCount;
    this.maxCount = maxCount;
  }
  code = "KEYSTORE_CAPACITY_ERROR";
  recoverable = false;
};
var BackupFormatError = class extends KeystoreError {
  constructor(reason, expectedVersion) {
    super(`Invalid backup format: ${reason}`, { reason, expectedVersion });
    this.reason = reason;
    this.expectedVersion = expectedVersion;
  }
  code = "BACKUP_FORMAT_ERROR";
  recoverable = false;
};
var NetworkMismatchError = class extends KeystoreError {
  constructor(walletNetwork, requestedNetwork) {
    super(`Network mismatch: wallet is ${walletNetwork}, requested ${requestedNetwork}`, {
      walletNetwork,
      requestedNetwork
    });
    this.walletNetwork = walletNetwork;
    this.requestedNetwork = requestedNetwork;
  }
  code = "NETWORK_MISMATCH";
  recoverable = false;
};
var ProviderUnavailableError = class extends KeystoreError {
  constructor(providerType, reason) {
    super(`Provider unavailable: ${reason}`, { providerType, reason });
    this.providerType = providerType;
    this.reason = reason;
  }
  code = "PROVIDER_UNAVAILABLE";
  recoverable = true;
};
function isKeystoreError(error) {
  return error instanceof KeystoreError;
}
function isKeystoreErrorCode(error, code) {
  return isKeystoreError(error) && error.code === code;
}
var ARGON2_CONFIG = {
  type: argon2.argon2id,
  memoryCost: 65536,
  // 64 MB
  timeCost: 3,
  // 3 iterations
  parallelism: 4,
  // 4 threads
  hashLength: 32,
  // 256-bit output
  saltLength: 32
  // 256-bit salt
};
var AES_CONFIG = {
  algorithm: "aes-256-gcm",
  keyLength: 32,
  // 256 bits
  ivLength: 12,
  // 96 bits (NIST recommended for GCM)
  authTagLength: 16
  // 128 bits
};
var PERMISSIONS = {
  FILE: 384,
  // Owner read/write only (rw-------)
  DIRECTORY: 448
  // Owner read/write/execute only (rwx------)
};
var DEFAULT_PASSWORD_POLICY = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecial: false,
  maxLength: 128
};
var RATE_LIMIT_CONFIG = {
  maxAttempts: 5,
  // Max failed attempts
  windowSeconds: 900,
  // 15 minute window
  lockoutSeconds: 1800,
  // 30 minute initial lockout
  lockoutMultiplier: 2
  // Doubles each time
};
function validatePassword(password, policy) {
  const errors = [];
  if (password.length < policy.minLength) {
    errors.push(`Minimum ${policy.minLength} characters required`);
  }
  if (password.length > policy.maxLength) {
    errors.push(`Maximum ${policy.maxLength} characters allowed`);
  }
  if (policy.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push("Must contain uppercase letter");
  }
  if (policy.requireLowercase && !/[a-z]/.test(password)) {
    errors.push("Must contain lowercase letter");
  }
  if (policy.requireNumbers && !/\d/.test(password)) {
    errors.push("Must contain number");
  }
  if (policy.requireSpecial && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push("Must contain special character");
  }
  return errors;
}
var FileLock = class {
  locks = /* @__PURE__ */ new Map();
  /**
   * Executes operation with exclusive access to the file.
   */
  async withLock(key, operation) {
    while (this.locks.has(key)) {
      await this.locks.get(key);
    }
    let releaseLock;
    const lockPromise = new Promise((resolve2) => {
      releaseLock = resolve2;
    });
    this.locks.set(key, lockPromise);
    try {
      return await operation();
    } finally {
      this.locks.delete(key);
      releaseLock();
    }
  }
};
var LocalKeystore = class {
  providerType = "local-file";
  providerVersion = "1.0.0";
  baseDir = "";
  passwordPolicy = DEFAULT_PASSWORD_POLICY;
  maxWalletsPerNetwork = 100;
  initialized = false;
  fileLock = new FileLock();
  // Rate limiting state
  authAttempts = /* @__PURE__ */ new Map();
  lockouts = /* @__PURE__ */ new Map();
  // ========================================================================
  // Lifecycle Methods
  // ========================================================================
  async initialize(config) {
    if (this.initialized) {
      throw new KeystoreInitializationError("Provider already initialized");
    }
    const homeDir = process.env["HOME"] || "";
    this.baseDir = config.baseDir ? path2.resolve(config.baseDir.replace(/^~/, homeDir)) : path2.join(homeDir, ".xrpl-wallet-mcp");
    if (config.passwordPolicy) {
      this.passwordPolicy = { ...DEFAULT_PASSWORD_POLICY, ...config.passwordPolicy };
    }
    if (config.maxWalletsPerNetwork !== void 0) {
      this.maxWalletsPerNetwork = config.maxWalletsPerNetwork;
    }
    await this.ensureDirectoryStructure();
    await this.verifyPermissions();
    this.initialized = true;
  }
  async healthCheck() {
    this.assertInitialized();
    const errors = [];
    let storageAccessible = true;
    let encryptionAvailable = true;
    let networkCount = 0;
    let walletCount = 0;
    try {
      await promises.access(this.baseDir, promises.constants.R_OK | promises.constants.W_OK);
    } catch {
      storageAccessible = false;
      errors.push("Base directory not accessible");
    }
    try {
      const testKey = crypto.randomBytes(32);
      const testIv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv("aes-256-gcm", testKey, testIv);
      cipher.update("test");
      cipher.final();
    } catch {
      encryptionAvailable = false;
      errors.push("AES-256-GCM encryption not available");
    }
    for (const network of ["mainnet", "testnet", "devnet"]) {
      const networkDir = path2.join(this.baseDir, network, "wallets");
      try {
        await promises.access(networkDir);
        networkCount++;
        const files = await promises.readdir(networkDir);
        walletCount += files.filter((f) => f.endsWith(".wallet.json")).length;
      } catch {
      }
    }
    const result = {
      healthy: storageAccessible && encryptionAvailable && errors.length === 0,
      providerType: this.providerType,
      providerVersion: this.providerVersion,
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      details: {
        storageAccessible,
        encryptionAvailable,
        networkCount,
        walletCount
      }
    };
    if (errors.length > 0) {
      result.errors = errors;
    }
    return result;
  }
  async close() {
    this.authAttempts.clear();
    this.lockouts.clear();
    this.initialized = false;
  }
  // ========================================================================
  // Wallet CRUD Operations
  // ========================================================================
  async createWallet(network, policy, options) {
    this.assertInitialized();
    if (!options?.password) {
      throw new WeakPasswordError(["Password is required"]);
    }
    const passwordErrors = validatePassword(options.password, this.passwordPolicy);
    if (passwordErrors.length > 0) {
      throw new WeakPasswordError(passwordErrors);
    }
    const currentCount = (await this.listWallets(network)).length;
    if (currentCount >= this.maxWalletsPerNetwork) {
      throw new KeystoreCapacityError(network, currentCount, this.maxWalletsPerNetwork);
    }
    const walletId = this.generateWalletId();
    const algorithm = options?.algorithm || "ed25519";
    const xrplAlgorithm = algorithm === "secp256k1" ? ECDSA.secp256k1 : ECDSA.ed25519;
    const xrplWallet = Wallet.generate(xrplAlgorithm);
    const seedHex = xrplWallet.seed;
    if (!seedHex) {
      throw new KeystoreWriteError("Failed to generate wallet seed", "create");
    }
    const seedBuffer = Buffer.from(xrplWallet.privateKey, "hex");
    const seed = SecureBuffer.from(seedBuffer);
    try {
      const salt = crypto.randomBytes(ARGON2_CONFIG.saltLength);
      const kek = await this.deriveKey(options.password, salt);
      const { encryptedData, iv, authTag } = await this.encrypt(seed.getBuffer(), kek);
      kek.dispose();
      const now = (/* @__PURE__ */ new Date()).toISOString();
      const entry = {
        walletId,
        name: options?.name || `Wallet ${walletId.slice(0, 8)}`,
        address: xrplWallet.classicAddress,
        publicKey: xrplWallet.publicKey,
        algorithm,
        network,
        policyId: policy.policyId,
        encryption: {
          algorithm: "aes-256-gcm",
          kdf: "argon2id",
          kdfParams: {
            memoryCost: ARGON2_CONFIG.memoryCost,
            timeCost: ARGON2_CONFIG.timeCost,
            parallelism: ARGON2_CONFIG.parallelism
          },
          salt: salt.toString("base64")
        },
        metadata: {
          ...options?.description && { description: options.description },
          ...options?.tags && { tags: options.tags }
        },
        createdAt: now,
        modifiedAt: now,
        status: "active"
      };
      const walletFile = {
        version: 1,
        walletId,
        entry,
        encryptedKey: {
          data: encryptedData.toString("base64"),
          iv: iv.toString("base64"),
          authTag: authTag.toString("base64")
        }
      };
      const walletPath = this.getWalletPath(network, walletId);
      await this.atomicWrite(walletPath, JSON.stringify(walletFile, null, 2));
      await this.updateIndex(network, entry, "add");
      return entry;
    } finally {
      seed.dispose();
    }
  }
  async loadKey(walletId, password) {
    this.assertInitialized();
    this.checkRateLimit(walletId);
    try {
      const { walletFile } = await this.findWallet(walletId);
      const salt = Buffer.from(walletFile.entry.encryption.salt, "base64");
      const kek = await this.deriveKey(password, salt);
      try {
        const encryptedData = Buffer.from(walletFile.encryptedKey.data, "base64");
        const iv = Buffer.from(walletFile.encryptedKey.iv, "base64");
        const authTag = Buffer.from(walletFile.encryptedKey.authTag, "base64");
        const decrypted = await this.decrypt(encryptedData, kek, iv, authTag);
        this.recordAuthSuccess(walletId);
        return decrypted;
      } finally {
        kek.dispose();
      }
    } catch (error) {
      if (error instanceof AuthenticationError || error instanceof KeyDecryptionError) {
        this.recordAuthFailure(walletId);
      }
      throw error;
    }
  }
  async storeKey(walletId, key, password, metadata) {
    this.assertInitialized();
    const passwordErrors = validatePassword(password, this.passwordPolicy);
    if (passwordErrors.length > 0) {
      throw new WeakPasswordError(passwordErrors);
    }
    try {
      await this.findWallet(walletId);
      throw new WalletExistsError(walletId);
    } catch (error) {
      if (!(error instanceof WalletNotFoundError)) {
        throw error;
      }
    }
    const keyBuffer = key.getBuffer();
    if (keyBuffer.length !== 16) {
      throw new InvalidKeyError("Invalid key length", "Expected 16 bytes (128-bit entropy)");
    }
    let xrplWallet;
    try {
      xrplWallet = Wallet.fromEntropy(keyBuffer);
    } catch {
      throw new InvalidKeyError("Could not derive wallet from key");
    }
    const network = "testnet";
    const salt = crypto.randomBytes(ARGON2_CONFIG.saltLength);
    const kek = await this.deriveKey(password, salt);
    try {
      const { encryptedData, iv, authTag } = await this.encrypt(keyBuffer, kek);
      const now = (/* @__PURE__ */ new Date()).toISOString();
      const entry = {
        walletId,
        name: walletId,
        address: xrplWallet.classicAddress,
        publicKey: xrplWallet.publicKey,
        algorithm: "ed25519",
        network,
        policyId: "imported",
        encryption: {
          algorithm: "aes-256-gcm",
          kdf: "argon2id",
          kdfParams: {
            memoryCost: ARGON2_CONFIG.memoryCost,
            timeCost: ARGON2_CONFIG.timeCost,
            parallelism: ARGON2_CONFIG.parallelism
          },
          salt: salt.toString("base64")
        },
        metadata,
        createdAt: now,
        modifiedAt: now,
        status: "active"
      };
      const walletFile = {
        version: 1,
        walletId,
        entry,
        encryptedKey: {
          data: encryptedData.toString("base64"),
          iv: iv.toString("base64"),
          authTag: authTag.toString("base64")
        }
      };
      const walletPath = this.getWalletPath(network, walletId);
      await this.atomicWrite(walletPath, JSON.stringify(walletFile, null, 2));
      await this.updateIndex(network, entry, "add");
    } finally {
      kek.dispose();
    }
  }
  async listWallets(network) {
    this.assertInitialized();
    const networks = network ? [network] : ["mainnet", "testnet", "devnet"];
    const summaries = [];
    for (const net of networks) {
      const indexPath = path2.join(this.baseDir, net, "index.json");
      try {
        const content = await promises.readFile(indexPath, "utf-8");
        const index = JSON.parse(content);
        for (const entry of index.wallets) {
          const summary = {
            walletId: entry.walletId,
            name: entry.name,
            address: entry.address,
            network: entry.network,
            status: entry.status,
            createdAt: entry.createdAt,
            policyId: entry.policyId
          };
          if (entry.metadata?.lastUsedAt) {
            summary.lastUsedAt = entry.metadata.lastUsedAt;
          }
          if (entry.metadata?.tags) {
            summary.tags = entry.metadata.tags;
          }
          summaries.push(summary);
        }
      } catch {
      }
    }
    return summaries;
  }
  async getWallet(walletId) {
    this.assertInitialized();
    const { walletFile } = await this.findWallet(walletId);
    return walletFile.entry;
  }
  async deleteWallet(walletId, password) {
    this.assertInitialized();
    this.checkRateLimit(walletId);
    const { network, walletFile, filePath } = await this.findWallet(walletId);
    const salt = Buffer.from(walletFile.entry.encryption.salt, "base64");
    const kek = await this.deriveKey(password, salt);
    try {
      const encryptedData = Buffer.from(walletFile.encryptedKey.data, "base64");
      const iv = Buffer.from(walletFile.encryptedKey.iv, "base64");
      const authTag = Buffer.from(walletFile.encryptedKey.authTag, "base64");
      const decrypted = await this.decrypt(encryptedData, kek, iv, authTag);
      decrypted.dispose();
      this.recordAuthSuccess(walletId);
    } catch (error) {
      this.recordAuthFailure(walletId);
      throw error;
    } finally {
      kek.dispose();
    }
    await this.fileLock.withLock(filePath, async () => {
      const fileSize = (await promises.stat(filePath)).size;
      const randomData = crypto.randomBytes(fileSize);
      await promises.writeFile(filePath, randomData);
      await promises.unlink(filePath);
    });
    await this.updateIndex(network, walletFile.entry, "remove");
  }
  async rotateKey(walletId, currentPassword, newPassword) {
    this.assertInitialized();
    const passwordErrors = validatePassword(newPassword, this.passwordPolicy);
    if (passwordErrors.length > 0) {
      throw new WeakPasswordError(passwordErrors);
    }
    const key = await this.loadKey(walletId, currentPassword);
    try {
      const { network, walletFile, filePath } = await this.findWallet(walletId);
      const newSalt = crypto.randomBytes(ARGON2_CONFIG.saltLength);
      const newKek = await this.deriveKey(newPassword, newSalt);
      try {
        const { encryptedData, iv, authTag } = await this.encrypt(key.getBuffer(), newKek);
        walletFile.entry.encryption.salt = newSalt.toString("base64");
        walletFile.entry.modifiedAt = (/* @__PURE__ */ new Date()).toISOString();
        walletFile.encryptedKey = {
          data: encryptedData.toString("base64"),
          iv: iv.toString("base64"),
          authTag: authTag.toString("base64")
        };
        await this.atomicWrite(filePath, JSON.stringify(walletFile, null, 2));
        await this.updateIndex(network, walletFile.entry, "update");
      } finally {
        newKek.dispose();
      }
    } finally {
      key.dispose();
    }
  }
  async updateMetadata(walletId, updates) {
    this.assertInitialized();
    const { network, walletFile, filePath } = await this.findWallet(walletId);
    walletFile.entry.metadata = {
      ...walletFile.entry.metadata,
      ...updates
    };
    walletFile.entry.modifiedAt = (/* @__PURE__ */ new Date()).toISOString();
    await this.atomicWrite(filePath, JSON.stringify(walletFile, null, 2));
    await this.updateIndex(network, walletFile.entry, "update");
  }
  async exportBackup(walletId, password, format) {
    this.assertInitialized();
    const key = await this.loadKey(walletId, password);
    try {
      const { walletFile } = await this.findWallet(walletId);
      const payload = {
        version: 1,
        exportedAt: (/* @__PURE__ */ new Date()).toISOString(),
        wallet: {
          entry: walletFile.entry,
          seed: key.getBuffer().toString("hex")
        }
      };
      const backupSalt = crypto.randomBytes(ARGON2_CONFIG.saltLength);
      const backupKek = await this.deriveKey(password, backupSalt);
      try {
        const payloadBuffer = Buffer.from(JSON.stringify(payload));
        const { encryptedData, iv, authTag } = await this.encrypt(payloadBuffer, backupKek);
        const checksum = crypto.createHash("sha256").update(encryptedData).digest("hex");
        const backup = {
          version: 1,
          format,
          createdAt: (/* @__PURE__ */ new Date()).toISOString(),
          sourceProvider: this.providerType,
          encryption: {
            algorithm: "aes-256-gcm",
            kdf: "argon2id",
            kdfParams: {
              memoryCost: ARGON2_CONFIG.memoryCost,
              timeCost: ARGON2_CONFIG.timeCost,
              parallelism: ARGON2_CONFIG.parallelism
            },
            salt: backupSalt.toString("base64"),
            iv: iv.toString("base64"),
            authTag: authTag.toString("base64")
          },
          payload: encryptedData.toString("base64"),
          checksum
        };
        return backup;
      } finally {
        backupKek.dispose();
      }
    } finally {
      key.dispose();
    }
  }
  async importBackup(backup, password, options) {
    this.assertInitialized();
    if (backup.version !== 1) {
      throw new BackupFormatError("Unsupported backup version", 1);
    }
    const payloadData = Buffer.from(backup.payload, "base64");
    const computedChecksum = crypto.createHash("sha256").update(payloadData).digest("hex");
    if (computedChecksum !== backup.checksum) {
      throw new BackupFormatError("Checksum verification failed");
    }
    const salt = Buffer.from(backup.encryption.salt, "base64");
    const kek = await this.deriveKey(password, salt);
    let decryptedPayload;
    try {
      const iv = Buffer.from(backup.encryption.iv, "base64");
      const authTag = Buffer.from(backup.encryption.authTag, "base64");
      decryptedPayload = await this.decrypt(payloadData, kek, iv, authTag);
    } finally {
      kek.dispose();
    }
    try {
      const payload = JSON.parse(decryptedPayload.getBuffer().toString());
      const walletId = options?.newName || payload.wallet.entry.walletId;
      const targetNetwork = options?.targetNetwork || payload.wallet.entry.network;
      try {
        await this.findWallet(walletId);
        if (!options?.force) {
          throw new WalletExistsError(walletId);
        }
      } catch (error) {
        if (!(error instanceof WalletNotFoundError)) {
          throw error;
        }
      }
      const seedBuffer = Buffer.from(payload.wallet.seed, "hex");
      const seed = SecureBuffer.from(seedBuffer);
      try {
        const storePassword = options?.newPassword || password;
        const newSalt = crypto.randomBytes(ARGON2_CONFIG.saltLength);
        const newKek = await this.deriveKey(storePassword, newSalt);
        try {
          const { encryptedData, iv, authTag } = await this.encrypt(seed.getBuffer(), newKek);
          const now = (/* @__PURE__ */ new Date()).toISOString();
          const entry = {
            ...payload.wallet.entry,
            walletId,
            network: targetNetwork,
            encryption: {
              algorithm: "aes-256-gcm",
              kdf: "argon2id",
              kdfParams: {
                memoryCost: ARGON2_CONFIG.memoryCost,
                timeCost: ARGON2_CONFIG.timeCost,
                parallelism: ARGON2_CONFIG.parallelism
              },
              salt: newSalt.toString("base64")
            },
            modifiedAt: now,
            metadata: {
              ...payload.wallet.entry.metadata || {},
              customData: {
                ...payload.wallet.entry.metadata?.customData || {},
                importedAt: now,
                importedFrom: backup.sourceProvider
              }
            }
          };
          const walletFile = {
            version: 1,
            walletId,
            entry,
            encryptedKey: {
              data: encryptedData.toString("base64"),
              iv: iv.toString("base64"),
              authTag: authTag.toString("base64")
            }
          };
          const walletPath = this.getWalletPath(targetNetwork, walletId);
          await this.atomicWrite(walletPath, JSON.stringify(walletFile, null, 2));
          await this.updateIndex(targetNetwork, entry, "add");
          return entry;
        } finally {
          newKek.dispose();
        }
      } finally {
        seed.dispose();
      }
    } finally {
      decryptedPayload.dispose();
    }
  }
  // ========================================================================
  // Private Helper Methods
  // ========================================================================
  assertInitialized() {
    if (!this.initialized) {
      throw new KeystoreInitializationError("Provider not initialized");
    }
  }
  async ensureDirectoryStructure() {
    await promises.mkdir(this.baseDir, { recursive: true, mode: PERMISSIONS.DIRECTORY });
    for (const network of ["mainnet", "testnet", "devnet"]) {
      const walletsDir = path2.join(this.baseDir, network, "wallets");
      await promises.mkdir(walletsDir, { recursive: true, mode: PERMISSIONS.DIRECTORY });
    }
    const backupDir = path2.join(this.baseDir, "backups");
    await promises.mkdir(backupDir, { recursive: true, mode: PERMISSIONS.DIRECTORY });
  }
  async verifyPermissions() {
    const stats = await promises.stat(this.baseDir);
    const mode = stats.mode & 511;
    if (mode !== PERMISSIONS.DIRECTORY) {
      await promises.chmod(this.baseDir, PERMISSIONS.DIRECTORY);
    }
  }
  generateWalletId() {
    const timestamp = Date.now().toString(36);
    const random = crypto.randomBytes(8).toString("hex");
    return `wallet_${timestamp}_${random}`;
  }
  getWalletPath(network, walletId) {
    return path2.join(this.baseDir, network, "wallets", `${walletId}.wallet.json`);
  }
  async findWallet(walletId) {
    for (const network of ["mainnet", "testnet", "devnet"]) {
      const filePath = this.getWalletPath(network, walletId);
      try {
        const content = await promises.readFile(filePath, "utf-8");
        const walletFile = JSON.parse(content);
        return { network, walletFile, filePath };
      } catch {
      }
    }
    throw new WalletNotFoundError(walletId);
  }
  async updateIndex(network, entry, operation) {
    const indexPath = path2.join(this.baseDir, network, "index.json");
    await this.fileLock.withLock(indexPath, async () => {
      let index;
      try {
        const content = await promises.readFile(indexPath, "utf-8");
        index = JSON.parse(content);
      } catch {
        index = { version: 1, wallets: [], modifiedAt: "" };
      }
      switch (operation) {
        case "add":
          index.wallets.push(entry);
          break;
        case "remove":
          index.wallets = index.wallets.filter((w) => w.walletId !== entry.walletId);
          break;
        case "update":
          index.wallets = index.wallets.map((w) => w.walletId === entry.walletId ? entry : w);
          break;
      }
      index.modifiedAt = (/* @__PURE__ */ new Date()).toISOString();
      await this.atomicWrite(indexPath, JSON.stringify(index, null, 2));
    });
  }
  // ========================================================================
  // Cryptographic Operations
  // ========================================================================
  /**
   * Derives a 256-bit key from password using Argon2id.
   */
  async deriveKey(password, salt) {
    const derivedKey = await argon2.hash(password, {
      type: ARGON2_CONFIG.type,
      memoryCost: ARGON2_CONFIG.memoryCost,
      timeCost: ARGON2_CONFIG.timeCost,
      parallelism: ARGON2_CONFIG.parallelism,
      hashLength: ARGON2_CONFIG.hashLength,
      salt,
      raw: true
      // Return raw bytes, not encoded string
    });
    return SecureBuffer.from(derivedKey);
  }
  /**
   * Encrypts data using AES-256-GCM.
   */
  async encrypt(plaintext, key) {
    const iv = crypto.randomBytes(AES_CONFIG.ivLength);
    const cipher = crypto.createCipheriv(AES_CONFIG.algorithm, key.getBuffer(), iv, {
      authTagLength: AES_CONFIG.authTagLength
    });
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return {
      encryptedData: encrypted,
      iv,
      authTag
    };
  }
  /**
   * Decrypts data using AES-256-GCM.
   */
  async decrypt(ciphertext, key, iv, authTag) {
    try {
      const decipher = crypto.createDecipheriv(AES_CONFIG.algorithm, key.getBuffer(), iv, {
        authTagLength: AES_CONFIG.authTagLength
      });
      decipher.setAuthTag(authTag);
      const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return SecureBuffer.from(decrypted);
    } catch (error) {
      if (error instanceof Error && error.message.includes("auth")) {
        throw new AuthenticationError();
      }
      throw new KeyDecryptionError("Decryption failed");
    }
  }
  // ========================================================================
  // File System Operations
  // ========================================================================
  /**
   * Atomically writes content to a file using temp file + rename pattern.
   */
  async atomicWrite(filePath, content) {
    const dir = path2.dirname(filePath);
    const tempPath = path2.join(dir, `.${path2.basename(filePath)}.tmp.${process.pid}`);
    try {
      await promises.writeFile(tempPath, content, {
        encoding: "utf-8",
        mode: PERMISSIONS.FILE
      });
      await promises.rename(tempPath, filePath);
    } catch (error) {
      try {
        await promises.unlink(tempPath);
      } catch {
      }
      throw new KeystoreWriteError(`Failed to write ${filePath}: ${error}`, "create");
    }
  }
  // ========================================================================
  // Rate Limiting
  // ========================================================================
  /**
   * Checks if wallet is currently locked out.
   */
  checkRateLimit(walletId) {
    const lockout = this.lockouts.get(walletId);
    if (lockout && lockout > /* @__PURE__ */ new Date()) {
      throw new AuthenticationError();
    }
    if (lockout) {
      this.lockouts.delete(walletId);
    }
  }
  /**
   * Records successful authentication.
   */
  recordAuthSuccess(walletId) {
    this.authAttempts.delete(walletId);
    this.lockouts.delete(walletId);
  }
  /**
   * Records failed authentication attempt.
   */
  recordAuthFailure(walletId) {
    const now = /* @__PURE__ */ new Date();
    const windowStart = new Date(now.getTime() - RATE_LIMIT_CONFIG.windowSeconds * 1e3);
    let attempts = this.authAttempts.get(walletId) || [];
    attempts = attempts.filter((a) => a.timestamp > windowStart);
    attempts.push({ timestamp: now, success: false });
    this.authAttempts.set(walletId, attempts);
    const failures = attempts.filter((a) => !a.success).length;
    if (failures >= RATE_LIMIT_CONFIG.maxAttempts) {
      const lockoutCount = Math.floor(failures / RATE_LIMIT_CONFIG.maxAttempts);
      const duration = RATE_LIMIT_CONFIG.lockoutSeconds * Math.pow(RATE_LIMIT_CONFIG.lockoutMultiplier, lockoutCount - 1);
      const lockoutUntil = new Date(now.getTime() + duration * 1e3);
      this.lockouts.set(walletId, lockoutUntil);
    }
  }
};

// src/keystore/index.ts
var DEFAULT_PASSWORD_POLICY2 = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecial: false,
  maxLength: 128
};
var ARGON2_CONFIG2 = {
  memoryCost: 65536,
  // 64 MB
  timeCost: 3,
  // 3 iterations
  parallelism: 4,
  // 4 threads
  hashLength: 32,
  // 256-bit output
  saltLength: 32
  // 256-bit salt
};
var AES_CONFIG2 = {
  algorithm: "aes-256-gcm",
  keyLength: 32,
  // 256 bits
  ivLength: 12,
  // 96 bits
  authTagLength: 16
  // 128 bits
};

// src/xrpl/config.ts
var NETWORK_ENDPOINTS = {
  mainnet: {
    websocket: {
      primary: "wss://xrplcluster.com",
      backup: ["wss://s1.ripple.com", "wss://s2.ripple.com"]
    },
    jsonRpc: {
      primary: "https://xrplcluster.com",
      backup: ["https://s1.ripple.com:51234", "https://s2.ripple.com:51234"]
    }
  },
  testnet: {
    websocket: {
      primary: "wss://s.altnet.rippletest.net:51233",
      backup: ["wss://testnet.xrpl-labs.com"]
    },
    jsonRpc: {
      primary: "https://s.altnet.rippletest.net:51234",
      backup: []
    }
  },
  devnet: {
    websocket: {
      primary: "wss://s.devnet.rippletest.net:51233",
      backup: []
    },
    jsonRpc: {
      primary: "https://s.devnet.rippletest.net:51234",
      backup: []
    }
  }
};
var EXPLORER_URLS = {
  mainnet: {
    home: "https://xrpscan.com",
    account: (address) => `https://xrpscan.com/account/${address}`,
    transaction: (hash2) => `https://xrpscan.com/tx/${hash2}`,
    ledger: (index) => `https://xrpscan.com/ledger/${index}`
  },
  testnet: {
    home: "https://testnet.xrpl.org",
    account: (address) => `https://testnet.xrpl.org/accounts/${address}`,
    transaction: (hash2) => `https://testnet.xrpl.org/transactions/${hash2}`,
    ledger: (index) => `https://testnet.xrpl.org/ledgers/${index}`
  },
  devnet: {
    home: "https://devnet.xrpl.org",
    account: (address) => `https://devnet.xrpl.org/accounts/${address}`,
    transaction: (hash2) => `https://devnet.xrpl.org/transactions/${hash2}`,
    ledger: (index) => `https://devnet.xrpl.org/ledgers/${index}`
  }
};
var FAUCET_CONFIG = {
  mainnet: {
    available: false
    // No faucet for mainnet - real XRP must be acquired through exchanges
  },
  testnet: {
    available: true,
    url: "https://faucet.altnet.rippletest.net/accounts",
    amountXrp: 1e3,
    rateLimitSeconds: 60,
    rateLimitRequests: 1
  },
  devnet: {
    available: true,
    url: "https://faucet.devnet.rippletest.net/accounts",
    amountXrp: 1e3,
    rateLimitSeconds: 60,
    rateLimitRequests: 1
  }
};
var DEFAULT_CONNECTION_CONFIG = {
  connectionTimeout: 1e4,
  // 10 seconds
  requestTimeout: 3e4,
  // 30 seconds
  maxReconnectAttempts: 3,
  reconnectDelay: 1e3,
  // 1 second
  reconnectBackoff: 2
  // Exponential backoff multiplier
};
function getWebSocketUrl(network) {
  const envKey = `XRPL_${network.toUpperCase()}_WEBSOCKET_URL`;
  const customUrl = process.env[envKey];
  if (customUrl) {
    if (!customUrl.startsWith("wss://") && !customUrl.startsWith("ws://localhost")) {
      throw new Error(
        `Custom endpoint must use WSS or ws://localhost: ${envKey}=${customUrl}`
      );
    }
    return customUrl;
  }
  return NETWORK_ENDPOINTS[network].websocket.primary;
}
function getBackupWebSocketUrls(network) {
  return NETWORK_ENDPOINTS[network].websocket.backup;
}
function getTransactionExplorerUrl(hash2, network) {
  return EXPLORER_URLS[network].transaction(hash2);
}
function getAccountExplorerUrl(address, network) {
  return EXPLORER_URLS[network].account(address);
}
function getLedgerExplorerUrl(index, network) {
  return EXPLORER_URLS[network].ledger(index);
}
function isFaucetAvailable(network) {
  return FAUCET_CONFIG[network].available;
}
function getFaucetUrl(network) {
  const config = FAUCET_CONFIG[network];
  return config.available ? config.url : null;
}
function getConnectionConfig() {
  const env = process.env;
  return {
    connectionTimeout: parseInt(
      env["XRPL_CONNECTION_TIMEOUT"] ?? String(DEFAULT_CONNECTION_CONFIG.connectionTimeout)
    ),
    requestTimeout: parseInt(
      env["XRPL_REQUEST_TIMEOUT"] ?? String(DEFAULT_CONNECTION_CONFIG.requestTimeout)
    ),
    maxReconnectAttempts: parseInt(
      env["XRPL_MAX_RECONNECT_ATTEMPTS"] ?? String(DEFAULT_CONNECTION_CONFIG.maxReconnectAttempts)
    ),
    reconnectDelay: DEFAULT_CONNECTION_CONFIG.reconnectDelay,
    reconnectBackoff: DEFAULT_CONNECTION_CONFIG.reconnectBackoff
  };
}

// src/xrpl/client.ts
var XRPLClientError = class extends Error {
  constructor(message, code, details) {
    super(message);
    this.code = code;
    this.details = details;
    this.name = "XRPLClientError";
  }
};
var ConnectionError = class extends XRPLClientError {
  constructor(message, details) {
    super(message, "CONNECTION_ERROR", details);
    this.name = "ConnectionError";
  }
};
var AccountNotFoundError = class extends XRPLClientError {
  constructor(address) {
    super(`Account not found: ${address}`, "ACCOUNT_NOT_FOUND", { address });
    this.name = "AccountNotFoundError";
  }
};
var TransactionTimeoutError = class extends XRPLClientError {
  constructor(hash2) {
    super(`Transaction not validated: ${hash2}`, "TX_TIMEOUT", { hash: hash2 });
    this.name = "TransactionTimeoutError";
  }
};
var MaxReconnectAttemptsError = class extends XRPLClientError {
  constructor(attempts) {
    super(`Maximum reconnection attempts reached: ${attempts}`, "MAX_RECONNECT", { attempts });
    this.name = "MaxReconnectAttemptsError";
  }
};
function sleep(ms) {
  return new Promise((resolve2) => setTimeout(resolve2, ms));
}
var XRPLClientWrapper = class {
  client;
  network;
  nodeUrl;
  backupUrls;
  connectionConfig;
  currentUrlIndex = 0;
  reconnectAttempts = 0;
  isConnected = false;
  /**
   * Create a new XRPL client wrapper
   *
   * @param config - Client configuration
   */
  constructor(config) {
    this.network = config.network;
    this.nodeUrl = config.nodeUrl ?? getWebSocketUrl(config.network);
    this.backupUrls = getBackupWebSocketUrls(config.network);
    this.connectionConfig = {
      ...getConnectionConfig(),
      ...config.connectionConfig
    };
    this.client = new Client(this.nodeUrl);
  }
  /**
   * Get the current network
   */
  getNetwork() {
    return this.network;
  }
  /**
   * Check if client is connected
   */
  isClientConnected() {
    return this.isConnected && this.client.isConnected();
  }
  /**
   * Connect to XRPL network
   *
   * @throws {ConnectionError} If connection fails after all retries
   */
  async connect() {
    try {
      await this.client.connect();
      this.isConnected = true;
      this.reconnectAttempts = 0;
    } catch (error) {
      this.isConnected = false;
      throw new ConnectionError(`Failed to connect to ${this.nodeUrl}`, error);
    }
  }
  /**
   * Disconnect from XRPL network
   */
  async disconnect() {
    if (this.client.isConnected()) {
      await this.client.disconnect();
    }
    this.isConnected = false;
  }
  /**
   * Reconnect with exponential backoff
   *
   * @throws {MaxReconnectAttemptsError} If max attempts exceeded
   */
  async reconnect() {
    if (this.reconnectAttempts >= this.connectionConfig.maxReconnectAttempts) {
      throw new MaxReconnectAttemptsError(this.reconnectAttempts);
    }
    const delay = Math.min(
      this.connectionConfig.reconnectDelay * Math.pow(this.connectionConfig.reconnectBackoff, this.reconnectAttempts),
      3e4
      // Max 30 seconds
    );
    await sleep(delay);
    this.reconnectAttempts++;
    try {
      if (this.reconnectAttempts > 1 && this.backupUrls.length > 0) {
        this.currentUrlIndex = (this.currentUrlIndex + 1) % (this.backupUrls.length + 1);
        const url = this.currentUrlIndex === 0 ? this.nodeUrl : this.backupUrls[this.currentUrlIndex - 1];
        await this.client.disconnect();
        this.client = new Client(url);
      }
      await this.client.connect();
      this.isConnected = true;
      this.reconnectAttempts = 0;
    } catch (error) {
      await this.reconnect();
    }
  }
  /**
   * Check server health
   *
   * @returns True if server is healthy (state is "full")
   */
  async isHealthy() {
    try {
      const response = await this.client.request({
        command: "server_state"
      });
      return response.result.state.server_state === "full";
    } catch {
      return false;
    }
  }
  /**
   * Get server information
   *
   * @returns Server information
   */
  async getServerInfo() {
    const response = await this.client.request({
      command: "server_info"
    });
    const info = response.result.info;
    return {
      server_state: info.server_state,
      validated_ledger: info.validated_ledger ?? void 0,
      complete_ledgers: info.complete_ledgers,
      peers: info.peers ?? void 0,
      validation_quorum: info.validation_quorum ?? void 0
    };
  }
  /**
   * Get account information
   *
   * @param address - Account address
   * @returns Account information
   * @throws {AccountNotFoundError} If account doesn't exist
   */
  async getAccountInfo(address) {
    try {
      const response = await this.client.request({
        command: "account_info",
        account: address,
        ledger_index: "validated"
      });
      const data = response.result.account_data;
      return {
        account: data.Account,
        balance: data.Balance,
        sequence: data.Sequence,
        ownerCount: data.OwnerCount,
        flags: data.Flags,
        previousTxnID: data.PreviousTxnID,
        previousTxnLgrSeq: data.PreviousTxnLgrSeq
      };
    } catch (error) {
      if (typeof error === "object" && error !== null && "data" in error) {
        const errorData = error;
        if (errorData.data?.error === "actNotFound") {
          throw new AccountNotFoundError(address);
        }
      }
      throw error;
    }
  }
  /**
   * Get account balance in drops
   *
   * @param address - Account address
   * @returns Balance in drops
   */
  async getBalance(address) {
    const accountInfo = await this.getAccountInfo(address);
    return accountInfo.balance;
  }
  /**
   * Get transaction information
   *
   * @param hash - Transaction hash
   * @returns Transaction response
   */
  async getTransaction(hash2) {
    return this.client.request({
      command: "tx",
      transaction: hash2
    });
  }
  /**
   * Wait for transaction validation
   *
   * @param hash - Transaction hash
   * @param options - Wait options
   * @returns Transaction result
   * @throws {TransactionTimeoutError} If transaction not validated within timeout
   */
  async waitForTransaction(hash2, options = {}) {
    const timeout = options.timeout ?? 2e4;
    const pollInterval = options.pollInterval ?? 1e3;
    const startTime = Date.now();
    while (Date.now() - startTime < timeout) {
      try {
        const response = await this.client.request({
          command: "tx",
          transaction: hash2
        });
        if (response.result.validated) {
          const meta = response.result.meta;
          const transactionResult = typeof meta === "object" && meta !== null && "XRPLTransactionResult" in meta ? meta.XRPLTransactionResult : "unknown";
          return {
            hash: hash2,
            resultCode: transactionResult,
            ledgerIndex: response.result.ledger_index,
            validated: true,
            meta: response.result.meta
          };
        }
      } catch (error) {
        if (typeof error === "object" && error !== null && "data" in error) {
          const errorData = error;
          if (errorData.data?.error !== "txnNotFound") {
            throw error;
          }
        }
      }
      await sleep(pollInterval);
    }
    throw new TransactionTimeoutError(hash2);
  }
  /**
   * Get current ledger index
   *
   * @returns Current validated ledger index
   */
  async getCurrentLedgerIndex() {
    const response = await this.client.request({
      command: "ledger",
      ledger_index: "validated"
    });
    return response.result.ledger_index;
  }
  /**
   * Get fee estimate for a transaction
   *
   * @returns Estimated fee in drops
   */
  async getFee() {
    const response = await this.client.request({
      command: "fee"
    });
    return response.result.drops.open_ledger_fee;
  }
  /**
   * Get account transaction history
   *
   * @param address - Account address
   * @param options - History options
   * @returns Array of transactions
   */
  async getAccountTransactions(address, options = {}) {
    const response = await this.client.request({
      command: "account_tx",
      account: address,
      ledger_index_min: options.ledgerIndexMin ?? -1,
      ledger_index_max: options.ledgerIndexMax ?? -1,
      limit: Math.min(options.limit ?? 50, 400),
      forward: options.forward ?? false
    });
    return response.result.transactions.map((tx) => tx.tx);
  }
  /**
   * Submit a signed transaction
   *
   * @param signedTx - Signed transaction blob (hex string)
   * @param options - Submit options
   * @returns Transaction result
   */
  async submitSignedTransaction(signedTx, options = {}) {
    const opts = {
      waitForValidation: true,
      timeout: 2e4,
      failHard: false,
      ...options
    };
    const response = await this.client.submit(signedTx, {
      failHard: opts.failHard
    });
    const { tx_json, engine_result, engine_result_message } = response.result;
    const hash2 = tx_json.hash ?? "unknown";
    if (engine_result !== "tesSUCCESS" && !engine_result.startsWith("ter")) {
      throw new XRPLClientError(
        `Transaction submission failed: ${engine_result} - ${engine_result_message}`,
        "TX_SUBMIT_FAILED",
        { hash: hash2, engine_result, engine_result_message }
      );
    }
    if (opts.waitForValidation) {
      return this.waitForTransaction(hash2, { timeout: opts.timeout });
    }
    return {
      hash: hash2,
      resultCode: engine_result,
      ledgerIndex: void 0,
      validated: false,
      meta: void 0
    };
  }
};
var SigningError = class extends Error {
  constructor(code, message, details) {
    super(message);
    this.code = code;
    this.details = details;
    this.name = "SigningError";
  }
};
var SigningService = class {
  constructor(keystore, auditLogger, multiSignOrchestrator) {
    this.keystore = keystore;
    this.auditLogger = auditLogger;
    this.multiSignOrchestrator = multiSignOrchestrator;
  }
  /**
   * Sign a transaction with a wallet's private key.
   *
   * Process:
   * 1. Decode unsigned transaction blob
   * 2. Validate transaction structure
   * 3. Load wallet key from keystore (SecureBuffer)
   * 4. Create XRPL Wallet instance
   * 5. Sign transaction
   * 6. Zero key material
   * 7. Return signed blob + hash
   *
   * @param walletId - Internal wallet identifier
   * @param unsignedTx - Unsigned transaction blob (hex) or Transaction object
   * @param password - User password for key decryption
   * @param multiSign - Whether to sign for multi-signature (default: false)
   * @returns Signed transaction with hash
   *
   * @throws SigningError TRANSACTION_DECODE_ERROR - Invalid transaction format
   * @throws SigningError WALLET_NOT_FOUND - Wallet doesn't exist
   * @throws SigningError AUTHENTICATION_FAILED - Incorrect password
   * @throws SigningError SIGNING_FAILED - Cryptographic signing error
   */
  async sign(walletId, unsignedTx, password, multiSign = false) {
    let secureKey = null;
    try {
      let transaction;
      if (typeof unsignedTx === "string") {
        try {
          transaction = decode(unsignedTx);
        } catch (error) {
          throw new SigningError(
            "TRANSACTION_DECODE_ERROR",
            `Failed to decode transaction: ${error instanceof Error ? error.message : "Unknown error"}`,
            { unsignedTx }
          );
        }
      } else {
        transaction = unsignedTx;
      }
      this.validateTransaction(transaction);
      const walletEntry = await this.keystore.getWallet(walletId);
      try {
        secureKey = await this.keystore.loadKey(walletId, password);
      } catch (error) {
        await this.auditLogger.log({
          event: "authentication_failed",
          wallet_id: walletId,
          wallet_address: walletEntry.address,
          context: "Authentication failed during transaction signing"
        });
        throw new SigningError(
          "AUTHENTICATION_FAILED",
          "Failed to decrypt wallet key - incorrect password or corrupted keystore",
          { wallet_id: walletId }
        );
      }
      let wallet;
      try {
        const seedString = secureKey.getBuffer().toString("utf-8");
        wallet = Wallet.fromSeed(seedString);
        if (wallet.address !== walletEntry.address) {
          throw new Error("Wallet address mismatch - keystore corruption detected");
        }
      } catch (error) {
        throw new SigningError(
          "WALLET_CREATION_ERROR",
          `Failed to create wallet from key: ${error instanceof Error ? error.message : "Unknown error"}`,
          { wallet_id: walletId }
        );
      }
      let signedResult;
      try {
        if (multiSign) {
          signedResult = wallet.sign(transaction, true);
        } else {
          signedResult = wallet.sign(transaction);
        }
      } catch (error) {
        throw new SigningError(
          "SIGNING_FAILED",
          `Cryptographic signing failed: ${error instanceof Error ? error.message : "Unknown error"}`,
          { wallet_id: walletId, transaction_type: transaction.TransactionType }
        );
      }
      await this.auditLogger.log({
        event: "transaction_signed",
        wallet_id: walletId,
        wallet_address: walletEntry.address,
        transaction_type: transaction.TransactionType,
        tx_hash: signedResult.hash,
        context: multiSign ? "Multi-signature signing" : "Single signature signing"
      });
      return {
        tx_blob: signedResult.tx_blob,
        hash: signedResult.hash,
        signer_address: wallet.address
      };
    } catch (error) {
      if (error instanceof SigningError && error.code !== "AUTHENTICATION_FAILED") {
        await this.auditLogger.log({
          event: "transaction_failed",
          wallet_id: walletId,
          context: `Signing failed: ${error.code} - ${error.message}`
        });
      }
      throw error;
    } finally {
      if (secureKey) {
        secureKey.dispose();
      }
    }
  }
  /**
   * Sign a transaction for multi-signature workflow.
   *
   * This is a convenience wrapper around sign() with multiSign=true.
   *
   * @param walletId - Internal wallet identifier
   * @param unsignedTx - Unsigned transaction blob or object
   * @param password - User password
   * @returns Multi-signature compatible signed transaction
   */
  async signForMultiSig(walletId, unsignedTx, password) {
    return this.sign(walletId, unsignedTx, password, true);
  }
  /**
   * Decode and validate a transaction blob without signing.
   *
   * Useful for displaying transaction details before signing.
   *
   * @param txBlob - Transaction blob (hex encoded)
   * @returns Decoded transaction object
   * @throws SigningError TRANSACTION_DECODE_ERROR
   */
  decodeTransaction(txBlob) {
    try {
      return decode(txBlob);
    } catch (error) {
      throw new SigningError(
        "TRANSACTION_DECODE_ERROR",
        `Failed to decode transaction: ${error instanceof Error ? error.message : "Unknown error"}`,
        { tx_blob: txBlob }
      );
    }
  }
  /**
   * Encode a transaction object to blob format.
   *
   * @param transaction - Transaction object
   * @returns Hex-encoded transaction blob
   * @throws SigningError TRANSACTION_ENCODE_ERROR
   */
  encodeTransaction(transaction) {
    try {
      return encode(transaction);
    } catch (error) {
      throw new SigningError(
        "TRANSACTION_ENCODE_ERROR",
        `Failed to encode transaction: ${error instanceof Error ? error.message : "Unknown error"}`,
        { transaction }
      );
    }
  }
  /**
   * Validate transaction structure before signing.
   *
   * Checks:
   * - Required fields present
   * - Account address is valid
   * - TransactionType is recognized
   *
   * @param transaction - Transaction to validate
   * @throws SigningError INVALID_TRANSACTION
   */
  validateTransaction(transaction) {
    if (!transaction.TransactionType) {
      throw new SigningError(
        "INVALID_TRANSACTION",
        "Transaction missing required field: TransactionType"
      );
    }
    if (!transaction.Account) {
      throw new SigningError(
        "INVALID_TRANSACTION",
        "Transaction missing required field: Account"
      );
    }
    if (!transaction.Account.startsWith("r") || transaction.Account.length < 25) {
      throw new SigningError(
        "INVALID_TRANSACTION",
        `Invalid Account address format: ${transaction.Account}`
      );
    }
    const validTypes = [
      "Payment",
      "OfferCreate",
      "OfferCancel",
      "TrustSet",
      "AccountSet",
      "SetRegularKey",
      "SignerListSet",
      "EscrowCreate",
      "EscrowFinish",
      "EscrowCancel",
      "PaymentChannelCreate",
      "PaymentChannelClaim",
      "PaymentChannelFund",
      "CheckCreate",
      "CheckCash",
      "CheckCancel",
      "NFTokenMint",
      "NFTokenBurn",
      "NFTokenCreateOffer",
      "NFTokenCancelOffer",
      "NFTokenAcceptOffer",
      "AMMCreate",
      "AMMDeposit",
      "AMMWithdraw",
      "AMMVote",
      "AMMBid",
      "AMMDelete",
      "DepositPreauth",
      "AccountDelete"
    ];
    if (!validTypes.includes(transaction.TransactionType)) {
      console.warn(`Unknown TransactionType: ${transaction.TransactionType}`);
    }
  }
};
var MultiSignError = class extends Error {
  constructor(code, message, details) {
    super(message);
    this.code = code;
    this.details = details;
    this.name = "MultiSignError";
  }
};
var MultiSignOrchestrator = class {
  constructor(xrplClient, store, notificationService, auditLogger) {
    this.xrplClient = xrplClient;
    this.store = store;
    this.notificationService = notificationService;
    this.auditLogger = auditLogger;
  }
  /**
   * Initiate a new multi-signature request.
   *
   * Creates a pending request, notifies approvers, and returns
   * the request ID for status tracking.
   *
   * @param walletId - Internal wallet identifier
   * @param walletAddress - XRPL address of the account
   * @param unsignedTx - Unsigned transaction blob (hex)
   * @param signerConfig - SignerList configuration for this wallet
   * @param context - Human-readable context for audit
   * @returns Multi-signature request with pending status
   *
   * @throws MultiSignError WALLET_NOT_FOUND - Wallet doesn't exist
   * @throws MultiSignError SIGNERLIST_NOT_CONFIGURED - Wallet has no SignerList
   * @throws MultiSignError INVALID_TRANSACTION - Cannot decode transaction
   */
  async initiate(walletId, walletAddress, unsignedTx, signerConfig, context) {
    if (!signerConfig || signerConfig.signers.length === 0) {
      throw new MultiSignError(
        "SIGNERLIST_NOT_CONFIGURED",
        "Wallet does not have multi-signature configured"
      );
    }
    let decodedTx;
    try {
      const { decode: decode5 } = await import('xrpl');
      decodedTx = decode5(unsignedTx);
    } catch (error) {
      throw new MultiSignError(
        "INVALID_TRANSACTION",
        `Cannot decode transaction: ${error instanceof Error ? error.message : "Unknown error"}`,
        { unsigned_tx: unsignedTx }
      );
    }
    const requestId = randomUUID();
    const now = /* @__PURE__ */ new Date();
    const timeoutSeconds = signerConfig.timeout_seconds || 86400;
    const expiresAt = new Date(now.getTime() + timeoutSeconds * 1e3);
    const amountDrops = this.extractAmount(decodedTx);
    const destination = this.extractDestination(decodedTx);
    const request = {
      id: requestId,
      wallet_id: walletId,
      wallet_address: walletAddress,
      transaction: {
        type: decodedTx.TransactionType,
        ...amountDrops !== void 0 && { amount_drops: amountDrops },
        ...destination !== void 0 && { destination },
        unsigned_blob: unsignedTx,
        decoded: decodedTx
      },
      signers: signerConfig.signers.map((s) => ({
        address: s.address,
        role: s.role,
        weight: s.weight,
        signed: false
      })),
      quorum: {
        required: signerConfig.quorum,
        collected: 0,
        met: false
      },
      status: "pending",
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
      ...context && { context },
      notifications_sent: []
    };
    await this.store.create(request);
    await this.auditLogger.log({
      event: "approval_requested",
      wallet_id: walletId,
      wallet_address: walletAddress,
      transaction_type: decodedTx.TransactionType,
      context: context || `Multi-sign requested: ${signerConfig.quorum} of ${signerConfig.signers.length} signatures`
    });
    this.notifySigners(request, "created").catch(
      (err) => console.error("Failed to send notifications:", err)
    );
    return request;
  }
  /**
   * Add a signature from a human approver.
   *
   * Validates the signature, stores it, and checks if quorum is met.
   * Updates request status and notifies if ready for completion.
   *
   * @param requestId - Multi-sign request UUID
   * @param signature - Signed transaction from approver
   * @param signerAddress - Address of the signer (for validation)
   * @returns Updated request with new signature and quorum status
   *
   * @throws MultiSignError REQUEST_NOT_FOUND - Request doesn't exist
   * @throws MultiSignError REQUEST_EXPIRED - Request timeout exceeded
   * @throws MultiSignError REQUEST_COMPLETED - Already finalized
   * @throws MultiSignError INVALID_SIGNER - Address not in SignerList
   * @throws MultiSignError DUPLICATE_SIGNATURE - Signer already signed
   * @throws MultiSignError SIGNATURE_INVALID - Cryptographic verification failed
   */
  async addSignature(requestId, signature, signerAddress) {
    const request = await this.store.get(requestId);
    if (!request) {
      throw new MultiSignError("REQUEST_NOT_FOUND", `No request found with ID ${requestId}`);
    }
    if (new Date(request.expires_at) < /* @__PURE__ */ new Date()) {
      throw new MultiSignError("REQUEST_EXPIRED", "Multi-sign request has expired");
    }
    if (request.status === "completed") {
      throw new MultiSignError("REQUEST_COMPLETED", "Request already completed");
    }
    if (request.status === "rejected") {
      throw new MultiSignError("REQUEST_REJECTED", "Request has been rejected");
    }
    const signer = request.signers.find((s) => s.address === signerAddress);
    if (!signer) {
      throw new MultiSignError(
        "INVALID_SIGNER",
        `Address ${signerAddress} is not in the SignerList`,
        { signer_address: signerAddress, request_id: requestId }
      );
    }
    if (signer.signed) {
      throw new MultiSignError(
        "DUPLICATE_SIGNATURE",
        `Signer ${signerAddress} has already signed this request`
      );
    }
    signer.signed = true;
    signer.signature = signature;
    signer.signed_at = (/* @__PURE__ */ new Date()).toISOString();
    const collectedWeight = request.signers.filter((s) => s.signed).reduce((sum, s) => sum + s.weight, 0);
    request.quorum.collected = collectedWeight;
    request.quorum.met = collectedWeight >= request.quorum.required;
    if (request.quorum.met) {
      request.status = "approved";
    }
    await this.store.update(request);
    await this.auditLogger.log({
      event: "approval_granted",
      wallet_id: request.wallet_id,
      wallet_address: request.wallet_address,
      context: `Signature added by ${signerAddress} (${signer.role}). Quorum: ${collectedWeight}/${request.quorum.required}`
    });
    if (request.quorum.met) {
      this.notifySigners(request, "signature_added").catch(
        (err) => console.error("Failed to send notifications:", err)
      );
    }
    return request;
  }
  /**
   * Complete multi-signature and submit to XRPL.
   *
   * Verifies quorum is met, adds agent signature if needed,
   * assembles the final multi-signed transaction, and submits.
   *
   * @param requestId - Multi-sign request UUID
   * @param agentWallet - Agent's wallet (for final signature if needed)
   * @returns Completed transaction with hash
   *
   * @throws MultiSignError REQUEST_NOT_FOUND - Request doesn't exist
   * @throws MultiSignError REQUEST_EXPIRED - Request timeout exceeded
   * @throws MultiSignError QUORUM_NOT_MET - Insufficient signatures
   * @throws MultiSignError SUBMISSION_FAILED - XRPL submission error
   */
  async complete(requestId, agentWallet) {
    const request = await this.store.get(requestId);
    if (!request) {
      throw new MultiSignError("REQUEST_NOT_FOUND", `No request found with ID ${requestId}`);
    }
    if (new Date(request.expires_at) < /* @__PURE__ */ new Date()) {
      throw new MultiSignError("REQUEST_EXPIRED", "Multi-sign request has expired");
    }
    const agentSigner = request.signers.find((s) => s.role === "agent");
    if (agentSigner && !agentSigner.signed && agentWallet) {
      const agentSig = agentWallet.sign(request.transaction.decoded, true);
      agentSigner.signed = true;
      agentSigner.signature = agentSig.tx_blob;
      agentSigner.signed_at = (/* @__PURE__ */ new Date()).toISOString();
      const collectedWeight = request.signers.filter((s) => s.signed).reduce((sum, s) => sum + s.weight, 0);
      request.quorum.collected = collectedWeight;
      request.quorum.met = collectedWeight >= request.quorum.required;
    }
    if (!request.quorum.met) {
      throw new MultiSignError(
        "QUORUM_NOT_MET",
        `Collected weight ${request.quorum.collected} < required ${request.quorum.required}`
      );
    }
    const signatures = request.signers.filter((s) => s.signed && s.signature).map((s) => s.signature);
    if (signatures.length === 0) {
      throw new MultiSignError("NO_SIGNATURES", "No signatures collected");
    }
    const multiSignedTx = multisign(signatures);
    let txHash;
    try {
      const response = await this.xrplClient.submitAndWait(multiSignedTx, {
        autofill: false,
        failHard: true
      });
      const meta = response.result.meta;
      const result = typeof meta === "object" && meta !== null && "TransactionResult" in meta ? meta.TransactionResult : "UNKNOWN";
      txHash = response.result.hash;
      if (result !== "tesSUCCESS") {
        throw new Error(`Transaction failed with result: ${result}`);
      }
    } catch (error) {
      throw new MultiSignError(
        "SUBMISSION_FAILED",
        `Failed to submit multi-signed transaction: ${error instanceof Error ? error.message : "Unknown error"}`,
        { request_id: requestId }
      );
    }
    request.status = "completed";
    request.completed_at = (/* @__PURE__ */ new Date()).toISOString();
    request.tx_hash = txHash;
    await this.store.update(request);
    await this.auditLogger.log({
      event: "transaction_submitted",
      wallet_id: request.wallet_id,
      wallet_address: request.wallet_address,
      transaction_type: request.transaction.type,
      tx_hash: txHash,
      context: `Multi-signed transaction completed with ${signatures.length} signatures`
    });
    return {
      request_id: requestId,
      signed_tx: multiSignedTx,
      tx_hash: txHash,
      final_quorum: request.quorum.collected,
      signers: request.signers.filter((s) => s.signed).map((s) => s.address),
      submitted_at: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
  /**
   * Reject a pending multi-sign request.
   *
   * Human approver explicitly rejects the transaction.
   * Discards all collected signatures and logs rejection.
   *
   * @param requestId - Multi-sign request UUID
   * @param rejectingAddress - Address of the rejecting approver
   * @param reason - Human-readable rejection reason
   * @returns Updated request with rejected status
   *
   * @throws MultiSignError REQUEST_NOT_FOUND - Request doesn't exist
   * @throws MultiSignError REQUEST_COMPLETED - Already finalized
   * @throws MultiSignError UNAUTHORIZED_REJECTOR - Not an authorized signer
   */
  async reject(requestId, rejectingAddress, reason) {
    const request = await this.store.get(requestId);
    if (!request) {
      throw new MultiSignError("REQUEST_NOT_FOUND", `No request found with ID ${requestId}`);
    }
    if (request.status === "completed") {
      throw new MultiSignError("REQUEST_COMPLETED", "Cannot reject completed request");
    }
    const rejector = request.signers.find((s) => s.address === rejectingAddress);
    if (!rejector) {
      throw new MultiSignError(
        "UNAUTHORIZED_REJECTOR",
        `Address ${rejectingAddress} is not an authorized signer`
      );
    }
    request.status = "rejected";
    request.rejection = {
      rejecting_address: rejectingAddress,
      reason,
      rejected_at: (/* @__PURE__ */ new Date()).toISOString()
    };
    await this.store.update(request);
    await this.auditLogger.log({
      event: "approval_denied",
      wallet_id: request.wallet_id,
      wallet_address: request.wallet_address,
      context: `Rejected by ${rejectingAddress}: ${reason}`
    });
    return request;
  }
  /**
   * Get current status of a multi-sign request.
   *
   * @param requestId - Multi-sign request UUID
   * @returns Current request state with signatures and quorum
   *
   * @throws MultiSignError REQUEST_NOT_FOUND - Request doesn't exist
   */
  async getStatus(requestId) {
    const request = await this.store.get(requestId);
    if (!request) {
      throw new MultiSignError("REQUEST_NOT_FOUND", `No request found with ID ${requestId}`);
    }
    return request;
  }
  /**
   * List all pending multi-sign requests for a wallet.
   *
   * @param walletId - Internal wallet identifier
   * @param includeExpired - Include expired requests (default: false)
   * @returns Array of pending requests sorted by creation time
   */
  async listPending(walletId, includeExpired = false) {
    return this.store.listByWallet(walletId, false);
  }
  /**
   * Cancel an expired request.
   *
   * Automated cleanup of requests that exceeded timeout.
   * Called by scheduled task, not directly by users.
   *
   * @param requestId - Multi-sign request UUID
   * @returns Updated request with expired status
   *
   * @internal
   */
  async expire(requestId) {
    const request = await this.store.get(requestId);
    if (!request) {
      throw new MultiSignError("REQUEST_NOT_FOUND", `No request found with ID ${requestId}`);
    }
    request.status = "expired";
    await this.store.update(request);
    await this.auditLogger.log({
      event: "approval_expired",
      wallet_id: request.wallet_id,
      wallet_address: request.wallet_address,
      context: `Request expired with ${request.signers.filter((s) => s.signed).length}/${request.quorum.required} signatures`
    });
    return request;
  }
  // ==========================================================================
  // PRIVATE HELPERS
  // ==========================================================================
  extractAmount(tx) {
    if ("Amount" in tx && typeof tx.Amount === "string") {
      return tx.Amount;
    }
    return void 0;
  }
  extractDestination(tx) {
    if ("Destination" in tx && typeof tx.Destination === "string") {
      return tx.Destination;
    }
    return void 0;
  }
  async notifySigners(request, type) {
    console.log(`[MultiSign] Notification: ${type} for request ${request.id}`);
  }
};

// src/tools/wallet-create.ts
async function handleWalletCreate(context, input) {
  const { keystore, policyEngine, auditLogger } = context;
  await policyEngine.setPolicy(input.policy);
  const walletEntry = await keystore.createWallet(
    input.network,
    {
      policyId: input.policy.policy_id,
      policyVersion: input.policy.policy_version
    },
    {
      name: input.wallet_name,
      password: process.env.XRPL_WALLET_PASSWORD || "",
      // TEMP: env-based password
      algorithm: "ed25519"
      // Recommended for XRPL
    }
  );
  const backup = await keystore.exportBackup(
    walletEntry.walletId,
    process.env.XRPL_WALLET_PASSWORD || "",
    "encrypted-json"
  );
  await auditLogger.log({
    event: "wallet_created",
    seq: 0,
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    wallet_id: walletEntry.walletId,
    wallet_address: walletEntry.address,
    context: `Policy: ${input.policy.policy_id}`,
    prev_hash: "",
    hash: ""
  });
  return {
    address: walletEntry.address,
    regular_key_public: walletEntry.publicKey,
    master_key_backup: JSON.stringify(backup),
    policy_id: input.policy.policy_id,
    wallet_id: walletEntry.walletId,
    network: input.network,
    created_at: walletEntry.createdAt
  };
}
async function handleWalletSign(context, input) {
  const { keystore, policyEngine, signingService, auditLogger } = context;
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);
  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }
  const decoded = decode(input.unsigned_tx);
  const policyResult = await policyEngine.evaluateTransaction(
    wallet.policyId,
    {
      type: decoded.TransactionType,
      destination: "Destination" in decoded ? decoded.Destination : void 0,
      amount_drops: "Amount" in decoded && typeof decoded.Amount === "string" ? decoded.Amount : void 0
    }
  );
  const timestamp = (/* @__PURE__ */ new Date()).toISOString();
  if (policyResult.tier === 4) {
    await auditLogger.log({
      event: "policy_violation",
      seq: 0,
      timestamp,
      wallet_id: wallet.walletId,
      wallet_address: wallet.address,
      transaction_type: decoded.TransactionType,
      tier: 4,
      policy_decision: "denied",
      context: input.context,
      prev_hash: "",
      hash: ""
    });
    return {
      status: "rejected",
      reason: policyResult.violations?.join("; ") || "Transaction violates policy",
      policy_tier: 4
    };
  }
  if (policyResult.tier === 2 || policyResult.tier === 3) {
    const approvalId = `approval_${Date.now()}_${wallet.walletId}`;
    await auditLogger.log({
      event: "approval_requested",
      seq: 0,
      timestamp,
      wallet_id: wallet.walletId,
      wallet_address: wallet.address,
      transaction_type: decoded.TransactionType,
      tier: policyResult.tier,
      policy_decision: "pending",
      context: input.context,
      prev_hash: "",
      hash: ""
    });
    return {
      status: "pending_approval",
      approval_id: approvalId,
      reason: policyResult.tier === 2 ? "exceeds_autonomous_limit" : "requires_cosign",
      expires_at: new Date(Date.now() + 3e5).toISOString(),
      // 5 minutes
      policy_tier: policyResult.tier
    };
  }
  const signed = await signingService.sign(
    wallet.walletId,
    input.unsigned_tx,
    process.env.XRPL_WALLET_PASSWORD || ""
  );
  await auditLogger.log({
    event: "transaction_signed",
    seq: 0,
    timestamp,
    wallet_id: wallet.walletId,
    wallet_address: wallet.address,
    transaction_type: decoded.TransactionType,
    tx_hash: signed.hash,
    tier: 1,
    policy_decision: "allowed",
    context: input.context,
    prev_hash: "",
    hash: ""
  });
  return {
    status: "approved",
    signed_tx: signed.tx_blob,
    tx_hash: signed.hash,
    policy_tier: 1,
    limits_after: {
      daily_remaining_drops: "0",
      // TEMP: Would come from policy engine
      hourly_tx_remaining: 0,
      daily_tx_remaining: 0
    },
    signed_at: timestamp
  };
}
async function handleWalletBalance(context, input) {
  const { keystore, xrplClient } = context;
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);
  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }
  const accountInfo = await xrplClient.getAccountInfo(wallet.network, input.wallet_address);
  const baseReserve = BigInt("1000000");
  const ownerReserve = BigInt("200000");
  const ownerCount = BigInt(accountInfo.OwnerCount || 0);
  const totalReserve = baseReserve + ownerReserve * ownerCount;
  const balance = BigInt(accountInfo.Balance);
  const available = balance > totalReserve ? balance - totalReserve : BigInt(0);
  return {
    address: input.wallet_address,
    balance_drops: balance.toString(),
    balance_xrp: dropsToXrp$1(balance.toString()),
    reserve_drops: totalReserve.toString(),
    available_drops: available.toString(),
    sequence: accountInfo.Sequence,
    regular_key_set: !!accountInfo.RegularKey,
    signer_list: null,
    // TEMP: Would parse SignerList from account objects
    policy_id: wallet.policyId,
    network: wallet.network,
    queried_at: (/* @__PURE__ */ new Date()).toISOString()
  };
}
async function handleWalletPolicyCheck(context, input) {
  const { keystore, policyEngine } = context;
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);
  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }
  const decoded = decode(input.unsigned_tx);
  const policyResult = await policyEngine.evaluateTransaction(
    wallet.policyId,
    {
      type: decoded.TransactionType,
      destination: "Destination" in decoded ? decoded.Destination : void 0,
      amount_drops: "Amount" in decoded && typeof decoded.Amount === "string" ? decoded.Amount : void 0
    }
  );
  const limits = {
    daily_volume_used_drops: "0",
    daily_volume_limit_drops: "10000000000",
    // 10,000 XRP
    hourly_tx_used: 0,
    hourly_tx_limit: 10,
    daily_tx_used: 0,
    daily_tx_limit: 100
  };
  return {
    would_approve: policyResult.tier === 1,
    tier: policyResult.tier,
    warnings: policyResult.warnings || [],
    violations: policyResult.violations || [],
    limits,
    transaction_details: {
      type: decoded.TransactionType,
      destination: "Destination" in decoded ? decoded.Destination : void 0,
      amount_drops: "Amount" in decoded && typeof decoded.Amount === "string" ? decoded.Amount : void 0
    }
  };
}

// src/tools/wallet-rotate.ts
async function handleWalletRotate(context, input) {
  const { keystore, auditLogger } = context;
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);
  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }
  const timestamp = (/* @__PURE__ */ new Date()).toISOString();
  await auditLogger.log({
    event: "key_rotated",
    seq: 0,
    timestamp,
    wallet_id: wallet.walletId,
    wallet_address: wallet.address,
    context: input.reason || "Manual rotation",
    prev_hash: "",
    hash: ""
  });
  return {
    status: "rotated",
    new_regular_key_public: "ED" + "0".repeat(64),
    // Placeholder
    old_key_disabled: true,
    rotation_tx_hash: "0".repeat(64),
    // Placeholder
    rotated_at: timestamp
  };
}

// src/tools/wallet-list.ts
async function handleWalletList(context, input) {
  const { keystore } = context;
  const walletSummaries = await keystore.listWallets(input.network);
  const wallets = walletSummaries.map((w) => ({
    wallet_id: w.walletId,
    address: w.address,
    name: w.name,
    network: w.network,
    policy_id: w.policyId,
    created_at: w.createdAt
  }));
  return {
    wallets,
    total: wallets.length
  };
}

// src/tools/wallet-history.ts
async function handleWalletHistory(context, input) {
  const { keystore, xrplClient } = context;
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);
  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }
  const txHistory = await xrplClient.getTransactionHistory(
    wallet.network,
    input.wallet_address,
    {
      limit: input.limit || 20,
      marker: input.marker
    }
  );
  const transactions = txHistory.transactions.map((tx) => ({
    hash: tx.hash,
    type: tx.tx.TransactionType,
    amount_drops: "Amount" in tx.tx && typeof tx.tx.Amount === "string" ? tx.tx.Amount : void 0,
    destination: "Destination" in tx.tx ? tx.tx.Destination : void 0,
    timestamp: new Date(tx.close_time_iso || "").toISOString(),
    policy_tier: 1,
    // TEMP: Would come from audit log
    context: void 0,
    // TEMP: Would come from audit log
    ledger_index: tx.ledger_index || 0,
    success: tx.meta?.TransactionResult === "tesSUCCESS"
  }));
  return {
    address: input.wallet_address,
    transactions,
    marker: txHistory.marker,
    has_more: !!txHistory.marker
  };
}

// src/tools/wallet-fund.ts
async function handleWalletFund(context, input) {
  const { xrplClient, auditLogger } = context;
  if (input.network === "mainnet") {
    throw new Error("Faucet not available on mainnet");
  }
  try {
    const fundResult = await xrplClient.fundWallet(input.network, input.wallet_address);
    await auditLogger.log({
      event: "wallet_created",
      // Using existing event type
      seq: 0,
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      wallet_address: input.wallet_address,
      context: `Funded from ${input.network} faucet`,
      prev_hash: "",
      hash: ""
    });
    return {
      status: "funded",
      amount_drops: fundResult.amount,
      tx_hash: fundResult.hash,
      new_balance_drops: fundResult.balance
    };
  } catch (error) {
    return {
      status: "failed",
      error: error instanceof Error ? error.message : "Unknown faucet error"
    };
  }
}

// src/tools/policy-set.ts
async function handlePolicySet(context, input) {
  const { keystore, policyEngine, auditLogger } = context;
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);
  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }
  const previousPolicyId = wallet.policyId;
  await policyEngine.setPolicy(input.policy);
  await keystore.updateMetadata(wallet.walletId, {
    customData: {
      policyId: input.policy.policy_id,
      policyVersion: input.policy.policy_version
    }
  });
  const timestamp = (/* @__PURE__ */ new Date()).toISOString();
  await auditLogger.log({
    event: "policy_updated",
    seq: 0,
    timestamp,
    wallet_id: wallet.walletId,
    wallet_address: wallet.address,
    context: input.reason,
    prev_hash: "",
    hash: ""
  });
  return {
    status: "pending_approval",
    // TEMP: Would be 'applied' after approval
    previous_policy_id: previousPolicyId,
    new_policy_id: input.policy.policy_id,
    approval_id: `policy_approval_${Date.now()}`
  };
}

// src/tools/tx-submit.ts
async function handleTxSubmit(context, input) {
  const { xrplClient, auditLogger } = context;
  const submittedAt = (/* @__PURE__ */ new Date()).toISOString();
  const result = await xrplClient.submitTransaction(
    input.network,
    input.signed_tx,
    input.wait_for_validation ?? true
  );
  await auditLogger.log({
    event: "transaction_submitted",
    seq: 0,
    timestamp: submittedAt,
    tx_hash: result.hash,
    policy_decision: result.validated ? "allowed" : "pending",
    prev_hash: "",
    hash: ""
  });
  return {
    tx_hash: result.hash,
    result: {
      result_code: result.resultCode,
      result_message: result.resultMessage,
      success: result.resultCode === "tesSUCCESS"
    },
    ledger_index: result.ledgerIndex,
    submitted_at: submittedAt,
    validated_at: result.validated ? (/* @__PURE__ */ new Date()).toISOString() : void 0
  };
}
async function handleTxDecode(_context, input) {
  const decoded = decode(input.tx_blob);
  const isSigned = "TxnSignature" in decoded || "Signers" in decoded;
  const signingPublicKey = "SigningPubKey" in decoded && typeof decoded.SigningPubKey === "string" ? decoded.SigningPubKey : void 0;
  let hash2;
  if (isSigned) {
    try {
      hash2 = hashes.hashSignedTx(input.tx_blob);
    } catch {
      hash2 = void 0;
    }
  }
  return {
    transaction: decoded,
    // Type assertion - decoded tx matches schema
    hash: hash2,
    is_signed: isSigned,
    signing_public_key: signingPublicKey
  };
}
var TOOLS = [
  {
    name: "wallet_create",
    description: "Create a new XRPL wallet with policy controls. Generates keys locally with encrypted storage.",
    inputSchema: {
      type: "object",
      properties: {
        network: { type: "string", enum: ["mainnet", "testnet", "devnet"] },
        policy: { type: "object" },
        wallet_name: { type: "string" },
        funding_source: { type: "string" },
        initial_funding_drops: { type: "string" }
      },
      required: ["network", "policy"]
    }
  },
  {
    name: "wallet_sign",
    description: "Sign a transaction with policy enforcement. Returns signed blob, pending approval, or rejection.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_address: { type: "string" },
        unsigned_tx: { type: "string" },
        context: { type: "string" }
      },
      required: ["wallet_address", "unsigned_tx"]
    }
  },
  {
    name: "wallet_balance",
    description: "Query wallet balance, reserves, and status. Returns current state from XRPL.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_address: { type: "string" }
      },
      required: ["wallet_address"]
    }
  },
  {
    name: "wallet_policy_check",
    description: "Dry-run policy evaluation without signing. Check if a transaction would be approved.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_address: { type: "string" },
        unsigned_tx: { type: "string" }
      },
      required: ["wallet_address", "unsigned_tx"]
    }
  },
  {
    name: "wallet_rotate",
    description: "Rotate the agent wallet signing key. Disables old key and generates new one.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_address: { type: "string" },
        reason: { type: "string" }
      },
      required: ["wallet_address"]
    }
  },
  {
    name: "wallet_list",
    description: "List all managed wallets, optionally filtered by network.",
    inputSchema: {
      type: "object",
      properties: {
        network: { type: "string", enum: ["mainnet", "testnet", "devnet"] }
      }
    }
  },
  {
    name: "wallet_history",
    description: "Retrieve transaction history for audit and analysis.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_address: { type: "string" },
        limit: { type: "number", minimum: 1, maximum: 100 },
        marker: { type: "string" }
      },
      required: ["wallet_address"]
    }
  },
  {
    name: "wallet_fund",
    description: "Fund wallet from testnet/devnet faucet. Only available on test networks.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_address: { type: "string" },
        network: { type: "string", enum: ["testnet", "devnet"] }
      },
      required: ["wallet_address", "network"]
    }
  },
  {
    name: "policy_set",
    description: "Update wallet policy (requires approval). Changes security constraints.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_address: { type: "string" },
        policy: { type: "object" },
        reason: { type: "string" }
      },
      required: ["wallet_address", "policy", "reason"]
    }
  },
  {
    name: "tx_submit",
    description: "Submit signed transaction to XRPL network.",
    inputSchema: {
      type: "object",
      properties: {
        signed_tx: { type: "string" },
        network: { type: "string", enum: ["mainnet", "testnet", "devnet"] },
        wait_for_validation: { type: "boolean" }
      },
      required: ["signed_tx", "network"]
    }
  },
  {
    name: "tx_decode",
    description: "Decode transaction blob for inspection. Works with signed or unsigned transactions.",
    inputSchema: {
      type: "object",
      properties: {
        tx_blob: { type: "string" }
      },
      required: ["tx_blob"]
    }
  }
];
function formatError(error) {
  const timestamp = (/* @__PURE__ */ new Date()).toISOString();
  if (typeof error === "object" && error !== null && "code" in error && "message" in error && "timestamp" in error) {
    return error;
  }
  if (error instanceof Error) {
    return {
      code: "INTERNAL_ERROR",
      message: error.message,
      details: { stack: error.stack },
      timestamp
    };
  }
  return {
    code: "INTERNAL_ERROR",
    message: "An unknown error occurred",
    details: { error: String(error) },
    timestamp
  };
}
function createServer(context, config) {
  const server = new Server(
    {
      name: config?.name ?? "xrpl-agent-wallet-mcp",
      version: config?.version ?? "0.1.0"
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS
  }));
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    try {
      const toolDef = TOOLS.find((t) => t.name === name);
      if (!toolDef) {
        throw new Error(`Unknown tool: ${name}`);
      }
      const inputSchema = InputSchemas[name];
      if (!inputSchema) {
        throw new Error(`No schema found for tool: ${name}`);
      }
      const validatedInput = inputSchema.parse(args);
      let result;
      switch (name) {
        case "wallet_create":
          result = await handleWalletCreate(context, validatedInput);
          break;
        case "wallet_sign":
          result = await handleWalletSign(context, validatedInput);
          break;
        case "wallet_balance":
          result = await handleWalletBalance(context, validatedInput);
          break;
        case "wallet_policy_check":
          result = await handleWalletPolicyCheck(context, validatedInput);
          break;
        case "wallet_rotate":
          result = await handleWalletRotate(context, validatedInput);
          break;
        case "wallet_list":
          result = await handleWalletList(context, validatedInput);
          break;
        case "wallet_history":
          result = await handleWalletHistory(context, validatedInput);
          break;
        case "wallet_fund":
          result = await handleWalletFund(context, validatedInput);
          break;
        case "policy_set":
          result = await handlePolicySet(context, validatedInput);
          break;
        case "tx_submit":
          result = await handleTxSubmit(context, validatedInput);
          break;
        case "tx_decode":
          result = await handleTxDecode(context, validatedInput);
          break;
        default:
          throw new Error(`Handler not implemented for tool: ${name}`);
      }
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2)
          }
        ]
      };
    } catch (error) {
      const errorResponse = formatError(error);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(errorResponse, null, 2)
          }
        ],
        isError: true
      };
    }
  });
  return server;
}
async function runServer(context, config) {
  const server = createServer(context, config);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  await context.auditLogger.log({
    event: "server_started"
  });
  console.error("XRPL Agent Wallet MCP Server running on stdio");
}

export { AES_CONFIG2 as AES_CONFIG, ARGON2_CONFIG2 as ARGON2_CONFIG, AccountNotFoundError, AuditLogInputSchema, AuditLogger, AuthenticationError, BackupFormatError, ChainStateSchema, ConnectionError, DEFAULT_AUDIT_LOGGER_CONFIG, DEFAULT_CONNECTION_CONFIG, DEFAULT_PASSWORD_POLICY2 as DEFAULT_PASSWORD_POLICY, EXPLORER_URLS, FAUCET_CONFIG, GENESIS_CONSTANT, HMAC_ALGORITHM, HMAC_KEY_LENGTH, HashChain, HmacKeySchema, InvalidKeyError, KeyDecryptionError, KeyEncryptionError, KeystoreCapacityError, KeystoreError, KeystoreInitializationError, KeystoreReadError, KeystoreWriteError, LimitExceededError, LimitTracker, LocalKeystore, MaxReconnectAttemptsError, MultiSignError, MultiSignOrchestrator, NETWORK_ENDPOINTS, NetworkMismatchError, PolicyEngine, PolicyError, PolicyEvaluationError, PolicyIntegrityError, PolicyLoadError, PolicyValidationError, ProviderUnavailableError, RuleEvaluator, SecureBuffer, SigningError, SigningService, TransactionTimeoutError, VerificationOptionsSchema, WalletExistsError, WalletNotFoundError, WeakPasswordError, XRPLClientError, XRPLClientWrapper, checkBlocklist, computeStandaloneHash, createLimitTracker, createMemoryKeyProvider, createPolicyEngine, createServer, createTestPolicy, generateHmacKey, getAccountExplorerUrl, getBackupWebSocketUrls, getConnectionConfig, getDefaultAuditDir, getFaucetUrl, getLedgerExplorerUrl, getTransactionCategory, getTransactionExplorerUrl, getWebSocketUrl, isFaucetAvailable, isInAllowlist, isKeystoreError, isKeystoreErrorCode, isValidHmacKey, numericToTier, runServer, sanitizeForLogging, tierToNumeric };
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map