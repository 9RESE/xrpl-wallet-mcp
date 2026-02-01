import { AuditEventType, TransactionType, Network, AuditLogEntry, ApprovalTier, AgentWalletPolicy, XRPLAddress, TransactionHash } from './schemas/index.js';
export { AgentWalletPolicySchema, ApprovalTierSchema, AuditEventTypeSchema, AuditLogEntrySchema, DecodedTransaction, DecodedTransactionSchema, DestinationMode, DestinationModeSchema, DropsAmount, DropsAmountOptionalZeroSchema, DropsAmountSchema, ErrorCode, ErrorCodeSchema, ErrorResponse, ErrorResponseSchema, EscrowReference, EscrowReferenceSchema, HexString, HexStringRaw, HexStringRawSchema, HexStringSchema, InputSchemas, LedgerIndex, LedgerIndexSchema, LimitStatus, LimitStatusSchema, NetworkConfigInput, NetworkConfigInputSchema, NetworkConfigOutput, NetworkConfigOutputSchema, NetworkSchema, NotificationEvent, NotificationEventSchema, OutputSchemas, PaginationMarker, PaginationMarkerSchema, PolicyDestinations, PolicyDestinationsSchema, PolicyEscalation, PolicyEscalationSchema, PolicyLimits, PolicyLimitsSchema, PolicyNotifications, PolicyNotificationsSchema, PolicySetInput, PolicySetInputSchema, PolicySetOutput, PolicySetOutputSchema, PolicyTimeControls, PolicyTimeControlsSchema, PolicyTransactionTypes, PolicyTransactionTypesSchema, PolicyViolation, PolicyViolationSchema, PublicKey, PublicKeySchema, RemainingLimits, RemainingLimitsSchema, SequenceNumber, SequenceNumberSchema, SignedTransactionBlob, SignedTransactionBlobSchema, SignerEntry, SignerEntrySchema, Timestamp, TimestampSchema, ToolName, TransactionHashSchema, TransactionHistoryEntry, TransactionHistoryEntrySchema, TransactionResult, TransactionResultSchema, TransactionTypeSchema, TxDecodeInput, TxDecodeInputSchema, TxDecodeOutput, TxDecodeOutputSchema, TxSubmitInput, TxSubmitInputSchema, TxSubmitOutput, TxSubmitOutputSchema, UnsignedTransactionBlob, UnsignedTransactionBlobSchema, WalletBalanceInput, WalletBalanceInputSchema, WalletBalanceOutput, WalletBalanceOutputSchema, WalletCreateInput, WalletCreateInputSchema, WalletCreateOutput, WalletCreateOutputSchema, WalletFundInput, WalletFundInputSchema, WalletFundOutput, WalletFundOutputSchema, WalletHistoryInput, WalletHistoryInputSchema, WalletHistoryOutput, WalletHistoryOutputSchema, WalletId, WalletIdSchema, WalletImportInput, WalletImportInputSchema, WalletListEntry, WalletListEntrySchema, WalletListInput, WalletListInputSchema, WalletListOutput, WalletListOutputSchema, WalletName, WalletNameSchema, WalletPolicyCheckInput, WalletPolicyCheckInputSchema, WalletPolicyCheckOutput, WalletPolicyCheckOutputSchema, WalletRotateInput, WalletRotateInputSchema, WalletRotateOutput, WalletRotateOutputSchema, WalletSignApprovedOutput, WalletSignApprovedOutputSchema, WalletSignInput, WalletSignInputSchema, WalletSignOutput, WalletSignOutputSchema, WalletSignPendingOutput, WalletSignPendingOutputSchema, WalletSignRejectedOutput, WalletSignRejectedOutputSchema, XRPLAddressSchema } from './schemas/index.js';
import { z } from 'zod';
import { EventEmitter } from 'events';
import { TxResponse, Client, Transaction, Wallet } from 'xrpl';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';

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

/**
 * Genesis constant used to compute the starting hash of a new chain
 */
declare const GENESIS_CONSTANT = "XRPL-WALLET-MCP-GENESIS-V1";
/**
 * HMAC algorithm used for hash chain
 */
declare const HMAC_ALGORITHM = "sha256";
/**
 * Required HMAC key length in bytes (256 bits)
 */
declare const HMAC_KEY_LENGTH = 32;
/**
 * Current state of the hash chain
 */
interface ChainState {
    /** Current sequence number (0 if no entries) */
    sequence: number;
    /** Hash of the previous entry (or genesis hash if sequence is 0) */
    previousHash: string;
}
/**
 * Error types that can occur during chain verification
 */
type ChainErrorType = 'sequence_gap' | 'chain_break' | 'tampered_entry' | 'invalid_timestamp';
/**
 * Represents an error found during chain verification
 */
interface ChainError {
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
interface ChainVerificationResult {
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
interface VerificationOptions {
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
interface HashableEntry {
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
/**
 * Schema for HMAC key validation
 */
declare const HmacKeySchema: z.ZodEffects<z.ZodType<Buffer<ArrayBufferLike>, z.ZodTypeDef, Buffer<ArrayBufferLike>>, Buffer<ArrayBufferLike>, Buffer<ArrayBufferLike>>;
/**
 * Schema for chain state
 */
declare const ChainStateSchema: z.ZodObject<{
    sequence: z.ZodNumber;
    previousHash: z.ZodString;
}, "strip", z.ZodTypeAny, {
    sequence: number;
    previousHash: string;
}, {
    sequence: number;
    previousHash: string;
}>;
/**
 * Schema for verification options
 */
declare const VerificationOptionsSchema: z.ZodObject<{
    fullChain: z.ZodOptional<z.ZodBoolean>;
    startSequence: z.ZodOptional<z.ZodNumber>;
    endSequence: z.ZodOptional<z.ZodNumber>;
    recentEntries: z.ZodOptional<z.ZodNumber>;
    continueOnError: z.ZodOptional<z.ZodBoolean>;
}, "strip", z.ZodTypeAny, {
    fullChain?: boolean | undefined;
    startSequence?: number | undefined;
    endSequence?: number | undefined;
    recentEntries?: number | undefined;
    continueOnError?: boolean | undefined;
}, {
    fullChain?: boolean | undefined;
    startSequence?: number | undefined;
    endSequence?: number | undefined;
    recentEntries?: number | undefined;
    continueOnError?: boolean | undefined;
}>;
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
declare class HashChain {
    private readonly hmacKey;
    private state;
    /**
     * Create a new HashChain instance
     *
     * @param hmacKey - 256-bit HMAC key (32 bytes)
     * @param initialState - Optional initial chain state (for resuming)
     * @throws Error if HMAC key is invalid
     */
    constructor(hmacKey: Buffer, initialState?: ChainState);
    /**
     * Compute the genesis hash for a new chain
     *
     * The genesis hash is a well-known constant computed from the
     * GENESIS_CONSTANT using the HMAC key. This provides a verifiable
     * starting point for the chain.
     *
     * @returns Hex-encoded genesis hash
     */
    computeGenesisHash(): string;
    /**
     * Compute HMAC-SHA256 hash of entry data
     *
     * The hash includes all fields except 'hash' itself. Fields are
     * sorted alphabetically for deterministic serialization.
     *
     * @param data - Entry data (hash field will be ignored)
     * @returns Hex-encoded HMAC-SHA256 hash
     */
    computeHash(data: Record<string, unknown>): string;
    /**
     * Get the current chain state
     *
     * @returns Current sequence number and previous hash
     */
    getState(): ChainState;
    /**
     * Set the chain state (for resuming from storage)
     *
     * @param state - Chain state to restore
     */
    setState(state: ChainState): void;
    /**
     * Create the next entry in the chain
     *
     * Adds integrity fields (sequence, timestamp, previousHash, hash)
     * to the provided data and updates the chain state.
     *
     * @param data - Entry data (without integrity fields)
     * @returns Complete entry with hash chain fields
     */
    createEntry<T extends Record<string, unknown>>(data: T): T & HashableEntry;
    /**
     * Verify hash integrity of a single entry
     *
     * @param entry - Entry to verify
     * @param expectedPrevHash - Expected previous hash (from prior entry or genesis)
     * @returns Array of errors found (empty if valid)
     */
    verifyEntry(entry: HashableEntry, expectedPrevHash?: string): ChainError[];
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
    verifyEntries(entries: HashableEntry[], options?: VerificationOptions): ChainVerificationResult;
    /**
     * Verify that an entry correctly links to a previous entry
     *
     * @param current - Current entry to verify
     * @param previous - Previous entry in the chain
     * @returns True if chain link is valid
     */
    verifyChainLink(current: HashableEntry, previous: HashableEntry): boolean;
    /**
     * Dispose of the hash chain and zero out the HMAC key
     *
     * Should be called when the chain is no longer needed to
     * prevent key material from remaining in memory.
     */
    dispose(): void;
}
/**
 * Validate that an HMAC key meets requirements
 *
 * @param key - Buffer to validate
 * @returns True if key is valid
 */
declare function isValidHmacKey(key: Buffer): boolean;
/**
 * Generate a cryptographically secure HMAC key
 *
 * @returns 256-bit HMAC key
 */
declare function generateHmacKey(): Buffer;
/**
 * Compute a standalone HMAC-SHA256 hash (without chain state)
 *
 * @param key - HMAC key
 * @param data - Data to hash
 * @returns Hex-encoded hash
 */
declare function computeStandaloneHash(key: Buffer, data: string): string;

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

/**
 * Severity levels for audit events
 */
type AuditSeverity = 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL';
/**
 * Event categories for filtering and analysis
 */
type EventCategory = 'security' | 'operation' | 'transaction' | 'system';
/**
 * Actor types that can trigger events
 */
type ActorType = 'agent' | 'system' | 'human' | 'scheduled';
/**
 * Operation result status
 */
type OperationResult = 'success' | 'failure' | 'denied' | 'timeout';
/**
 * Input for logging an audit event (without auto-generated fields)
 */
interface AuditLogInput {
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
interface AuditLoggerConfig {
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
declare const DEFAULT_AUDIT_LOGGER_CONFIG: AuditLoggerConfig;
/**
 * Provider interface for HMAC key
 */
interface IHmacKeyProvider {
    /** Get the HMAC key for audit logging */
    getKey(): Promise<Buffer>;
}
/**
 * Options for creating an AuditLogger
 */
interface AuditLoggerOptions {
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
interface AuditLogQuery {
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
interface AuditStorageStats {
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
/**
 * Schema for audit log input validation
 */
declare const AuditLogInputSchema: z.ZodObject<{
    event: z.ZodEnum<["wallet_created", "wallet_imported", "wallet_deleted", "key_rotated", "transaction_signed", "transaction_submitted", "transaction_validated", "transaction_failed", "policy_evaluated", "policy_violation", "policy_updated", "approval_requested", "approval_granted", "approval_denied", "approval_expired", "rate_limit_triggered", "injection_detected", "authentication_failed", "server_started", "server_stopped", "keystore_unlocked", "keystore_locked"]>;
    wallet_id: z.ZodOptional<z.ZodString>;
    wallet_address: z.ZodOptional<z.ZodString>;
    transaction_type: z.ZodOptional<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>>;
    amount_xrp: z.ZodOptional<z.ZodString>;
    destination: z.ZodOptional<z.ZodString>;
    tier: z.ZodOptional<z.ZodUnion<[z.ZodLiteral<1>, z.ZodLiteral<2>, z.ZodLiteral<3>, z.ZodLiteral<4>]>>;
    policy_decision: z.ZodOptional<z.ZodEnum<["allowed", "denied", "pending"]>>;
    tx_hash: z.ZodOptional<z.ZodString>;
    context: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    event: "policy_violation" | "wallet_created" | "wallet_imported" | "wallet_deleted" | "key_rotated" | "transaction_signed" | "transaction_submitted" | "transaction_validated" | "transaction_failed" | "policy_evaluated" | "policy_updated" | "approval_requested" | "approval_granted" | "approval_denied" | "approval_expired" | "rate_limit_triggered" | "injection_detected" | "authentication_failed" | "server_started" | "server_stopped" | "keystore_unlocked" | "keystore_locked";
    wallet_address?: string | undefined;
    context?: string | undefined;
    wallet_id?: string | undefined;
    tx_hash?: string | undefined;
    tier?: 1 | 2 | 3 | 4 | undefined;
    destination?: string | undefined;
    transaction_type?: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge" | undefined;
    amount_xrp?: string | undefined;
    policy_decision?: "allowed" | "pending" | "denied" | undefined;
}, {
    event: "policy_violation" | "wallet_created" | "wallet_imported" | "wallet_deleted" | "key_rotated" | "transaction_signed" | "transaction_submitted" | "transaction_validated" | "transaction_failed" | "policy_evaluated" | "policy_updated" | "approval_requested" | "approval_granted" | "approval_denied" | "approval_expired" | "rate_limit_triggered" | "injection_detected" | "authentication_failed" | "server_started" | "server_stopped" | "keystore_unlocked" | "keystore_locked";
    wallet_address?: string | undefined;
    context?: string | undefined;
    wallet_id?: string | undefined;
    tx_hash?: string | undefined;
    tier?: 1 | 2 | 3 | 4 | undefined;
    destination?: string | undefined;
    transaction_type?: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge" | undefined;
    amount_xrp?: string | undefined;
    policy_decision?: "allowed" | "pending" | "denied" | undefined;
}>;
/**
 * Sanitize object for logging - removes all sensitive data
 *
 * @param obj - Object to sanitize
 * @param depth - Current recursion depth
 * @returns Sanitized copy of object
 */
declare function sanitizeForLogging(obj: unknown, depth?: number): unknown;
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
declare class AuditLogger extends EventEmitter {
    private readonly config;
    private readonly chain;
    private readonly logDir;
    private currentLogPath;
    private isInitialized;
    private writeLock;
    /**
     * Private constructor - use AuditLogger.create() factory method
     */
    private constructor();
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
    static create(options: AuditLoggerOptions): Promise<AuditLogger>;
    /**
     * Initialize the audit log storage
     */
    private initialize;
    /**
     * Restore chain state from existing log files
     */
    private restoreChainState;
    /**
     * Get the log file path for a given date
     */
    private getLogFilePath;
    /**
     * Get the last entry from the current log file
     */
    private getLastEntry;
    /**
     * Log an audit event
     *
     * @param input - Event data
     * @returns Complete log entry with integrity fields
     * @throws Error if logging fails
     */
    log(input: AuditLogInput): Promise<AuditLogEntry>;
    /**
     * Verify hash chain integrity
     *
     * @param options - Verification options
     * @returns Verification result with any detected errors
     */
    verifyChain(options?: VerificationOptions): Promise<ChainVerificationResult>;
    /**
     * Load entries for verification/querying
     */
    private loadEntries;
    /**
     * Query logs by criteria
     *
     * @param query - Query parameters
     * @returns Matching log entries
     */
    query(query: AuditLogQuery): Promise<AuditLogEntry[]>;
    /**
     * Get current chain state
     *
     * @returns Current sequence number and previous hash
     */
    getChainState(): ChainState;
    /**
     * Get storage statistics
     *
     * @returns Storage statistics
     */
    getStats(): Promise<AuditStorageStats>;
    /**
     * Graceful shutdown
     *
     * Ensures all pending writes complete and disposes of the hash chain.
     *
     * @param timeout - Maximum wait time for pending writes (ms)
     */
    shutdown(timeout?: number): Promise<void>;
}
/**
 * Create an in-memory HMAC key provider for testing
 *
 * @param key - HMAC key buffer
 * @returns HMAC key provider
 */
declare function createMemoryKeyProvider(key: Buffer): IHmacKeyProvider;
/**
 * Get the default audit log directory for a network
 *
 * @param network - XRPL network
 * @returns Directory path
 */
declare function getDefaultAuditDir(network: Network): string;

/**
 * Policy Engine Type Definitions
 *
 * Core types for policy evaluation, rule matching, and tier classification.
 * These types support the OPA-inspired policy engine for the XRPL Agent Wallet.
 *
 * @module policy/types
 * @version 1.0.0
 */

/**
 * String representation of approval tiers for policy engine internal use.
 * Maps to ApprovalTier (1-4) for external API.
 */
type Tier = 'autonomous' | 'delayed' | 'cosign' | 'prohibited';
/**
 * Convert string tier to numeric ApprovalTier
 */
declare function tierToNumeric(tier: Tier): ApprovalTier;
/**
 * Convert numeric ApprovalTier to string tier
 */
declare function numericToTier(tier: ApprovalTier): Tier;
/**
 * Transaction context for policy evaluation.
 * Contains all fields that can be used in policy conditions.
 */
interface TransactionContext {
    /** XRPL transaction type */
    type: TransactionType;
    /** Destination address (if applicable) */
    destination?: string;
    /** Amount in XRP */
    amount_xrp?: number;
    /** Amount in drops */
    amount_drops?: bigint;
    /** Memo content (text) */
    memo?: string;
    /** Memo type field */
    memo_type?: string;
    /** Transaction fee in drops */
    fee_drops?: number;
    /** Destination tag */
    destination_tag?: number;
    /** Source tag */
    source_tag?: number;
    /** Currency code (for issued currencies) */
    currency?: string;
    /** Token issuer address */
    issuer?: string;
}
/**
 * Wallet context for policy evaluation.
 */
interface WalletContext {
    /** Wallet's XRPL address */
    address: string;
    /** Network the wallet operates on */
    network: 'mainnet' | 'testnet' | 'devnet';
}
/**
 * Complete context for policy evaluation.
 */
interface PolicyContext {
    /** Transaction being evaluated */
    transaction: TransactionContext;
    /** Wallet making the transaction */
    wallet: WalletContext;
    /** Evaluation timestamp */
    timestamp: Date;
    /** Correlation ID for audit trail */
    correlationId: string;
}
/**
 * Factor that contributed to tier determination.
 */
interface TierFactor {
    /** What triggered this factor */
    source: 'rule' | 'transaction_type' | 'amount_limit' | 'new_destination' | 'prohibited_type' | 'blocklist' | 'limit_exceeded' | 'time_control';
    /** Tier this factor suggests */
    tier: Tier;
    /** Explanation */
    reason: string;
}
/**
 * Complete policy evaluation result.
 */
interface PolicyResult {
    /** Whether transaction can proceed (in some form) */
    allowed: boolean;
    /** Assigned tier determining approval workflow */
    tier: Tier;
    /** Numeric tier for API responses */
    tierNumeric: ApprovalTier;
    /** Human-readable explanation */
    reason: string;
    /** ID of the rule that matched */
    matchedRule: string;
    /** Contributing factors to tier determination */
    factors?: TierFactor[];
    /** Evaluation duration in milliseconds */
    evaluationTimeMs?: number;
    /** Delay in seconds (for delayed tier) */
    delaySeconds?: number;
    /** Whether veto is possible (for delayed tier) */
    vetoEnabled?: boolean;
    /** Required signatures (for cosign tier) */
    signerQuorum?: number;
    /** Approval timeout (for cosign tier) */
    approvalTimeoutHours?: number;
    /** Authorized signer addresses (for cosign tier) */
    signerAddresses?: string[];
    /** Whether to send notification */
    notify?: boolean;
    /** Prompt injection detected in memo */
    injectionDetected?: boolean;
}
/**
 * Operators for condition evaluation.
 */
type Operator = '==' | '!=' | '>' | '>=' | '<' | '<=' | 'in' | 'not_in' | 'matches' | 'contains' | 'starts_with' | 'ends_with' | 'in_category';
/**
 * Reference to a policy list (blocklist/allowlist).
 */
interface ValueReference {
    ref: string;
}
/**
 * Simple field condition.
 */
interface FieldCondition {
    field: string;
    operator: Operator;
    value: unknown | ValueReference;
}
/**
 * Logical AND condition.
 */
interface AndCondition {
    and: Condition[];
}
/**
 * Logical OR condition.
 */
interface OrCondition {
    or: Condition[];
}
/**
 * Logical NOT condition.
 */
interface NotCondition {
    not: Condition;
}
/**
 * Always-true condition (for default rules).
 */
interface AlwaysCondition {
    always: true;
}
/**
 * Union of all condition types.
 */
type Condition = FieldCondition | AndCondition | OrCondition | NotCondition | AlwaysCondition;
/**
 * Rule action - what tier to assign.
 */
interface RuleAction {
    tier: Tier;
    reason?: string;
    override_delay_seconds?: number;
    notify?: boolean;
    log_level?: 'info' | 'warn' | 'error';
}
/**
 * Policy rule definition.
 */
interface PolicyRule {
    id: string;
    name: string;
    description?: string;
    priority: number;
    enabled?: boolean;
    condition: Condition;
    action: RuleAction;
}
/**
 * Limit check result.
 */
interface LimitCheckResult {
    /** Whether limit was exceeded */
    exceeded: boolean;
    /** Human-readable reason */
    reason?: string;
    /** Type of limit exceeded */
    limitType?: 'daily_count' | 'hourly_count' | 'daily_volume' | 'unique_destinations' | 'cooldown' | 'per_tx_amount';
    /** Current value */
    currentValue?: number;
    /** Limit value */
    limitValue?: number;
    /** Requested amount (if volume limit) */
    requestedAmount?: number;
    /** When limit resets */
    expiresAt?: Date;
}
/**
 * Current limit state for monitoring.
 */
interface LimitState {
    daily: {
        date: string;
        transactionCount: number;
        totalVolumeXrp: number;
        uniqueDestinations: Set<string>;
        lastTransactionTime: Date | null;
    };
    hourly: {
        transactions: Array<{
            timestamp: Date;
            amountXrp: number;
            destination: string;
        }>;
    };
    cooldown: {
        active: boolean;
        reason: string | null;
        expiresAt: Date | null;
        triggeredBy: string | null;
    };
}
/**
 * Limit configuration.
 */
interface LimitConfig {
    dailyResetHour: number;
    maxTransactionsPerHour: number;
    maxTransactionsPerDay: number;
    maxUniqueDestinationsPerDay?: number | undefined;
    maxTotalVolumeXrpPerDay: number;
    maxAmountPerTxXrp?: number | undefined;
    cooldownAfterHighValue?: {
        enabled: boolean;
        thresholdXrp: number;
        cooldownSeconds: number;
    } | undefined;
}
/**
 * Policy metadata (safe to expose).
 */
interface PolicyInfo {
    name: string;
    version: string;
    network: string;
    description?: string | undefined;
    enabled: boolean;
    loadedAt: Date;
    hash: string;
    ruleCount: number;
    enabledRuleCount: number;
}
/**
 * Function type for condition evaluation.
 */
type ConditionEvaluator = (context: PolicyContext, policy: InternalPolicy) => boolean;
/**
 * Compiled rule for efficient evaluation.
 */
interface CompiledRule {
    id: string;
    name: string;
    priority: number;
    evaluator: ConditionEvaluator;
    action: RuleAction;
}
/**
 * Internal policy structure used by the engine.
 * Extended from AgentWalletPolicy with additional fields.
 */
interface InternalPolicy {
    version: string;
    name: string;
    description?: string;
    network: 'mainnet' | 'testnet' | 'devnet';
    enabled: boolean;
    tiers: {
        autonomous?: {
            max_amount_xrp: number;
            daily_limit_xrp?: number;
            require_known_destination?: boolean;
            allowed_transaction_types?: TransactionType[];
            max_fee_drops?: number;
        };
        delayed?: {
            max_amount_xrp: number;
            daily_limit_xrp?: number;
            delay_seconds: number;
            veto_enabled?: boolean;
            notify_on_queue?: boolean;
        };
        cosign?: {
            min_amount_xrp?: number;
            new_destination_always?: boolean;
            signer_quorum: number;
            approval_timeout_hours?: number;
            notify_signers?: boolean;
            signer_addresses?: string[];
        };
        prohibited?: {
            reasons?: string[];
            prohibited_transaction_types?: TransactionType[];
        };
    };
    rules: PolicyRule[];
    blocklist?: {
        addresses?: string[];
        memo_patterns?: string[];
        currency_issuers?: string[];
    };
    allowlist?: {
        addresses?: string[];
        trusted_tags?: number[];
        auto_learn?: boolean;
        exchange_addresses?: Array<{
            address: string;
            name?: string;
            require_tag?: boolean;
        }>;
    };
    limits: {
        daily_reset_utc_hour?: number;
        max_transactions_per_hour: number;
        max_transactions_per_day: number;
        max_unique_destinations_per_day?: number;
        max_total_volume_xrp_per_day: number;
        cooldown_after_high_value?: {
            enabled: boolean;
            threshold_xrp: number;
            cooldown_seconds: number;
        };
    };
    transaction_types?: Record<TransactionType, {
        enabled?: boolean;
        default_tier?: Tier;
        max_amount_xrp?: number;
        require_cosign?: boolean;
    }>;
}
/**
 * Options for PolicyEngine constructor.
 */
interface PolicyEngineOptions {
    /** Path for persisting limit state across restarts */
    limitPersistencePath?: string;
    /** Watch policy file for changes and log warnings */
    watchForChanges?: boolean;
    /** Custom clock for testing time-dependent logic */
    clock?: () => Date;
    /** Maximum regex execution time in milliseconds (ReDoS protection) */
    regexTimeoutMs?: number;
}
/**
 * Base error for policy-related failures.
 */
declare class PolicyError extends Error {
    readonly code: string;
    readonly recoverable: boolean;
    constructor(message: string, code: string, recoverable?: boolean);
    toJSON(): object;
}
/**
 * Policy file loading failed.
 */
declare class PolicyLoadError extends PolicyError {
    constructor(message: string);
}
/**
 * Policy validation against schema failed.
 */
declare class PolicyValidationError extends PolicyError {
    readonly issues: z.ZodIssue[];
    constructor(message: string, issues: z.ZodIssue[]);
}
/**
 * Error during policy evaluation.
 */
declare class PolicyEvaluationError extends PolicyError {
    constructor(message: string);
}
/**
 * Policy integrity check failed.
 */
declare class PolicyIntegrityError extends PolicyError {
    constructor();
}
/**
 * Limit exceeded error.
 */
declare class LimitExceededError extends PolicyError {
    readonly limitType: string;
    readonly currentValue: number;
    readonly limitValue: number;
    constructor(message: string, limitType: string, currentValue: number, limitValue: number);
}

/**
 * Policy Engine Implementation
 *
 * The core policy engine that evaluates transactions against declarative
 * policies before allowing signing operations. Implements an OPA-inspired
 * rule evaluation system entirely in TypeScript.
 *
 * @module policy/engine
 * @version 1.0.0
 */

/**
 * Simple transaction context for tool-based evaluation.
 * Used by MCP tools that don't have full PolicyContext.
 */
interface SimpleTransactionContext {
    /** XRPL transaction type */
    type: string;
    /** Destination address */
    destination?: string;
    /** Amount in drops (as string) */
    amount_drops?: string;
    /** Memo content */
    memo?: string;
}
/**
 * Simplified evaluation result for tools.
 */
interface SimpleEvaluationResult {
    /** Tier (1=autonomous, 2=delayed, 3=cosign, 4=prohibited) */
    tier: 1 | 2 | 3 | 4;
    /** Reason for decision */
    reason: string;
    /** Policy violations (for prohibited) */
    violations?: string[];
    /** Warnings (non-blocking) */
    warnings?: string[];
    /** Whether transaction is allowed */
    allowed: boolean;
}
/**
 * Core policy engine interface.
 * All evaluation methods are synchronous and deterministic.
 */
interface IPolicyEngine {
    /**
     * Evaluate a transaction against the loaded policy.
     * This is the primary entry point for all transaction authorization.
     */
    evaluate(context: PolicyContext): PolicyResult;
    /**
     * Simplified transaction evaluation for MCP tools.
     * Creates a PolicyContext internally from the simple transaction context.
     *
     * @param policyId - Policy ID (for validation)
     * @param txContext - Simple transaction context from decoded transaction
     * @returns Simplified evaluation result with tier and violations
     */
    evaluateTransaction(policyId: string, txContext: SimpleTransactionContext): Promise<SimpleEvaluationResult>;
    /**
     * Set or update the policy configuration.
     * SECURITY: In production, this should require approval workflow.
     *
     * @param policy - New policy configuration
     */
    setPolicy(policy: AgentWalletPolicy): Promise<void>;
    /**
     * Get the SHA-256 hash of the currently loaded policy.
     * Used for integrity verification and audit logging.
     */
    getPolicyHash(): string;
    /**
     * Get policy metadata without exposing internal rules.
     */
    getPolicyInfo(): PolicyInfo;
    /**
     * Verify policy integrity against stored hash.
     * Should be called periodically and before signing operations.
     */
    verifyIntegrity(): boolean;
    /**
     * Get current limit state for monitoring/debugging.
     * Does not expose sensitive policy details.
     */
    getLimitState(): LimitState;
    /**
     * Reset limit counters. Only for testing or administrative override.
     * Requires explicit confirmation and is logged.
     */
    resetLimits(confirmation: string): void;
    /**
     * Record a successful transaction for limit tracking.
     */
    recordTransaction(context: PolicyContext): void;
    /**
     * Clean up resources (intervals, etc).
     */
    dispose(): void;
}
/**
 * Policy Engine - Security boundary for transaction authorization.
 *
 * Features:
 * - Immutable policy after loading
 * - Priority-based rule evaluation
 * - 4-tier classification (autonomous, delayed, co-sign, prohibited)
 * - Blocklist/allowlist support
 * - Memo pattern detection for prompt injection
 * - Rate and volume limiting
 * - Policy integrity verification
 *
 * Security Guarantees:
 * - LLM/agent cannot modify policies at runtime
 * - Policy integrity verified on each evaluation
 * - Fail-secure: any error results in denial
 * - Hard limits enforce absolute ceilings
 */
declare class PolicyEngine implements IPolicyEngine {
    /** Frozen policy data */
    private readonly policy;
    /** SHA-256 hash of serialized policy */
    private readonly policyHash;
    /** When policy was loaded */
    private readonly loadedAt;
    /** Rule evaluator */
    private readonly ruleEvaluator;
    /** Limit tracker */
    private readonly limitTracker;
    /** Custom clock for testing */
    private readonly clock;
    /** Regex cache for blocklist patterns */
    private readonly regexCache;
    constructor(policy: InternalPolicy, options?: PolicyEngineOptions);
    /**
     * Evaluate a transaction against the loaded policy.
     */
    evaluate(context: PolicyContext): PolicyResult;
    /**
     * Check global limits.
     */
    private checkGlobalLimits;
    /**
     * Check transaction type restrictions.
     */
    private checkTransactionType;
    /**
     * Apply tier-specific constraints and amount escalation.
     */
    private applyTierConstraints;
    /**
     * Apply amount-based tier escalation.
     */
    private applyAmountEscalation;
    /**
     * Apply new destination escalation.
     */
    private applyNewDestinationEscalation;
    /**
     * Compare two tiers and return the more restrictive one.
     */
    private compareTiers;
    /**
     * Create a prohibited result.
     */
    private createProhibitedResult;
    /**
     * Get policy hash.
     */
    getPolicyHash(): string;
    /**
     * Get policy info.
     */
    getPolicyInfo(): PolicyInfo;
    /**
     * Verify policy integrity.
     */
    verifyIntegrity(): boolean;
    /**
     * Get limit state.
     */
    getLimitState(): LimitState;
    /**
     * Reset limits.
     */
    resetLimits(confirmation: string): void;
    /**
     * Record a successful transaction.
     */
    recordTransaction(context: PolicyContext): void;
    /**
     * Dispose of resources.
     */
    dispose(): void;
    /**
     * Simplified transaction evaluation for MCP tools.
     * Creates a PolicyContext internally from the simple transaction context.
     */
    evaluateTransaction(policyId: string, txContext: SimpleTransactionContext): Promise<SimpleEvaluationResult>;
    /**
     * Set or update the policy configuration.
     *
     * NOTE: PolicyEngine is IMMUTABLE by design (ADR-003 security requirement).
     * This method throws an error to prevent silent failures.
     *
     * To update a policy, you must:
     * 1. Create a new PolicyEngine instance with the new policy
     * 2. Replace the old engine atomically at the server level
     * 3. Consider requiring human approval for policy changes
     *
     * @throws PolicyLoadError always - policies cannot be changed at runtime
     */
    setPolicy(policy: AgentWalletPolicy): Promise<void>;
    /**
     * Compute SHA-256 hash of policy.
     */
    private computeHash;
    /**
     * Deep freeze an object.
     */
    private deepFreeze;
}
/**
 * Create a PolicyEngine from an AgentWalletPolicy.
 */
declare function createPolicyEngine(policy: AgentWalletPolicy, options?: PolicyEngineOptions): PolicyEngine;
/**
 * Create a simple test policy for development.
 */
declare function createTestPolicy(network?: 'mainnet' | 'testnet' | 'devnet', overrides?: Partial<InternalPolicy>): InternalPolicy;

/**
 * Rule Evaluator Implementation
 *
 * Priority-based rule matching with condition compilation for
 * efficient policy evaluation.
 *
 * @module policy/evaluator
 * @version 1.0.0
 */

/**
 * Get transaction category for a transaction type.
 */
declare function getTransactionCategory(type: string): string;
/**
 * Result of rule evaluation.
 */
interface RuleResult {
    matched: boolean;
    ruleId: string;
    ruleName: string;
    tier: Tier;
    reason: string;
    overrideDelaySeconds?: number | undefined;
    notify?: boolean | undefined;
    logLevel?: 'info' | 'warn' | 'error' | undefined;
}
/**
 * Options for RuleEvaluator.
 */
interface RuleEvaluatorOptions {
    /** Maximum regex execution time in ms (ReDoS protection) */
    regexTimeoutMs?: number;
    /** Maximum input length for regex matching */
    maxRegexInputLength?: number;
}
/**
 * Evaluates policy rules in priority order.
 *
 * Features:
 * - Rule compilation for efficient repeated evaluation
 * - Priority-based evaluation (lower = higher priority)
 * - Logical operators (AND, OR, NOT)
 * - Field comparisons with multiple operators
 * - Reference resolution for blocklist/allowlist
 * - Regex caching with ReDoS protection
 */
declare class RuleEvaluator {
    private readonly compiledRules;
    private readonly regexCache;
    private readonly options;
    constructor(options?: RuleEvaluatorOptions);
    /**
     * Compile rules for efficient evaluation.
     * Rules are sorted by priority (lower = higher priority).
     */
    compileRules(rules: PolicyRule[]): void;
    /**
     * Compile a single rule.
     */
    private compileRule;
    /**
     * Compile a condition into an evaluator function.
     */
    private compileCondition;
    /**
     * Compile a field condition.
     */
    private compileFieldCondition;
    /**
     * Extract a field value from the policy context.
     */
    private extractFieldValue;
    /**
     * Resolve a value (may be a reference to policy lists).
     */
    private resolveValue;
    /**
     * Resolve a reference to a policy list.
     */
    private resolveReference;
    /**
     * Evaluate an operator.
     */
    private evaluateOperator;
    /**
     * Check if a regex pattern is potentially vulnerable to ReDoS.
     *
     * Detects common ReDoS patterns:
     * - Nested quantifiers: (a+)+, (a*)*
     * - Overlapping alternation: (a|a)+
     * - Exponential backtracking patterns
     */
    private isReDoSVulnerable;
    /**
     * Match a value against a regex pattern.
     */
    private matchesRegex;
    /**
     * Check if a transaction type is in a category.
     */
    private isInCategory;
    private isAlwaysCondition;
    private isAndCondition;
    private isOrCondition;
    private isNotCondition;
    private isFieldCondition;
    private isValueReference;
    private asNumber;
    private asString;
    private asArray;
    /**
     * Evaluate rules against a context.
     * Returns the first matching rule's result.
     */
    evaluate(context: PolicyContext, policy: InternalPolicy): RuleResult;
    /**
     * Get the number of compiled rules.
     */
    getRuleCount(): number;
    /**
     * Clear compiled rules and caches.
     */
    clear(): void;
}
/**
 * Check if a transaction matches blocklist criteria.
 */
interface BlocklistCheckResult {
    blocked: boolean;
    reason?: string;
    matchedRule?: string;
    injectionDetected?: boolean;
}
/**
 * Check transaction against blocklist.
 *
 * This is a separate check from rule evaluation because
 * blocklist should ALWAYS be checked first, regardless of rules.
 */
declare function checkBlocklist(context: PolicyContext, policy: InternalPolicy, regexCache?: Map<string, RegExp>): BlocklistCheckResult;
/**
 * Check if a destination is in the allowlist.
 */
declare function isInAllowlist(context: PolicyContext, policy: InternalPolicy): boolean;

/**
 * Limit Tracker Implementation
 *
 * Token bucket rate limiting with rolling window counters for
 * transaction count, volume, and destination tracking.
 *
 * @module policy/limits
 * @version 1.0.0
 */

/**
 * Options for LimitTracker construction.
 */
interface LimitTrackerOptions {
    /** Limit configuration */
    config: LimitConfig;
    /** Path for persisting state (optional) */
    persistencePath?: string | undefined;
    /** Custom clock for testing */
    clock?: (() => Date) | undefined;
}
/**
 * Tracks transaction limits using rolling windows and daily resets.
 *
 * Features:
 * - Daily transaction count limits (resets at configured UTC hour)
 * - Hourly transaction count limits (sliding 1-hour window)
 * - Daily XRP volume limits
 * - Unique destination tracking per day
 * - Optional cooldown after high-value transactions
 * - State persistence across restarts (optional)
 */
declare class LimitTracker {
    private state;
    private readonly config;
    private readonly persistencePath;
    private readonly clock;
    private resetInterval;
    constructor(options: LimitTrackerOptions);
    /**
     * Create fresh limit state.
     */
    private createFreshState;
    /**
     * Check if a transaction would exceed any limits.
     * Does NOT record the transaction - call recordTransaction after successful signing.
     */
    checkLimits(context: PolicyContext): LimitCheckResult;
    /**
     * Record a successfully signed transaction.
     * Call this AFTER signing succeeds, not before.
     */
    recordTransaction(context: PolicyContext): void;
    /**
     * Check if daily reset should happen.
     */
    private maybeResetDaily;
    /**
     * Remove transactions older than 1 hour from sliding window.
     */
    private pruneHourlyWindow;
    /**
     * Activate cooldown period.
     */
    private activateCooldown;
    /**
     * Clear active cooldown.
     */
    private clearCooldown;
    /**
     * Schedule periodic check for daily reset.
     */
    private schedulePeriodicCheck;
    /** Track disposal state */
    private isDisposed;
    /**
     * Stop periodic checks (for cleanup).
     */
    dispose(): void;
    /**
     * Check if the tracker has been disposed.
     */
    get disposed(): boolean;
    /**
     * Get current daily XRP volume.
     */
    getDailyVolumeXrp(): number;
    /**
     * Get transactions in the last hour.
     */
    getHourlyCount(): number;
    /**
     * Get daily transaction count.
     */
    getDailyCount(): number;
    /**
     * Get unique destination count for today.
     */
    getUniqueDestinationCount(): number;
    /**
     * Check if a destination has been used before today.
     */
    isDestinationKnown(destination: string): boolean;
    /**
     * Get complete limit state (copy for safety).
     */
    getState(): LimitState;
    /**
     * Get remaining limits for current period.
     */
    getRemainingLimits(): {
        dailyTxRemaining: number;
        hourlyTxRemaining: number;
        dailyVolumeRemainingXrp: number;
        uniqueDestinationsRemaining: number;
    };
    /**
     * Reset all limits. Requires confirmation string for safety.
     */
    reset(confirmation: string): void;
    /**
     * Get date string in YYYY-MM-DD format.
     */
    private getDateString;
}
/**
 * Create a LimitTracker from policy limits configuration.
 */
declare function createLimitTracker(limits: {
    max_tx_per_hour: number;
    max_tx_per_day: number;
    max_daily_volume_drops: string;
    max_amount_per_tx_drops: string;
}, options?: {
    dailyResetHour?: number | undefined;
    maxUniqueDestinationsPerDay?: number | undefined;
    cooldownAfterHighValue?: {
        enabled: boolean;
        thresholdXrp: number;
        cooldownSeconds: number;
    } | undefined;
    clock?: (() => Date) | undefined;
}): LimitTracker;

/**
 * SecureBuffer - Memory-safe container for sensitive cryptographic data.
 *
 * This class provides controlled access to sensitive data (private keys, seeds)
 * with automatic memory zeroing and serialization prevention.
 *
 * Security Features:
 * - Automatic zeroing of source buffer on creation
 * - Explicit disposal with multiple overwrite passes
 * - Prevention of accidental serialization (JSON, toString)
 * - Clear lifecycle tracking
 *
 * @module keystore/secure-buffer
 * @version 1.0.0
 */
/**
 * SecureBuffer provides memory-safe handling of sensitive data.
 *
 * USAGE:
 * ```typescript
 * const secure = SecureBuffer.from(sensitiveData);
 * try {
 *   // Use secure.getBuffer() for operations
 *   const result = someOperation(secure.getBuffer());
 * } finally {
 *   secure.dispose(); // Always dispose when done
 * }
 * ```
 *
 * SECURITY NOTES:
 * - Source buffer is zeroed when creating from existing data
 * - Buffer contents are overwritten with multiple passes on dispose
 * - Serialization methods throw to prevent accidental exposure
 */
declare class SecureBuffer {
    private buffer;
    private isDisposed;
    /**
     * Private constructor - use static factory methods.
     */
    private constructor();
    /**
     * Creates a new SecureBuffer with uninitialized content of specified size.
     *
     * @param size - Size in bytes
     * @returns New SecureBuffer instance
     */
    static alloc(size: number): SecureBuffer;
    /**
     * Creates a SecureBuffer from existing data.
     *
     * IMPORTANT: The source buffer is zeroed immediately after copying
     * to prevent the original data from remaining in memory.
     *
     * @param data - Source buffer (will be zeroed)
     * @param verify - If true, verify source was zeroed (default: false for performance)
     * @returns New SecureBuffer containing the copied data
     */
    static from(data: Buffer, verify?: boolean): SecureBuffer;
    /**
     * Gets the buffer contents for use in cryptographic operations.
     *
     * @returns The internal Buffer
     * @throws Error if buffer has been disposed
     */
    getBuffer(): Buffer;
    /**
     * Disposes the buffer by securely zeroing its contents.
     *
     * This operation is irreversible. Multiple overwrite passes are used
     * to help prevent data recovery.
     */
    dispose(): void;
    /**
     * Alias for dispose() - matches common naming conventions.
     */
    zero(): void;
    /**
     * Returns whether the buffer has been disposed.
     */
    get disposed(): boolean;
    /**
     * Alias for disposed getter - matches spec naming.
     */
    get zeroed(): boolean;
    /**
     * Buffer length in bytes.
     */
    get length(): number;
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
    static withSecure<T>(secure: SecureBuffer, operation: (buffer: Buffer) => Promise<T>): Promise<T>;
    /**
     * Creates a SecureBuffer, executes an operation, and disposes it.
     *
     * @param data - Source buffer (will be zeroed)
     * @param operation - Async operation that uses the buffer
     * @returns Result of the operation
     */
    static withSecureBuffer<T>(data: Buffer, operation: (buffer: Buffer) => Promise<T>): Promise<T>;
    /**
     * Prevents JSON serialization of sensitive data.
     * @throws Error always
     */
    toJSON(): never;
    /**
     * Returns a placeholder string instead of buffer contents.
     */
    toString(): string;
    /**
     * Prevents spreading/iteration of buffer contents.
     */
    [Symbol.iterator](): never;
}

/**
 * Keystore Interface Definitions
 *
 * Defines the pluggable abstraction layer for secure key storage
 * in the XRPL Agent Wallet MCP server.
 *
 * @module keystore/interface
 * @version 1.0.0
 */

/**
 * XRPL Network identifiers.
 */
type XRPLNetwork = 'mainnet' | 'testnet' | 'devnet';
/**
 * Keystore provider types.
 */
type KeystoreProviderType = 'local-file' | 'cloud-kms' | 'hsm' | 'mock';
/**
 * Key algorithm types supported by XRPL.
 */
type KeyAlgorithm = 'ed25519' | 'secp256k1';
/**
 * Wallet status states.
 */
type WalletStatus = 'active' | 'locked' | 'archived' | 'pending';
/**
 * Backup format types.
 */
type BackupFormat = 'encrypted-json' | 'kms-wrapped';
/**
 * Password complexity requirements.
 */
interface PasswordPolicy {
    /** Minimum password length (default: 12) */
    minLength: number;
    /** Require uppercase letters (default: true) */
    requireUppercase: boolean;
    /** Require lowercase letters (default: true) */
    requireLowercase: boolean;
    /** Require numbers (default: true) */
    requireNumbers: boolean;
    /** Require special characters (default: false) */
    requireSpecial: boolean;
    /** Maximum password length (default: 128) */
    maxLength: number;
}
/**
 * Audit logging configuration.
 */
interface AuditConfig {
    /** Whether audit logging is enabled */
    enabled: boolean;
    /** Path to audit log file */
    logPath: string;
    /** Log rotation size in MB */
    rotationSizeMB: number;
    /** Log retention in days */
    retentionDays: number;
}
/**
 * HSM configuration (for Phase 3).
 */
interface HSMConfig {
    /** Path to PKCS#11 library */
    libraryPath: string;
    /** HSM slot number */
    slot: number;
    /** HSM PIN */
    pin: string;
    /** Key label in HSM */
    keyLabel: string;
}
/**
 * Keystore provider configuration.
 */
interface KeystoreConfig {
    /** Base directory for file storage (local-file provider) */
    baseDir?: string;
    /** KMS key URI (cloud-kms provider) */
    kmsKeyUri?: string;
    /** HSM configuration (hsm provider) */
    hsmConfig?: HSMConfig;
    /** Password complexity requirements */
    passwordPolicy?: PasswordPolicy;
    /** Audit logging configuration */
    auditConfig?: AuditConfig;
    /** Maximum number of wallets per network */
    maxWalletsPerNetwork?: number;
}
/**
 * Key derivation function parameters.
 */
interface KdfParams {
    /** Memory cost in KB (Argon2id) or iterations (PBKDF2) */
    memoryCost?: number;
    /** Iterations (PBKDF2) */
    iterations?: number;
    /** Time cost / iterations for Argon2id */
    timeCost?: number;
    /** Parallelism factor */
    parallelism?: number;
    /** Hash algorithm for PBKDF2 */
    hash?: 'sha256' | 'sha512';
}
/**
 * Encryption metadata stored with wallet.
 */
interface EncryptionMetadata {
    /** Encryption algorithm */
    algorithm: 'aes-256-gcm';
    /** Key derivation function */
    kdf: 'argon2id' | 'pbkdf2';
    /** KDF parameters */
    kdfParams: KdfParams;
    /** Salt (base64 encoded, unique per wallet) */
    salt: string;
    /** Provider-specific metadata */
    providerData?: Record<string, unknown>;
}
/**
 * Wallet metadata (non-sensitive).
 */
interface WalletMetadata {
    /** Optional description */
    description?: string;
    /** Custom tags for organization */
    tags?: string[];
    /** Has regular key configured on-chain */
    hasRegularKey?: boolean;
    /** Has multi-sign configured on-chain */
    hasMultiSign?: boolean;
    /** Last used timestamp */
    lastUsedAt?: string;
    /** Transaction count for this wallet */
    transactionCount?: number;
    /** Custom application data */
    customData?: Record<string, unknown>;
}
/**
 * Complete wallet information (no private key material).
 */
interface WalletEntry {
    /** Unique internal identifier */
    walletId: string;
    /** Human-readable name */
    name: string;
    /** XRPL Classic Address (r...) */
    address: string;
    /** Public key (hex encoded) */
    publicKey: string;
    /** Key algorithm used */
    algorithm: KeyAlgorithm;
    /** Target XRPL network */
    network: XRPLNetwork;
    /** Associated policy identifier */
    policyId: string;
    /** Encryption metadata (for decryption) */
    encryption: EncryptionMetadata;
    /** Wallet metadata */
    metadata: WalletMetadata;
    /** Creation timestamp (ISO 8601) */
    createdAt: string;
    /** Last modification timestamp (ISO 8601) */
    modifiedAt: string;
    /** Wallet status */
    status: WalletStatus;
}
/**
 * Lightweight wallet summary for list operations.
 */
interface WalletSummary {
    /** Unique internal identifier */
    walletId: string;
    /** Human-readable name */
    name: string;
    /** XRPL Classic Address */
    address: string;
    /** Target network */
    network: XRPLNetwork;
    /** Wallet status */
    status: WalletStatus;
    /** Creation timestamp */
    createdAt: string;
    /** Last used timestamp */
    lastUsedAt?: string;
    /** Associated policy identifier */
    policyId: string;
    /** Custom tags */
    tags?: string[];
}
/**
 * Wallet policy reference.
 */
interface WalletPolicy {
    /** Policy identifier */
    policyId: string;
    /** Policy version */
    policyVersion: string;
}
/**
 * Entropy source for key generation (testing only).
 */
interface EntropySource {
    /** Generate random bytes (must be cryptographically secure) */
    randomBytes(length: number): Buffer;
}
/**
 * Options for wallet creation.
 */
interface WalletCreateOptions {
    /** Custom wallet name (default: auto-generated) */
    name?: string;
    /** User password for encryption */
    password: string;
    /** Key algorithm preference (default: ed25519) */
    algorithm?: KeyAlgorithm;
    /** Optional description */
    description?: string;
    /** Custom tags */
    tags?: string[];
    /** Generate regular key pair as well */
    generateRegularKey?: boolean;
    /** Custom entropy source (testing only) */
    entropySource?: EntropySource;
}
/**
 * Encrypted backup file format.
 */
interface EncryptedBackup {
    /** Backup format version */
    version: number;
    /** Format type */
    format: BackupFormat;
    /** Creation timestamp */
    createdAt: string;
    /** Provider that created the backup */
    sourceProvider: KeystoreProviderType;
    /** Encryption parameters */
    encryption: {
        algorithm: 'aes-256-gcm';
        kdf: 'argon2id';
        kdfParams: KdfParams;
        salt: string;
        iv: string;
        authTag: string;
    };
    /** Encrypted payload (base64) */
    payload: string;
    /** Checksum for integrity verification */
    checksum: string;
}
/**
 * Options for importing a backup.
 */
interface ImportOptions {
    /** Override wallet name */
    newName?: string;
    /** Override network (use with caution) */
    targetNetwork?: XRPLNetwork;
    /** Force import even if wallet exists */
    force?: boolean;
    /** New password (re-encrypts with different key) */
    newPassword?: string;
}
/**
 * Health check result.
 */
interface KeystoreHealthResult {
    /** Overall health status */
    healthy: boolean;
    /** Provider type */
    providerType: KeystoreProviderType;
    /** Provider version */
    providerVersion: string;
    /** Timestamp of health check */
    timestamp: string;
    /** Detailed status information */
    details: {
        /** Whether storage is accessible */
        storageAccessible: boolean;
        /** Whether encryption is available */
        encryptionAvailable: boolean;
        /** Number of networks with keystores */
        networkCount: number;
        /** Total wallet count */
        walletCount: number;
        /** Last operation timestamp */
        lastOperationTime?: string;
    };
    /** Any error messages */
    errors?: string[];
}
/**
 * KeystoreProvider - Pluggable interface for secure key storage backends.
 *
 * All implementations MUST:
 * - Encrypt keys at rest
 * - Provide network isolation
 * - Support atomic operations
 * - Implement secure memory handling
 * - Log all operations to audit trail
 */
interface KeystoreProvider {
    /**
     * Provider type identifier.
     */
    readonly providerType: KeystoreProviderType;
    /**
     * Provider version string.
     */
    readonly providerVersion: string;
    /**
     * Initialize the keystore provider.
     * Must be called before any other operations.
     *
     * @param config - Provider-specific configuration
     * @throws KeystoreInitializationError if initialization fails
     */
    initialize(config: KeystoreConfig): Promise<void>;
    /**
     * Verify the provider is ready for operations.
     *
     * @returns Health check result with provider status
     */
    healthCheck(): Promise<KeystoreHealthResult>;
    /**
     * Create a new wallet with encrypted key storage.
     *
     * @param network - Target XRPL network (mainnet/testnet/devnet)
     * @param policy - Policy configuration for the wallet
     * @param options - Optional wallet creation parameters
     * @returns Created wallet entry (without private key material)
     * @throws WalletCreationError if creation fails
     * @throws KeystoreCapacityError if storage limit reached
     */
    createWallet(network: XRPLNetwork, policy: WalletPolicy, options?: WalletCreateOptions): Promise<WalletEntry>;
    /**
     * Load and decrypt a wallet's private key material.
     *
     * SECURITY: Returns SecureBuffer that MUST be disposed after use.
     * The caller is responsible for calling SecureBuffer.dispose().
     *
     * @param walletId - Unique wallet identifier
     * @param password - User password for key derivation
     * @returns SecureBuffer containing decrypted key material
     * @throws WalletNotFoundError if wallet doesn't exist
     * @throws AuthenticationError if password is incorrect
     * @throws KeyDecryptionError if decryption fails
     */
    loadKey(walletId: string, password: string): Promise<SecureBuffer>;
    /**
     * Store an externally-provided key in the keystore.
     * Used for wallet import scenarios.
     *
     * @param walletId - Unique wallet identifier
     * @param key - Secret key material (will be encrypted)
     * @param password - User password for key derivation
     * @param metadata - Additional wallet metadata
     * @throws WalletExistsError if walletId already exists
     * @throws InvalidKeyError if key format is invalid
     * @throws KeystoreWriteError if storage fails
     */
    storeKey(walletId: string, key: SecureBuffer, password: string, metadata: WalletMetadata): Promise<void>;
    /**
     * List all wallets, optionally filtered by network.
     *
     * SECURITY: Returns summaries only, never key material.
     *
     * @param network - Optional network filter
     * @returns Array of wallet summaries
     */
    listWallets(network?: XRPLNetwork): Promise<WalletSummary[]>;
    /**
     * Get detailed information about a specific wallet.
     *
     * SECURITY: Returns metadata only, never key material.
     *
     * @param walletId - Unique wallet identifier
     * @returns Wallet entry with full metadata
     * @throws WalletNotFoundError if wallet doesn't exist
     */
    getWallet(walletId: string): Promise<WalletEntry>;
    /**
     * Permanently delete a wallet and its associated keys.
     *
     * WARNING: This operation is irreversible.
     * The wallet's private keys will be securely wiped.
     *
     * @param walletId - Unique wallet identifier
     * @param password - User password to confirm deletion
     * @throws WalletNotFoundError if wallet doesn't exist
     * @throws AuthenticationError if password is incorrect
     * @throws KeystoreWriteError if deletion fails
     */
    deleteWallet(walletId: string, password: string): Promise<void>;
    /**
     * Rotate the encryption key for a wallet.
     * Re-encrypts all key material with a new password.
     *
     * @param walletId - Unique wallet identifier
     * @param currentPassword - Current password
     * @param newPassword - New password
     * @throws WalletNotFoundError if wallet doesn't exist
     * @throws AuthenticationError if current password is incorrect
     * @throws WeakPasswordError if new password doesn't meet requirements
     */
    rotateKey(walletId: string, currentPassword: string, newPassword: string): Promise<void>;
    /**
     * Update wallet metadata without touching key material.
     *
     * @param walletId - Unique wallet identifier
     * @param updates - Metadata fields to update
     * @throws WalletNotFoundError if wallet doesn't exist
     */
    updateMetadata(walletId: string, updates: Partial<WalletMetadata>): Promise<void>;
    /**
     * Export encrypted backup of a wallet.
     *
     * @param walletId - Unique wallet identifier
     * @param password - User password
     * @param format - Export format
     * @returns Encrypted backup blob
     * @throws WalletNotFoundError if wallet doesn't exist
     * @throws AuthenticationError if password is incorrect
     */
    exportBackup(walletId: string, password: string, format: BackupFormat): Promise<EncryptedBackup>;
    /**
     * Import a wallet from encrypted backup.
     *
     * @param backup - Encrypted backup data
     * @param password - Password used during export
     * @param options - Import options (rename, network override)
     * @returns Imported wallet entry
     * @throws BackupFormatError if backup is invalid
     * @throws AuthenticationError if password is incorrect
     * @throws WalletExistsError if wallet already exists (without force)
     */
    importBackup(backup: EncryptedBackup, password: string, options?: ImportOptions): Promise<WalletEntry>;
    /**
     * Close the keystore provider and release resources.
     * Zeros any cached key material from memory.
     */
    close(): Promise<void>;
}

/**
 * Keystore Error Types
 *
 * Defines all error types for keystore operations.
 * All errors extend the base KeystoreError class.
 *
 * @module keystore/errors
 * @version 1.0.0
 */

/**
 * Error codes for keystore operations.
 */
type KeystoreErrorCode = 'KEYSTORE_INIT_ERROR' | 'WALLET_NOT_FOUND' | 'WALLET_EXISTS' | 'AUTHENTICATION_ERROR' | 'WEAK_PASSWORD' | 'KEY_DECRYPTION_ERROR' | 'KEY_ENCRYPTION_ERROR' | 'INVALID_KEY_FORMAT' | 'KEYSTORE_WRITE_ERROR' | 'KEYSTORE_READ_ERROR' | 'KEYSTORE_CAPACITY_ERROR' | 'BACKUP_FORMAT_ERROR' | 'NETWORK_MISMATCH' | 'PROVIDER_UNAVAILABLE' | 'OPERATION_TIMEOUT' | 'INTERNAL_ERROR';
/**
 * Base error class for all keystore operations.
 *
 * All keystore errors include:
 * - A specific error code for programmatic handling
 * - Whether the error is recoverable
 * - Timestamp of when the error occurred
 * - Optional additional details
 */
declare abstract class KeystoreError extends Error {
    readonly details?: Record<string, unknown> | undefined;
    /** Error code for programmatic handling */
    abstract readonly code: KeystoreErrorCode;
    /** Whether this error is recoverable (can be retried) */
    abstract readonly recoverable: boolean;
    /** Timestamp when error occurred */
    readonly timestamp: string;
    /** Correlation ID for tracking */
    readonly correlationId?: string;
    constructor(message: string, details?: Record<string, unknown> | undefined);
    /**
     * Convert to safe JSON representation (excludes sensitive data).
     */
    toSafeJSON(): Record<string, unknown>;
}
/**
 * Keystore initialization failed.
 */
declare class KeystoreInitializationError extends KeystoreError {
    readonly code: "KEYSTORE_INIT_ERROR";
    readonly recoverable = false;
    readonly originalCause: Error | undefined;
    constructor(message: string, originalCause?: Error);
}
/**
 * Wallet not found in keystore.
 */
declare class WalletNotFoundError extends KeystoreError {
    readonly walletId: string;
    readonly code: "WALLET_NOT_FOUND";
    readonly recoverable = false;
    constructor(walletId: string);
}
/**
 * Wallet already exists (duplicate ID or address).
 */
declare class WalletExistsError extends KeystoreError {
    readonly walletId: string;
    readonly existingAddress?: string | undefined;
    readonly code: "WALLET_EXISTS";
    readonly recoverable = false;
    constructor(walletId: string, existingAddress?: string | undefined);
}
/**
 * Authentication failed (wrong password).
 *
 * Note: Intentionally vague message to prevent enumeration attacks.
 */
declare class AuthenticationError extends KeystoreError {
    readonly code: "AUTHENTICATION_ERROR";
    readonly recoverable = true;
    constructor();
}
/**
 * Password does not meet complexity requirements.
 */
declare class WeakPasswordError extends KeystoreError {
    readonly requirements: string[];
    readonly code: "WEAK_PASSWORD";
    readonly recoverable = true;
    constructor(requirements: string[]);
}
/**
 * Key decryption failed.
 * Could be wrong password, corrupted data, or algorithm mismatch.
 */
declare class KeyDecryptionError extends KeystoreError {
    readonly code: "KEY_DECRYPTION_ERROR";
    readonly recoverable = false;
    constructor(message?: string);
}
/**
 * Key encryption failed during storage.
 */
declare class KeyEncryptionError extends KeystoreError {
    readonly code: "KEY_ENCRYPTION_ERROR";
    readonly recoverable = false;
    constructor(message?: string);
}
/**
 * Invalid key format or length.
 */
declare class InvalidKeyError extends KeystoreError {
    readonly reason: string;
    readonly expectedFormat?: string | undefined;
    readonly code: "INVALID_KEY_FORMAT";
    readonly recoverable = false;
    constructor(reason: string, expectedFormat?: string | undefined);
}
/**
 * Keystore write operation failed.
 */
declare class KeystoreWriteError extends KeystoreError {
    readonly operation: 'create' | 'update' | 'delete';
    readonly code: "KEYSTORE_WRITE_ERROR";
    readonly recoverable = true;
    constructor(message: string, operation: 'create' | 'update' | 'delete');
}
/**
 * Keystore read operation failed.
 */
declare class KeystoreReadError extends KeystoreError {
    readonly code: "KEYSTORE_READ_ERROR";
    readonly recoverable = true;
    constructor(message: string);
}
/**
 * Keystore capacity limit reached.
 */
declare class KeystoreCapacityError extends KeystoreError {
    readonly network: XRPLNetwork;
    readonly currentCount: number;
    readonly maxCount: number;
    readonly code: "KEYSTORE_CAPACITY_ERROR";
    readonly recoverable = false;
    constructor(network: XRPLNetwork, currentCount: number, maxCount: number);
}
/**
 * Backup format invalid or unsupported.
 */
declare class BackupFormatError extends KeystoreError {
    readonly reason: string;
    readonly expectedVersion?: number | undefined;
    readonly code: "BACKUP_FORMAT_ERROR";
    readonly recoverable = false;
    constructor(reason: string, expectedVersion?: number | undefined);
}
/**
 * Network mismatch between wallet and operation.
 */
declare class NetworkMismatchError extends KeystoreError {
    readonly walletNetwork: XRPLNetwork;
    readonly requestedNetwork: XRPLNetwork;
    readonly code: "NETWORK_MISMATCH";
    readonly recoverable = false;
    constructor(walletNetwork: XRPLNetwork, requestedNetwork: XRPLNetwork);
}
/**
 * Provider service unavailable.
 */
declare class ProviderUnavailableError extends KeystoreError {
    readonly providerType: KeystoreProviderType;
    readonly reason: string;
    readonly code: "PROVIDER_UNAVAILABLE";
    readonly recoverable = true;
    constructor(providerType: KeystoreProviderType, reason: string);
}
/**
 * Type guard to check if an error is a KeystoreError.
 */
declare function isKeystoreError(error: unknown): error is KeystoreError;
/**
 * Type guard to check if error is a specific keystore error code.
 */
declare function isKeystoreErrorCode(error: unknown, code: KeystoreErrorCode): boolean;

/**
 * Local File Keystore Provider
 *
 * Implements secure local file-based storage for XRPL wallet private keys
 * using AES-256-GCM encryption and Argon2id key derivation.
 *
 * Security Features:
 * - AES-256-GCM encryption for all key material
 * - Argon2id key derivation (64MB memory, 3 iterations, 4 parallelism)
 * - Unique salt per wallet, unique IV per encryption
 * - Atomic file writes (temp + rename)
 * - Strict file permissions (0600)
 * - Network isolation (mainnet/testnet/devnet separated)
 * - Rate limiting for authentication attempts
 *
 * @module keystore/local
 * @version 1.0.0
 */

/**
 * Local file-based keystore provider implementing the KeystoreProvider interface.
 *
 * Security features:
 * - AES-256-GCM encryption for all key material
 * - Argon2id key derivation (64MB, 3 iterations, 4 parallelism)
 * - Unique salt and IV per encryption operation
 * - Atomic file writes (temp + rename)
 * - Strict file permissions (0600)
 * - SecureBuffer for memory safety
 */
declare class LocalKeystore implements KeystoreProvider {
    readonly providerType: "local-file";
    readonly providerVersion = "1.0.0";
    private baseDir;
    private passwordPolicy;
    private maxWalletsPerNetwork;
    private initialized;
    private fileLock;
    private authAttempts;
    private lockouts;
    private rateLimitStatePath;
    initialize(config: KeystoreConfig): Promise<void>;
    /**
     * Persist rate limiting state to disk.
     * Called after auth attempts and lockouts change.
     */
    private persistRateLimitState;
    /**
     * Restore rate limiting state from disk.
     * Called during initialization.
     */
    private restoreRateLimitState;
    healthCheck(): Promise<KeystoreHealthResult>;
    close(): Promise<void>;
    createWallet(network: XRPLNetwork, policy: WalletPolicy, options?: WalletCreateOptions): Promise<WalletEntry>;
    loadKey(walletId: string, password: string): Promise<SecureBuffer>;
    storeKey(walletId: string, key: SecureBuffer, password: string, metadata: WalletMetadata): Promise<void>;
    listWallets(network?: XRPLNetwork): Promise<WalletSummary[]>;
    getWallet(walletId: string): Promise<WalletEntry>;
    deleteWallet(walletId: string, password: string): Promise<void>;
    rotateKey(walletId: string, currentPassword: string, newPassword: string): Promise<void>;
    updateMetadata(walletId: string, updates: Partial<WalletMetadata>): Promise<void>;
    /**
     * Store a regular key for a wallet.
     *
     * This allows the wallet to sign transactions with the regular key
     * instead of the master key, providing better security through key rotation.
     *
     * @param walletId - Unique wallet identifier
     * @param regularKeySeed - Regular key seed (base58 encoded)
     * @param regularKeyAddress - Regular key's XRPL address
     * @param password - User password for encryption
     */
    storeRegularKey(walletId: string, regularKeySeed: string, regularKeyAddress: string, password: string): Promise<void>;
    /**
     * Load the regular key for a wallet.
     *
     * @param walletId - Unique wallet identifier
     * @param password - User password for decryption
     * @returns SecureBuffer containing the regular key seed, or null if no regular key
     */
    loadRegularKey(walletId: string, password: string): Promise<SecureBuffer | null>;
    exportBackup(walletId: string, password: string, format: BackupFormat): Promise<EncryptedBackup>;
    importBackup(backup: EncryptedBackup, password: string, options?: ImportOptions): Promise<WalletEntry>;
    private assertInitialized;
    private ensureDirectoryStructure;
    private verifyPermissions;
    private generateWalletId;
    private getWalletPath;
    private findWallet;
    private updateIndex;
    /**
     * Derives a 256-bit key from password using Argon2id.
     */
    private deriveKey;
    /**
     * Encrypts data using AES-256-GCM.
     */
    private encrypt;
    /**
     * Decrypts data using AES-256-GCM.
     */
    private decrypt;
    /**
     * Atomically writes content to a file using temp file + rename pattern.
     */
    private atomicWrite;
    /**
     * Checks if wallet is currently locked out.
     */
    private checkRateLimit;
    /**
     * Records successful authentication.
     */
    private recordAuthSuccess;
    /**
     * Records failed authentication attempt.
     */
    private recordAuthFailure;
}

/**
 * Keystore Module
 *
 * Provides secure key storage functionality for the XRPL Agent Wallet MCP server.
 *
 * Features:
 * - Pluggable provider interface (IKeystore)
 * - Memory-safe key handling (SecureBuffer)
 * - Local file-based storage with AES-256-GCM encryption (LocalKeystore)
 * - Argon2id key derivation for password protection
 * - Network-isolated storage (mainnet/testnet/devnet)
 *
 * @module keystore
 * @version 1.0.0
 */

/**
 * Default password policy for keystore operations.
 *
 * Requirements:
 * - Minimum 12 characters
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one number
 * - Maximum 128 characters
 */
declare const DEFAULT_PASSWORD_POLICY: {
    readonly minLength: 12;
    readonly requireUppercase: true;
    readonly requireLowercase: true;
    readonly requireNumbers: true;
    readonly requireSpecial: false;
    readonly maxLength: 128;
};
/**
 * Argon2id KDF configuration per ADR-002.
 *
 * Parameters:
 * - memoryCost: 64MB
 * - timeCost: 3 iterations
 * - parallelism: 4 threads
 * - hashLength: 32 bytes (256 bits)
 */
declare const ARGON2_CONFIG: {
    readonly memoryCost: 65536;
    readonly timeCost: 3;
    readonly parallelism: 4;
    readonly hashLength: 32;
    readonly saltLength: 32;
};
/**
 * AES-256-GCM encryption configuration per ADR-001.
 *
 * Parameters:
 * - keyLength: 32 bytes (256 bits)
 * - ivLength: 12 bytes (96 bits, NIST recommended)
 * - authTagLength: 16 bytes (128 bits)
 */
declare const AES_CONFIG: {
    readonly algorithm: "aes-256-gcm";
    readonly keyLength: 32;
    readonly ivLength: 12;
    readonly authTagLength: 16;
};

/**
 * XRPL Network Configuration
 *
 * Provides network-specific configuration for XRPL connections including
 * WebSocket endpoints, explorers, and faucets.
 *
 * @module xrpl/config
 * @version 1.0.0
 * @since 2026-01-28
 */

/**
 * Network connection endpoints
 */
interface NetworkEndpoints {
    /** WebSocket endpoints for this network */
    websocket: {
        /** Primary WebSocket URL */
        primary: string;
        /** Backup WebSocket URLs */
        backup: string[];
    };
    /** JSON-RPC endpoints (optional) */
    jsonRpc?: {
        /** Primary JSON-RPC URL */
        primary: string;
        /** Backup JSON-RPC URLs */
        backup: string[];
    };
}
/**
 * Explorer URL functions
 */
interface ExplorerUrls {
    /** Main explorer URL */
    home: string;
    /** Account/wallet lookup */
    account: (address: string) => string;
    /** Transaction lookup */
    transaction: (hash: string) => string;
    /** Ledger lookup */
    ledger: (index: number) => string;
}
/**
 * Faucet configuration
 */
interface FaucetConfig {
    /** Whether faucet is available for this network */
    available: boolean;
    /** Faucet API endpoint */
    url?: string;
    /** Amount dispensed per request (XRP) */
    amountXrp?: number;
    /** Rate limit window in seconds */
    rateLimitSeconds?: number;
    /** Rate limit requests per window */
    rateLimitRequests?: number;
}
/**
 * Connection configuration
 */
interface ConnectionConfig {
    /** Connection timeout in milliseconds */
    connectionTimeout: number;
    /** Request timeout in milliseconds */
    requestTimeout: number;
    /** Maximum reconnection attempts */
    maxReconnectAttempts: number;
    /** Initial reconnection delay in milliseconds */
    reconnectDelay: number;
    /** Reconnection backoff multiplier */
    reconnectBackoff: number;
}
/**
 * Default network endpoints
 *
 * IMPORTANT: These are the official public endpoints. For production,
 * consider using a private node via environment variable override.
 */
declare const NETWORK_ENDPOINTS: Record<Network, NetworkEndpoints>;
/**
 * Block explorer URLs
 */
declare const EXPLORER_URLS: Record<Network, ExplorerUrls>;
/**
 * Faucet configuration by network
 *
 * NOTE: As of 2026, testnet faucet provides ~100 XRP (previously 1000 XRP).
 * Do not hardcode faucet amounts in tests - use initial_balance_drops from wallet_fund response.
 */
declare const FAUCET_CONFIG: Record<Network, FaucetConfig>;
/**
 * Default connection configuration
 */
declare const DEFAULT_CONNECTION_CONFIG: ConnectionConfig;
/**
 * Get WebSocket URL for a network
 *
 * Checks for environment variable override first, then uses default.
 *
 * @param network - Target network
 * @returns WebSocket URL
 * @throws {Error} If custom URL doesn't use WSS protocol
 */
declare function getWebSocketUrl(network: Network): string;
/**
 * Get backup WebSocket URLs for a network
 *
 * @param network - Target network
 * @returns Array of backup WebSocket URLs
 */
declare function getBackupWebSocketUrls(network: Network): string[];
/**
 * Get explorer URL for a transaction
 *
 * @param hash - Transaction hash
 * @param network - Network the transaction is on
 * @returns Explorer URL
 */
declare function getTransactionExplorerUrl(hash: string, network: Network): string;
/**
 * Get explorer URL for an account
 *
 * @param address - Account address
 * @param network - Network the account is on
 * @returns Explorer URL
 */
declare function getAccountExplorerUrl(address: string, network: Network): string;
/**
 * Get explorer URL for a ledger
 *
 * @param index - Ledger index
 * @param network - Network the ledger is on
 * @returns Explorer URL
 */
declare function getLedgerExplorerUrl(index: number, network: Network): string;
/**
 * Check if faucet is available for a network
 *
 * @param network - Network to check
 * @returns True if faucet is available
 */
declare function isFaucetAvailable(network: Network): boolean;
/**
 * Get faucet URL for a network
 *
 * @param network - Network to get faucet for
 * @returns Faucet URL or null if not available
 */
declare function getFaucetUrl(network: Network): string | null;
/**
 * Get connection configuration with environment overrides
 *
 * @returns Connection configuration
 */
declare function getConnectionConfig(): ConnectionConfig;

/**
 * XRPL Client Wrapper
 *
 * Provides a robust wrapper around xrpl.js with connection management,
 * automatic retries, and transaction helpers.
 *
 * @module xrpl/client
 * @version 1.0.0
 * @since 2026-01-28
 */

/**
 * XRPL Client configuration
 */
interface XRPLClientConfig {
    /** Target network */
    network: Network;
    /** Custom WebSocket URL (overrides network default) */
    nodeUrl?: string;
    /** Connection configuration */
    connectionConfig?: Partial<ConnectionConfig>;
}
/**
 * Account information from XRPL
 */
interface AccountInfo {
    /** Account address */
    account: string;
    /** Balance in drops */
    balance: string;
    /** Account sequence number */
    sequence: number;
    /** Number of objects owned (affects reserve) */
    ownerCount: number;
    /** Account flags */
    flags: number;
    /** Previous transaction ID */
    previousTxnID: string;
    /** Previous transaction ledger sequence */
    previousTxnLgrSeq: number;
}
/**
 * XRPL transaction submission result
 */
interface XRPLTransactionResult {
    /** Transaction hash */
    hash: string;
    /** Result code (e.g., "tesSUCCESS") */
    resultCode: string;
    /** Ledger index where validated */
    ledgerIndex: number | undefined;
    /** Whether transaction was validated */
    validated: boolean;
    /** Transaction metadata */
    meta: unknown | undefined;
}
/**
 * Transaction history options
 */
interface TxHistoryOptions {
    /** Maximum number of transactions to return */
    limit?: number;
    /** Oldest ledger index */
    ledgerIndexMin?: number;
    /** Newest ledger index */
    ledgerIndexMax?: number;
    /** Return transactions in chronological order */
    forward?: boolean;
}
/**
 * Submit options for transactions
 */
interface SubmitOptions {
    /** Wait for validation (default: true) */
    waitForValidation?: boolean;
    /** Timeout for validation wait in ms (default: 20000) */
    timeout?: number;
    /** Fail if transaction not in validated ledger */
    failHard?: boolean;
}
/**
 * Wait options for transaction validation
 */
interface WaitOptions {
    /** Timeout in milliseconds */
    timeout?: number;
    /** Poll interval in milliseconds */
    pollInterval?: number;
}
/**
 * Server information
 */
interface ServerInfo {
    /** Server state (e.g., "full", "syncing") */
    server_state: string;
    /** Validated ledger information */
    validated_ledger: {
        /** Ledger index */
        seq: number;
        /** Ledger hash */
        hash: string;
        /** Base reserve in XRP */
        reserve_base_xrp: number;
        /** Incremental reserve in XRP */
        reserve_inc_xrp: number;
        /** Base fee in XRP */
        base_fee_xrp: number;
    } | undefined;
    /** Complete ledgers range */
    complete_ledgers: string;
    /** Number of peers */
    peers: number | undefined;
    /** Validation quorum */
    validation_quorum: number | undefined;
}
/**
 * Custom error for XRPL client operations
 */
declare class XRPLClientError extends Error {
    code: string;
    details?: unknown | undefined;
    constructor(message: string, code: string, details?: unknown | undefined);
}
/**
 * Connection failed error
 */
declare class ConnectionError extends XRPLClientError {
    constructor(message: string, details?: unknown);
}
/**
 * Account not found error
 */
declare class AccountNotFoundError extends XRPLClientError {
    constructor(address: string);
}
/**
 * Transaction timeout error
 */
declare class TransactionTimeoutError extends XRPLClientError {
    constructor(hash: string);
}
/**
 * Max reconnect attempts error
 */
declare class MaxReconnectAttemptsError extends XRPLClientError {
    constructor(attempts: number);
}
/**
 * XRPL Client Wrapper
 *
 * Provides connection management, auto-reconnection, and transaction helpers
 * for interacting with the XRPL.
 */
declare class XRPLClientWrapper {
    private client;
    private readonly network;
    private readonly nodeUrl;
    private readonly backupUrls;
    private readonly connectionConfig;
    private currentUrlIndex;
    private reconnectAttempts;
    private isConnected;
    /**
     * Create a new XRPL client wrapper
     *
     * @param config - Client configuration
     */
    constructor(config: XRPLClientConfig);
    /**
     * Get the current network
     */
    getNetwork(): Network;
    /**
     * Check if client is connected
     */
    isClientConnected(): boolean;
    /**
     * Connect to XRPL network
     *
     * @throws {ConnectionError} If connection fails after all retries
     */
    connect(): Promise<void>;
    /**
     * Disconnect from XRPL network
     */
    disconnect(): Promise<void>;
    /**
     * Reconnect with exponential backoff (iterative, not recursive)
     *
     * @throws {MaxReconnectAttemptsError} If max attempts exceeded
     */
    private reconnect;
    /**
     * Check server health
     *
     * @returns True if server is healthy (state is "full")
     */
    isHealthy(): Promise<boolean>;
    /**
     * Get server information
     *
     * @returns Server information
     * @throws {XRPLClientError} If request times out
     */
    getServerInfo(): Promise<ServerInfo>;
    /**
     * Get account information
     *
     * @param address - Account address
     * @returns Account information
     * @throws {AccountNotFoundError} If account doesn't exist
     * @throws {XRPLClientError} If request times out
     */
    getAccountInfo(address: XRPLAddress): Promise<AccountInfo>;
    /**
     * Get account balance in drops
     *
     * @param address - Account address
     * @returns Balance in drops
     */
    getBalance(address: XRPLAddress): Promise<string>;
    /**
     * Get transaction information
     *
     * @param hash - Transaction hash
     * @returns Transaction response
     */
    getTransaction(hash: TransactionHash): Promise<TxResponse>;
    /**
     * Wait for transaction validation
     *
     * @param hash - Transaction hash
     * @param options - Wait options
     * @returns Transaction result
     * @throws {TransactionTimeoutError} If transaction not validated within timeout
     */
    waitForTransaction(hash: TransactionHash, options?: WaitOptions): Promise<XRPLTransactionResult>;
    /**
     * Get current ledger index
     *
     * @returns Current validated ledger index
     */
    getCurrentLedgerIndex(): Promise<number>;
    /**
     * Get fee estimate for a transaction
     *
     * @returns Estimated fee in drops
     */
    getFee(): Promise<string>;
    /**
     * Get account transaction history
     *
     * @param address - Account address
     * @param options - History options
     * @returns Array of transactions
     */
    getAccountTransactions(address: XRPLAddress, options?: TxHistoryOptions): Promise<unknown[]>;
    /**
     * Submit a signed transaction
     *
     * @param signedTx - Signed transaction blob (hex string)
     * @param options - Submit options
     * @returns Transaction result
     */
    submitSignedTransaction(signedTx: string, options?: SubmitOptions): Promise<XRPLTransactionResult>;
}

/**
 * Sequence Tracker for XRPL Transactions
 *
 * Tracks locally-signed sequences to prevent tefPAST_SEQ errors in
 * multi-transaction workflows where ledger queries may return stale data.
 *
 * The problem: After signing TX with sequence N, the ledger's account_info
 * may still return sequence N until the TX is validated. If we sign TX B
 * immediately after, it would also get sequence N and fail.
 *
 * The solution: Track sequences we've signed locally and use
 * MAX(ledger_sequence, last_signed_sequence + 1) for the next TX.
 *
 * @module xrpl/sequence-tracker
 * @version 1.0.0
 * @since 2026-01-29 - ADR-013 race condition fix
 */
/**
 * Tracks signed transaction sequences per address to prevent race conditions.
 *
 * When multiple transactions are signed in quick succession, the XRPL
 * ledger query may return stale sequence numbers. This tracker ensures
 * we always use the correct next sequence by remembering what we've signed.
 *
 * Entries expire after a configurable TTL (default: 60 seconds) to handle
 * cases where transactions fail or are never submitted.
 */
declare class SequenceTracker {
    /** Map of address -> last signed sequence entry */
    private sequences;
    /** TTL for sequence entries in milliseconds (default: 60 seconds) */
    private readonly ttlMs;
    /**
     * Create a new SequenceTracker.
     *
     * @param ttlMs - Time-to-live for entries in milliseconds (default: 60000)
     */
    constructor(ttlMs?: number);
    /**
     * Get the next sequence number to use for an address.
     *
     * Returns MAX(ledgerSequence, lastSignedSequence + 1) to handle
     * the race condition where ledger hasn't caught up yet.
     *
     * @param address - The XRPL account address
     * @param ledgerSequence - Current sequence from ledger query
     * @returns The sequence number to use for signing
     */
    getNextSequence(address: string, ledgerSequence: number): number;
    /**
     * Record that a transaction was signed with a specific sequence.
     *
     * Call this AFTER successful signing to track the sequence used.
     * Only updates if the new sequence is greater than the current tracked value.
     *
     * @param address - The XRPL account address
     * @param sequence - The sequence number that was signed
     */
    recordSignedSequence(address: string, sequence: number): void;
    /**
     * Clear the tracked sequence for an address.
     *
     * Useful when a transaction is known to have failed or been rejected,
     * allowing the sequence to be reused.
     *
     * @param address - The XRPL account address
     */
    clearSequence(address: string): void;
    /**
     * Clear all expired entries from the tracker.
     *
     * Called periodically to prevent memory growth. Entries older than
     * TTL are removed.
     */
    cleanup(): void;
    /**
     * Get debug info about tracked sequences.
     *
     * @returns Map of address to sequence info (for debugging/testing)
     */
    getDebugInfo(): Map<string, {
        sequence: number;
        ageMs: number;
    }>;
}
/**
 * Get or create the global sequence tracker instance.
 *
 * @param ttlMs - TTL for entries (only used on first call)
 * @returns The global SequenceTracker instance
 */
declare function getSequenceTracker(ttlMs?: number): SequenceTracker;
/**
 * Reset the global sequence tracker (for testing).
 */
declare function resetSequenceTracker(): void;

/**
 * Multi-Signature Orchestration
 *
 * Implements XRPL native multi-signature workflows for Tier 3 transactions.
 * Coordinates signature collection, quorum tracking, and transaction assembly.
 *
 * @module signing/multisig
 * @version 1.0.0
 */

/**
 * Signer configuration entry.
 */
interface SignerConfig {
    /**
     * XRPL address of the signer.
     */
    address: string;
    /**
     * Weight assigned to this signer.
     */
    weight: number;
    /**
     * Role designation for UI/audit.
     */
    role: 'agent' | 'human_approver' | 'emergency';
    /**
     * Display name for notifications.
     */
    name?: string;
    /**
     * Contact info for notifications.
     */
    email?: string;
    /**
     * Optional: Hardware wallet locator.
     */
    walletLocator?: string;
}
/**
 * SignerList configuration for a wallet.
 */
interface SignerListConfig {
    /**
     * Array of authorized signers.
     */
    signers: SignerConfig[];
    /**
     * Total weight required for valid signature.
     */
    quorum: number;
    /**
     * Timeout in seconds for pending requests.
     * Default: 86400 (24 hours)
     */
    timeout_seconds?: number;
}
/**
 * Multi-signature request status.
 */
type MultiSignStatus = 'pending' | 'approved' | 'rejected' | 'expired' | 'completed';
/**
 * Signer state tracking.
 */
interface SignerState {
    /**
     * Signer's XRPL address.
     */
    address: string;
    /**
     * Role designation.
     */
    role: 'agent' | 'human_approver' | 'emergency';
    /**
     * Assigned weight.
     */
    weight: number;
    /**
     * Whether this signer has signed.
     */
    signed: boolean;
    /**
     * Signature blob (if signed).
     */
    signature?: string;
    /**
     * When signature was received.
     */
    signed_at?: string;
}
/**
 * Multi-signature request state.
 */
interface MultiSignRequest {
    /**
     * Unique identifier (UUID v4).
     */
    id: string;
    /**
     * Internal wallet identifier.
     */
    wallet_id: string;
    /**
     * XRPL address of the account.
     */
    wallet_address: string;
    /**
     * Transaction details.
     */
    transaction: {
        /**
         * Transaction type (e.g., 'Payment', 'AccountSet').
         */
        type: string;
        /**
         * Amount in drops (if applicable).
         */
        amount_drops?: string;
        /**
         * Destination address (if applicable).
         */
        destination?: string;
        /**
         * Unsigned transaction blob (hex).
         */
        unsigned_blob: string;
        /**
         * Decoded transaction JSON (for display).
         */
        decoded: Transaction;
    };
    /**
     * Signer tracking.
     */
    signers: SignerState[];
    /**
     * Quorum tracking.
     */
    quorum: {
        /**
         * Total weight required.
         */
        required: number;
        /**
         * Current collected weight.
         */
        collected: number;
        /**
         * Whether quorum is met.
         */
        met: boolean;
    };
    /**
     * Request lifecycle status.
     */
    status: MultiSignStatus;
    /**
     * Timestamps.
     */
    created_at: string;
    expires_at: string;
    completed_at?: string;
    /**
     * Result (if completed).
     */
    tx_hash?: string;
    /**
     * Rejection details (if rejected).
     */
    rejection?: {
        rejecting_address: string;
        reason: string;
        rejected_at: string;
    };
    /**
     * Audit context.
     */
    context?: string;
    /**
     * Notification tracking.
     */
    notifications_sent: Array<{
        recipient: string;
        sent_at: string;
        type: 'created' | 'signature_added' | 'completed' | 'rejected' | 'expired';
    }>;
}
/**
 * Result of completing a multi-sign request.
 */
interface MultiSignCompleteResult {
    /**
     * Request ID.
     */
    request_id: string;
    /**
     * Fully assembled multi-signed transaction blob (hex).
     */
    signed_tx: string;
    /**
     * Transaction hash from XRPL.
     */
    tx_hash: string;
    /**
     * Final quorum weight collected.
     */
    final_quorum: number;
    /**
     * Addresses that signed.
     */
    signers: string[];
    /**
     * Timestamp when submitted to XRPL.
     */
    submitted_at: string;
}
/**
 * Multi-signature storage interface.
 */
interface MultiSignStore {
    /**
     * Create a new multi-sign request.
     */
    create(request: MultiSignRequest): Promise<void>;
    /**
     * Get request by ID.
     */
    get(requestId: string): Promise<MultiSignRequest | null>;
    /**
     * Update existing request.
     */
    update(request: MultiSignRequest): Promise<void>;
    /**
     * List requests by wallet ID.
     */
    listByWallet(walletId: string, includeCompleted?: boolean): Promise<MultiSignRequest[]>;
    /**
     * List requests by status.
     */
    listByStatus(status: MultiSignStatus): Promise<MultiSignRequest[]>;
    /**
     * Find pending requests older than timestamp.
     */
    findPendingOlderThan(timestamp: Date): Promise<MultiSignRequest[]>;
    /**
     * Delete completed/expired requests older than retention period.
     */
    cleanup(retentionDays: number): Promise<number>;
}
/**
 * Notification service interface.
 */
interface NotificationService {
    /**
     * Send notification about multi-sign event.
     *
     * @param notification - Notification details
     * @returns Array of successful deliveries
     */
    notify(notification: unknown): Promise<unknown[]>;
    /**
     * Send reminder for pending signature.
     *
     * @param requestId - Multi-sign request ID
     * @param recipientAddress - Signer's XRPL address
     */
    sendReminder(requestId: string, recipientAddress: string): Promise<void>;
}
/**
 * Multi-signature error class.
 */
declare class MultiSignError extends Error {
    code: string;
    details?: unknown | undefined;
    constructor(code: string, message: string, details?: unknown | undefined);
}
/**
 * MultiSignOrchestrator - Coordinates multi-signature workflows.
 *
 * Responsibilities:
 * - Create pending multi-sign requests
 * - Collect signatures from multiple signers
 * - Track quorum progress
 * - Assemble final multi-signed transaction
 * - Handle timeouts and errors
 * - Notify approvers
 *
 * Security Features:
 * - Validates all signatures cryptographically
 * - Enforces quorum requirements
 * - Prevents duplicate signatures
 * - Handles request expiration
 * - Audits all operations
 *
 * @example
 * ```typescript
 * const orchestrator = new MultiSignOrchestrator(
 *   xrplClient,
 *   store,
 *   notifier,
 *   auditLogger
 * );
 *
 * // Initiate multi-sign request
 * const request = await orchestrator.initiate(
 *   'wallet_123',
 *   'rWallet...',
 *   unsignedTxBlob,
 *   signerConfig,
 *   'High-value payment'
 * );
 *
 * // Human approver adds signature
 * await orchestrator.addSignature(
 *   request.id,
 *   humanSignatureBlob,
 *   'rHuman...'
 * );
 *
 * // Complete and submit
 * const result = await orchestrator.complete(request.id, agentWallet);
 * ```
 */
declare class MultiSignOrchestrator {
    private readonly xrplClient;
    private readonly store;
    private readonly notificationService;
    private readonly auditLogger;
    constructor(xrplClient: Client, store: MultiSignStore, notificationService: NotificationService, auditLogger: AuditLogger);
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
    initiate(walletId: string, walletAddress: string, unsignedTx: string, signerConfig: SignerListConfig, context?: string): Promise<MultiSignRequest>;
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
    addSignature(requestId: string, signature: string, signerAddress: string): Promise<MultiSignRequest>;
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
    complete(requestId: string, agentWallet?: Wallet): Promise<MultiSignCompleteResult>;
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
    reject(requestId: string, rejectingAddress: string, reason: string): Promise<MultiSignRequest>;
    /**
     * Get current status of a multi-sign request.
     *
     * @param requestId - Multi-sign request UUID
     * @returns Current request state with signatures and quorum
     *
     * @throws MultiSignError REQUEST_NOT_FOUND - Request doesn't exist
     */
    getStatus(requestId: string): Promise<MultiSignRequest>;
    /**
     * List all pending multi-sign requests for a wallet.
     *
     * @param walletId - Internal wallet identifier
     * @param includeExpired - Include expired requests (default: false)
     * @returns Array of pending requests sorted by creation time
     */
    listPending(walletId: string, includeExpired?: boolean): Promise<MultiSignRequest[]>;
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
    expire(requestId: string): Promise<MultiSignRequest>;
    /**
     * Validate a multi-signature cryptographically.
     *
     * Verifies that:
     * 1. The signature blob is a valid signed transaction
     * 2. The signer in the blob matches the claimed signer address
     * 3. The signature covers the expected unsigned transaction
     *
     * @param signatureBlob - Signed transaction blob from the signer
     * @param expectedSigner - Expected signer's XRPL address
     * @param unsignedBlob - Original unsigned transaction blob
     * @returns Validation result with reason if invalid
     */
    private validateSignature;
    private extractAmount;
    private extractDestination;
    private notifySigners;
}

/**
 * Signing Service Implementation
 *
 * Orchestrates transaction signing with secure key material handling.
 * Coordinates with keystore, policy engine, and multi-sign orchestrator.
 *
 * @module signing/service
 * @version 1.0.0
 */

/**
 * Result of a single-sign operation.
 */
interface SignedTransaction {
    /**
     * Signed transaction blob (hex encoded).
     */
    tx_blob: string;
    /**
     * Transaction hash.
     */
    hash: string;
    /**
     * Wallet address that signed.
     */
    signer_address: string;
}
/**
 * Error class for signing operations.
 */
declare class SigningError extends Error {
    code: string;
    details?: unknown | undefined;
    constructor(code: string, message: string, details?: unknown | undefined);
}
/**
 * Configuration options for SigningService.
 */
interface SigningServiceOptions {
    /**
     * If true, reject unknown transaction types instead of warning.
     * Recommended for production to avoid signing experimental/unknown transactions.
     * Default: false (warn only)
     */
    strictTransactionTypes?: boolean;
}
/**
 * SigningService - Orchestrates secure transaction signing.
 *
 * Responsibilities:
 * - Load wallet keys from keystore securely
 * - Sign transactions with proper XRPL formatting
 * - Zero key material immediately after use
 * - Audit all signing operations
 * - Coordinate multi-signature workflows
 *
 * Security Features:
 * - Uses SecureBuffer for key material
 * - Never exposes private keys to calling code
 * - Validates transaction format before signing
 * - Logs all signing attempts (success and failure)
 *
 * @example
 * ```typescript
 * const signer = new SigningService(keystore, auditLogger);
 *
 * // Single-sign transaction
 * const result = await signer.sign(
 *   'wallet_123',
 *   unsignedTxBlob,
 *   password
 * );
 *
 * console.log('Signed:', result.tx_blob);
 * console.log('Hash:', result.hash);
 * ```
 */
declare class SigningService {
    private readonly keystore;
    private readonly auditLogger;
    private readonly multiSignOrchestrator?;
    private readonly options;
    constructor(keystore: KeystoreProvider, auditLogger: AuditLogger, multiSignOrchestrator?: MultiSignOrchestrator | undefined, options?: SigningServiceOptions);
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
    sign(walletId: string, unsignedTx: string | Transaction, password: string, multiSign?: boolean): Promise<SignedTransaction>;
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
    signForMultiSig(walletId: string, unsignedTx: string | Transaction, password: string): Promise<SignedTransaction>;
    /**
     * Decode and validate a transaction blob without signing.
     *
     * Useful for displaying transaction details before signing.
     *
     * @param txBlob - Transaction blob (hex encoded)
     * @returns Decoded transaction object
     * @throws SigningError TRANSACTION_DECODE_ERROR
     */
    decodeTransaction(txBlob: string): Transaction;
    /**
     * Encode a transaction object to blob format.
     *
     * @param transaction - Transaction object
     * @returns Hex-encoded transaction blob
     * @throws SigningError TRANSACTION_ENCODE_ERROR
     */
    encodeTransaction(transaction: Transaction): string;
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
    private validateTransaction;
}

/**
 * MCP Server Implementation
 *
 * Main MCP server setup using @modelcontextprotocol/sdk.
 * Registers all wallet operation tools and wires up service dependencies.
 *
 * @module server
 * @version 1.0.0
 */

/**
 * Server context holding all service instances.
 */
interface ServerContext {
    keystore: KeystoreProvider;
    policyEngine: PolicyEngine;
    signingService: SigningService;
    auditLogger: AuditLogger;
    xrplClient: XRPLClientWrapper;
}
/**
 * Server configuration options.
 */
interface ServerConfig {
    /** Server name (for MCP identification) */
    name?: string;
    /** Server version */
    version?: string;
}
/**
 * Create and initialize the MCP server.
 *
 * @param context - Service instances (keystore, policy, signing, audit, xrpl)
 * @param config - Server configuration options
 * @returns Configured MCP server instance
 */
declare function createServer(context: ServerContext, config?: ServerConfig): Server;
/**
 * Run the MCP server with stdio transport.
 *
 * @param context - Service instances
 * @param config - Server configuration
 */
declare function runServer(context: ServerContext, config?: ServerConfig): Promise<void>;

export { AES_CONFIG, ARGON2_CONFIG, type AccountInfo, AccountNotFoundError, type ActorType, AgentWalletPolicy, type AlwaysCondition, type AndCondition, ApprovalTier, type AuditConfig, AuditEventType, AuditLogEntry, type AuditLogInput, AuditLogInputSchema, type AuditLogQuery, AuditLogger, type AuditLoggerConfig, type AuditLoggerOptions, type AuditSeverity, type AuditStorageStats, AuthenticationError, type BackupFormat, BackupFormatError, type BlocklistCheckResult, type ChainError, type ChainErrorType, type ChainState, ChainStateSchema, type ChainVerificationResult, type CompiledRule, type Condition, type ConditionEvaluator, type ConnectionConfig, ConnectionError, DEFAULT_AUDIT_LOGGER_CONFIG, DEFAULT_CONNECTION_CONFIG, DEFAULT_PASSWORD_POLICY, EXPLORER_URLS, type EncryptedBackup, type EncryptionMetadata, type EntropySource, type EventCategory, type ExplorerUrls, FAUCET_CONFIG, type FaucetConfig, type FieldCondition, GENESIS_CONSTANT, HMAC_ALGORITHM, HMAC_KEY_LENGTH, type HSMConfig, HashChain, type HashableEntry, HmacKeySchema, type IHmacKeyProvider, type IPolicyEngine, type ImportOptions, type InternalPolicy, InvalidKeyError, type KdfParams, type KeyAlgorithm, KeyDecryptionError, KeyEncryptionError, KeystoreCapacityError, type KeystoreConfig, KeystoreError, type KeystoreErrorCode, type KeystoreHealthResult, KeystoreInitializationError, type KeystoreProvider, type KeystoreProviderType, KeystoreReadError, KeystoreWriteError, type LimitCheckResult, type LimitConfig, LimitExceededError, type LimitState, LimitTracker, type LimitTrackerOptions, LocalKeystore, MaxReconnectAttemptsError, type MultiSignCompleteResult, MultiSignError, MultiSignOrchestrator, type MultiSignRequest, type MultiSignStatus, type MultiSignStore, NETWORK_ENDPOINTS, Network, type NetworkEndpoints, NetworkMismatchError, type NotCondition, type NotificationService, type OperationResult, type Operator, type OrCondition, type PasswordPolicy, type PolicyContext, PolicyEngine, type PolicyEngineOptions, PolicyError, PolicyEvaluationError, type PolicyInfo, PolicyIntegrityError, PolicyLoadError, type PolicyResult, type PolicyRule, PolicyValidationError, ProviderUnavailableError, type RuleAction, RuleEvaluator, type RuleEvaluatorOptions, type RuleResult, SecureBuffer, SequenceTracker, type ServerConfig, type ServerContext, type ServerInfo, type SignedTransaction, type SignerConfig, type SignerListConfig, type SignerState, SigningError, SigningService, type SimpleEvaluationResult, type SimpleTransactionContext, type SubmitOptions, type Tier, type TierFactor, type TransactionContext, TransactionHash, TransactionTimeoutError, TransactionType, type TxHistoryOptions, type ValueReference, type VerificationOptions, VerificationOptionsSchema, type WaitOptions, type WalletContext, type WalletCreateOptions, type WalletEntry, WalletExistsError, type WalletMetadata, WalletNotFoundError, type WalletPolicy, type WalletStatus, type WalletSummary, WeakPasswordError, XRPLAddress, type XRPLClientConfig, XRPLClientError, XRPLClientWrapper, type XRPLNetwork, type XRPLTransactionResult, checkBlocklist, computeStandaloneHash, createLimitTracker, createMemoryKeyProvider, createPolicyEngine, createServer, createTestPolicy, generateHmacKey, getAccountExplorerUrl, getBackupWebSocketUrls, getConnectionConfig, getDefaultAuditDir, getFaucetUrl, getLedgerExplorerUrl, getSequenceTracker, getTransactionCategory, getTransactionExplorerUrl, getWebSocketUrl, isFaucetAvailable, isInAllowlist, isKeystoreError, isKeystoreErrorCode, isValidHmacKey, numericToTier, resetSequenceTracker, runServer, sanitizeForLogging, tierToNumeric };
