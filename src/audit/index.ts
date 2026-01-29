/**
 * Audit Module Exports
 *
 * Provides tamper-evident audit logging with HMAC-SHA256 hash chains
 * for the XRPL Agent Wallet MCP server.
 *
 * @module audit
 * @version 1.0.0
 * @since 2026-01-28
 *
 * @example
 * ```typescript
 * import {
 *   AuditLogger,
 *   HashChain,
 *   generateHmacKey,
 *   createMemoryKeyProvider
 * } from './audit/index.js';
 *
 * // Create logger with HMAC key
 * const hmacKey = generateHmacKey();
 * const logger = await AuditLogger.create({
 *   hmacKeyProvider: createMemoryKeyProvider(hmacKey),
 *   config: { network: 'testnet' }
 * });
 *
 * // Log events
 * await logger.log({
 *   event: 'wallet_created',
 *   wallet_id: 'my-wallet'
 * });
 *
 * // Verify chain integrity
 * const result = await logger.verifyChain();
 * console.log('Chain valid:', result.valid);
 *
 * // Cleanup
 * await logger.shutdown();
 * ```
 */

// ============================================================================
// HASH CHAIN EXPORTS
// ============================================================================

export {
  // Class
  HashChain,

  // Types
  type ChainState,
  type ChainError,
  type ChainErrorType,
  type ChainVerificationResult,
  type VerificationOptions,
  type HashableEntry,

  // Schemas
  HmacKeySchema,
  ChainStateSchema,
  VerificationOptionsSchema,

  // Functions
  isValidHmacKey,
  generateHmacKey,
  computeStandaloneHash,

  // Constants
  GENESIS_CONSTANT,
  HMAC_ALGORITHM,
  HMAC_KEY_LENGTH,
} from './chain.js';

// ============================================================================
// AUDIT LOGGER EXPORTS
// ============================================================================

export {
  // Class
  AuditLogger,

  // Types
  type AuditSeverity,
  type EventCategory,
  type ActorType,
  type OperationResult,
  type AuditLogInput,
  type AuditLoggerConfig,
  type AuditLoggerOptions,
  type AuditLogQuery,
  type AuditStorageStats,
  type IHmacKeyProvider,

  // Schemas
  AuditLogInputSchema,

  // Constants
  DEFAULT_AUDIT_LOGGER_CONFIG,

  // Functions
  sanitizeForLogging,
  createMemoryKeyProvider,
  getDefaultAuditDir,
} from './logger.js';
