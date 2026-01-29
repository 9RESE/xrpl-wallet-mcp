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

// Interface and types
export type {
  KeystoreProvider,
  KeystoreConfig,
  KeystoreHealthResult,
  XRPLNetwork,
  KeystoreProviderType,
  KeyAlgorithm,
  WalletStatus,
  BackupFormat,
  PasswordPolicy,
  AuditConfig,
  HSMConfig,
  KdfParams,
  EncryptionMetadata,
  WalletMetadata,
  WalletEntry,
  WalletSummary,
  WalletPolicy,
  WalletCreateOptions,
  EntropySource,
  EncryptedBackup,
  ImportOptions,
} from './interface.js';

// SecureBuffer for memory-safe key handling
export { SecureBuffer } from './secure-buffer.js';

// Error types
export {
  KeystoreError,
  KeystoreInitializationError,
  WalletNotFoundError,
  WalletExistsError,
  AuthenticationError,
  WeakPasswordError,
  KeyDecryptionError,
  KeyEncryptionError,
  InvalidKeyError,
  KeystoreWriteError,
  KeystoreReadError,
  KeystoreCapacityError,
  BackupFormatError,
  NetworkMismatchError,
  ProviderUnavailableError,
  isKeystoreError,
  isKeystoreErrorCode,
  type KeystoreErrorCode,
} from './errors.js';

// LocalKeystore implementation
export { LocalKeystore } from './local.js';

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
export const DEFAULT_PASSWORD_POLICY = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecial: false,
  maxLength: 128,
} as const;

/**
 * Argon2id KDF configuration per ADR-002.
 *
 * Parameters:
 * - memoryCost: 64MB
 * - timeCost: 3 iterations
 * - parallelism: 4 threads
 * - hashLength: 32 bytes (256 bits)
 */
export const ARGON2_CONFIG = {
  memoryCost: 65536, // 64 MB
  timeCost: 3, // 3 iterations
  parallelism: 4, // 4 threads
  hashLength: 32, // 256-bit output
  saltLength: 32, // 256-bit salt
} as const;

/**
 * AES-256-GCM encryption configuration per ADR-001.
 *
 * Parameters:
 * - keyLength: 32 bytes (256 bits)
 * - ivLength: 12 bytes (96 bits, NIST recommended)
 * - authTagLength: 16 bytes (128 bits)
 */
export const AES_CONFIG = {
  algorithm: 'aes-256-gcm',
  keyLength: 32, // 256 bits
  ivLength: 12, // 96 bits
  authTagLength: 16, // 128 bits
} as const;
