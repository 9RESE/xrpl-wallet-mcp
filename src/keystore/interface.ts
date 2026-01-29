/**
 * Keystore Interface Definitions
 *
 * Defines the pluggable abstraction layer for secure key storage
 * in the XRPL Agent Wallet MCP server.
 *
 * @module keystore/interface
 * @version 1.0.0
 */

import type { SecureBuffer } from './secure-buffer.js';

// ============================================================================
// Core Types
// ============================================================================

/**
 * XRPL Network identifiers.
 */
export type XRPLNetwork = 'mainnet' | 'testnet' | 'devnet';

/**
 * Keystore provider types.
 */
export type KeystoreProviderType =
  | 'local-file' // Phase 1: Local encrypted files
  | 'cloud-kms' // Phase 2: AWS/GCP/Azure KMS
  | 'hsm' // Phase 3: Hardware Security Module
  | 'mock'; // Testing only

/**
 * Key algorithm types supported by XRPL.
 */
export type KeyAlgorithm = 'ed25519' | 'secp256k1';

/**
 * Wallet status states.
 */
export type WalletStatus =
  | 'active' // Normal operation
  | 'locked' // Temporarily locked (failed auth attempts)
  | 'archived' // Soft-deleted, can be restored
  | 'pending'; // Creation in progress

/**
 * Backup format types.
 */
export type BackupFormat =
  | 'encrypted-json' // Standard JSON with AES-256-GCM
  | 'kms-wrapped'; // KEK wrapped by Cloud KMS

// ============================================================================
// Configuration Types
// ============================================================================

/**
 * Password complexity requirements.
 */
export interface PasswordPolicy {
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
export interface AuditConfig {
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
export interface HSMConfig {
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
export interface KeystoreConfig {
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

// ============================================================================
// Key Derivation Types
// ============================================================================

/**
 * Key derivation function parameters.
 */
export interface KdfParams {
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
export interface EncryptionMetadata {
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

// ============================================================================
// Wallet Types
// ============================================================================

/**
 * Wallet metadata (non-sensitive).
 */
export interface WalletMetadata {
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
export interface WalletEntry {
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
export interface WalletSummary {
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
export interface WalletPolicy {
  /** Policy identifier */
  policyId: string;
  /** Policy version */
  policyVersion: string;
}

/**
 * Entropy source for key generation (testing only).
 */
export interface EntropySource {
  /** Generate random bytes (must be cryptographically secure) */
  randomBytes(length: number): Buffer;
}

/**
 * Options for wallet creation.
 */
export interface WalletCreateOptions {
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

// ============================================================================
// Backup Types
// ============================================================================

/**
 * Encrypted backup file format.
 */
export interface EncryptedBackup {
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
export interface ImportOptions {
  /** Override wallet name */
  newName?: string;
  /** Override network (use with caution) */
  targetNetwork?: XRPLNetwork;
  /** Force import even if wallet exists */
  force?: boolean;
  /** New password (re-encrypts with different key) */
  newPassword?: string;
}

// ============================================================================
// Health Check Types
// ============================================================================

/**
 * Health check result.
 */
export interface KeystoreHealthResult {
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

// ============================================================================
// Provider Interface
// ============================================================================

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
export interface KeystoreProvider {
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
  createWallet(
    network: XRPLNetwork,
    policy: WalletPolicy,
    options?: WalletCreateOptions
  ): Promise<WalletEntry>;

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
  storeKey(
    walletId: string,
    key: SecureBuffer,
    password: string,
    metadata: WalletMetadata
  ): Promise<void>;

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
  importBackup(
    backup: EncryptedBackup,
    password: string,
    options?: ImportOptions
  ): Promise<WalletEntry>;

  /**
   * Close the keystore provider and release resources.
   * Zeros any cached key material from memory.
   */
  close(): Promise<void>;
}
