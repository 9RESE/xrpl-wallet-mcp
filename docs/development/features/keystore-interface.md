# Keystore Interface Specification

**Version**: 1.0.0
**Date**: 2026-01-28
**Author**: Backend Engineer
**Status**: Draft

---

## Table of Contents

1. [Overview](#1-overview)
2. [KeystoreProvider Interface](#2-keystoreprovider-interface)
3. [Core Types](#3-core-types)
4. [Error Types](#4-error-types)
5. [Pluggable Backend Design](#5-pluggable-backend-design)
6. [Security Requirements](#6-security-requirements)
7. [Test Interface](#7-test-interface)
8. [Implementation Guidelines](#8-implementation-guidelines)
9. [Migration Path](#9-migration-path)

---

## 1. Overview

### 1.1 Purpose

The Keystore Interface defines a pluggable abstraction layer for secure key storage in the XRPL Agent Wallet MCP server. This interface enables multiple backend implementations (local file, cloud KMS, HSM) while maintaining a consistent API for the signing service.

### 1.2 Design Goals

| Goal | Description |
|------|-------------|
| **Pluggability** | Swap backends without modifying business logic |
| **Security First** | All implementations must meet security requirements |
| **Testability** | Mock implementations for unit testing |
| **Type Safety** | Full TypeScript typing for compile-time guarantees |
| **Network Isolation** | Per-network keystore separation |

### 1.3 Architecture Context

```
┌─────────────────────────────────────────────────────────────┐
│                     Signing Service                          │
│  (consumes KeystoreProvider interface)                      │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           │ KeystoreProvider
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
         ▼                 ▼                 ▼
┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐
│ LocalFileStore  │ │ CloudKMS    │ │ HSMProvider     │
│ (Phase 1)       │ │ (Phase 2)   │ │ (Phase 3)       │
└─────────────────┘ └─────────────┘ └─────────────────┘
```

---

## 2. KeystoreProvider Interface

### 2.1 Complete Interface Definition

```typescript
import { SecureBuffer } from './secure-buffer';

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
   * Provider identification
   */
  readonly providerType: KeystoreProviderType;
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
   * SECURITY: Returns SecureBuffer that MUST be zeroed after use.
   * The caller is responsible for calling SecureBuffer.zero().
   *
   * @param walletId - Unique wallet identifier
   * @param password - User password for key derivation
   * @returns SecureBuffer containing decrypted key material
   * @throws WalletNotFoundError if wallet doesn't exist
   * @throws AuthenticationError if password is incorrect
   * @throws KeyDecryptionError if decryption fails
   */
  loadKey(
    walletId: string,
    password: string
  ): Promise<SecureBuffer>;

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
  deleteWallet(
    walletId: string,
    password: string
  ): Promise<void>;

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
  rotateKey(
    walletId: string,
    currentPassword: string,
    newPassword: string
  ): Promise<void>;

  /**
   * Update wallet metadata without touching key material.
   *
   * @param walletId - Unique wallet identifier
   * @param updates - Metadata fields to update
   * @throws WalletNotFoundError if wallet doesn't exist
   */
  updateMetadata(
    walletId: string,
    updates: Partial<WalletMetadata>
  ): Promise<void>;

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
  exportBackup(
    walletId: string,
    password: string,
    format: BackupFormat
  ): Promise<EncryptedBackup>;

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

type KeystoreProviderType =
  | 'local-file'     // Phase 1: Local encrypted files
  | 'cloud-kms'      // Phase 2: AWS/GCP/Azure KMS
  | 'hsm'            // Phase 3: Hardware Security Module
  | 'mock';          // Testing only

type XRPLNetwork = 'mainnet' | 'testnet' | 'devnet';

type BackupFormat =
  | 'encrypted-json'  // Standard JSON with AES-256-GCM
  | 'kms-wrapped';    // KEK wrapped by Cloud KMS

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

interface HSMConfig {
  libraryPath: string;
  slot: number;
  pin: string;
  keyLabel: string;
}

interface PasswordPolicy {
  minLength: number;           // Minimum: 12
  requireUppercase: boolean;   // Default: true
  requireLowercase: boolean;   // Default: true
  requireNumbers: boolean;     // Default: true
  requireSpecial: boolean;     // Default: false
  maxLength: number;           // Maximum: 128
}

interface AuditConfig {
  enabled: boolean;
  logPath: string;
  rotationSizeMB: number;
  retentionDays: number;
}

interface KeystoreHealthResult {
  healthy: boolean;
  providerType: KeystoreProviderType;
  providerVersion: string;
  timestamp: string;
  details: {
    storageAccessible: boolean;
    encryptionAvailable: boolean;
    networkCount: number;
    walletCount: number;
    lastOperationTime?: string;
  };
  errors?: string[];
}
```

---

## 3. Core Types

### 3.1 WalletEntry

Represents a complete wallet record (returned after creation/retrieval).

```typescript
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

type KeyAlgorithm = 'ed25519' | 'secp256k1';

type WalletStatus =
  | 'active'      // Normal operation
  | 'locked'      // Temporarily locked (failed auth attempts)
  | 'archived'    // Soft-deleted, can be restored
  | 'pending';    // Creation in progress

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

interface KdfParams {
  /** Memory cost in KB (Argon2id) or iterations (PBKDF2) */
  memoryCost?: number;
  iterations?: number;

  /** Time cost / iterations for Argon2id */
  timeCost?: number;

  /** Parallelism factor */
  parallelism?: number;

  /** Hash algorithm for PBKDF2 */
  hash?: 'sha256' | 'sha512';
}

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
```

### 3.2 WalletSummary

Lightweight wallet representation for list operations.

```typescript
/**
 * Lightweight wallet summary for list operations.
 * Contains no sensitive cryptographic data.
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
```

### 3.3 Wallet Creation Options

```typescript
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

interface EntropySource {
  /** Generate random bytes (must be cryptographically secure) */
  randomBytes(length: number): Buffer;
}

interface WalletPolicy {
  policyId: string;
  policyVersion: string;
  // Full policy structure defined in policy-schema.md
}
```

### 3.4 Backup Types

```typescript
interface EncryptedBackup {
  /** Backup format version */
  version: number;

  /** Format type */
  format: BackupFormat;

  /** Creation timestamp */
  createdAt: string;

  /** Provider that created the backup */
  sourceProvider: KeystoreProviderType;

  /** Encryption algorithm used */
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
```

---

## 4. Error Types

### 4.1 Error Hierarchy

```typescript
/**
 * Base error class for all keystore operations.
 */
abstract class KeystoreError extends Error {
  abstract readonly code: KeystoreErrorCode;
  abstract readonly recoverable: boolean;
  readonly timestamp: string;
  readonly correlationId?: string;

  constructor(
    message: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = this.constructor.name;
    this.timestamp = new Date().toISOString();
  }

  /** Convert to safe JSON (no sensitive data) */
  toSafeJSON(): object {
    return {
      code: this.code,
      message: this.message,
      recoverable: this.recoverable,
      timestamp: this.timestamp,
      correlationId: this.correlationId,
    };
  }
}

type KeystoreErrorCode =
  | 'KEYSTORE_INIT_ERROR'
  | 'WALLET_NOT_FOUND'
  | 'WALLET_EXISTS'
  | 'AUTHENTICATION_ERROR'
  | 'WEAK_PASSWORD'
  | 'KEY_DECRYPTION_ERROR'
  | 'KEY_ENCRYPTION_ERROR'
  | 'INVALID_KEY_FORMAT'
  | 'KEYSTORE_WRITE_ERROR'
  | 'KEYSTORE_READ_ERROR'
  | 'KEYSTORE_CAPACITY_ERROR'
  | 'BACKUP_FORMAT_ERROR'
  | 'NETWORK_MISMATCH'
  | 'PROVIDER_UNAVAILABLE'
  | 'OPERATION_TIMEOUT'
  | 'INTERNAL_ERROR';
```

### 4.2 Specific Error Classes

```typescript
/**
 * Keystore initialization failed.
 */
class KeystoreInitializationError extends KeystoreError {
  readonly code = 'KEYSTORE_INIT_ERROR' as const;
  readonly recoverable = false;

  constructor(message: string, public readonly cause?: Error) {
    super(message, { cause: cause?.message });
  }
}

/**
 * Wallet not found in keystore.
 */
class WalletNotFoundError extends KeystoreError {
  readonly code = 'WALLET_NOT_FOUND' as const;
  readonly recoverable = false;

  constructor(public readonly walletId: string) {
    super(`Wallet not found: ${walletId}`, { walletId });
  }
}

/**
 * Wallet already exists (duplicate ID or address).
 */
class WalletExistsError extends KeystoreError {
  readonly code = 'WALLET_EXISTS' as const;
  readonly recoverable = false;

  constructor(
    public readonly walletId: string,
    public readonly existingAddress?: string
  ) {
    super(`Wallet already exists: ${walletId}`, { walletId, existingAddress });
  }
}

/**
 * Authentication failed (wrong password).
 * Note: Intentionally vague to prevent enumeration.
 */
class AuthenticationError extends KeystoreError {
  readonly code = 'AUTHENTICATION_ERROR' as const;
  readonly recoverable = true;

  constructor() {
    super('Authentication failed');
    // No details to prevent password guessing attacks
  }
}

/**
 * Password does not meet complexity requirements.
 */
class WeakPasswordError extends KeystoreError {
  readonly code = 'WEAK_PASSWORD' as const;
  readonly recoverable = true;

  constructor(public readonly requirements: string[]) {
    super('Password does not meet security requirements', { requirements });
  }
}

/**
 * Key decryption failed.
 * Could be wrong password, corrupted data, or algorithm mismatch.
 */
class KeyDecryptionError extends KeystoreError {
  readonly code = 'KEY_DECRYPTION_ERROR' as const;
  readonly recoverable = false;

  constructor(message: string = 'Key decryption failed') {
    super(message);
  }
}

/**
 * Key encryption failed during storage.
 */
class KeyEncryptionError extends KeystoreError {
  readonly code = 'KEY_ENCRYPTION_ERROR' as const;
  readonly recoverable = false;

  constructor(message: string = 'Key encryption failed') {
    super(message);
  }
}

/**
 * Invalid key format or length.
 */
class InvalidKeyError extends KeystoreError {
  readonly code = 'INVALID_KEY_FORMAT' as const;
  readonly recoverable = false;

  constructor(
    public readonly reason: string,
    public readonly expectedFormat?: string
  ) {
    super(`Invalid key format: ${reason}`, { reason, expectedFormat });
  }
}

/**
 * Keystore write operation failed.
 */
class KeystoreWriteError extends KeystoreError {
  readonly code = 'KEYSTORE_WRITE_ERROR' as const;
  readonly recoverable = true;

  constructor(
    message: string,
    public readonly operation: 'create' | 'update' | 'delete'
  ) {
    super(message, { operation });
  }
}

/**
 * Keystore read operation failed.
 */
class KeystoreReadError extends KeystoreError {
  readonly code = 'KEYSTORE_READ_ERROR' as const;
  readonly recoverable = true;

  constructor(message: string) {
    super(message);
  }
}

/**
 * Keystore capacity limit reached.
 */
class KeystoreCapacityError extends KeystoreError {
  readonly code = 'KEYSTORE_CAPACITY_ERROR' as const;
  readonly recoverable = false;

  constructor(
    public readonly network: XRPLNetwork,
    public readonly currentCount: number,
    public readonly maxCount: number
  ) {
    super(
      `Keystore capacity exceeded for ${network}`,
      { network, currentCount, maxCount }
    );
  }
}

/**
 * Backup format invalid or unsupported.
 */
class BackupFormatError extends KeystoreError {
  readonly code = 'BACKUP_FORMAT_ERROR' as const;
  readonly recoverable = false;

  constructor(
    public readonly reason: string,
    public readonly expectedVersion?: number
  ) {
    super(`Invalid backup format: ${reason}`, { reason, expectedVersion });
  }
}

/**
 * Network mismatch between wallet and operation.
 */
class NetworkMismatchError extends KeystoreError {
  readonly code = 'NETWORK_MISMATCH' as const;
  readonly recoverable = false;

  constructor(
    public readonly walletNetwork: XRPLNetwork,
    public readonly requestedNetwork: XRPLNetwork
  ) {
    super(
      `Network mismatch: wallet is ${walletNetwork}, requested ${requestedNetwork}`,
      { walletNetwork, requestedNetwork }
    );
  }
}

/**
 * Provider service unavailable.
 */
class ProviderUnavailableError extends KeystoreError {
  readonly code = 'PROVIDER_UNAVAILABLE' as const;
  readonly recoverable = true;

  constructor(
    public readonly providerType: KeystoreProviderType,
    public readonly reason: string
  ) {
    super(`Provider unavailable: ${reason}`, { providerType, reason });
  }
}
```

---

## 5. Pluggable Backend Design

### 5.1 Backend Registry

```typescript
/**
 * Registry for keystore provider implementations.
 */
class KeystoreProviderRegistry {
  private static providers = new Map<KeystoreProviderType, KeystoreProviderFactory>();

  /**
   * Register a provider implementation.
   */
  static register(
    type: KeystoreProviderType,
    factory: KeystoreProviderFactory
  ): void {
    this.providers.set(type, factory);
  }

  /**
   * Create a provider instance.
   */
  static create(
    type: KeystoreProviderType,
    config: KeystoreConfig
  ): KeystoreProvider {
    const factory = this.providers.get(type);
    if (!factory) {
      throw new Error(`Unknown provider type: ${type}`);
    }
    return factory(config);
  }

  /**
   * Get all registered provider types.
   */
  static getAvailableTypes(): KeystoreProviderType[] {
    return Array.from(this.providers.keys());
  }
}

type KeystoreProviderFactory = (config: KeystoreConfig) => KeystoreProvider;
```

### 5.2 Phase 1: Local File Provider

```typescript
/**
 * Local file-based keystore provider.
 * Keys encrypted with AES-256-GCM, Argon2id key derivation.
 */
class LocalFileKeystoreProvider implements KeystoreProvider {
  readonly providerType = 'local-file' as const;
  readonly providerVersion = '1.0.0';

  private baseDir: string;
  private passwordPolicy: PasswordPolicy;
  private initialized = false;

  async initialize(config: KeystoreConfig): Promise<void> {
    this.baseDir = config.baseDir ?? '~/.xrpl-wallet-mcp';
    this.passwordPolicy = config.passwordPolicy ?? DEFAULT_PASSWORD_POLICY;

    // Create directory structure
    await this.ensureDirectoryStructure();

    // Verify file permissions
    await this.verifyPermissions();

    this.initialized = true;
  }

  private async ensureDirectoryStructure(): Promise<void> {
    // Create per-network directories
    for (const network of ['mainnet', 'testnet', 'devnet']) {
      await fs.mkdir(
        path.join(this.baseDir, network, 'keystore'),
        { recursive: true, mode: 0o700 }
      );
    }
  }

  // Implementation continues...
}
```

### 5.3 Phase 2: Cloud KMS Provider

```typescript
/**
 * Cloud KMS-backed keystore provider.
 * KEK managed by cloud provider, DEK generated per-wallet.
 */
class CloudKMSKeystoreProvider implements KeystoreProvider {
  readonly providerType = 'cloud-kms' as const;
  readonly providerVersion = '1.0.0';

  private kmsClient: KMSClient;
  private kmsKeyUri: string;

  async initialize(config: KeystoreConfig): Promise<void> {
    if (!config.kmsKeyUri) {
      throw new KeystoreInitializationError('KMS key URI required');
    }

    this.kmsKeyUri = config.kmsKeyUri;
    this.kmsClient = await this.createKMSClient(config.kmsKeyUri);

    // Verify KMS key access
    await this.verifyKMSAccess();
  }

  async loadKey(walletId: string, password: string): Promise<SecureBuffer> {
    // 1. Load encrypted wallet file
    const encryptedWallet = await this.loadEncryptedWallet(walletId);

    // 2. Derive user key from password
    const userKey = await this.deriveKey(password, encryptedWallet.encryption);

    // 3. Decrypt DEK using user key
    const wrappedDek = Buffer.from(encryptedWallet.wrappedDek, 'base64');
    const dek = await this.unwrapDekWithUserKey(wrappedDek, userKey);

    // 4. Optionally: Unwrap DEK with KMS (double encryption)
    const unwrappedDek = await this.kmsUnwrap(dek);

    // 5. Decrypt actual key material
    return this.decryptKeyMaterial(
      encryptedWallet.encryptedKey,
      unwrappedDek,
      encryptedWallet.encryption
    );
  }

  // Implementation continues...
}
```

### 5.4 Phase 3: HSM Provider

```typescript
/**
 * Hardware Security Module keystore provider.
 * Keys never leave the HSM boundary.
 */
class HSMKeystoreProvider implements KeystoreProvider {
  readonly providerType = 'hsm' as const;
  readonly providerVersion = '1.0.0';

  private pkcs11: PKCS11Module;
  private session: number;

  async initialize(config: KeystoreConfig): Promise<void> {
    if (!config.hsmConfig) {
      throw new KeystoreInitializationError('HSM configuration required');
    }

    // Load PKCS#11 library
    this.pkcs11 = await loadPKCS11(config.hsmConfig.libraryPath);

    // Open session
    this.session = await this.openSession(
      config.hsmConfig.slot,
      config.hsmConfig.pin
    );
  }

  async createWallet(
    network: XRPLNetwork,
    policy: WalletPolicy,
    options?: WalletCreateOptions
  ): Promise<WalletEntry> {
    // Generate key pair inside HSM
    const keyHandle = await this.pkcs11.generateKeyPair(this.session, {
      mechanism: CKM_ECDSA_KEY_PAIR_GEN,
      publicKeyTemplate: {
        CKA_EC_PARAMS: SECP256K1_OID,
        CKA_TOKEN: true,
        CKA_VERIFY: true,
      },
      privateKeyTemplate: {
        CKA_TOKEN: true,
        CKA_PRIVATE: true,
        CKA_SENSITIVE: true,
        CKA_EXTRACTABLE: false, // Key can NEVER leave HSM
        CKA_SIGN: true,
      },
    });

    // Store metadata (key stays in HSM)
    return this.createWalletEntry(keyHandle, network, policy, options);
  }

  async loadKey(walletId: string, password: string): Promise<SecureBuffer> {
    // For HSM, we don't actually return the key
    // Instead, return a reference that signing service uses
    throw new Error(
      'HSM keys cannot be exported. Use signWithHSM() instead.'
    );
  }

  /**
   * HSM-specific: Sign transaction directly in HSM.
   */
  async signWithHSM(
    walletId: string,
    password: string,
    transactionBlob: Buffer
  ): Promise<Buffer> {
    // Verify user authentication
    await this.verifyPassword(walletId, password);

    // Get key handle
    const keyHandle = await this.getKeyHandle(walletId);

    // Sign in HSM (private key never leaves)
    return this.pkcs11.sign(this.session, keyHandle, transactionBlob);
  }

  // Implementation continues...
}
```

### 5.5 Provider Selection

```typescript
/**
 * Configuration-driven provider selection.
 */
function createKeystoreProvider(
  config: KeystoreConfig & { provider: KeystoreProviderType }
): KeystoreProvider {
  return KeystoreProviderRegistry.create(config.provider, config);
}

// Usage in application startup
const keystoreConfig: KeystoreConfig & { provider: KeystoreProviderType } = {
  provider: process.env.KEYSTORE_PROVIDER as KeystoreProviderType || 'local-file',
  baseDir: process.env.KEYSTORE_PATH,
  kmsKeyUri: process.env.KMS_KEY_URI,
  passwordPolicy: {
    minLength: 12,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecial: false,
    maxLength: 128,
  },
};

const keystore = createKeystoreProvider(keystoreConfig);
await keystore.initialize(keystoreConfig);
```

---

## 6. Security Requirements

### 6.1 Mandatory Requirements

All keystore implementations MUST satisfy these requirements:

| ID | Requirement | Verification |
|----|-------------|--------------|
| **SEC-KS-001** | Keys encrypted at rest with AES-256-GCM | Audit file format |
| **SEC-KS-002** | Password-derived keys use Argon2id (64MB, 3 iterations) | Check KDF params |
| **SEC-KS-003** | Unique salt per wallet (32 bytes) | File inspection |
| **SEC-KS-004** | Unique IV per encryption operation (12 bytes) | Code review |
| **SEC-KS-005** | Authentication tag verification before use | Code review |
| **SEC-KS-006** | File permissions: 0600 (files), 0700 (directories) | Runtime check |
| **SEC-KS-007** | Atomic write operations (temp + rename) | Code review |
| **SEC-KS-008** | SecureBuffer zeroed after use | Memory testing |
| **SEC-KS-009** | No key material in logs | Log audit |
| **SEC-KS-010** | Rate limiting on authentication attempts | Integration test |
| **SEC-KS-011** | Network isolation (mainnet/testnet/devnet) | Directory structure |
| **SEC-KS-012** | Audit logging for all operations | Log review |

### 6.2 Password Policy Defaults

```typescript
const DEFAULT_PASSWORD_POLICY: PasswordPolicy = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecial: false,
  maxLength: 128,
};

function validatePassword(password: string, policy: PasswordPolicy): string[] {
  const errors: string[] = [];

  if (password.length < policy.minLength) {
    errors.push(`Minimum ${policy.minLength} characters required`);
  }
  if (password.length > policy.maxLength) {
    errors.push(`Maximum ${policy.maxLength} characters allowed`);
  }
  if (policy.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Must contain uppercase letter');
  }
  if (policy.requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Must contain lowercase letter');
  }
  if (policy.requireNumbers && !/\d/.test(password)) {
    errors.push('Must contain number');
  }
  if (policy.requireSpecial && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Must contain special character');
  }

  return errors;
}
```

### 6.3 Authentication Rate Limiting

```typescript
interface AuthRateLimitConfig {
  /** Maximum failed attempts before lockout */
  maxAttempts: number;

  /** Window for counting attempts (seconds) */
  windowSeconds: number;

  /** Lockout duration (seconds) */
  lockoutSeconds: number;

  /** Progressive lockout multiplier */
  lockoutMultiplier: number;
}

const DEFAULT_AUTH_RATE_LIMIT: AuthRateLimitConfig = {
  maxAttempts: 5,
  windowSeconds: 900,      // 15 minutes
  lockoutSeconds: 1800,    // 30 minutes
  lockoutMultiplier: 2,    // Doubles each time
};
```

### 6.4 Secure Memory Handling

```typescript
/**
 * SecureBuffer implementation for sensitive data.
 */
class SecureBuffer {
  private buffer: Buffer;
  private isZeroed: boolean = false;

  private constructor(size: number) {
    this.buffer = Buffer.allocUnsafe(size);
  }

  static alloc(size: number): SecureBuffer {
    return new SecureBuffer(size);
  }

  static from(data: Buffer): SecureBuffer {
    const secure = new SecureBuffer(data.length);
    data.copy(secure.buffer);
    // Zero source immediately
    data.fill(0);
    return secure;
  }

  /**
   * Get buffer contents.
   * @throws Error if buffer has been zeroed
   */
  getBuffer(): Buffer {
    if (this.isZeroed) {
      throw new Error('SecureBuffer has been zeroed');
    }
    return this.buffer;
  }

  /**
   * Zero the buffer contents.
   * This operation is irreversible.
   */
  zero(): void {
    if (!this.isZeroed) {
      this.buffer.fill(0);
      this.isZeroed = true;
    }
  }

  /**
   * Check if buffer has been zeroed.
   */
  get zeroed(): boolean {
    return this.isZeroed;
  }

  /**
   * Execute operation with automatic cleanup.
   */
  static async withSecureBuffer<T>(
    data: Buffer,
    operation: (buffer: Buffer) => Promise<T>
  ): Promise<T> {
    const secure = SecureBuffer.from(data);
    try {
      return await operation(secure.getBuffer());
    } finally {
      secure.zero();
    }
  }

  // Prevent accidental serialization
  toJSON(): never {
    throw new Error('SecureBuffer cannot be serialized');
  }

  toString(): string {
    return '[SecureBuffer]';
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return '[SecureBuffer]';
  }
}
```

---

## 7. Test Interface

### 7.1 Mock Provider

```typescript
/**
 * Mock keystore provider for unit testing.
 * Stores keys in memory without encryption.
 *
 * WARNING: NEVER use in production.
 */
class MockKeystoreProvider implements KeystoreProvider {
  readonly providerType = 'mock' as const;
  readonly providerVersion = '1.0.0-test';

  private wallets = new Map<string, MockWalletData>();
  private authAttempts = new Map<string, number>();

  // Configurable behaviors for testing
  public simulateAuthFailure = false;
  public simulateWriteFailure = false;
  public simulateReadFailure = false;
  public authDelayMs = 0;

  async initialize(config: KeystoreConfig): Promise<void> {
    // No-op for mock
  }

  async healthCheck(): Promise<KeystoreHealthResult> {
    return {
      healthy: true,
      providerType: 'mock',
      providerVersion: this.providerVersion,
      timestamp: new Date().toISOString(),
      details: {
        storageAccessible: true,
        encryptionAvailable: true,
        networkCount: 3,
        walletCount: this.wallets.size,
      },
    };
  }

  async createWallet(
    network: XRPLNetwork,
    policy: WalletPolicy,
    options?: WalletCreateOptions
  ): Promise<WalletEntry> {
    if (this.simulateWriteFailure) {
      throw new KeystoreWriteError('Simulated write failure', 'create');
    }

    const walletId = `mock-wallet-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const seed = crypto.randomBytes(32);
    const keypair = deriveKeypair(seed);

    const entry: WalletEntry = {
      walletId,
      name: options?.name ?? walletId,
      address: keypair.address,
      publicKey: keypair.publicKey,
      algorithm: options?.algorithm ?? 'ed25519',
      network,
      policyId: policy.policyId,
      encryption: {
        algorithm: 'aes-256-gcm',
        kdf: 'argon2id',
        kdfParams: { memoryCost: 65536, timeCost: 3, parallelism: 4 },
        salt: crypto.randomBytes(32).toString('base64'),
      },
      metadata: {
        description: options?.description,
        tags: options?.tags,
      },
      createdAt: new Date().toISOString(),
      modifiedAt: new Date().toISOString(),
      status: 'active',
    };

    this.wallets.set(walletId, {
      entry,
      seed,
      password: options?.password ?? 'test-password',
    });

    return entry;
  }

  async loadKey(walletId: string, password: string): Promise<SecureBuffer> {
    if (this.authDelayMs > 0) {
      await new Promise(resolve => setTimeout(resolve, this.authDelayMs));
    }

    if (this.simulateAuthFailure) {
      throw new AuthenticationError();
    }

    if (this.simulateReadFailure) {
      throw new KeystoreReadError('Simulated read failure');
    }

    const wallet = this.wallets.get(walletId);
    if (!wallet) {
      throw new WalletNotFoundError(walletId);
    }

    if (wallet.password !== password) {
      throw new AuthenticationError();
    }

    return SecureBuffer.from(Buffer.from(wallet.seed));
  }

  async storeKey(
    walletId: string,
    key: SecureBuffer,
    password: string,
    metadata: WalletMetadata
  ): Promise<void> {
    if (this.wallets.has(walletId)) {
      throw new WalletExistsError(walletId);
    }

    const seed = Buffer.from(key.getBuffer());
    const keypair = deriveKeypair(seed);

    const entry: WalletEntry = {
      walletId,
      name: walletId,
      address: keypair.address,
      publicKey: keypair.publicKey,
      algorithm: 'ed25519',
      network: 'testnet',
      policyId: 'imported',
      encryption: {
        algorithm: 'aes-256-gcm',
        kdf: 'argon2id',
        kdfParams: { memoryCost: 65536, timeCost: 3, parallelism: 4 },
        salt: crypto.randomBytes(32).toString('base64'),
      },
      metadata,
      createdAt: new Date().toISOString(),
      modifiedAt: new Date().toISOString(),
      status: 'active',
    };

    this.wallets.set(walletId, {
      entry,
      seed,
      password,
    });
  }

  async listWallets(network?: XRPLNetwork): Promise<WalletSummary[]> {
    return Array.from(this.wallets.values())
      .filter(w => !network || w.entry.network === network)
      .map(w => ({
        walletId: w.entry.walletId,
        name: w.entry.name,
        address: w.entry.address,
        network: w.entry.network,
        status: w.entry.status,
        createdAt: w.entry.createdAt,
        policyId: w.entry.policyId,
        tags: w.entry.metadata.tags,
      }));
  }

  async getWallet(walletId: string): Promise<WalletEntry> {
    const wallet = this.wallets.get(walletId);
    if (!wallet) {
      throw new WalletNotFoundError(walletId);
    }
    return wallet.entry;
  }

  async deleteWallet(walletId: string, password: string): Promise<void> {
    const wallet = this.wallets.get(walletId);
    if (!wallet) {
      throw new WalletNotFoundError(walletId);
    }
    if (wallet.password !== password) {
      throw new AuthenticationError();
    }
    this.wallets.delete(walletId);
  }

  async rotateKey(
    walletId: string,
    currentPassword: string,
    newPassword: string
  ): Promise<void> {
    const wallet = this.wallets.get(walletId);
    if (!wallet) {
      throw new WalletNotFoundError(walletId);
    }
    if (wallet.password !== currentPassword) {
      throw new AuthenticationError();
    }
    wallet.password = newPassword;
    wallet.entry.modifiedAt = new Date().toISOString();
  }

  async updateMetadata(
    walletId: string,
    updates: Partial<WalletMetadata>
  ): Promise<void> {
    const wallet = this.wallets.get(walletId);
    if (!wallet) {
      throw new WalletNotFoundError(walletId);
    }
    wallet.entry.metadata = { ...wallet.entry.metadata, ...updates };
    wallet.entry.modifiedAt = new Date().toISOString();
  }

  async exportBackup(
    walletId: string,
    password: string,
    format: BackupFormat
  ): Promise<EncryptedBackup> {
    const wallet = this.wallets.get(walletId);
    if (!wallet) {
      throw new WalletNotFoundError(walletId);
    }
    if (wallet.password !== password) {
      throw new AuthenticationError();
    }

    // Mock backup - not actually encrypted
    return {
      version: 1,
      format,
      createdAt: new Date().toISOString(),
      sourceProvider: 'mock',
      encryption: {
        algorithm: 'aes-256-gcm',
        kdf: 'argon2id',
        kdfParams: wallet.entry.encryption.kdfParams,
        salt: wallet.entry.encryption.salt,
        iv: crypto.randomBytes(12).toString('base64'),
        authTag: crypto.randomBytes(16).toString('base64'),
      },
      payload: Buffer.from(JSON.stringify({
        entry: wallet.entry,
        seed: wallet.seed.toString('hex'),
      })).toString('base64'),
      checksum: 'mock-checksum',
    };
  }

  async importBackup(
    backup: EncryptedBackup,
    password: string,
    options?: ImportOptions
  ): Promise<WalletEntry> {
    try {
      const data = JSON.parse(
        Buffer.from(backup.payload, 'base64').toString()
      );

      const walletId = options?.newName ?? data.entry.walletId;

      if (this.wallets.has(walletId) && !options?.force) {
        throw new WalletExistsError(walletId);
      }

      const entry = {
        ...data.entry,
        walletId,
        modifiedAt: new Date().toISOString(),
      };

      this.wallets.set(walletId, {
        entry,
        seed: Buffer.from(data.seed, 'hex'),
        password: options?.newPassword ?? password,
      });

      return entry;
    } catch (error) {
      if (error instanceof KeystoreError) throw error;
      throw new BackupFormatError('Invalid backup data');
    }
  }

  async close(): Promise<void> {
    // Zero all stored seeds
    for (const wallet of this.wallets.values()) {
      wallet.seed.fill(0);
    }
    this.wallets.clear();
  }

  // Test helpers

  /**
   * Reset mock state.
   */
  reset(): void {
    this.wallets.clear();
    this.authAttempts.clear();
    this.simulateAuthFailure = false;
    this.simulateWriteFailure = false;
    this.simulateReadFailure = false;
    this.authDelayMs = 0;
  }

  /**
   * Get internal state for test assertions.
   */
  getInternalState(): {
    walletCount: number;
    walletIds: string[];
  } {
    return {
      walletCount: this.wallets.size,
      walletIds: Array.from(this.wallets.keys()),
    };
  }
}

interface MockWalletData {
  entry: WalletEntry;
  seed: Buffer;
  password: string;
}
```

### 7.2 Test Fixtures

```typescript
/**
 * Test fixtures for keystore testing.
 */
const TestFixtures = {
  /** Valid test password meeting all requirements */
  validPassword: 'TestPassword123!',

  /** Weak passwords for testing rejection */
  weakPasswords: [
    'short',           // Too short
    'alllowercase',    // No uppercase
    'ALLUPPERCASE',    // No lowercase
    'NoNumbers!',      // No numbers
  ],

  /** Test network configurations */
  networks: ['mainnet', 'testnet', 'devnet'] as XRPLNetwork[],

  /** Sample policy for testing */
  samplePolicy: {
    policyId: 'test-policy-v1',
    policyVersion: '1.0.0',
    limits: {
      max_amount_per_tx_drops: '10000000',
      max_daily_volume_drops: '100000000',
      max_tx_per_hour: 10,
      max_tx_per_day: 50,
    },
    destinations: {
      mode: 'open' as const,
      allow_new_destinations: true,
      blocklist: [],
    },
    transaction_types: {
      allowed: ['Payment'],
      blocked: ['AccountDelete'],
    },
    escalation: {
      amount_threshold_drops: '5000000',
      new_destination: 2 as const,
      account_settings: 3 as const,
    },
  },

  /** Create mock keystore for testing */
  createMockKeystore(): MockKeystoreProvider {
    return new MockKeystoreProvider();
  },
};
```

---

## 8. Implementation Guidelines

### 8.1 Implementation Checklist

For each new keystore provider implementation:

- [ ] Implements all `KeystoreProvider` interface methods
- [ ] Passes all security requirements (SEC-KS-001 through SEC-KS-012)
- [ ] Uses provided error types correctly
- [ ] Handles SecureBuffer lifecycle properly
- [ ] Implements atomic write operations
- [ ] Provides correct health check information
- [ ] Logs all operations to audit trail
- [ ] Handles concurrent access safely
- [ ] Implements rate limiting for authentication
- [ ] Documents provider-specific configuration
- [ ] Includes integration tests
- [ ] Passes security review

### 8.2 Concurrency Considerations

```typescript
/**
 * Example: File locking for concurrent access.
 */
class FileLock {
  private locks = new Map<string, Promise<void>>();

  async withLock<T>(
    key: string,
    operation: () => Promise<T>
  ): Promise<T> {
    // Wait for any existing lock
    while (this.locks.has(key)) {
      await this.locks.get(key);
    }

    // Create lock promise
    let releaseLock: () => void;
    const lockPromise = new Promise<void>(resolve => {
      releaseLock = resolve;
    });
    this.locks.set(key, lockPromise);

    try {
      return await operation();
    } finally {
      this.locks.delete(key);
      releaseLock!();
    }
  }
}
```

### 8.3 Audit Integration

```typescript
/**
 * Required audit events for keystore operations.
 */
enum KeystoreAuditEvent {
  WALLET_CREATED = 'keystore.wallet_created',
  WALLET_DELETED = 'keystore.wallet_deleted',
  KEY_LOADED = 'keystore.key_loaded',
  KEY_STORED = 'keystore.key_stored',
  KEY_ROTATED = 'keystore.key_rotated',
  AUTH_SUCCESS = 'keystore.auth_success',
  AUTH_FAILURE = 'keystore.auth_failure',
  AUTH_LOCKOUT = 'keystore.auth_lockout',
  BACKUP_EXPORTED = 'keystore.backup_exported',
  BACKUP_IMPORTED = 'keystore.backup_imported',
}

interface KeystoreAuditData {
  event: KeystoreAuditEvent;
  walletId?: string;
  network?: XRPLNetwork;
  providerType: KeystoreProviderType;
  success: boolean;
  errorCode?: KeystoreErrorCode;
  // Never include: password, key material, seeds
}
```

---

## 9. Migration Path

### 9.1 Phase 1 to Phase 2 Migration

When migrating from local-file to cloud-kms:

```typescript
/**
 * Migrate wallet from local file to Cloud KMS.
 */
async function migrateToCloudKMS(
  localProvider: LocalFileKeystoreProvider,
  kmsProvider: CloudKMSKeystoreProvider,
  walletId: string,
  password: string
): Promise<void> {
  // 1. Load key from local provider
  const key = await localProvider.loadKey(walletId, password);

  try {
    // 2. Get wallet metadata
    const wallet = await localProvider.getWallet(walletId);

    // 3. Store in KMS provider
    await kmsProvider.storeKey(
      walletId,
      key,
      password,
      wallet.metadata
    );

    // 4. Verify migration
    const kmsKey = await kmsProvider.loadKey(walletId, password);

    if (!buffersEqual(key.getBuffer(), kmsKey.getBuffer())) {
      throw new Error('Migration verification failed');
    }

    kmsKey.zero();

    // 5. Archive local copy (don't delete yet)
    await localProvider.updateMetadata(walletId, {
      customData: {
        migratedToKMS: true,
        migrationDate: new Date().toISOString(),
      },
    });

  } finally {
    key.zero();
  }
}
```

### 9.2 Compatibility Matrix

| Source | Target | Migration | Notes |
|--------|--------|-----------|-------|
| local-file | cloud-kms | Supported | Re-encrypts with KMS-wrapped DEK |
| local-file | hsm | Supported | Imports key to HSM (extractable becomes false) |
| cloud-kms | local-file | Supported | Downgrades security |
| cloud-kms | hsm | Supported | Imports unwrapped key to HSM |
| hsm | local-file | NOT SUPPORTED | Non-extractable keys |
| hsm | cloud-kms | NOT SUPPORTED | Non-extractable keys |

---

## Related Documents

- [ADR-001: Key Storage Strategy](../../architecture/09-decisions/ADR-001-key-storage.md)
- [ADR-002: Key Derivation Function](../../architecture/09-decisions/ADR-002-key-derivation.md)
- [Security Architecture](../../security/SECURITY-ARCHITECTURE.md)
- [Building Blocks View](../../architecture/05-building-blocks.md)
- [wallet_create Tool Specification](../../api/tools/wallet-create.md)

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Backend Engineer | Initial specification |

---

*XRPL Agent Wallet MCP - Keystore Interface Specification*
