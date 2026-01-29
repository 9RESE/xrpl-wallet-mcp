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

import { promises as fs } from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as argon2 from 'argon2';
import { Wallet, ECDSA } from 'xrpl';

import { SecureBuffer } from './secure-buffer.js';
import {
  type KeystoreProvider,
  type KeystoreConfig,
  type KeystoreHealthResult,
  type WalletEntry,
  type WalletSummary,
  type WalletPolicy,
  type WalletCreateOptions,
  type WalletMetadata,
  type EncryptedBackup,
  type ImportOptions,
  type BackupFormat,
  type XRPLNetwork,
  type PasswordPolicy,
  type KdfParams,
} from './interface.js';
import {
  KeystoreInitializationError,
  WalletNotFoundError,
  WalletExistsError,
  AuthenticationError,
  WeakPasswordError,
  KeyDecryptionError,
  KeystoreWriteError,
  KeystoreCapacityError,
  BackupFormatError,
  InvalidKeyError,
} from './errors.js';

// ============================================================================
// Constants
// ============================================================================

/**
 * Argon2id configuration per ADR-002.
 */
const ARGON2_CONFIG = {
  type: argon2.argon2id,
  memoryCost: 65536, // 64 MB
  timeCost: 3, // 3 iterations
  parallelism: 4, // 4 threads
  hashLength: 32, // 256-bit output
  saltLength: 32, // 256-bit salt
} as const;

/**
 * AES-256-GCM configuration per ADR-001.
 */
const AES_CONFIG = {
  algorithm: 'aes-256-gcm' as const,
  keyLength: 32, // 256 bits
  ivLength: 12, // 96 bits (NIST recommended for GCM)
  authTagLength: 16, // 128 bits
} as const;

/**
 * File permission constants.
 */
const PERMISSIONS = {
  FILE: 0o600, // Owner read/write only (rw-------)
  DIRECTORY: 0o700, // Owner read/write/execute only (rwx------)
} as const;

/**
 * Default password policy.
 */
const DEFAULT_PASSWORD_POLICY: PasswordPolicy = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecial: false,
  maxLength: 128,
};

/**
 * Rate limiting configuration.
 */
const RATE_LIMIT_CONFIG = {
  maxAttempts: 5, // Max failed attempts
  windowSeconds: 900, // 15 minute window
  lockoutSeconds: 1800, // 30 minute initial lockout
  lockoutMultiplier: 2, // Doubles each time
} as const;

// ============================================================================
// Types
// ============================================================================

/**
 * Wallet file format stored on disk.
 */
interface WalletFile {
  /** File format version */
  version: 1;
  /** Unique wallet identifier */
  walletId: string;
  /** Wallet metadata and public information */
  entry: WalletEntry;
  /** Encrypted private key material */
  encryptedKey: {
    /** Base64-encoded encrypted seed/key */
    data: string;
    /** Base64-encoded initialization vector (12 bytes) */
    iv: string;
    /** Base64-encoded GCM authentication tag (16 bytes) */
    authTag: string;
  };
}

/**
 * Wallet index stored per network.
 */
interface WalletIndex {
  /** Index format version */
  version: 1;
  /** List of wallet entries (metadata only, no keys) */
  wallets: WalletEntry[];
  /** Last modification timestamp */
  modifiedAt: string;
}

/**
 * Authentication attempt record.
 */
interface AuthAttemptRecord {
  timestamp: Date;
  success: boolean;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Validates password against policy requirements.
 *
 * @param password - Password to validate
 * @param policy - Password policy to check against
 * @returns Array of error messages (empty if valid)
 */
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

/**
 * Simple file locking mechanism for concurrent access safety.
 */
class FileLock {
  private locks = new Map<string, Promise<void>>();

  /**
   * Executes operation with exclusive access to the file.
   */
  async withLock<T>(key: string, operation: () => Promise<T>): Promise<T> {
    // Wait for any existing lock
    while (this.locks.has(key)) {
      await this.locks.get(key);
    }

    // Create lock
    let releaseLock: () => void;
    const lockPromise = new Promise<void>((resolve) => {
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

// ============================================================================
// LocalKeystore Implementation
// ============================================================================

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
export class LocalKeystore implements KeystoreProvider {
  readonly providerType = 'local-file' as const;
  readonly providerVersion = '1.0.0';

  private baseDir: string = '';
  private passwordPolicy: PasswordPolicy = DEFAULT_PASSWORD_POLICY;
  private maxWalletsPerNetwork: number = 100;
  private initialized: boolean = false;
  private fileLock: FileLock = new FileLock();

  // Rate limiting state
  private authAttempts: Map<string, AuthAttemptRecord[]> = new Map();
  private lockouts: Map<string, Date> = new Map();

  // ========================================================================
  // Lifecycle Methods
  // ========================================================================

  async initialize(config: KeystoreConfig): Promise<void> {
    if (this.initialized) {
      throw new KeystoreInitializationError('Provider already initialized');
    }

    // Resolve base directory
    const homeDir = process.env['HOME'] || '';
    this.baseDir = config.baseDir
      ? path.resolve(config.baseDir.replace(/^~/, homeDir))
      : path.join(homeDir, '.xrpl-wallet-mcp');

    // Apply configuration
    if (config.passwordPolicy) {
      this.passwordPolicy = { ...DEFAULT_PASSWORD_POLICY, ...config.passwordPolicy };
    }
    if (config.maxWalletsPerNetwork !== undefined) {
      this.maxWalletsPerNetwork = config.maxWalletsPerNetwork;
    }

    // Create directory structure
    await this.ensureDirectoryStructure();

    // Verify permissions
    await this.verifyPermissions();

    this.initialized = true;
  }

  async healthCheck(): Promise<KeystoreHealthResult> {
    this.assertInitialized();

    const errors: string[] = [];
    let storageAccessible = true;
    let encryptionAvailable = true;
    let networkCount = 0;
    let walletCount = 0;

    // Check storage access
    try {
      await fs.access(this.baseDir, fs.constants.R_OK | fs.constants.W_OK);
    } catch {
      storageAccessible = false;
      errors.push('Base directory not accessible');
    }

    // Check encryption availability
    try {
      const testKey = crypto.randomBytes(32);
      const testIv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', testKey, testIv);
      cipher.update('test');
      cipher.final();
    } catch {
      encryptionAvailable = false;
      errors.push('AES-256-GCM encryption not available');
    }

    // Count networks and wallets
    for (const network of ['mainnet', 'testnet', 'devnet'] as XRPLNetwork[]) {
      const networkDir = path.join(this.baseDir, network, 'wallets');
      try {
        await fs.access(networkDir);
        networkCount++;
        const files = await fs.readdir(networkDir);
        walletCount += files.filter((f) => f.endsWith('.wallet.json')).length;
      } catch {
        // Network directory doesn't exist yet
      }
    }

    const result: KeystoreHealthResult = {
      healthy: storageAccessible && encryptionAvailable && errors.length === 0,
      providerType: this.providerType,
      providerVersion: this.providerVersion,
      timestamp: new Date().toISOString(),
      details: {
        storageAccessible,
        encryptionAvailable,
        networkCount,
        walletCount,
      },
    };
    if (errors.length > 0) {
      result.errors = errors;
    }
    return result;
  }

  async close(): Promise<void> {
    // Clear rate limiting state
    this.authAttempts.clear();
    this.lockouts.clear();
    this.initialized = false;
  }

  // ========================================================================
  // Wallet CRUD Operations
  // ========================================================================

  async createWallet(
    network: XRPLNetwork,
    policy: WalletPolicy,
    options?: WalletCreateOptions
  ): Promise<WalletEntry> {
    this.assertInitialized();

    if (!options?.password) {
      throw new WeakPasswordError(['Password is required']);
    }

    // Validate password
    const passwordErrors = validatePassword(options.password, this.passwordPolicy);
    if (passwordErrors.length > 0) {
      throw new WeakPasswordError(passwordErrors);
    }

    // Check capacity
    const currentCount = (await this.listWallets(network)).length;
    if (currentCount >= this.maxWalletsPerNetwork) {
      throw new KeystoreCapacityError(network, currentCount, this.maxWalletsPerNetwork);
    }

    // Generate wallet ID
    const walletId = this.generateWalletId();

    // Generate wallet using xrpl library
    const algorithm = options?.algorithm || 'ed25519';
    // Map our algorithm type to xrpl's ECDSA enum
    const xrplAlgorithm = algorithm === 'secp256k1' ? ECDSA.secp256k1 : ECDSA.ed25519;
    const xrplWallet = Wallet.generate(xrplAlgorithm);

    // Get seed as buffer
    const seedHex = xrplWallet.seed;
    if (!seedHex) {
      throw new KeystoreWriteError('Failed to generate wallet seed', 'create');
    }

    // Convert seed to buffer (xrpl seeds are base58, we'll store the entropy)
    const seedBuffer = Buffer.from(xrplWallet.privateKey, 'hex');
    const seed = SecureBuffer.from(seedBuffer);

    try {
      // Derive encryption key
      const salt = crypto.randomBytes(ARGON2_CONFIG.saltLength);
      const kek = await this.deriveKey(options.password, salt);

      // Encrypt seed
      const { encryptedData, iv, authTag } = await this.encrypt(seed.getBuffer(), kek);

      // Zero KEK immediately
      kek.dispose();

      // Create wallet entry
      const now = new Date().toISOString();
      const entry: WalletEntry = {
        walletId,
        name: options?.name || `Wallet ${walletId.slice(0, 8)}`,
        address: xrplWallet.classicAddress,
        publicKey: xrplWallet.publicKey,
        algorithm,
        network,
        policyId: policy.policyId,
        encryption: {
          algorithm: 'aes-256-gcm',
          kdf: 'argon2id',
          kdfParams: {
            memoryCost: ARGON2_CONFIG.memoryCost,
            timeCost: ARGON2_CONFIG.timeCost,
            parallelism: ARGON2_CONFIG.parallelism,
          },
          salt: salt.toString('base64'),
        },
        metadata: {
          ...(options?.description && { description: options.description }),
          ...(options?.tags && { tags: options.tags }),
        },
        createdAt: now,
        modifiedAt: now,
        status: 'active',
      };

      // Create wallet file content
      const walletFile: WalletFile = {
        version: 1,
        walletId,
        entry,
        encryptedKey: {
          data: encryptedData.toString('base64'),
          iv: iv.toString('base64'),
          authTag: authTag.toString('base64'),
        },
      };

      // Write wallet file atomically
      const walletPath = this.getWalletPath(network, walletId);
      await this.atomicWrite(walletPath, JSON.stringify(walletFile, null, 2));

      // Update index
      await this.updateIndex(network, entry, 'add');

      return entry;
    } finally {
      // Always zero seed
      seed.dispose();
    }
  }

  async loadKey(walletId: string, password: string): Promise<SecureBuffer> {
    this.assertInitialized();

    // Check rate limiting
    this.checkRateLimit(walletId);

    try {
      // Find wallet file
      const { walletFile } = await this.findWallet(walletId);

      // Derive KEK from password
      const salt = Buffer.from(walletFile.entry.encryption.salt, 'base64');
      const kek = await this.deriveKey(password, salt);

      try {
        // Decrypt key material
        const encryptedData = Buffer.from(walletFile.encryptedKey.data, 'base64');
        const iv = Buffer.from(walletFile.encryptedKey.iv, 'base64');
        const authTag = Buffer.from(walletFile.encryptedKey.authTag, 'base64');

        const decrypted = await this.decrypt(encryptedData, kek, iv, authTag);

        // Record successful auth
        this.recordAuthSuccess(walletId);

        return decrypted;
      } finally {
        kek.dispose();
      }
    } catch (error) {
      // Record failed auth attempt
      if (error instanceof AuthenticationError || error instanceof KeyDecryptionError) {
        this.recordAuthFailure(walletId);
      }
      throw error;
    }
  }

  async storeKey(
    walletId: string,
    key: SecureBuffer,
    password: string,
    metadata: WalletMetadata
  ): Promise<void> {
    this.assertInitialized();

    // Validate password
    const passwordErrors = validatePassword(password, this.passwordPolicy);
    if (passwordErrors.length > 0) {
      throw new WeakPasswordError(passwordErrors);
    }

    // Check if wallet already exists
    try {
      await this.findWallet(walletId);
      throw new WalletExistsError(walletId);
    } catch (error) {
      if (!(error instanceof WalletNotFoundError)) {
        throw error;
      }
    }

    // Validate key format - must be 16 bytes (128-bit entropy)
    const keyBuffer = key.getBuffer();
    if (keyBuffer.length !== 16) {
      throw new InvalidKeyError('Invalid key length', 'Expected 16 bytes (128-bit entropy)');
    }

    // Derive wallet from entropy (private key material)
    let xrplWallet: Wallet;
    try {
      xrplWallet = Wallet.fromEntropy(keyBuffer);
    } catch {
      throw new InvalidKeyError('Could not derive wallet from key');
    }

    // Default to testnet for imported keys
    const network: XRPLNetwork = 'testnet';

    // Derive encryption key
    const salt = crypto.randomBytes(ARGON2_CONFIG.saltLength);
    const kek = await this.deriveKey(password, salt);

    try {
      // Encrypt key
      const { encryptedData, iv, authTag } = await this.encrypt(keyBuffer, kek);

      const now = new Date().toISOString();
      const entry: WalletEntry = {
        walletId,
        name: walletId,
        address: xrplWallet.classicAddress,
        publicKey: xrplWallet.publicKey,
        algorithm: 'ed25519',
        network,
        policyId: 'imported',
        encryption: {
          algorithm: 'aes-256-gcm',
          kdf: 'argon2id',
          kdfParams: {
            memoryCost: ARGON2_CONFIG.memoryCost,
            timeCost: ARGON2_CONFIG.timeCost,
            parallelism: ARGON2_CONFIG.parallelism,
          },
          salt: salt.toString('base64'),
        },
        metadata,
        createdAt: now,
        modifiedAt: now,
        status: 'active',
      };

      const walletFile: WalletFile = {
        version: 1,
        walletId,
        entry,
        encryptedKey: {
          data: encryptedData.toString('base64'),
          iv: iv.toString('base64'),
          authTag: authTag.toString('base64'),
        },
      };

      const walletPath = this.getWalletPath(network, walletId);
      await this.atomicWrite(walletPath, JSON.stringify(walletFile, null, 2));

      await this.updateIndex(network, entry, 'add');
    } finally {
      kek.dispose();
    }
  }

  async listWallets(network?: XRPLNetwork): Promise<WalletSummary[]> {
    this.assertInitialized();

    const networks = network ? [network] : (['mainnet', 'testnet', 'devnet'] as XRPLNetwork[]);
    const summaries: WalletSummary[] = [];

    for (const net of networks) {
      const indexPath = path.join(this.baseDir, net, 'index.json');
      try {
        const content = await fs.readFile(indexPath, 'utf-8');
        const index: WalletIndex = JSON.parse(content);

        for (const entry of index.wallets) {
          const summary: WalletSummary = {
            walletId: entry.walletId,
            name: entry.name,
            address: entry.address,
            network: entry.network,
            status: entry.status,
            createdAt: entry.createdAt,
            policyId: entry.policyId,
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
        // Index doesn't exist yet
      }
    }

    return summaries;
  }

  async getWallet(walletId: string): Promise<WalletEntry> {
    this.assertInitialized();

    const { walletFile } = await this.findWallet(walletId);
    return walletFile.entry;
  }

  async deleteWallet(walletId: string, password: string): Promise<void> {
    this.assertInitialized();

    // Verify authentication
    this.checkRateLimit(walletId);

    const { network, walletFile, filePath } = await this.findWallet(walletId);

    // Verify password by attempting to decrypt
    const salt = Buffer.from(walletFile.entry.encryption.salt, 'base64');
    const kek = await this.deriveKey(password, salt);

    try {
      const encryptedData = Buffer.from(walletFile.encryptedKey.data, 'base64');
      const iv = Buffer.from(walletFile.encryptedKey.iv, 'base64');
      const authTag = Buffer.from(walletFile.encryptedKey.authTag, 'base64');

      const decrypted = await this.decrypt(encryptedData, kek, iv, authTag);
      decrypted.dispose();

      this.recordAuthSuccess(walletId);
    } catch (error) {
      this.recordAuthFailure(walletId);
      throw error;
    } finally {
      kek.dispose();
    }

    // Delete wallet file
    await this.fileLock.withLock(filePath, async () => {
      // Overwrite file contents before deletion (secure delete)
      const fileSize = (await fs.stat(filePath)).size;
      const randomData = crypto.randomBytes(fileSize);
      await fs.writeFile(filePath, randomData);
      await fs.unlink(filePath);
    });

    // Update index
    await this.updateIndex(network, walletFile.entry, 'remove');
  }

  async rotateKey(walletId: string, currentPassword: string, newPassword: string): Promise<void> {
    this.assertInitialized();

    // Validate new password
    const passwordErrors = validatePassword(newPassword, this.passwordPolicy);
    if (passwordErrors.length > 0) {
      throw new WeakPasswordError(passwordErrors);
    }

    // Load current key
    const key = await this.loadKey(walletId, currentPassword);

    try {
      const { network, walletFile, filePath } = await this.findWallet(walletId);

      // Generate new salt and derive new KEK
      const newSalt = crypto.randomBytes(ARGON2_CONFIG.saltLength);
      const newKek = await this.deriveKey(newPassword, newSalt);

      try {
        // Re-encrypt with new key
        const { encryptedData, iv, authTag } = await this.encrypt(key.getBuffer(), newKek);

        // Update wallet file
        walletFile.entry.encryption.salt = newSalt.toString('base64');
        walletFile.entry.modifiedAt = new Date().toISOString();
        walletFile.encryptedKey = {
          data: encryptedData.toString('base64'),
          iv: iv.toString('base64'),
          authTag: authTag.toString('base64'),
        };

        // Write atomically
        await this.atomicWrite(filePath, JSON.stringify(walletFile, null, 2));

        // Update index
        await this.updateIndex(network, walletFile.entry, 'update');
      } finally {
        newKek.dispose();
      }
    } finally {
      key.dispose();
    }
  }

  async updateMetadata(walletId: string, updates: Partial<WalletMetadata>): Promise<void> {
    this.assertInitialized();

    const { network, walletFile, filePath } = await this.findWallet(walletId);

    // Update metadata
    walletFile.entry.metadata = {
      ...walletFile.entry.metadata,
      ...updates,
    };
    walletFile.entry.modifiedAt = new Date().toISOString();

    // Write atomically
    await this.atomicWrite(filePath, JSON.stringify(walletFile, null, 2));

    // Update index
    await this.updateIndex(network, walletFile.entry, 'update');
  }

  async exportBackup(
    walletId: string,
    password: string,
    format: BackupFormat
  ): Promise<EncryptedBackup> {
    this.assertInitialized();

    // Verify password and load key
    const key = await this.loadKey(walletId, password);

    try {
      const { walletFile } = await this.findWallet(walletId);

      // Create backup payload
      const payload = {
        version: 1,
        exportedAt: new Date().toISOString(),
        wallet: {
          entry: walletFile.entry,
          seed: key.getBuffer().toString('hex'),
        },
      };

      // Generate new salt for backup encryption
      const backupSalt = crypto.randomBytes(ARGON2_CONFIG.saltLength);
      const backupKek = await this.deriveKey(password, backupSalt);

      try {
        // Encrypt backup payload
        const payloadBuffer = Buffer.from(JSON.stringify(payload));
        const { encryptedData, iv, authTag } = await this.encrypt(payloadBuffer, backupKek);

        // Calculate checksum
        const checksum = crypto.createHash('sha256').update(encryptedData).digest('hex');

        const backup: EncryptedBackup = {
          version: 1,
          format,
          createdAt: new Date().toISOString(),
          sourceProvider: this.providerType,
          encryption: {
            algorithm: 'aes-256-gcm',
            kdf: 'argon2id',
            kdfParams: {
              memoryCost: ARGON2_CONFIG.memoryCost,
              timeCost: ARGON2_CONFIG.timeCost,
              parallelism: ARGON2_CONFIG.parallelism,
            },
            salt: backupSalt.toString('base64'),
            iv: iv.toString('base64'),
            authTag: authTag.toString('base64'),
          },
          payload: encryptedData.toString('base64'),
          checksum,
        };

        return backup;
      } finally {
        backupKek.dispose();
      }
    } finally {
      key.dispose();
    }
  }

  async importBackup(
    backup: EncryptedBackup,
    password: string,
    options?: ImportOptions
  ): Promise<WalletEntry> {
    this.assertInitialized();

    // Validate backup format
    if (backup.version !== 1) {
      throw new BackupFormatError('Unsupported backup version', 1);
    }

    // Verify checksum
    const payloadData = Buffer.from(backup.payload, 'base64');
    const computedChecksum = crypto.createHash('sha256').update(payloadData).digest('hex');

    if (computedChecksum !== backup.checksum) {
      throw new BackupFormatError('Checksum verification failed');
    }

    // Derive KEK from password
    const salt = Buffer.from(backup.encryption.salt, 'base64');
    const kek = await this.deriveKey(password, salt);

    let decryptedPayload: SecureBuffer;
    try {
      const iv = Buffer.from(backup.encryption.iv, 'base64');
      const authTag = Buffer.from(backup.encryption.authTag, 'base64');

      decryptedPayload = await this.decrypt(payloadData, kek, iv, authTag);
    } finally {
      kek.dispose();
    }

    try {
      // Parse payload
      const payload = JSON.parse(decryptedPayload.getBuffer().toString());

      const walletId = options?.newName || payload.wallet.entry.walletId;
      const targetNetwork = options?.targetNetwork || payload.wallet.entry.network;

      // Check if wallet exists
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

      // Import the seed
      const seedBuffer = Buffer.from(payload.wallet.seed, 'hex');
      const seed = SecureBuffer.from(seedBuffer);

      try {
        // Store with potentially new password
        const storePassword = options?.newPassword || password;

        // Derive new encryption key
        const newSalt = crypto.randomBytes(ARGON2_CONFIG.saltLength);
        const newKek = await this.deriveKey(storePassword, newSalt);

        try {
          const { encryptedData, iv, authTag } = await this.encrypt(seed.getBuffer(), newKek);

          const now = new Date().toISOString();
          const entry: WalletEntry = {
            ...payload.wallet.entry,
            walletId,
            network: targetNetwork,
            encryption: {
              algorithm: 'aes-256-gcm',
              kdf: 'argon2id',
              kdfParams: {
                memoryCost: ARGON2_CONFIG.memoryCost,
                timeCost: ARGON2_CONFIG.timeCost,
                parallelism: ARGON2_CONFIG.parallelism,
              },
              salt: newSalt.toString('base64'),
            },
            modifiedAt: now,
            metadata: {
              ...(payload.wallet.entry.metadata || {}),
              customData: {
                ...(payload.wallet.entry.metadata?.customData || {}),
                importedAt: now,
                importedFrom: backup.sourceProvider,
              },
            },
          };

          const walletFile: WalletFile = {
            version: 1,
            walletId,
            entry,
            encryptedKey: {
              data: encryptedData.toString('base64'),
              iv: iv.toString('base64'),
              authTag: authTag.toString('base64'),
            },
          };

          const walletPath = this.getWalletPath(targetNetwork, walletId);
          await this.atomicWrite(walletPath, JSON.stringify(walletFile, null, 2));

          await this.updateIndex(targetNetwork, entry, 'add');

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

  private assertInitialized(): void {
    if (!this.initialized) {
      throw new KeystoreInitializationError('Provider not initialized');
    }
  }

  private async ensureDirectoryStructure(): Promise<void> {
    // Create base directory
    await fs.mkdir(this.baseDir, { recursive: true, mode: PERMISSIONS.DIRECTORY });

    // Create network directories
    for (const network of ['mainnet', 'testnet', 'devnet']) {
      const walletsDir = path.join(this.baseDir, network, 'wallets');
      await fs.mkdir(walletsDir, { recursive: true, mode: PERMISSIONS.DIRECTORY });
    }

    // Create backups directory
    const backupDir = path.join(this.baseDir, 'backups');
    await fs.mkdir(backupDir, { recursive: true, mode: PERMISSIONS.DIRECTORY });
  }

  private async verifyPermissions(): Promise<void> {
    // Verify base directory permissions
    const stats = await fs.stat(this.baseDir);
    const mode = stats.mode & 0o777;

    if (mode !== PERMISSIONS.DIRECTORY) {
      // Attempt to fix
      await fs.chmod(this.baseDir, PERMISSIONS.DIRECTORY);
    }
  }

  private generateWalletId(): string {
    const timestamp = Date.now().toString(36);
    const random = crypto.randomBytes(8).toString('hex');
    return `wallet_${timestamp}_${random}`;
  }

  private getWalletPath(network: XRPLNetwork, walletId: string): string {
    return path.join(this.baseDir, network, 'wallets', `${walletId}.wallet.json`);
  }

  private async findWallet(
    walletId: string
  ): Promise<{ network: XRPLNetwork; walletFile: WalletFile; filePath: string }> {
    for (const network of ['mainnet', 'testnet', 'devnet'] as XRPLNetwork[]) {
      const filePath = this.getWalletPath(network, walletId);
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const walletFile: WalletFile = JSON.parse(content);
        return { network, walletFile, filePath };
      } catch {
        // Not in this network
      }
    }
    throw new WalletNotFoundError(walletId);
  }

  private async updateIndex(
    network: XRPLNetwork,
    entry: WalletEntry,
    operation: 'add' | 'remove' | 'update'
  ): Promise<void> {
    const indexPath = path.join(this.baseDir, network, 'index.json');

    await this.fileLock.withLock(indexPath, async () => {
      let index: WalletIndex;

      try {
        const content = await fs.readFile(indexPath, 'utf-8');
        index = JSON.parse(content);
      } catch {
        index = { version: 1, wallets: [], modifiedAt: '' };
      }

      switch (operation) {
        case 'add':
          index.wallets.push(entry);
          break;
        case 'remove':
          index.wallets = index.wallets.filter((w) => w.walletId !== entry.walletId);
          break;
        case 'update':
          index.wallets = index.wallets.map((w) => (w.walletId === entry.walletId ? entry : w));
          break;
      }

      index.modifiedAt = new Date().toISOString();

      await this.atomicWrite(indexPath, JSON.stringify(index, null, 2));
    });
  }

  // ========================================================================
  // Cryptographic Operations
  // ========================================================================

  /**
   * Derives a 256-bit key from password using Argon2id.
   */
  private async deriveKey(password: string, salt: Buffer): Promise<SecureBuffer> {
    const derivedKey = await argon2.hash(password, {
      type: ARGON2_CONFIG.type,
      memoryCost: ARGON2_CONFIG.memoryCost,
      timeCost: ARGON2_CONFIG.timeCost,
      parallelism: ARGON2_CONFIG.parallelism,
      hashLength: ARGON2_CONFIG.hashLength,
      salt,
      raw: true, // Return raw bytes, not encoded string
    });

    return SecureBuffer.from(derivedKey);
  }

  /**
   * Encrypts data using AES-256-GCM.
   */
  private async encrypt(
    plaintext: Buffer,
    key: SecureBuffer
  ): Promise<{ encryptedData: Buffer; iv: Buffer; authTag: Buffer }> {
    // Generate cryptographically secure random IV
    const iv = crypto.randomBytes(AES_CONFIG.ivLength);

    // Create cipher
    const cipher = crypto.createCipheriv(AES_CONFIG.algorithm, key.getBuffer(), iv, {
      authTagLength: AES_CONFIG.authTagLength,
    });

    // Encrypt
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);

    // Get authentication tag
    const authTag = cipher.getAuthTag();

    return {
      encryptedData: encrypted,
      iv,
      authTag,
    };
  }

  /**
   * Decrypts data using AES-256-GCM.
   */
  private async decrypt(
    ciphertext: Buffer,
    key: SecureBuffer,
    iv: Buffer,
    authTag: Buffer
  ): Promise<SecureBuffer> {
    try {
      // Create decipher
      const decipher = crypto.createDecipheriv(AES_CONFIG.algorithm, key.getBuffer(), iv, {
        authTagLength: AES_CONFIG.authTagLength,
      });

      // Set auth tag BEFORE decryption (required for GCM)
      decipher.setAuthTag(authTag);

      // Decrypt
      const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

      // Return as SecureBuffer for memory safety
      return SecureBuffer.from(decrypted);
    } catch (error) {
      // GCM auth failure or other crypto error
      if (error instanceof Error && error.message.includes('auth')) {
        throw new AuthenticationError();
      }
      throw new KeyDecryptionError('Decryption failed');
    }
  }

  // ========================================================================
  // File System Operations
  // ========================================================================

  /**
   * Atomically writes content to a file using temp file + rename pattern.
   */
  private async atomicWrite(filePath: string, content: string): Promise<void> {
    const dir = path.dirname(filePath);
    const tempPath = path.join(dir, `.${path.basename(filePath)}.tmp.${process.pid}`);

    try {
      // Write to temp file with secure permissions
      await fs.writeFile(tempPath, content, {
        encoding: 'utf-8',
        mode: PERMISSIONS.FILE,
      });

      // Atomic rename
      await fs.rename(tempPath, filePath);
    } catch (error) {
      // Clean up temp file on failure
      try {
        await fs.unlink(tempPath);
      } catch {
        // Ignore cleanup errors
      }
      throw new KeystoreWriteError(`Failed to write ${filePath}: ${error}`, 'create');
    }
  }

  // ========================================================================
  // Rate Limiting
  // ========================================================================

  /**
   * Checks if wallet is currently locked out.
   */
  private checkRateLimit(walletId: string): void {
    const lockout = this.lockouts.get(walletId);
    if (lockout && lockout > new Date()) {
      throw new AuthenticationError();
    }

    // Clean old lockout
    if (lockout) {
      this.lockouts.delete(walletId);
    }
  }

  /**
   * Records successful authentication.
   */
  private recordAuthSuccess(walletId: string): void {
    this.authAttempts.delete(walletId);
    this.lockouts.delete(walletId);
  }

  /**
   * Records failed authentication attempt.
   */
  private recordAuthFailure(walletId: string): void {
    const now = new Date();
    const windowStart = new Date(now.getTime() - RATE_LIMIT_CONFIG.windowSeconds * 1000);

    // Get or create attempt list
    let attempts = this.authAttempts.get(walletId) || [];

    // Filter to recent attempts
    attempts = attempts.filter((a) => a.timestamp > windowStart);

    // Add new failure
    attempts.push({ timestamp: now, success: false });
    this.authAttempts.set(walletId, attempts);

    // Check if lockout needed
    const failures = attempts.filter((a) => !a.success).length;
    if (failures >= RATE_LIMIT_CONFIG.maxAttempts) {
      // Calculate lockout duration (progressive)
      const lockoutCount = Math.floor(failures / RATE_LIMIT_CONFIG.maxAttempts);
      const duration =
        RATE_LIMIT_CONFIG.lockoutSeconds *
        Math.pow(RATE_LIMIT_CONFIG.lockoutMultiplier, lockoutCount - 1);

      const lockoutUntil = new Date(now.getTime() + duration * 1000);
      this.lockouts.set(walletId, lockoutUntil);
    }
  }
}
