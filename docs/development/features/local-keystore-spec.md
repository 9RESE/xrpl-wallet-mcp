# Local File Keystore Provider Implementation Specification

**Version**: 1.0.0
**Date**: 2026-01-28
**Author**: Backend Engineer
**Status**: Draft

---

## Table of Contents

1. [Overview](#1-overview)
2. [LocalFileKeystoreProvider Class](#2-localfilekeystoreprovider-class)
3. [File Format Specification](#3-file-format-specification)
4. [AES-256-GCM Encryption Implementation](#4-aes-256-gcm-encryption-implementation)
5. [Argon2id Key Derivation](#5-argon2id-key-derivation)
6. [File System Operations](#6-file-system-operations)
7. [SecureBuffer Integration](#7-securebuffer-integration)
8. [Backup File Format](#8-backup-file-format)
9. [Recovery Procedures](#9-recovery-procedures)
10. [Error Handling](#10-error-handling)
11. [Test Fixtures](#11-test-fixtures)

---

## 1. Overview

### 1.1 Purpose

This document specifies the implementation of the `LocalFileKeystoreProvider` class, which provides secure local file-based storage for XRPL wallet private keys. This is the Phase 1 implementation of the keystore interface as defined in ADR-001.

### 1.2 Security Model

```
User Password
      │
      ▼
  ┌───────────────────────────────────────────┐
  │              Argon2id KDF                  │
  │  (64MB memory, 3 iterations, 4 parallel)  │
  │  + Unique 32-byte salt per wallet         │
  └───────────────────────────────────────────┘
      │
      ▼
Key Encryption Key (KEK) - 256 bits
      │
      ▼
  ┌───────────────────────────────────────────┐
  │            AES-256-GCM                     │
  │  + 12-byte IV (unique per operation)      │
  │  + 16-byte authentication tag             │
  └───────────────────────────────────────────┘
      │
      ▼
Encrypted Private Key Material
      │
      ▼
Wallet File (.wallet.json)
      │
Stored with 0600 permissions
```

### 1.3 Directory Structure

```
~/.xrpl-wallet-mcp/
├── config.json                    # Global configuration
├── mainnet/
│   ├── keystore/
│   │   ├── {wallet-id}.wallet.json    # Individual wallet files
│   │   ├── {wallet-id}.wallet.json
│   │   └── ...
│   ├── index.json                 # Wallet index (metadata only)
│   └── audit.log                  # Network-specific audit log
├── testnet/
│   └── ...
├── devnet/
│   └── ...
└── backups/
    ├── {wallet-id}_{timestamp}.backup.json
    └── ...
```

---

## 2. LocalFileKeystoreProvider Class

### 2.1 Class Definition

```typescript
import { promises as fs } from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as argon2 from 'argon2';
import { SecureBuffer } from './secure-buffer';
import {
  KeystoreProvider,
  KeystoreConfig,
  KeystoreHealthResult,
  WalletEntry,
  WalletSummary,
  WalletPolicy,
  WalletCreateOptions,
  WalletMetadata,
  EncryptedBackup,
  ImportOptions,
  BackupFormat,
  XRPLNetwork,
} from './keystore-interface';

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
 *
 * @implements {KeystoreProvider}
 */
export class LocalFileKeystoreProvider implements KeystoreProvider {
  readonly providerType = 'local-file' as const;
  readonly providerVersion = '1.0.0';

  private baseDir: string = '';
  private passwordPolicy: PasswordPolicy;
  private auditConfig: AuditConfig | null = null;
  private maxWalletsPerNetwork: number;
  private initialized: boolean = false;
  private fileLock: FileLock;

  // Rate limiting state
  private authAttempts: Map<string, AuthAttemptRecord[]> = new Map();
  private lockouts: Map<string, Date> = new Map();

  constructor() {
    this.passwordPolicy = DEFAULT_PASSWORD_POLICY;
    this.maxWalletsPerNetwork = 100;
    this.fileLock = new FileLock();
  }

  // --- Lifecycle Methods ---

  async initialize(config: KeystoreConfig): Promise<void> {
    if (this.initialized) {
      throw new KeystoreInitializationError('Provider already initialized');
    }

    // Resolve base directory
    this.baseDir = config.baseDir
      ? path.resolve(config.baseDir.replace(/^~/, process.env.HOME || ''))
      : path.join(process.env.HOME || '', '.xrpl-wallet-mcp');

    // Apply configuration
    if (config.passwordPolicy) {
      this.passwordPolicy = { ...DEFAULT_PASSWORD_POLICY, ...config.passwordPolicy };
    }
    if (config.auditConfig) {
      this.auditConfig = config.auditConfig;
    }
    if (config.maxWalletsPerNetwork !== undefined) {
      this.maxWalletsPerNetwork = config.maxWalletsPerNetwork;
    }

    // Create directory structure
    await this.ensureDirectoryStructure();

    // Verify permissions
    await this.verifyPermissions();

    this.initialized = true;

    await this.audit('PROVIDER_INITIALIZED', {
      baseDir: this.baseDir,
      version: this.providerVersion,
    });
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
    } catch (err) {
      encryptionAvailable = false;
      errors.push('AES-256-GCM encryption not available');
    }

    // Count networks and wallets
    for (const network of ['mainnet', 'testnet', 'devnet'] as XRPLNetwork[]) {
      const networkDir = path.join(this.baseDir, network, 'keystore');
      try {
        await fs.access(networkDir);
        networkCount++;
        const files = await fs.readdir(networkDir);
        walletCount += files.filter(f => f.endsWith('.wallet.json')).length;
      } catch {
        // Network directory doesn't exist yet
      }
    }

    return {
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
      errors: errors.length > 0 ? errors : undefined,
    };
  }

  async close(): Promise<void> {
    // Clear rate limiting state
    this.authAttempts.clear();
    this.lockouts.clear();

    await this.audit('PROVIDER_CLOSED', {});

    this.initialized = false;
  }

  // --- Wallet CRUD Operations ---

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

    // Generate key pair
    const { seed, keypair } = await this.generateKeyPair(options?.algorithm || 'ed25519');

    try {
      // Derive encryption key
      const salt = crypto.randomBytes(32);
      const kek = await this.deriveKey(options.password, salt);

      // Encrypt seed
      const { encryptedData, iv, authTag } = await this.encrypt(seed.getBuffer(), kek);

      // Zero KEK immediately
      kek.zero();

      // Create wallet entry
      const now = new Date().toISOString();
      const entry: WalletEntry = {
        walletId,
        name: options?.name || `Wallet ${walletId.slice(0, 8)}`,
        address: keypair.address,
        publicKey: keypair.publicKey,
        algorithm: options?.algorithm || 'ed25519',
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
          description: options?.description,
          tags: options?.tags,
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

      await this.audit('WALLET_CREATED', {
        walletId,
        network,
        address: keypair.address,
        algorithm: options?.algorithm || 'ed25519',
      });

      return entry;
    } finally {
      // Always zero seed
      seed.zero();
    }
  }

  async loadKey(walletId: string, password: string): Promise<SecureBuffer> {
    this.assertInitialized();

    // Check rate limiting
    await this.checkRateLimit(walletId);

    try {
      // Find wallet file
      const { network, walletFile } = await this.findWallet(walletId);

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

        await this.audit('KEY_LOADED', { walletId, network });

        return decrypted;
      } finally {
        kek.zero();
      }
    } catch (error) {
      // Record failed auth attempt
      if (error instanceof AuthenticationError || error instanceof KeyDecryptionError) {
        this.recordAuthFailure(walletId);
        await this.audit('AUTH_FAILURE', { walletId });
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

    // Validate key format
    const keyBuffer = key.getBuffer();
    if (keyBuffer.length !== 32) {
      throw new InvalidKeyError('Invalid key length', 'Expected 32 bytes');
    }

    // Derive keypair from seed to get address/pubkey
    const keypair = this.deriveKeypairFromSeed(keyBuffer);

    // Default to testnet for imported keys
    const network: XRPLNetwork = 'testnet';

    // Derive encryption key
    const salt = crypto.randomBytes(32);
    const kek = await this.deriveKey(password, salt);

    try {
      // Encrypt key
      const { encryptedData, iv, authTag } = await this.encrypt(keyBuffer, kek);

      const now = new Date().toISOString();
      const entry: WalletEntry = {
        walletId,
        name: walletId,
        address: keypair.address,
        publicKey: keypair.publicKey,
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

      await this.audit('KEY_STORED', { walletId, network, address: keypair.address });
    } finally {
      kek.zero();
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
          summaries.push({
            walletId: entry.walletId,
            name: entry.name,
            address: entry.address,
            network: entry.network,
            status: entry.status,
            createdAt: entry.createdAt,
            lastUsedAt: entry.metadata?.lastUsedAt,
            policyId: entry.policyId,
            tags: entry.metadata?.tags,
          });
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
    await this.checkRateLimit(walletId);

    const { network, walletFile, filePath } = await this.findWallet(walletId);

    // Verify password by attempting to decrypt
    const salt = Buffer.from(walletFile.entry.encryption.salt, 'base64');
    const kek = await this.deriveKey(password, salt);

    try {
      const encryptedData = Buffer.from(walletFile.encryptedKey.data, 'base64');
      const iv = Buffer.from(walletFile.encryptedKey.iv, 'base64');
      const authTag = Buffer.from(walletFile.encryptedKey.authTag, 'base64');

      const decrypted = await this.decrypt(encryptedData, kek, iv, authTag);
      decrypted.zero();

      this.recordAuthSuccess(walletId);
    } catch (error) {
      this.recordAuthFailure(walletId);
      await this.audit('AUTH_FAILURE', { walletId, operation: 'delete' });
      throw error;
    } finally {
      kek.zero();
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

    await this.audit('WALLET_DELETED', { walletId, network });
  }

  async rotateKey(
    walletId: string,
    currentPassword: string,
    newPassword: string
  ): Promise<void> {
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
      const newSalt = crypto.randomBytes(32);
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

        await this.audit('KEY_ROTATED', { walletId, network });
      } finally {
        newKek.zero();
      }
    } finally {
      key.zero();
    }
  }

  async updateMetadata(
    walletId: string,
    updates: Partial<WalletMetadata>
  ): Promise<void> {
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

    await this.audit('METADATA_UPDATED', { walletId, network });
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
      const { network, walletFile } = await this.findWallet(walletId);

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
      const backupSalt = crypto.randomBytes(32);
      const backupKek = await this.deriveKey(password, backupSalt);

      try {
        // Encrypt backup payload
        const payloadBuffer = Buffer.from(JSON.stringify(payload));
        const { encryptedData, iv, authTag } = await this.encrypt(payloadBuffer, backupKek);

        // Calculate checksum
        const checksum = crypto
          .createHash('sha256')
          .update(encryptedData)
          .digest('hex');

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

        await this.audit('BACKUP_EXPORTED', { walletId, network, format });

        return backup;
      } finally {
        backupKek.zero();
      }
    } finally {
      key.zero();
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
    const computedChecksum = crypto
      .createHash('sha256')
      .update(payloadData)
      .digest('hex');

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
      kek.zero();
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
        const newSalt = crypto.randomBytes(32);
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
              ...payload.wallet.entry.metadata,
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

          await this.audit('BACKUP_IMPORTED', {
            walletId,
            network: targetNetwork,
            address: entry.address,
          });

          return entry;
        } finally {
          newKek.zero();
        }
      } finally {
        seed.zero();
      }
    } finally {
      decryptedPayload.zero();
    }
  }

  // --- Private Helper Methods ---

  private assertInitialized(): void {
    if (!this.initialized) {
      throw new KeystoreInitializationError('Provider not initialized');
    }
  }

  private async ensureDirectoryStructure(): Promise<void> {
    // Create base directory
    await fs.mkdir(this.baseDir, { recursive: true, mode: 0o700 });

    // Create network directories
    for (const network of ['mainnet', 'testnet', 'devnet']) {
      const keystoreDir = path.join(this.baseDir, network, 'keystore');
      await fs.mkdir(keystoreDir, { recursive: true, mode: 0o700 });
    }

    // Create backups directory
    const backupDir = path.join(this.baseDir, 'backups');
    await fs.mkdir(backupDir, { recursive: true, mode: 0o700 });
  }

  private async verifyPermissions(): Promise<void> {
    // Verify base directory permissions
    const stats = await fs.stat(this.baseDir);
    const mode = stats.mode & 0o777;

    if (mode !== 0o700) {
      // Attempt to fix
      await fs.chmod(this.baseDir, 0o700);
    }
  }

  private generateWalletId(): string {
    const timestamp = Date.now().toString(36);
    const random = crypto.randomBytes(8).toString('hex');
    return `wallet_${timestamp}_${random}`;
  }

  private async generateKeyPair(
    algorithm: 'ed25519' | 'secp256k1'
  ): Promise<{ seed: SecureBuffer; keypair: { address: string; publicKey: string } }> {
    // Generate 32 bytes of entropy
    const seedBuffer = crypto.randomBytes(32);
    const seed = SecureBuffer.from(seedBuffer);

    // Derive keypair (implementation depends on XRPL library)
    const keypair = this.deriveKeypairFromSeed(seedBuffer, algorithm);

    return { seed, keypair };
  }

  private deriveKeypairFromSeed(
    seed: Buffer,
    algorithm: 'ed25519' | 'secp256k1' = 'ed25519'
  ): { address: string; publicKey: string } {
    // This would use xrpl-lib in actual implementation
    // For specification purposes, we show the interface
    // const wallet = xrpl.Wallet.fromSeed(seed.toString('hex'), { algorithm });
    // return { address: wallet.classicAddress, publicKey: wallet.publicKey };

    // Placeholder for specification
    const hash = crypto.createHash('sha256').update(seed).digest();
    return {
      address: `r${hash.toString('hex').slice(0, 33)}`,
      publicKey: hash.toString('hex'),
    };
  }

  private getWalletPath(network: XRPLNetwork, walletId: string): string {
    return path.join(this.baseDir, network, 'keystore', `${walletId}.wallet.json`);
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
          index.wallets = index.wallets.filter(w => w.walletId !== entry.walletId);
          break;
        case 'update':
          index.wallets = index.wallets.map(w =>
            w.walletId === entry.walletId ? entry : w
          );
          break;
      }

      index.modifiedAt = new Date().toISOString();

      await this.atomicWrite(indexPath, JSON.stringify(index, null, 2));
    });
  }

  private async audit(event: string, data: Record<string, unknown>): Promise<void> {
    if (!this.auditConfig?.enabled) return;

    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      provider: this.providerType,
      ...data,
    };

    // This would write to audit log file
    // For specification, we show the interface
    console.log('[AUDIT]', JSON.stringify(logEntry));
  }
}
```

---

## 3. File Format Specification

### 3.1 Wallet File Structure

Each wallet is stored as an individual JSON file with the following structure:

```typescript
/**
 * Wallet file format (stored as {walletId}.wallet.json)
 */
interface WalletFile {
  /** File format version */
  version: 1;

  /** Unique wallet identifier */
  walletId: string;

  /** Wallet metadata and public information */
  entry: WalletEntry;

  /** Encrypted private key material */
  encryptedKey: EncryptedKeyData;
}

interface EncryptedKeyData {
  /** Base64-encoded encrypted seed/key */
  data: string;

  /** Base64-encoded initialization vector (12 bytes) */
  iv: string;

  /** Base64-encoded GCM authentication tag (16 bytes) */
  authTag: string;
}
```

### 3.2 Example Wallet File

```json
{
  "version": 1,
  "walletId": "wallet_m1a2b3c4_d5e6f7g8h9i0j1k2",
  "entry": {
    "walletId": "wallet_m1a2b3c4_d5e6f7g8h9i0j1k2",
    "name": "Trading Wallet",
    "address": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
    "publicKey": "ED5F5AC8B98974A3CA843326D9B88CEBD79A5E79B4A3C3F7A3E8F1B2C3D4E5F6A7",
    "algorithm": "ed25519",
    "network": "mainnet",
    "policyId": "policy_default_v1",
    "encryption": {
      "algorithm": "aes-256-gcm",
      "kdf": "argon2id",
      "kdfParams": {
        "memoryCost": 65536,
        "timeCost": 3,
        "parallelism": 4
      },
      "salt": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5"
    },
    "metadata": {
      "description": "Primary trading wallet",
      "tags": ["trading", "primary"],
      "lastUsedAt": "2026-01-28T12:00:00.000Z",
      "transactionCount": 42
    },
    "createdAt": "2026-01-28T00:00:00.000Z",
    "modifiedAt": "2026-01-28T12:00:00.000Z",
    "status": "active"
  },
  "encryptedKey": {
    "data": "c3VwZXJzZWNyZXRlbmNyeXB0ZWRkYXRh...",
    "iv": "MTIzNDU2Nzg5MDEy",
    "authTag": "YXV0aGVudGljYXRpb250YWc="
  }
}
```

### 3.3 Wallet Index Structure

The index file provides quick access to wallet metadata without decryption:

```typescript
interface WalletIndex {
  /** Index format version */
  version: 1;

  /** List of wallet entries (metadata only, no keys) */
  wallets: WalletEntry[];

  /** Last modification timestamp */
  modifiedAt: string;
}
```

### 3.4 Metadata Fields

| Field | Type | Description | Encrypted |
|-------|------|-------------|-----------|
| `walletId` | string | Unique identifier | No |
| `name` | string | Human-readable name | No |
| `address` | string | XRPL classic address | No |
| `publicKey` | string | Hex-encoded public key | No |
| `algorithm` | string | Key algorithm (ed25519/secp256k1) | No |
| `network` | string | Target network | No |
| `policyId` | string | Associated policy | No |
| `encryption.salt` | string | KDF salt (base64) | No |
| `encryption.kdfParams` | object | Argon2id parameters | No |
| `encryptedKey.data` | string | Encrypted seed (base64) | Yes |
| `encryptedKey.iv` | string | Encryption IV (base64) | No |
| `encryptedKey.authTag` | string | GCM auth tag (base64) | No |

---

## 4. AES-256-GCM Encryption Implementation

### 4.1 Encryption Function

```typescript
/**
 * AES-256-GCM encryption configuration
 */
const AES_CONFIG = {
  algorithm: 'aes-256-gcm' as const,
  keyLength: 32,      // 256 bits
  ivLength: 12,       // 96 bits (NIST recommended for GCM)
  authTagLength: 16,  // 128 bits
};

/**
 * Encrypts data using AES-256-GCM with the provided key.
 *
 * @param plaintext - Data to encrypt
 * @param key - SecureBuffer containing 256-bit encryption key
 * @returns Encrypted data, IV, and authentication tag
 */
async function encrypt(
  plaintext: Buffer,
  key: SecureBuffer
): Promise<{ encryptedData: Buffer; iv: Buffer; authTag: Buffer }> {
  // Generate cryptographically secure random IV
  const iv = crypto.randomBytes(AES_CONFIG.ivLength);

  // Create cipher
  const cipher = crypto.createCipheriv(
    AES_CONFIG.algorithm,
    key.getBuffer(),
    iv,
    { authTagLength: AES_CONFIG.authTagLength }
  );

  // Encrypt
  const encrypted = Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
  ]);

  // Get authentication tag
  const authTag = cipher.getAuthTag();

  return {
    encryptedData: encrypted,
    iv,
    authTag,
  };
}
```

### 4.2 Decryption Function

```typescript
/**
 * Decrypts data using AES-256-GCM with the provided key.
 *
 * SECURITY: Authentication tag is verified before decryption.
 * If verification fails, throws KeyDecryptionError.
 *
 * @param ciphertext - Encrypted data
 * @param key - SecureBuffer containing 256-bit decryption key
 * @param iv - Initialization vector used during encryption
 * @param authTag - Authentication tag for verification
 * @returns SecureBuffer containing decrypted data
 * @throws KeyDecryptionError if authentication fails or decryption errors
 */
async function decrypt(
  ciphertext: Buffer,
  key: SecureBuffer,
  iv: Buffer,
  authTag: Buffer
): Promise<SecureBuffer> {
  try {
    // Create decipher
    const decipher = crypto.createDecipheriv(
      AES_CONFIG.algorithm,
      key.getBuffer(),
      iv,
      { authTagLength: AES_CONFIG.authTagLength }
    );

    // Set auth tag BEFORE decryption (required for GCM)
    decipher.setAuthTag(authTag);

    // Decrypt
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(), // This verifies the auth tag
    ]);

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
```

### 4.3 IV Generation Requirements

| Requirement | Specification |
|-------------|---------------|
| Length | 12 bytes (96 bits) |
| Source | `crypto.randomBytes()` (CSPRNG) |
| Uniqueness | New IV for every encryption operation |
| Storage | Stored alongside ciphertext (not secret) |
| Never Reuse | Same IV + Key combination must never be used twice |

### 4.4 Authentication Tag Handling

```typescript
/**
 * GCM authentication tag requirements:
 *
 * 1. Tag length: 16 bytes (128 bits) - maximum security
 * 2. Tag is generated during encryption (cipher.getAuthTag())
 * 3. Tag MUST be set before any decryption (decipher.setAuthTag())
 * 4. decipher.final() verifies the tag and throws on failure
 * 5. Tag is NOT secret - stored alongside ciphertext
 * 6. Tag prevents:
 *    - Ciphertext modification
 *    - IV modification
 *    - Truncation attacks
 *    - Bit-flipping attacks
 */
```

### 4.5 Key Wrapping Pattern

```typescript
/**
 * Key wrapping flow:
 *
 * User Password
 *       │
 *       ▼
 * ┌─────────────────┐
 * │   Argon2id KDF  │ ← Salt (32 bytes, unique per wallet)
 * └─────────────────┘
 *       │
 *       ▼
 * KEK (256-bit Key Encryption Key)
 *       │
 *       ▼
 * ┌─────────────────┐
 * │  AES-256-GCM    │ ← IV (12 bytes, unique per operation)
 * └─────────────────┘
 *       │
 *       ▼
 * Encrypted Seed + Auth Tag
 */
```

---

## 5. Argon2id Key Derivation

### 5.1 Configuration

```typescript
/**
 * Argon2id configuration per ADR-002
 */
const ARGON2_CONFIG = {
  type: argon2.argon2id,      // Hybrid mode
  memoryCost: 65536,          // 64 MB
  timeCost: 3,                // 3 iterations
  parallelism: 4,             // 4 threads
  hashLength: 32,             // 256-bit output (matches AES-256)
  saltLength: 32,             // 256-bit salt
};
```

### 5.2 Key Derivation Implementation

```typescript
import * as argon2 from 'argon2';

/**
 * Derives a 256-bit key from password using Argon2id.
 *
 * Time: ~500ms on modern hardware (64MB memory, 3 iterations)
 *
 * @param password - User password
 * @param salt - 32-byte random salt (unique per wallet)
 * @returns SecureBuffer containing 256-bit derived key
 */
async function deriveKey(password: string, salt: Buffer): Promise<SecureBuffer> {
  // Validate salt
  if (salt.length !== ARGON2_CONFIG.saltLength) {
    throw new Error(`Salt must be ${ARGON2_CONFIG.saltLength} bytes`);
  }

  // Derive key using Argon2id
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
```

### 5.3 Salt Generation

```typescript
/**
 * Generates a cryptographically secure salt for key derivation.
 *
 * Requirements:
 * - 32 bytes (256 bits) of entropy
 * - Generated using crypto.randomBytes (CSPRNG)
 * - Unique per wallet (not per operation)
 * - Stored alongside encrypted data (not secret)
 *
 * @returns 32-byte random salt
 */
function generateSalt(): Buffer {
  return crypto.randomBytes(ARGON2_CONFIG.saltLength);
}
```

### 5.4 Parameter Validation

```typescript
/**
 * Validates KDF parameters meet security requirements.
 *
 * @param params - KDF parameters from wallet file
 * @throws Error if parameters don't meet minimum requirements
 */
function validateKdfParams(params: KdfParams): void {
  // Minimum memory cost: 64MB
  if ((params.memoryCost ?? 0) < 65536) {
    throw new KeyDecryptionError('KDF memory cost below minimum (64MB)');
  }

  // Minimum time cost: 3 iterations
  if ((params.timeCost ?? 0) < 3) {
    throw new KeyDecryptionError('KDF time cost below minimum (3)');
  }

  // Parallelism: 1-16
  if ((params.parallelism ?? 0) < 1 || (params.parallelism ?? 0) > 16) {
    throw new KeyDecryptionError('KDF parallelism out of valid range (1-16)');
  }
}
```

### 5.5 Performance Characteristics

| Hardware | Memory | Derivation Time |
|----------|--------|-----------------|
| Modern Desktop (8-core, 32GB RAM) | 64MB | ~500ms |
| Cloud VM (4-core, 8GB RAM) | 64MB | ~800ms |
| Raspberry Pi 4 (4-core, 4GB RAM) | 64MB | ~2000ms |
| Low-end VPS (1-core, 2GB RAM) | 64MB | ~1500ms |

### 5.6 Memory Management

```typescript
/**
 * Limits concurrent key derivations to prevent memory exhaustion.
 * Each Argon2id derivation uses 64MB.
 */
const derivationSemaphore = new Semaphore(2); // Max 128MB concurrent

async function deriveKeyWithLimit(password: string, salt: Buffer): Promise<SecureBuffer> {
  return derivationSemaphore.acquire(async () => {
    return deriveKey(password, salt);
  });
}
```

---

## 6. File System Operations

### 6.1 Atomic Write Implementation

```typescript
/**
 * Atomically writes content to a file using temp file + rename pattern.
 *
 * This ensures:
 * - No partial writes (crash safety)
 * - No data corruption during write
 * - Original file preserved until write completes
 *
 * @param filePath - Target file path
 * @param content - Content to write
 */
async function atomicWrite(filePath: string, content: string): Promise<void> {
  // Create temp file in same directory (for same-filesystem rename)
  const dir = path.dirname(filePath);
  const tempPath = path.join(dir, `.${path.basename(filePath)}.tmp.${process.pid}`);

  try {
    // Write to temp file with secure permissions
    await fs.writeFile(tempPath, content, {
      encoding: 'utf-8',
      mode: 0o600, // Owner read/write only
      flag: 'wx',  // Exclusive create (fail if exists)
    });

    // Sync to disk before rename
    const fd = await fs.open(tempPath, 'r');
    await fd.sync();
    await fd.close();

    // Atomic rename
    await fs.rename(tempPath, filePath);

    // Sync directory to ensure rename is persisted
    const dirFd = await fs.open(dir, 'r');
    await dirFd.sync();
    await dirFd.close();
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
```

### 6.2 Permission Enforcement

```typescript
/**
 * File permission constants
 */
const PERMISSIONS = {
  FILE: 0o600,      // Owner read/write only (rw-------)
  DIRECTORY: 0o700, // Owner read/write/execute only (rwx------)
};

/**
 * Ensures a file has correct permissions.
 *
 * @param filePath - File to check
 * @throws KeystoreWriteError if permissions cannot be set
 */
async function enforceFilePermissions(filePath: string): Promise<void> {
  try {
    const stats = await fs.stat(filePath);
    const currentMode = stats.mode & 0o777;

    if (currentMode !== PERMISSIONS.FILE) {
      await fs.chmod(filePath, PERMISSIONS.FILE);
    }
  } catch (error) {
    throw new KeystoreWriteError(`Cannot enforce permissions on ${filePath}`, 'update');
  }
}

/**
 * Ensures a directory has correct permissions.
 *
 * @param dirPath - Directory to check
 */
async function enforceDirectoryPermissions(dirPath: string): Promise<void> {
  try {
    const stats = await fs.stat(dirPath);
    const currentMode = stats.mode & 0o777;

    if (currentMode !== PERMISSIONS.DIRECTORY) {
      await fs.chmod(dirPath, PERMISSIONS.DIRECTORY);
    }
  } catch (error) {
    throw new KeystoreWriteError(`Cannot enforce permissions on ${dirPath}`, 'update');
  }
}
```

### 6.3 Directory Structure

```
~/.xrpl-wallet-mcp/                     # Base directory (0700)
├── config.json                          # Global config (0600)
├── mainnet/                             # Network directory (0700)
│   ├── keystore/                        # Wallet storage (0700)
│   │   ├── wallet_xxx.wallet.json       # Wallet file (0600)
│   │   └── ...
│   ├── index.json                       # Wallet index (0600)
│   └── audit.log                        # Audit log (0600)
├── testnet/
│   └── ...
├── devnet/
│   └── ...
└── backups/                             # Backup storage (0700)
    ├── wallet_xxx_1706400000.backup.json
    └── ...
```

### 6.4 File Locking

```typescript
/**
 * Simple file locking mechanism for concurrent access safety.
 */
class FileLock {
  private locks = new Map<string, Promise<void>>();

  /**
   * Executes operation with exclusive access to the file.
   *
   * @param key - File path or lock key
   * @param operation - Async operation to execute
   * @returns Result of the operation
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
```

### 6.5 Secure Deletion

```typescript
/**
 * Securely deletes a wallet file by overwriting before unlinking.
 *
 * @param filePath - File to securely delete
 */
async function secureDelete(filePath: string): Promise<void> {
  try {
    // Get file size
    const stats = await fs.stat(filePath);
    const size = stats.size;

    // Overwrite with random data (3 passes)
    for (let pass = 0; pass < 3; pass++) {
      const randomData = crypto.randomBytes(size);
      await fs.writeFile(filePath, randomData);

      // Sync to ensure write reaches disk
      const fd = await fs.open(filePath, 'r');
      await fd.sync();
      await fd.close();
    }

    // Final overwrite with zeros
    await fs.writeFile(filePath, Buffer.alloc(size, 0));

    // Delete file
    await fs.unlink(filePath);
  } catch (error) {
    throw new KeystoreWriteError(`Secure delete failed: ${error}`, 'delete');
  }
}
```

---

## 7. SecureBuffer Integration

### 7.1 SecureBuffer Class

```typescript
/**
 * SecureBuffer - Memory-safe container for sensitive data.
 *
 * Features:
 * - Automatic zeroing after use
 * - Prevention of accidental serialization
 * - Clear ownership semantics
 * - Integration with crypto operations
 */
export class SecureBuffer {
  private buffer: Buffer;
  private isZeroed: boolean = false;

  private constructor(size: number) {
    this.buffer = Buffer.allocUnsafe(size);
  }

  /**
   * Creates a new SecureBuffer with uninitialized content.
   */
  static alloc(size: number): SecureBuffer {
    return new SecureBuffer(size);
  }

  /**
   * Creates a SecureBuffer from existing data.
   * IMPORTANT: Source buffer is zeroed immediately.
   */
  static from(data: Buffer): SecureBuffer {
    const secure = new SecureBuffer(data.length);
    data.copy(secure.buffer);
    // Zero source immediately
    data.fill(0);
    return secure;
  }

  /**
   * Gets the buffer contents.
   * @throws Error if buffer has been zeroed
   */
  getBuffer(): Buffer {
    if (this.isZeroed) {
      throw new Error('SecureBuffer has been zeroed');
    }
    return this.buffer;
  }

  /**
   * Zeros the buffer contents irreversibly.
   */
  zero(): void {
    if (!this.isZeroed) {
      // Multiple overwrite passes
      this.buffer.fill(0x00);
      this.buffer.fill(0xFF);
      this.buffer.fill(0x00);
      this.isZeroed = true;
    }
  }

  /**
   * Returns whether the buffer has been zeroed.
   */
  get zeroed(): boolean {
    return this.isZeroed;
  }

  /**
   * Buffer length in bytes.
   */
  get length(): number {
    return this.buffer.length;
  }

  // Prevent serialization
  toJSON(): never {
    throw new Error('SecureBuffer cannot be serialized to JSON');
  }

  toString(): string {
    return '[SecureBuffer]';
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return `[SecureBuffer length=${this.length} zeroed=${this.isZeroed}]`;
  }
}
```

### 7.2 Usage Patterns

```typescript
/**
 * Pattern 1: Manual lifecycle management
 */
async function signTransaction(walletId: string, password: string, tx: Transaction) {
  const key = await keystore.loadKey(walletId, password);
  try {
    return await xrpl.sign(tx, key.getBuffer().toString('hex'));
  } finally {
    key.zero(); // Always zero after use
  }
}

/**
 * Pattern 2: Scoped execution with automatic cleanup
 */
async function signWithCleanup(
  walletId: string,
  password: string,
  tx: Transaction
): Promise<string> {
  return SecureBuffer.withSecure(
    await keystore.loadKey(walletId, password),
    async (keyBuffer) => {
      return xrpl.sign(tx, keyBuffer.toString('hex'));
    }
  );
}

/**
 * Pattern 3: Chained operations
 */
async function rotateKeySecurely(
  walletId: string,
  currentPassword: string,
  newPassword: string
): Promise<void> {
  const currentKey = await keystore.loadKey(walletId, currentPassword);
  try {
    const newSalt = crypto.randomBytes(32);
    const newKek = await deriveKey(newPassword, newSalt);
    try {
      const { encryptedData, iv, authTag } = await encrypt(
        currentKey.getBuffer(),
        newKek
      );
      // Save new encrypted data...
    } finally {
      newKek.zero();
    }
  } finally {
    currentKey.zero();
  }
}
```

### 7.3 Integration with Crypto Operations

```typescript
/**
 * Secure key derivation that returns SecureBuffer
 */
async function deriveKey(password: string, salt: Buffer): Promise<SecureBuffer> {
  const rawKey = await argon2.hash(password, {
    ...ARGON2_CONFIG,
    salt,
    raw: true,
  });
  return SecureBuffer.from(rawKey);
}

/**
 * Secure decryption that returns SecureBuffer
 */
async function decrypt(
  ciphertext: Buffer,
  key: SecureBuffer,
  iv: Buffer,
  authTag: Buffer
): Promise<SecureBuffer> {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key.getBuffer(), iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return SecureBuffer.from(decrypted);
}
```

---

## 8. Backup File Format

### 8.1 Backup Structure

```typescript
/**
 * Encrypted backup file format
 */
interface EncryptedBackup {
  /** Backup format version */
  version: 1;

  /** Backup format type */
  format: 'encrypted-json' | 'kms-wrapped';

  /** Creation timestamp (ISO 8601) */
  createdAt: string;

  /** Provider that created the backup */
  sourceProvider: 'local-file' | 'cloud-kms' | 'hsm';

  /** Encryption parameters */
  encryption: {
    algorithm: 'aes-256-gcm';
    kdf: 'argon2id';
    kdfParams: {
      memoryCost: number;
      timeCost: number;
      parallelism: number;
    };
    /** Base64-encoded salt (32 bytes) */
    salt: string;
    /** Base64-encoded IV (12 bytes) */
    iv: string;
    /** Base64-encoded auth tag (16 bytes) */
    authTag: string;
  };

  /** Base64-encoded encrypted payload */
  payload: string;

  /** SHA-256 checksum of encrypted payload */
  checksum: string;
}
```

### 8.2 Backup Payload Structure

```typescript
/**
 * Decrypted backup payload
 */
interface BackupPayload {
  /** Payload format version */
  version: 1;

  /** Export timestamp */
  exportedAt: string;

  /** Wallet data */
  wallet: {
    /** Full wallet entry (metadata) */
    entry: WalletEntry;

    /** Hex-encoded seed (32 bytes = 64 hex chars) */
    seed: string;
  };
}
```

### 8.3 Example Backup File

```json
{
  "version": 1,
  "format": "encrypted-json",
  "createdAt": "2026-01-28T12:00:00.000Z",
  "sourceProvider": "local-file",
  "encryption": {
    "algorithm": "aes-256-gcm",
    "kdf": "argon2id",
    "kdfParams": {
      "memoryCost": 65536,
      "timeCost": 3,
      "parallelism": 4
    },
    "salt": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5",
    "iv": "MTIzNDU2Nzg5MDEy",
    "authTag": "YXV0aGVudGljYXRpb250YWc="
  },
  "payload": "ZW5jcnlwdGVkYmFja3VwcGF5bG9hZGRhdGE...",
  "checksum": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
}
```

### 8.4 Backup File Naming

```
{walletId}_{timestamp}.backup.json

Examples:
- wallet_m1a2b3c4_d5e6f7g8h9i0j1k2_1706400000.backup.json
- wallet_m1a2b3c4_d5e6f7g8h9i0j1k2_2026-01-28T12-00-00Z.backup.json
```

### 8.5 Backup Security Properties

| Property | Implementation |
|----------|----------------|
| Confidentiality | AES-256-GCM encryption |
| Integrity | GCM authentication tag + SHA-256 checksum |
| Key Protection | Argon2id key derivation (same as wallet) |
| Portability | Self-contained JSON format |
| Version Control | Format version for future upgrades |
| Provenance | Source provider recorded |

---

## 9. Recovery Procedures

### 9.1 Password Recovery (Not Supported)

```
WARNING: Password recovery is NOT supported.

If the password is lost:
- The wallet cannot be decrypted
- The private key cannot be recovered
- Any funds in the wallet are permanently inaccessible

Mitigation strategies:
1. Keep secure backup of password
2. Use password manager
3. Maintain encrypted backups in multiple locations
4. Consider multi-signature wallets for high-value accounts
```

### 9.2 Wallet Recovery from Backup

```typescript
/**
 * Recovery procedure from backup file:
 *
 * 1. Locate backup file
 * 2. Verify backup format and checksum
 * 3. Enter backup password
 * 4. Decrypt and import wallet
 * 5. Optionally set new password
 */
async function recoverFromBackup(
  backupPath: string,
  password: string,
  newPassword?: string
): Promise<WalletEntry> {
  // Read backup file
  const backupContent = await fs.readFile(backupPath, 'utf-8');
  const backup: EncryptedBackup = JSON.parse(backupContent);

  // Import with optional new password
  return keystore.importBackup(backup, password, {
    newPassword,
    force: true, // Overwrite if exists
  });
}
```

### 9.3 Corrupted Wallet File Recovery

```typescript
/**
 * Recovery procedure for corrupted wallet file:
 *
 * 1. Check if backup exists
 * 2. Attempt to parse JSON (syntax errors)
 * 3. Verify encryption metadata intact
 * 4. If metadata OK, attempt decryption
 * 5. If decryption fails, restore from backup
 */
async function recoverCorruptedWallet(
  walletId: string,
  password: string
): Promise<RecoveryResult> {
  const results: RecoveryResult = {
    success: false,
    method: 'unknown',
    errors: [],
  };

  // Step 1: Try to read wallet file
  try {
    const wallet = await keystore.getWallet(walletId);

    // Step 2: Try to decrypt
    const key = await keystore.loadKey(walletId, password);
    key.zero();

    results.success = true;
    results.method = 'direct';
    return results;
  } catch (error) {
    results.errors.push(`Direct recovery failed: ${error}`);
  }

  // Step 3: Try backup recovery
  const backups = await findBackups(walletId);
  for (const backupPath of backups) {
    try {
      const entry = await recoverFromBackup(backupPath, password);
      results.success = true;
      results.method = 'backup';
      results.backupUsed = backupPath;
      return results;
    } catch (error) {
      results.errors.push(`Backup ${backupPath} failed: ${error}`);
    }
  }

  return results;
}

interface RecoveryResult {
  success: boolean;
  method: 'direct' | 'backup' | 'unknown';
  backupUsed?: string;
  errors: string[];
}
```

### 9.4 Emergency Key Export

```typescript
/**
 * Emergency key export for migration to different system.
 *
 * WARNING: This exports the raw seed in the backup.
 * Handle the backup file with extreme care.
 */
async function emergencyExport(
  walletId: string,
  password: string,
  outputPath: string
): Promise<void> {
  // Create encrypted backup
  const backup = await keystore.exportBackup(walletId, password, 'encrypted-json');

  // Write to specified path
  await fs.writeFile(outputPath, JSON.stringify(backup, null, 2), {
    mode: 0o600,
  });

  console.log(`Backup exported to: ${outputPath}`);
  console.log('SECURITY WARNING: This backup contains encrypted key material.');
  console.log('Store securely and delete after successful import to new system.');
}
```

### 9.5 Recovery Checklist

| Scenario | Recovery Method | Prerequisites |
|----------|-----------------|---------------|
| Lost password | Cannot recover | None (prevention only) |
| Deleted wallet file | Restore from backup | Valid backup + password |
| Corrupted wallet file | Restore from backup | Valid backup + password |
| Corrupted backup | Use older backup | Multiple backups |
| System migration | Export/import backup | Password |
| Provider upgrade | Migration utility | Password + both providers |

---

## 10. Error Handling

### 10.1 Error Type Hierarchy

```typescript
/**
 * All keystore errors extend this base class.
 */
abstract class KeystoreError extends Error {
  abstract readonly code: KeystoreErrorCode;
  abstract readonly recoverable: boolean;
  readonly timestamp: string;

  constructor(
    message: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = this.constructor.name;
    this.timestamp = new Date().toISOString();
  }
}
```

### 10.2 Specific Error Types

```typescript
/**
 * Provider not initialized or initialization failed.
 */
class KeystoreInitializationError extends KeystoreError {
  readonly code = 'KEYSTORE_INIT_ERROR' as const;
  readonly recoverable = false;

  constructor(message: string, cause?: Error) {
    super(message, { cause: cause?.message });
  }
}

/**
 * Wallet not found in any network keystore.
 */
class WalletNotFoundError extends KeystoreError {
  readonly code = 'WALLET_NOT_FOUND' as const;
  readonly recoverable = false;

  constructor(walletId: string) {
    super(`Wallet not found: ${walletId}`, { walletId });
  }
}

/**
 * Wallet already exists (duplicate ID or address).
 */
class WalletExistsError extends KeystoreError {
  readonly code = 'WALLET_EXISTS' as const;
  readonly recoverable = false;

  constructor(walletId: string, existingAddress?: string) {
    super(`Wallet already exists: ${walletId}`, { walletId, existingAddress });
  }
}

/**
 * Authentication failed. Intentionally vague to prevent enumeration.
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

  constructor(requirements: string[]) {
    super('Password does not meet security requirements', { requirements });
  }
}

/**
 * Key decryption failed (wrong password, corrupted data, etc.).
 */
class KeyDecryptionError extends KeystoreError {
  readonly code = 'KEY_DECRYPTION_ERROR' as const;
  readonly recoverable = false;

  constructor(message: string = 'Key decryption failed') {
    super(message);
  }
}

/**
 * Invalid key format or length.
 */
class InvalidKeyError extends KeystoreError {
  readonly code = 'INVALID_KEY_FORMAT' as const;
  readonly recoverable = false;

  constructor(reason: string, expectedFormat?: string) {
    super(`Invalid key format: ${reason}`, { reason, expectedFormat });
  }
}

/**
 * File write operation failed.
 */
class KeystoreWriteError extends KeystoreError {
  readonly code = 'KEYSTORE_WRITE_ERROR' as const;
  readonly recoverable = true;

  constructor(message: string, operation: 'create' | 'update' | 'delete') {
    super(message, { operation });
  }
}

/**
 * File read operation failed.
 */
class KeystoreReadError extends KeystoreError {
  readonly code = 'KEYSTORE_READ_ERROR' as const;
  readonly recoverable = true;

  constructor(message: string) {
    super(message);
  }
}

/**
 * Maximum wallet limit reached.
 */
class KeystoreCapacityError extends KeystoreError {
  readonly code = 'KEYSTORE_CAPACITY_ERROR' as const;
  readonly recoverable = false;

  constructor(network: XRPLNetwork, currentCount: number, maxCount: number) {
    super(`Keystore capacity exceeded for ${network}`, {
      network,
      currentCount,
      maxCount,
    });
  }
}

/**
 * Backup format invalid or unsupported.
 */
class BackupFormatError extends KeystoreError {
  readonly code = 'BACKUP_FORMAT_ERROR' as const;
  readonly recoverable = false;

  constructor(reason: string, expectedVersion?: number) {
    super(`Invalid backup format: ${reason}`, { reason, expectedVersion });
  }
}
```

### 10.3 Error Handling Patterns

```typescript
/**
 * Pattern 1: Safe error handling with logging
 */
async function safeLoadKey(
  walletId: string,
  password: string
): Promise<SecureBuffer | null> {
  try {
    return await keystore.loadKey(walletId, password);
  } catch (error) {
    if (error instanceof AuthenticationError) {
      logger.warn('Authentication failed', { walletId });
      return null;
    }
    if (error instanceof WalletNotFoundError) {
      logger.info('Wallet not found', { walletId });
      return null;
    }
    // Re-throw unexpected errors
    throw error;
  }
}

/**
 * Pattern 2: Error transformation for API responses
 */
function keystoreErrorToApiResponse(error: KeystoreError): ApiErrorResponse {
  return {
    success: false,
    error: {
      code: error.code,
      message: error.message,
      recoverable: error.recoverable,
      // Never include sensitive details
    },
  };
}

/**
 * Pattern 3: Retry with backoff for transient errors
 */
async function withRetry<T>(
  operation: () => Promise<T>,
  maxRetries: number = 3
): Promise<T> {
  let lastError: Error | undefined;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      if (error instanceof KeystoreError && !error.recoverable) {
        throw error; // Don't retry non-recoverable errors
      }
      lastError = error as Error;
      await sleep(Math.pow(2, attempt) * 100); // Exponential backoff
    }
  }

  throw lastError;
}
```

### 10.4 Rate Limiting Implementation

```typescript
/**
 * Rate limiting configuration
 */
const RATE_LIMIT_CONFIG = {
  maxAttempts: 5,           // Max failed attempts
  windowSeconds: 900,        // 15 minute window
  lockoutSeconds: 1800,      // 30 minute initial lockout
  lockoutMultiplier: 2,      // Doubles each time
};

interface AuthAttemptRecord {
  timestamp: Date;
  success: boolean;
}

/**
 * Checks if wallet is currently locked out.
 */
private async checkRateLimit(walletId: string): Promise<void> {
  const lockout = this.lockouts.get(walletId);
  if (lockout && lockout > new Date()) {
    const remainingMs = lockout.getTime() - Date.now();
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
  attempts = attempts.filter(a => a.timestamp > windowStart);

  // Add new failure
  attempts.push({ timestamp: now, success: false });
  this.authAttempts.set(walletId, attempts);

  // Check if lockout needed
  const failures = attempts.filter(a => !a.success).length;
  if (failures >= RATE_LIMIT_CONFIG.maxAttempts) {
    // Calculate lockout duration (progressive)
    const lockoutCount = Math.floor(failures / RATE_LIMIT_CONFIG.maxAttempts);
    const duration = RATE_LIMIT_CONFIG.lockoutSeconds *
      Math.pow(RATE_LIMIT_CONFIG.lockoutMultiplier, lockoutCount - 1);

    const lockoutUntil = new Date(now.getTime() + duration * 1000);
    this.lockouts.set(walletId, lockoutUntil);

    // Log lockout event
    this.audit('AUTH_LOCKOUT', {
      walletId,
      failures,
      lockoutUntil: lockoutUntil.toISOString(),
    });
  }
}
```

---

## 11. Test Fixtures

### 11.1 Test Configuration

```typescript
/**
 * Test fixtures for LocalFileKeystoreProvider testing.
 */
export const TestFixtures = {
  /** Test directory (cleaned up after each test) */
  testDir: '/tmp/xrpl-wallet-mcp-test',

  /** Valid test passwords */
  passwords: {
    valid: 'TestPassword123!',
    validAlternate: 'AnotherPass456@',
    weak: {
      tooShort: 'short',
      noUppercase: 'alllowercase123',
      noLowercase: 'ALLUPPERCASE123',
      noNumbers: 'NoNumbersHere!',
    },
  },

  /** Test networks */
  networks: ['mainnet', 'testnet', 'devnet'] as XRPLNetwork[],

  /** Sample wallet policy */
  samplePolicy: {
    policyId: 'test-policy-v1',
    policyVersion: '1.0.0',
  } as WalletPolicy,

  /** Sample wallet options */
  sampleOptions: {
    name: 'Test Wallet',
    password: 'TestPassword123!',
    algorithm: 'ed25519' as const,
    description: 'A test wallet',
    tags: ['test', 'development'],
  },

  /** Known test seed (DO NOT USE IN PRODUCTION) */
  testSeed: Buffer.from(
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    'hex'
  ),

  /** Expected address for test seed (ed25519) */
  expectedAddress: 'rTestAddressForKnownSeed12345',
};
```

### 11.2 Test Helper Functions

```typescript
/**
 * Creates a test keystore provider with isolated storage.
 */
export async function createTestProvider(): Promise<LocalFileKeystoreProvider> {
  const provider = new LocalFileKeystoreProvider();

  // Use unique test directory
  const testDir = path.join(TestFixtures.testDir, `test-${Date.now()}`);

  await provider.initialize({
    baseDir: testDir,
    passwordPolicy: {
      minLength: 12,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecial: false,
      maxLength: 128,
    },
  });

  return provider;
}

/**
 * Cleans up test directory.
 */
export async function cleanupTestProvider(provider: LocalFileKeystoreProvider): Promise<void> {
  await provider.close();
  // Clean up test directory
  await fs.rm(TestFixtures.testDir, { recursive: true, force: true });
}

/**
 * Creates a test wallet and returns its ID.
 */
export async function createTestWallet(
  provider: LocalFileKeystoreProvider,
  network: XRPLNetwork = 'testnet'
): Promise<string> {
  const entry = await provider.createWallet(
    network,
    TestFixtures.samplePolicy,
    TestFixtures.sampleOptions
  );
  return entry.walletId;
}
```

### 11.3 Unit Test Examples

```typescript
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

describe('LocalFileKeystoreProvider', () => {
  let provider: LocalFileKeystoreProvider;

  beforeEach(async () => {
    provider = await createTestProvider();
  });

  afterEach(async () => {
    await cleanupTestProvider(provider);
  });

  describe('createWallet', () => {
    it('should create wallet with valid password', async () => {
      const entry = await provider.createWallet(
        'testnet',
        TestFixtures.samplePolicy,
        TestFixtures.sampleOptions
      );

      expect(entry.walletId).toBeDefined();
      expect(entry.address).toMatch(/^r[a-zA-Z0-9]+$/);
      expect(entry.network).toBe('testnet');
      expect(entry.status).toBe('active');
    });

    it('should reject weak password', async () => {
      await expect(
        provider.createWallet('testnet', TestFixtures.samplePolicy, {
          ...TestFixtures.sampleOptions,
          password: TestFixtures.passwords.weak.tooShort,
        })
      ).rejects.toThrow(WeakPasswordError);
    });

    it('should enforce capacity limits', async () => {
      // Create max wallets
      for (let i = 0; i < 100; i++) {
        await provider.createWallet(
          'testnet',
          TestFixtures.samplePolicy,
          { ...TestFixtures.sampleOptions, name: `Wallet ${i}` }
        );
      }

      // Next should fail
      await expect(
        provider.createWallet('testnet', TestFixtures.samplePolicy, TestFixtures.sampleOptions)
      ).rejects.toThrow(KeystoreCapacityError);
    });
  });

  describe('loadKey', () => {
    it('should load key with correct password', async () => {
      const walletId = await createTestWallet(provider);

      const key = await provider.loadKey(walletId, TestFixtures.passwords.valid);

      expect(key).toBeInstanceOf(SecureBuffer);
      expect(key.length).toBe(32);

      key.zero();
    });

    it('should reject incorrect password', async () => {
      const walletId = await createTestWallet(provider);

      await expect(
        provider.loadKey(walletId, 'WrongPassword123!')
      ).rejects.toThrow(AuthenticationError);
    });

    it('should rate limit after failed attempts', async () => {
      const walletId = await createTestWallet(provider);

      // Make 5 failed attempts
      for (let i = 0; i < 5; i++) {
        await expect(
          provider.loadKey(walletId, 'WrongPassword123!')
        ).rejects.toThrow(AuthenticationError);
      }

      // 6th attempt should also fail (lockout)
      await expect(
        provider.loadKey(walletId, TestFixtures.passwords.valid)
      ).rejects.toThrow(AuthenticationError);
    });
  });

  describe('encryption', () => {
    it('should use unique IV for each encryption', async () => {
      const walletId1 = await createTestWallet(provider);
      const walletId2 = await createTestWallet(provider);

      const wallet1 = await provider.getWallet(walletId1);
      const wallet2 = await provider.getWallet(walletId2);

      // Read wallet files to get IVs
      // IVs should be different
      expect(wallet1.encryption.salt).not.toBe(wallet2.encryption.salt);
    });

    it('should detect tampered ciphertext', async () => {
      const walletId = await createTestWallet(provider);

      // Tamper with wallet file
      const walletPath = path.join(
        TestFixtures.testDir,
        'testnet',
        'keystore',
        `${walletId}.wallet.json`
      );

      const content = JSON.parse(await fs.readFile(walletPath, 'utf-8'));
      content.encryptedKey.data = content.encryptedKey.data.replace('a', 'b');
      await fs.writeFile(walletPath, JSON.stringify(content));

      // Decryption should fail
      await expect(
        provider.loadKey(walletId, TestFixtures.passwords.valid)
      ).rejects.toThrow();
    });
  });

  describe('backup/restore', () => {
    it('should export and import backup', async () => {
      const walletId = await createTestWallet(provider);
      const originalEntry = await provider.getWallet(walletId);

      // Export backup
      const backup = await provider.exportBackup(
        walletId,
        TestFixtures.passwords.valid,
        'encrypted-json'
      );

      // Delete original
      await provider.deleteWallet(walletId, TestFixtures.passwords.valid);

      // Import backup
      const restored = await provider.importBackup(
        backup,
        TestFixtures.passwords.valid
      );

      expect(restored.address).toBe(originalEntry.address);
      expect(restored.publicKey).toBe(originalEntry.publicKey);
    });

    it('should verify backup checksum', async () => {
      const walletId = await createTestWallet(provider);

      const backup = await provider.exportBackup(
        walletId,
        TestFixtures.passwords.valid,
        'encrypted-json'
      );

      // Tamper with checksum
      backup.checksum = 'invalid_checksum';

      await expect(
        provider.importBackup(backup, TestFixtures.passwords.valid)
      ).rejects.toThrow(BackupFormatError);
    });
  });
});
```

### 11.4 Integration Test Examples

```typescript
describe('LocalFileKeystoreProvider Integration', () => {
  it('should survive process restart', async () => {
    const testDir = path.join(TestFixtures.testDir, 'persistence');

    // Create provider and wallet
    const provider1 = new LocalFileKeystoreProvider();
    await provider1.initialize({ baseDir: testDir });

    const entry = await provider1.createWallet(
      'testnet',
      TestFixtures.samplePolicy,
      TestFixtures.sampleOptions
    );

    await provider1.close();

    // Create new provider instance
    const provider2 = new LocalFileKeystoreProvider();
    await provider2.initialize({ baseDir: testDir });

    // Should find wallet
    const loaded = await provider2.getWallet(entry.walletId);
    expect(loaded.address).toBe(entry.address);

    // Should decrypt with same password
    const key = await provider2.loadKey(entry.walletId, TestFixtures.passwords.valid);
    expect(key.length).toBe(32);
    key.zero();

    await provider2.close();
  });

  it('should handle concurrent access', async () => {
    const provider = await createTestProvider();
    const walletId = await createTestWallet(provider);

    // Concurrent load operations
    const operations = Array(10).fill(null).map(() =>
      provider.loadKey(walletId, TestFixtures.passwords.valid)
        .then(key => { key.zero(); return 'success'; })
        .catch(() => 'failure')
    );

    const results = await Promise.all(operations);
    expect(results.every(r => r === 'success')).toBe(true);

    await cleanupTestProvider(provider);
  });
});
```

---

## Related Documents

- [Keystore Interface Specification](./keystore-interface.md)
- [ADR-001: Key Storage Strategy](../../architecture/09-decisions/ADR-001-key-storage.md)
- [ADR-002: Key Derivation Function](../../architecture/09-decisions/ADR-002-key-derivation.md)
- [Security Architecture](../../security/SECURITY-ARCHITECTURE.md)

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Backend Engineer | Initial specification |

---

*XRPL Agent Wallet MCP - Local File Keystore Provider Implementation Specification*
