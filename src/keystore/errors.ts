/**
 * Keystore Error Types
 *
 * Defines all error types for keystore operations.
 * All errors extend the base KeystoreError class.
 *
 * @module keystore/errors
 * @version 1.0.0
 */

import type { XRPLNetwork, KeystoreProviderType } from './interface.js';

/**
 * Error codes for keystore operations.
 */
export type KeystoreErrorCode =
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

/**
 * Base error class for all keystore operations.
 *
 * All keystore errors include:
 * - A specific error code for programmatic handling
 * - Whether the error is recoverable
 * - Timestamp of when the error occurred
 * - Optional additional details
 */
export abstract class KeystoreError extends Error {
  /** Error code for programmatic handling */
  abstract readonly code: KeystoreErrorCode;

  /** Whether this error is recoverable (can be retried) */
  abstract readonly recoverable: boolean;

  /** Timestamp when error occurred */
  readonly timestamp: string;

  /** Correlation ID for tracking */
  readonly correlationId?: string;

  constructor(
    message: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = this.constructor.name;
    this.timestamp = new Date().toISOString();

    // Maintain proper stack trace in V8
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  /**
   * Convert to safe JSON representation (excludes sensitive data).
   */
  toSafeJSON(): Record<string, unknown> {
    return {
      code: this.code,
      message: this.message,
      recoverable: this.recoverable,
      timestamp: this.timestamp,
      correlationId: this.correlationId,
    };
  }
}

// ============================================================================
// Initialization Errors
// ============================================================================

/**
 * Keystore initialization failed.
 */
export class KeystoreInitializationError extends KeystoreError {
  readonly code = 'KEYSTORE_INIT_ERROR' as const;
  readonly recoverable = false;

  readonly originalCause: Error | undefined;

  constructor(message: string, originalCause?: Error) {
    super(message, { cause: originalCause?.message });
    this.originalCause = originalCause;
  }
}

// ============================================================================
// Wallet Errors
// ============================================================================

/**
 * Wallet not found in keystore.
 */
export class WalletNotFoundError extends KeystoreError {
  readonly code = 'WALLET_NOT_FOUND' as const;
  readonly recoverable = false;

  constructor(public readonly walletId: string) {
    super(`Wallet not found: ${walletId}`, { walletId });
  }
}

/**
 * Wallet already exists (duplicate ID or address).
 */
export class WalletExistsError extends KeystoreError {
  readonly code = 'WALLET_EXISTS' as const;
  readonly recoverable = false;

  constructor(
    public readonly walletId: string,
    public readonly existingAddress?: string
  ) {
    super(`Wallet already exists: ${walletId}`, { walletId, existingAddress });
  }
}

// ============================================================================
// Authentication Errors
// ============================================================================

/**
 * Authentication failed (wrong password).
 *
 * Note: Intentionally vague message to prevent enumeration attacks.
 */
export class AuthenticationError extends KeystoreError {
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
export class WeakPasswordError extends KeystoreError {
  readonly code = 'WEAK_PASSWORD' as const;
  readonly recoverable = true;

  constructor(public readonly requirements: string[]) {
    super('Password does not meet security requirements', { requirements });
  }
}

// ============================================================================
// Cryptographic Errors
// ============================================================================

/**
 * Key decryption failed.
 * Could be wrong password, corrupted data, or algorithm mismatch.
 */
export class KeyDecryptionError extends KeystoreError {
  readonly code = 'KEY_DECRYPTION_ERROR' as const;
  readonly recoverable = false;

  constructor(message: string = 'Key decryption failed') {
    super(message);
  }
}

/**
 * Key encryption failed during storage.
 */
export class KeyEncryptionError extends KeystoreError {
  readonly code = 'KEY_ENCRYPTION_ERROR' as const;
  readonly recoverable = false;

  constructor(message: string = 'Key encryption failed') {
    super(message);
  }
}

/**
 * Invalid key format or length.
 */
export class InvalidKeyError extends KeystoreError {
  readonly code = 'INVALID_KEY_FORMAT' as const;
  readonly recoverable = false;

  constructor(
    public readonly reason: string,
    public readonly expectedFormat?: string
  ) {
    super(`Invalid key format: ${reason}`, { reason, expectedFormat });
  }
}

// ============================================================================
// Storage Errors
// ============================================================================

/**
 * Keystore write operation failed.
 */
export class KeystoreWriteError extends KeystoreError {
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
export class KeystoreReadError extends KeystoreError {
  readonly code = 'KEYSTORE_READ_ERROR' as const;
  readonly recoverable = true;

  constructor(message: string) {
    super(message);
  }
}

/**
 * Keystore capacity limit reached.
 */
export class KeystoreCapacityError extends KeystoreError {
  readonly code = 'KEYSTORE_CAPACITY_ERROR' as const;
  readonly recoverable = false;

  constructor(
    public readonly network: XRPLNetwork,
    public readonly currentCount: number,
    public readonly maxCount: number
  ) {
    super(`Keystore capacity exceeded for ${network}`, {
      network,
      currentCount,
      maxCount,
    });
  }
}

// ============================================================================
// Backup Errors
// ============================================================================

/**
 * Backup format invalid or unsupported.
 */
export class BackupFormatError extends KeystoreError {
  readonly code = 'BACKUP_FORMAT_ERROR' as const;
  readonly recoverable = false;

  constructor(
    public readonly reason: string,
    public readonly expectedVersion?: number
  ) {
    super(`Invalid backup format: ${reason}`, { reason, expectedVersion });
  }
}

// ============================================================================
// Network Errors
// ============================================================================

/**
 * Network mismatch between wallet and operation.
 */
export class NetworkMismatchError extends KeystoreError {
  readonly code = 'NETWORK_MISMATCH' as const;
  readonly recoverable = false;

  constructor(
    public readonly walletNetwork: XRPLNetwork,
    public readonly requestedNetwork: XRPLNetwork
  ) {
    super(`Network mismatch: wallet is ${walletNetwork}, requested ${requestedNetwork}`, {
      walletNetwork,
      requestedNetwork,
    });
  }
}

/**
 * Provider service unavailable.
 */
export class ProviderUnavailableError extends KeystoreError {
  readonly code = 'PROVIDER_UNAVAILABLE' as const;
  readonly recoverable = true;

  constructor(
    public readonly providerType: KeystoreProviderType,
    public readonly reason: string
  ) {
    super(`Provider unavailable: ${reason}`, { providerType, reason });
  }
}

// ============================================================================
// Type Guards
// ============================================================================

/**
 * Type guard to check if an error is a KeystoreError.
 */
export function isKeystoreError(error: unknown): error is KeystoreError {
  return error instanceof KeystoreError;
}

/**
 * Type guard to check if error is a specific keystore error code.
 */
export function isKeystoreErrorCode(error: unknown, code: KeystoreErrorCode): boolean {
  return isKeystoreError(error) && error.code === code;
}
