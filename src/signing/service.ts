/**
 * Signing Service Implementation
 *
 * Orchestrates transaction signing with secure key material handling.
 * Coordinates with keystore, policy engine, and multi-sign orchestrator.
 *
 * @module signing/service
 * @version 1.0.0
 */

import { Wallet, decode, encode, type Transaction } from 'xrpl';
import type { KeystoreProvider } from '../keystore/interface.js';
import { SecureBuffer } from '../keystore/secure-buffer.js';
import type { AuditLogger } from '../audit/logger.js';
import type { MultiSignOrchestrator } from './multisig.js';

// ============================================================================
// TYPES
// ============================================================================

/**
 * Result of a single-sign operation.
 */
export interface SignedTransaction {
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
export class SigningError extends Error {
  constructor(
    public code: string,
    message: string,
    public details?: unknown
  ) {
    super(message);
    this.name = 'SigningError';
  }
}

// ============================================================================
// SIGNING SERVICE
// ============================================================================

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
export class SigningService {
  constructor(
    private readonly keystore: KeystoreProvider,
    private readonly auditLogger: AuditLogger,
    private readonly multiSignOrchestrator?: MultiSignOrchestrator
  ) {}

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
  async sign(
    walletId: string,
    unsignedTx: string | Transaction,
    password: string,
    multiSign: boolean = false
  ): Promise<SignedTransaction> {
    let secureKey: SecureBuffer | null = null;
    const startTime = Date.now();

    try {
      // Step 1: Decode transaction if it's a blob
      let transaction: Transaction;
      if (typeof unsignedTx === 'string') {
        try {
          transaction = decode(unsignedTx) as Transaction;
        } catch (error) {
          throw new SigningError(
            'TRANSACTION_DECODE_ERROR',
            `Failed to decode transaction: ${error instanceof Error ? error.message : 'Unknown error'}`,
            { unsignedTx }
          );
        }
      } else {
        transaction = unsignedTx;
      }

      // Step 2: Validate transaction structure
      this.validateTransaction(transaction);

      // Step 3: Load wallet metadata
      const walletEntry = await this.keystore.getWallet(walletId);

      // Step 4: Load encrypted key from keystore (returns SecureBuffer)
      try {
        secureKey = await this.keystore.loadKey(walletId, password);
      } catch (error) {
        // Audit failed authentication
        await this.auditLogger.log({
          event: 'authentication_failed',
          wallet_id: walletId,
          wallet_address: walletEntry.address,
          context: 'Authentication failed during transaction signing',
        });

        throw new SigningError(
          'AUTHENTICATION_FAILED',
          'Failed to decrypt wallet key - incorrect password or corrupted keystore',
          { wallet_id: walletId }
        );
      }

      // Step 5: Create ephemeral Wallet instance using SecureBuffer
      let wallet: Wallet;
      try {
        // Convert buffer to seed string for xrpl.js Wallet
        const seedString = secureKey.getBuffer().toString('utf-8');
        wallet = Wallet.fromSeed(seedString);

        // Verify address matches
        if (wallet.address !== walletEntry.address) {
          throw new Error('Wallet address mismatch - keystore corruption detected');
        }
      } catch (error) {
        throw new SigningError(
          'WALLET_CREATION_ERROR',
          `Failed to create wallet from key: ${error instanceof Error ? error.message : 'Unknown error'}`,
          { wallet_id: walletId }
        );
      }

      // Step 6: Sign the transaction
      let signedResult: { tx_blob: string; hash: string };
      try {
        if (multiSign) {
          // Multi-sign mode: SigningPubKey must be empty
          signedResult = wallet.sign(transaction, true);
        } else {
          // Single-sign mode (normal)
          signedResult = wallet.sign(transaction);
        }
      } catch (error) {
        throw new SigningError(
          'SIGNING_FAILED',
          `Cryptographic signing failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
          { wallet_id: walletId, transaction_type: transaction.TransactionType }
        );
      }

      // Step 7: Audit successful signing
      await this.auditLogger.log({
        event: 'transaction_signed',
        wallet_id: walletId,
        wallet_address: walletEntry.address,
        transaction_type: transaction.TransactionType as any,
        tx_hash: signedResult.hash,
        context: multiSign ? 'Multi-signature signing' : 'Single signature signing',
      });

      return {
        tx_blob: signedResult.tx_blob,
        hash: signedResult.hash,
        signer_address: wallet.address,
      };
    } catch (error) {
      // Audit signing failure (if not already logged)
      if (error instanceof SigningError && error.code !== 'AUTHENTICATION_FAILED') {
        await this.auditLogger.log({
          event: 'transaction_failed',
          wallet_id: walletId,
          context: `Signing failed: ${error.code} - ${error.message}`,
        });
      }

      throw error;
    } finally {
      // Step 8: CRITICAL - Zero key material
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
  async signForMultiSig(
    walletId: string,
    unsignedTx: string | Transaction,
    password: string
  ): Promise<SignedTransaction> {
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
  decodeTransaction(txBlob: string): Transaction {
    try {
      return decode(txBlob) as Transaction;
    } catch (error) {
      throw new SigningError(
        'TRANSACTION_DECODE_ERROR',
        `Failed to decode transaction: ${error instanceof Error ? error.message : 'Unknown error'}`,
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
  encodeTransaction(transaction: Transaction): string {
    try {
      return encode(transaction);
    } catch (error) {
      throw new SigningError(
        'TRANSACTION_ENCODE_ERROR',
        `Failed to encode transaction: ${error instanceof Error ? error.message : 'Unknown error'}`,
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
  private validateTransaction(transaction: Transaction): void {
    // Check required fields
    if (!transaction.TransactionType) {
      throw new SigningError(
        'INVALID_TRANSACTION',
        'Transaction missing required field: TransactionType'
      );
    }

    if (!transaction.Account) {
      throw new SigningError(
        'INVALID_TRANSACTION',
        'Transaction missing required field: Account'
      );
    }

    // Validate Account address format (basic check)
    if (!transaction.Account.startsWith('r') || transaction.Account.length < 25) {
      throw new SigningError(
        'INVALID_TRANSACTION',
        `Invalid Account address format: ${transaction.Account}`
      );
    }

    // Check for common XRPL transaction types
    const validTypes = [
      'Payment',
      'OfferCreate',
      'OfferCancel',
      'TrustSet',
      'AccountSet',
      'SetRegularKey',
      'SignerListSet',
      'EscrowCreate',
      'EscrowFinish',
      'EscrowCancel',
      'PaymentChannelCreate',
      'PaymentChannelClaim',
      'PaymentChannelFund',
      'CheckCreate',
      'CheckCash',
      'CheckCancel',
      'NFTokenMint',
      'NFTokenBurn',
      'NFTokenCreateOffer',
      'NFTokenCancelOffer',
      'NFTokenAcceptOffer',
      'AMMCreate',
      'AMMDeposit',
      'AMMWithdraw',
      'AMMVote',
      'AMMBid',
      'AMMDelete',
      'DepositPreauth',
      'AccountDelete',
    ];

    if (!validTypes.includes(transaction.TransactionType)) {
      // Log warning but don't fail - new transaction types may be added
      console.warn(`Unknown TransactionType: ${transaction.TransactionType}`);
    }
  }
}
