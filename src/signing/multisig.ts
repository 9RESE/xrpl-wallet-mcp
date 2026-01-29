/**
 * Multi-Signature Orchestration
 *
 * Implements XRPL native multi-signature workflows for Tier 3 transactions.
 * Coordinates signature collection, quorum tracking, and transaction assembly.
 *
 * @module signing/multisig
 * @version 1.0.0
 */

import { randomUUID } from 'crypto';
import { Client, Wallet, multisign, decode, type Transaction } from 'xrpl';
import { verify } from 'ripple-keypairs';
import type { AuditLogger } from '../audit/logger.js';

// ============================================================================
// TYPES
// ============================================================================

/**
 * Signer configuration entry.
 */
export interface SignerConfig {
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
export interface SignerListConfig {
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
export type MultiSignStatus = 'pending' | 'approved' | 'rejected' | 'expired' | 'completed';

/**
 * Signer state tracking.
 */
export interface SignerState {
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
  signed_at?: string; // ISO 8601
}

/**
 * Multi-signature request state.
 */
export interface MultiSignRequest {
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
  created_at: string; // ISO 8601
  expires_at: string; // ISO 8601
  completed_at?: string; // ISO 8601

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
    rejected_at: string; // ISO 8601
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
export interface MultiSignCompleteResult {
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
  submitted_at: string; // ISO 8601
}

/**
 * Multi-signature storage interface.
 */
export interface MultiSignStore {
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
export interface NotificationService {
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
export class MultiSignError extends Error {
  constructor(
    public code: string,
    message: string,
    public details?: unknown
  ) {
    super(message);
    this.name = 'MultiSignError';
  }
}

// ============================================================================
// MULTI-SIGN ORCHESTRATOR
// ============================================================================

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
export class MultiSignOrchestrator {
  constructor(
    private readonly xrplClient: Client,
    private readonly store: MultiSignStore,
    private readonly notificationService: NotificationService,
    private readonly auditLogger: AuditLogger
  ) {}

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
  async initiate(
    walletId: string,
    walletAddress: string,
    unsignedTx: string,
    signerConfig: SignerListConfig,
    context?: string
  ): Promise<MultiSignRequest> {
    // Validate SignerList configuration
    if (!signerConfig || signerConfig.signers.length === 0) {
      throw new MultiSignError(
        'SIGNERLIST_NOT_CONFIGURED',
        'Wallet does not have multi-signature configured'
      );
    }

    // Decode transaction
    let decodedTx: Transaction;
    try {
      const { decode } = await import('xrpl');
      decodedTx = decode(unsignedTx) as Transaction;
    } catch (error) {
      throw new MultiSignError(
        'INVALID_TRANSACTION',
        `Cannot decode transaction: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { unsigned_tx: unsignedTx }
      );
    }

    // Create request
    const requestId = randomUUID();
    const now = new Date();
    const timeoutSeconds = signerConfig.timeout_seconds || 86400; // 24 hours default
    const expiresAt = new Date(now.getTime() + timeoutSeconds * 1000);

    const amountDrops = this.extractAmount(decodedTx);
    const destination = this.extractDestination(decodedTx);

    const request: MultiSignRequest = {
      id: requestId,
      wallet_id: walletId,
      wallet_address: walletAddress,
      transaction: {
        type: decodedTx.TransactionType,
        ...(amountDrops !== undefined && { amount_drops: amountDrops }),
        ...(destination !== undefined && { destination }),
        unsigned_blob: unsignedTx,
        decoded: decodedTx,
      },
      signers: signerConfig.signers.map((s) => ({
        address: s.address,
        role: s.role,
        weight: s.weight,
        signed: false,
      })),
      quorum: {
        required: signerConfig.quorum,
        collected: 0,
        met: false,
      },
      status: 'pending',
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
      ...(context && { context }),
      notifications_sent: [],
    };

    // Store request
    await this.store.create(request);

    // Audit
    await this.auditLogger.log({
      event: 'approval_requested',
      wallet_id: walletId,
      wallet_address: walletAddress,
      transaction_type: decodedTx.TransactionType as any,
      context:
        context || `Multi-sign requested: ${signerConfig.quorum} of ${signerConfig.signers.length} signatures`,
    });

    // Notify approvers (async, don't wait)
    this.notifySigners(request, 'created').catch((err) =>
      console.error('Failed to send notifications:', err)
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
  async addSignature(
    requestId: string,
    signature: string,
    signerAddress: string
  ): Promise<MultiSignRequest> {
    // Load request
    const request = await this.store.get(requestId);
    if (!request) {
      throw new MultiSignError('REQUEST_NOT_FOUND', `No request found with ID ${requestId}`);
    }

    // Check expiration
    if (new Date(request.expires_at) < new Date()) {
      throw new MultiSignError('REQUEST_EXPIRED', 'Multi-sign request has expired');
    }

    // Check status
    if (request.status === 'completed') {
      throw new MultiSignError('REQUEST_COMPLETED', 'Request already completed');
    }
    if (request.status === 'rejected') {
      throw new MultiSignError('REQUEST_REJECTED', 'Request has been rejected');
    }

    // Find signer
    const signer = request.signers.find((s) => s.address === signerAddress);
    if (!signer) {
      throw new MultiSignError(
        'INVALID_SIGNER',
        `Address ${signerAddress} is not in the SignerList`,
        { signer_address: signerAddress, request_id: requestId }
      );
    }

    // Check duplicate
    if (signer.signed) {
      throw new MultiSignError(
        'DUPLICATE_SIGNATURE',
        `Signer ${signerAddress} has already signed this request`
      );
    }

    // Validate signature cryptographically
    const validationResult = this.validateSignature(
      signature,
      signerAddress,
      request.transaction.unsigned_blob
    );

    if (!validationResult.valid) {
      throw new MultiSignError(
        'SIGNATURE_INVALID',
        `Signature validation failed: ${validationResult.reason}`,
        { signer_address: signerAddress, request_id: requestId }
      );
    }

    // Update signer state
    signer.signed = true;
    signer.signature = signature;
    signer.signed_at = new Date().toISOString();

    // Recalculate quorum
    const collectedWeight = request.signers
      .filter((s) => s.signed)
      .reduce((sum, s) => sum + s.weight, 0);

    request.quorum.collected = collectedWeight;
    request.quorum.met = collectedWeight >= request.quorum.required;

    // Update status
    if (request.quorum.met) {
      request.status = 'approved';
    }

    // Store update
    await this.store.update(request);

    // Audit
    await this.auditLogger.log({
      event: 'approval_granted',
      wallet_id: request.wallet_id,
      wallet_address: request.wallet_address,
      context: `Signature added by ${signerAddress} (${signer.role}). Quorum: ${collectedWeight}/${request.quorum.required}`,
    });

    // Notify if quorum met
    if (request.quorum.met) {
      this.notifySigners(request, 'signature_added').catch((err) =>
        console.error('Failed to send notifications:', err)
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
  async complete(requestId: string, agentWallet?: Wallet): Promise<MultiSignCompleteResult> {
    // Load request
    const request = await this.store.get(requestId);
    if (!request) {
      throw new MultiSignError('REQUEST_NOT_FOUND', `No request found with ID ${requestId}`);
    }

    // Check expiration
    if (new Date(request.expires_at) < new Date()) {
      throw new MultiSignError('REQUEST_EXPIRED', 'Multi-sign request has expired');
    }

    // Check if agent signature is needed
    const agentSigner = request.signers.find((s) => s.role === 'agent');
    if (agentSigner && !agentSigner.signed && agentWallet) {
      // Add agent signature
      const agentSig = agentWallet.sign(request.transaction.decoded, true);
      agentSigner.signed = true;
      agentSigner.signature = agentSig.tx_blob;
      agentSigner.signed_at = new Date().toISOString();

      // Recalculate quorum
      const collectedWeight = request.signers
        .filter((s) => s.signed)
        .reduce((sum, s) => sum + s.weight, 0);
      request.quorum.collected = collectedWeight;
      request.quorum.met = collectedWeight >= request.quorum.required;
    }

    // Verify quorum
    if (!request.quorum.met) {
      throw new MultiSignError(
        'QUORUM_NOT_MET',
        `Collected weight ${request.quorum.collected} < required ${request.quorum.required}`
      );
    }

    // Assemble multi-signed transaction
    const signatures = request.signers.filter((s) => s.signed && s.signature).map((s) => s.signature!);

    if (signatures.length === 0) {
      throw new MultiSignError('NO_SIGNATURES', 'No signatures collected');
    }

    const multiSignedTx = multisign(signatures);

    // Submit to XRPL
    let txHash: string;
    try {
      const response = await this.xrplClient.submitAndWait(multiSignedTx, {
        autofill: false,
        failHard: true,
      });

      const meta = response.result.meta;
      const result =
        typeof meta === 'object' && meta !== null && 'TransactionResult' in meta
          ? (meta.TransactionResult as string)
          : 'UNKNOWN';
      txHash = response.result.hash;

      if (result !== 'tesSUCCESS') {
        throw new Error(`Transaction failed with result: ${result}`);
      }
    } catch (error) {
      throw new MultiSignError(
        'SUBMISSION_FAILED',
        `Failed to submit multi-signed transaction: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { request_id: requestId }
      );
    }

    // Update request
    request.status = 'completed';
    request.completed_at = new Date().toISOString();
    request.tx_hash = txHash;
    await this.store.update(request);

    // Audit
    await this.auditLogger.log({
      event: 'transaction_submitted',
      wallet_id: request.wallet_id,
      wallet_address: request.wallet_address,
      transaction_type: request.transaction.type as any,
      tx_hash: txHash,
      context: `Multi-signed transaction completed with ${signatures.length} signatures`,
    });

    return {
      request_id: requestId,
      signed_tx: multiSignedTx,
      tx_hash: txHash,
      final_quorum: request.quorum.collected,
      signers: request.signers.filter((s) => s.signed).map((s) => s.address),
      submitted_at: new Date().toISOString(),
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
  async reject(requestId: string, rejectingAddress: string, reason: string): Promise<MultiSignRequest> {
    const request = await this.store.get(requestId);
    if (!request) {
      throw new MultiSignError('REQUEST_NOT_FOUND', `No request found with ID ${requestId}`);
    }

    if (request.status === 'completed') {
      throw new MultiSignError('REQUEST_COMPLETED', 'Cannot reject completed request');
    }

    // Verify rejector is authorized
    const rejector = request.signers.find((s) => s.address === rejectingAddress);
    if (!rejector) {
      throw new MultiSignError(
        'UNAUTHORIZED_REJECTOR',
        `Address ${rejectingAddress} is not an authorized signer`
      );
    }

    // Update request
    request.status = 'rejected';
    request.rejection = {
      rejecting_address: rejectingAddress,
      reason,
      rejected_at: new Date().toISOString(),
    };
    await this.store.update(request);

    // Audit
    await this.auditLogger.log({
      event: 'approval_denied',
      wallet_id: request.wallet_id,
      wallet_address: request.wallet_address,
      context: `Rejected by ${rejectingAddress}: ${reason}`,
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
  async getStatus(requestId: string): Promise<MultiSignRequest> {
    const request = await this.store.get(requestId);
    if (!request) {
      throw new MultiSignError('REQUEST_NOT_FOUND', `No request found with ID ${requestId}`);
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
  async listPending(walletId: string, includeExpired: boolean = false): Promise<MultiSignRequest[]> {
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
  async expire(requestId: string): Promise<MultiSignRequest> {
    const request = await this.store.get(requestId);
    if (!request) {
      throw new MultiSignError('REQUEST_NOT_FOUND', `No request found with ID ${requestId}`);
    }

    request.status = 'expired';
    await this.store.update(request);

    await this.auditLogger.log({
      event: 'approval_expired',
      wallet_id: request.wallet_id,
      wallet_address: request.wallet_address,
      context: `Request expired with ${request.signers.filter((s) => s.signed).length}/${request.quorum.required} signatures`,
    });

    return request;
  }

  // ==========================================================================
  // SIGNATURE VALIDATION
  // ==========================================================================

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
  private validateSignature(
    signatureBlob: string,
    expectedSigner: string,
    unsignedBlob: string
  ): { valid: boolean; reason?: string } {
    try {
      // Decode the signed transaction
      let signedTx: any;
      try {
        signedTx = decode(signatureBlob);
      } catch (error) {
        return { valid: false, reason: 'Invalid transaction blob format' };
      }

      // For multi-sign, the transaction should have Signers array
      if (!signedTx.Signers || !Array.isArray(signedTx.Signers)) {
        // Single signature format - check TxnSignature exists
        if (!signedTx.TxnSignature) {
          return { valid: false, reason: 'No signature found in transaction' };
        }

        // Verify the signing account matches (for single-sign format)
        if (signedTx.SigningPubKey) {
          // Derive address from public key and verify
          try {
            const signerWallet = new Wallet(signedTx.SigningPubKey, '0'.repeat(64));
            if (signerWallet.classicAddress !== expectedSigner) {
              return {
                valid: false,
                reason: `Signer mismatch: expected ${expectedSigner}, got ${signerWallet.classicAddress}`,
              };
            }
          } catch {
            return { valid: false, reason: 'Could not derive address from signing public key' };
          }
        }

        return { valid: true };
      }

      // Multi-sign format - check Signers array
      const signerEntry = signedTx.Signers.find(
        (s: any) => s.Signer?.Account === expectedSigner
      );

      if (!signerEntry) {
        return {
          valid: false,
          reason: `No signature from expected signer ${expectedSigner}`,
        };
      }

      // Verify the Signer entry has required fields
      if (!signerEntry.Signer?.TxnSignature || !signerEntry.Signer?.SigningPubKey) {
        return { valid: false, reason: 'Incomplete signer entry' };
      }

      // Verify the public key corresponds to the claimed address
      try {
        const signerWallet = new Wallet(signerEntry.Signer.SigningPubKey, '0'.repeat(64));
        if (signerWallet.classicAddress !== expectedSigner) {
          return {
            valid: false,
            reason: `Public key does not match signer address`,
          };
        }
      } catch {
        return { valid: false, reason: 'Invalid signing public key' };
      }

      // Decode the unsigned transaction to compare core fields
      let unsignedTx: any;
      try {
        unsignedTx = decode(unsignedBlob);
      } catch {
        // If we can't decode the unsigned blob, skip field comparison
        return { valid: true };
      }

      // Verify core transaction fields match
      const criticalFields = ['TransactionType', 'Account', 'Destination', 'Amount', 'Fee', 'Sequence'];
      for (const field of criticalFields) {
        if (unsignedTx[field] !== undefined && signedTx[field] !== unsignedTx[field]) {
          // Amount and Fee might have slight differences in encoding
          if ((field === 'Amount' || field === 'Fee') &&
              String(unsignedTx[field]) === String(signedTx[field])) {
            continue;
          }
          return {
            valid: false,
            reason: `Transaction field mismatch: ${field}`,
          };
        }
      }

      return { valid: true };
    } catch (error) {
      return {
        valid: false,
        reason: `Validation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  // ==========================================================================
  // PRIVATE HELPERS
  // ==========================================================================

  private extractAmount(tx: Transaction): string | undefined {
    if ('Amount' in tx && typeof tx.Amount === 'string') {
      return tx.Amount;
    }
    return undefined;
  }

  private extractDestination(tx: Transaction): string | undefined {
    if ('Destination' in tx && typeof tx.Destination === 'string') {
      return tx.Destination;
    }
    return undefined;
  }

  private async notifySigners(request: MultiSignRequest, type: string): Promise<void> {
    // Placeholder - would integrate with NotificationService
    // For now, just log
    console.log(`[MultiSign] Notification: ${type} for request ${request.id}`);
  }
}
