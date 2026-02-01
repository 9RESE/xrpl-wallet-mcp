/**
 * tx_submit Tool Implementation
 *
 * Submits signed transaction to XRPL with enhanced response
 * including tx_type, sequence_used, escrow_reference, and next_sequence.
 *
 * After successful submission, increments the local sequence tracker to
 * prevent tefPAST_SEQ race conditions in rapid multi-transaction workflows.
 *
 * @module tools/tx-submit
 * @version 2.1.0
 * @since 2026-01-29 - Added next_sequence tracking to fix race condition
 */

import * as xrpl from 'xrpl';
import type { ServerContext } from '../server.js';
import type { TxSubmitInput, TxSubmitOutput, TransactionType, EscrowReference } from '../schemas/index.js';
import { getSequenceTracker } from '../xrpl/sequence-tracker.js';

/**
 * Extract transaction metadata from decoded transaction.
 *
 * @param decoded - Decoded transaction object
 * @returns Transaction metadata (type, sequence, account, escrow reference)
 */
function extractTransactionMetadata(decoded: Record<string, unknown>): {
  txType: TransactionType | undefined;
  sequenceUsed: number | undefined;
  account: string | undefined;
  escrowReference: EscrowReference | undefined;
} {
  const txType = decoded.TransactionType as TransactionType | undefined;
  const sequenceUsed = typeof decoded.Sequence === 'number' ? decoded.Sequence : undefined;
  const account = decoded.Account as string | undefined;

  // For EscrowCreate, build escrow reference for finish/cancel operations
  let escrowReference: EscrowReference | undefined;

  if (txType === 'EscrowCreate' && sequenceUsed !== undefined && account) {
    escrowReference = {
      owner: account,
      sequence: sequenceUsed,
    };
  }

  return { txType, sequenceUsed, account, escrowReference };
}

/**
 * Handle tx_submit tool invocation.
 *
 * Submits a signed transaction blob to the XRPL network
 * and optionally waits for validation.
 *
 * Enhanced response includes:
 * - tx_type: The transaction type for routing logic
 * - sequence_used: The sequence number consumed
 * - escrow_reference: For EscrowCreate, the owner+sequence for finish/cancel
 *
 * @param context - Service instances
 * @param input - Validated submission request
 * @returns Submission result with enhanced metadata
 */
export async function handleTxSubmit(
  context: ServerContext,
  input: TxSubmitInput
): Promise<TxSubmitOutput> {
  const { xrplClient, auditLogger } = context;

  const submittedAt = new Date().toISOString();

  // Decode transaction to extract metadata before submission
  let txType: TransactionType | undefined;
  let sequenceUsed: number | undefined;
  let account: string | undefined;
  let escrowReference: EscrowReference | undefined;

  try {
    const decoded = xrpl.decode(input.signed_tx) as Record<string, unknown>;
    const metadata = extractTransactionMetadata(decoded);
    txType = metadata.txType;
    sequenceUsed = metadata.sequenceUsed;
    account = metadata.account;
    escrowReference = metadata.escrowReference;
  } catch (decodeError) {
    // Continue with submission even if decode fails
    // The XRPL will validate the transaction
    console.warn('[tx_submit] Could not decode transaction for metadata:', decodeError);
  }

  // Submit transaction to XRPL
  const result = await xrplClient.submitSignedTransaction(input.signed_tx, {
    waitForValidation: input.wait_for_validation ?? true,
  });

  // Audit submission
  await auditLogger.log({
    event: 'transaction_submitted',
    tx_hash: result.hash,
    policy_decision: result.validated ? 'allowed' : 'pending',
    transaction_type: txType,
    context: escrowReference
      ? `EscrowCreate: owner=${escrowReference.owner}, sequence=${escrowReference.sequence}`
      : undefined,
  });

  // Track sequence after successful submission to prevent race conditions
  // This is the KEY FIX: record sequence at submit time, not just sign time
  // The next transaction for this account MUST use sequenceUsed + 1
  let nextSequence: number | undefined;

  if (result.resultCode === 'tesSUCCESS' && account && sequenceUsed !== undefined) {
    const sequenceTracker = getSequenceTracker();
    sequenceTracker.recordSignedSequence(account, sequenceUsed);
    nextSequence = sequenceUsed + 1;

    // Log for debugging sequence race conditions
    console.error(
      `[tx_submit] Recorded sequence ${sequenceUsed} for ${account}, ` +
      `next tx should use ${nextSequence}`
    );
  }

  // Build response with enhanced metadata
  const response: TxSubmitOutput = {
    tx_hash: result.hash,
    result: {
      result_code: result.resultCode,
      result_message: result.resultCode, // resultCode serves as message
      success: result.resultCode === 'tesSUCCESS',
    },
    ledger_index: result.ledgerIndex,
    submitted_at: submittedAt,
    validated_at: result.validated ? new Date().toISOString() : undefined,
    tx_type: txType,
    sequence_used: sequenceUsed,
    next_sequence: nextSequence,
  };

  // Add escrow reference for EscrowCreate transactions
  // This provides the owner+sequence needed for EscrowFinish/EscrowCancel
  if (escrowReference && result.resultCode === 'tesSUCCESS') {
    response.escrow_reference = escrowReference;
  }

  return response;
}
