/**
 * tx_submit Tool Implementation
 *
 * Submits signed transaction to XRPL with enhanced response
 * including tx_type, sequence_used, and escrow_reference.
 *
 * @module tools/tx-submit
 * @version 2.0.0
 */

import { decode } from 'xrpl';
import type { ServerContext } from '../server.js';
import type { TxSubmitInput, TxSubmitOutput, TransactionType, EscrowReference } from '../schemas/index.js';

/**
 * Extract transaction metadata from decoded transaction.
 *
 * @param decoded - Decoded transaction object
 * @returns Transaction metadata (type, sequence, escrow reference)
 */
function extractTransactionMetadata(decoded: Record<string, unknown>): {
  txType: TransactionType | undefined;
  sequenceUsed: number | undefined;
  escrowReference: EscrowReference | undefined;
} {
  const txType = decoded.TransactionType as TransactionType | undefined;
  const sequenceUsed = typeof decoded.Sequence === 'number' ? decoded.Sequence : undefined;

  // For EscrowCreate, build escrow reference for finish/cancel operations
  let escrowReference: EscrowReference | undefined;

  if (txType === 'EscrowCreate' && sequenceUsed !== undefined) {
    const owner = decoded.Account as string | undefined;
    if (owner) {
      escrowReference = {
        owner,
        sequence: sequenceUsed,
      };
    }
  }

  return { txType, sequenceUsed, escrowReference };
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
  let escrowReference: EscrowReference | undefined;

  try {
    const decoded = decode(input.signed_tx) as Record<string, unknown>;
    const metadata = extractTransactionMetadata(decoded);
    txType = metadata.txType;
    sequenceUsed = metadata.sequenceUsed;
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
  };

  // Add escrow reference for EscrowCreate transactions
  // This provides the owner+sequence needed for EscrowFinish/EscrowCancel
  if (escrowReference && result.resultCode === 'tesSUCCESS') {
    response.escrow_reference = escrowReference;
  }

  return response;
}
