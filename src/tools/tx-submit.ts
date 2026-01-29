/**
 * tx_submit Tool Implementation
 *
 * Submits signed transaction to XRPL.
 *
 * @module tools/tx-submit
 * @version 1.0.0
 */

import type { ServerContext } from '../server.js';
import type { TxSubmitInput, TxSubmitOutput } from '../schemas/index.js';

/**
 * Handle tx_submit tool invocation.
 *
 * Submits a signed transaction blob to the XRPL network
 * and optionally waits for validation.
 *
 * @param context - Service instances
 * @param input - Validated submission request
 * @returns Submission result
 */
export async function handleTxSubmit(
  context: ServerContext,
  input: TxSubmitInput
): Promise<TxSubmitOutput> {
  const { xrplClient, auditLogger } = context;

  const submittedAt = new Date().toISOString();

  // Submit transaction to XRPL
  const result = await xrplClient.submitTransaction(
    input.network,
    input.signed_tx,
    input.wait_for_validation ?? true
  );

  // Audit submission
  await auditLogger.log({
    event: 'transaction_submitted',
    seq: 0,
    timestamp: submittedAt,
    tx_hash: result.hash,
    policy_decision: result.validated ? 'allowed' : 'pending',
    prev_hash: '',
    hash: '',
  });

  return {
    tx_hash: result.hash,
    result: {
      result_code: result.resultCode,
      result_message: result.resultMessage,
      success: result.resultCode === 'tesSUCCESS',
    },
    ledger_index: result.ledgerIndex,
    submitted_at: submittedAt,
    validated_at: result.validated ? new Date().toISOString() : undefined,
  };
}
