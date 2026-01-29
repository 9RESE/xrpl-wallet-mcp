/**
 * wallet_sign Tool Implementation
 *
 * Signs transactions with policy enforcement (autonomous, delayed, co-sign, or prohibited).
 * Supports auto-sequence filling to prevent tefPAST_SEQ errors in multi-transaction workflows.
 *
 * @module tools/wallet-sign
 * @version 2.0.0
 * @since 2026-01-29 - Added auto_sequence support (ADR-013)
 */

import { decode, encode, type Transaction } from 'xrpl';
import type { ServerContext } from '../server.js';
import type { WalletSignInput, WalletSignOutput } from '../schemas/index.js';
import { getWalletPassword } from '../utils/env.js';

/**
 * Handle wallet_sign tool invocation.
 *
 * Process:
 * 1. Decode transaction to extract policy-relevant fields
 * 2. Evaluate transaction against wallet's policy
 * 3. Route based on tier:
 *    - Tier 1: Sign immediately (autonomous)
 *    - Tier 2: Queue for delayed approval
 *    - Tier 3: Request human co-signature
 *    - Tier 4: Reject with reason
 * 4. Audit all attempts (approved, pending, rejected)
 *
 * @param context - Service instances
 * @param input - Validated signing request
 * @returns Discriminated union: approved, pending, or rejected
 */
export async function handleWalletSign(
  context: ServerContext,
  input: WalletSignInput
): Promise<WalletSignOutput> {
  const { keystore, policyEngine, signingService, auditLogger, xrplClient } = context;

  // Get wallet entry to find associated policy
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);

  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }

  // Decode transaction to extract fields
  let decoded = decode(input.unsigned_tx) as Transaction & Record<string, unknown>;

  // Auto-sequence: fetch fresh sequence from ledger (default: true)
  // This prevents tefPAST_SEQ errors in multi-transaction workflows
  let transactionBlob = input.unsigned_tx;

  if (input.auto_sequence !== false) {
    try {
      // Get fresh account info from validated ledger
      const accountInfo = await xrplClient.getAccountInfo(input.wallet_address);
      const currentSequence = accountInfo.sequence;

      // Track if we need to re-encode
      let needsReencode = false;

      // Update sequence if different or missing
      if (decoded.Sequence !== currentSequence) {
        decoded.Sequence = currentSequence;
        needsReencode = true;
      }

      // Autofill Fee if missing
      if (!decoded.Fee) {
        const fee = await xrplClient.getFee();
        decoded.Fee = fee;
        needsReencode = true;
      }

      // Autofill LastLedgerSequence if missing (current + 20 for ~80 seconds)
      if (!decoded.LastLedgerSequence) {
        const currentLedger = await xrplClient.getCurrentLedgerIndex();
        decoded.LastLedgerSequence = currentLedger + 20;
        needsReencode = true;
      }

      // Re-encode transaction if we modified it
      if (needsReencode) {
        transactionBlob = encode(decoded);
      }
    } catch (error) {
      // Log warning but continue with original transaction
      // This allows offline signing to work if auto_sequence query fails
      console.warn(
        '[wallet_sign] Failed to autofill sequence:',
        error instanceof Error ? error.message : 'Unknown error'
      );
    }
  }

  // Evaluate policy - access fields using bracket notation for index signature types
  const transactionType = decoded['TransactionType'] as string;
  const destination = 'Destination' in decoded ? (decoded['Destination'] as string) : undefined;
  const amountField = 'Amount' in decoded ? decoded['Amount'] : undefined;
  const amountDrops = typeof amountField === 'string' ? amountField : undefined;

  const policyResult = await policyEngine.evaluateTransaction(
    wallet.policyId,
    {
      type: transactionType,
      ...(destination ? { destination } : {}),
      ...(amountDrops ? { amount_drops: amountDrops } : {}),
    }
  );

  const timestamp = new Date().toISOString();

  // Tier 4: Prohibited - reject immediately
  if (policyResult.tier === 4) {
    await auditLogger.log({
      event: 'policy_violation',
      wallet_id: wallet.walletId,
      wallet_address: wallet.address,
      transaction_type: transactionType as any, // Cast to TransactionType enum
      tier: 4,
      policy_decision: 'denied',
      ...(input.context ? { context: input.context } : {}),
    });

    return {
      status: 'rejected',
      reason: policyResult.violations?.join('; ') || 'Transaction violates policy',
      policy_tier: 4,
    };
  }

  // Tier 2/3: Requires approval (not implemented yet - return pending)
  if (policyResult.tier === 2 || policyResult.tier === 3) {
    const approvalId = `approval_${Date.now()}_${wallet.walletId}`;

    await auditLogger.log({
      event: 'approval_requested',
      wallet_id: wallet.walletId,
      wallet_address: wallet.address,
      transaction_type: transactionType as any, // Cast to TransactionType enum
      tier: policyResult.tier,
      policy_decision: 'pending',
      ...(input.context ? { context: input.context } : {}),
    });

    return {
      status: 'pending_approval',
      approval_id: approvalId,
      reason: policyResult.tier === 2 ? 'exceeds_autonomous_limit' : 'requires_cosign',
      expires_at: new Date(Date.now() + 300000).toISOString(), // 5 minutes
      policy_tier: policyResult.tier,
    };
  }

  // Tier 1: Autonomous - sign immediately
  // Use transactionBlob which may have been updated with fresh sequence
  const password = getWalletPassword();
  const signed = await signingService.sign(
    wallet.walletId,
    transactionBlob,
    password
  );

  await auditLogger.log({
    event: 'transaction_signed',
    wallet_id: wallet.walletId,
    wallet_address: wallet.address,
    transaction_type: transactionType as any, // Cast to TransactionType enum
    tx_hash: signed.hash,
    tier: 1,
    policy_decision: 'allowed',
    ...(input.context ? { context: input.context } : {}),
  });

  // Get limit state from policy engine for accurate reporting
  const limitState = policyEngine.getLimitState();
  const policyInfo = policyEngine.getPolicyInfo();

  // Calculate remaining limits based on current state
  // Note: These are estimates based on the policy engine's internal tracking
  const dailyTransactionsUsed = limitState.daily.transactionCount;
  const hourlyTransactionsUsed = limitState.hourly.transactions.length;
  const dailyVolumeUsedXrp = limitState.daily.totalVolumeXrp;

  // Get limit configuration (default values if not available)
  const maxTxPerDay = 100; // Default, should come from policy
  const maxTxPerHour = 10; // Default, should come from policy
  const maxDailyVolumeXrp = 10000; // Default, should come from policy

  return {
    status: 'approved',
    signed_tx: signed.tx_blob,
    tx_hash: signed.hash,
    policy_tier: 1,
    limits_after: {
      daily_remaining_drops: String(Math.max(0, (maxDailyVolumeXrp - dailyVolumeUsedXrp) * 1_000_000)),
      hourly_tx_remaining: Math.max(0, maxTxPerHour - hourlyTransactionsUsed),
      daily_tx_remaining: Math.max(0, maxTxPerDay - dailyTransactionsUsed),
    },
    signed_at: timestamp,
  };
}
