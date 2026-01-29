/**
 * wallet_sign Tool Implementation
 *
 * Signs transactions with policy enforcement (autonomous, delayed, co-sign, or prohibited).
 *
 * @module tools/wallet-sign
 * @version 1.0.0
 */

import { decode } from 'xrpl';
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
  const { keystore, policyEngine, signingService, auditLogger } = context;

  // Get wallet entry to find associated policy
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);

  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }

  // Decode transaction to extract fields
  const decoded = decode(input.unsigned_tx);

  // Evaluate policy
  const policyResult = await policyEngine.evaluateTransaction(
    wallet.policyId,
    {
      type: decoded.TransactionType,
      destination: 'Destination' in decoded ? (decoded.Destination as string) : undefined,
      amount_drops: 'Amount' in decoded && typeof decoded.Amount === 'string' ? decoded.Amount : undefined,
    }
  );

  const timestamp = new Date().toISOString();

  // Tier 4: Prohibited - reject immediately
  if (policyResult.tier === 4) {
    await auditLogger.log({
      event: 'policy_violation',
      wallet_id: wallet.walletId,
      wallet_address: wallet.address,
      transaction_type: decoded.TransactionType as any,
      tier: 4,
      policy_decision: 'denied',
      context: input.context,
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
      transaction_type: decoded.TransactionType as any,
      tier: policyResult.tier,
      policy_decision: 'pending',
      context: input.context,
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
  const password = getWalletPassword();
  const signed = await signingService.sign(
    wallet.walletId,
    input.unsigned_tx,
    password
  );

  await auditLogger.log({
    event: 'transaction_signed',
    wallet_id: wallet.walletId,
    wallet_address: wallet.address,
    transaction_type: decoded.TransactionType as any,
    tx_hash: signed.hash,
    tier: 1,
    policy_decision: 'allowed',
    context: input.context,
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
