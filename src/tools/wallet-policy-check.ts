/**
 * wallet_policy_check Tool Implementation
 *
 * Dry-run policy evaluation without signing.
 *
 * @module tools/wallet-policy-check
 * @version 1.0.0
 */

import * as xrpl from 'xrpl';
import type { ServerContext } from '../server.js';
import type { WalletPolicyCheckInput, WalletPolicyCheckOutput } from '../schemas/index.js';

/**
 * Handle wallet_policy_check tool invocation.
 *
 * Evaluates a transaction against policy without signing.
 * Useful for checking if a transaction will be approved before building it.
 *
 * @param context - Service instances
 * @param input - Validated policy check request
 * @returns Policy evaluation result
 */
export async function handleWalletPolicyCheck(
  context: ServerContext,
  input: WalletPolicyCheckInput
): Promise<WalletPolicyCheckOutput> {
  const { keystore, policyEngine } = context;

  // Get wallet entry to find associated policy
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);

  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }

  // Decode transaction to extract fields (use bracket notation for index signature)
  const decoded = xrpl.decode(input.unsigned_tx);
  const transactionType = decoded['TransactionType'] as string;
  const destinationField = 'Destination' in decoded ? decoded['Destination'] : undefined;
  const destination = typeof destinationField === 'string' ? destinationField : undefined;
  const amountField = 'Amount' in decoded ? decoded['Amount'] : undefined;
  const amountDrops = typeof amountField === 'string' ? amountField : undefined;

  // Evaluate policy
  const policyResult = await policyEngine.evaluateTransaction(
    wallet.policyId,
    {
      type: transactionType,
      ...(destination ? { destination } : {}),
      ...(amountDrops ? { amount_drops: amountDrops } : {}),
    }
  );

  // Get current limit status from policy engine
  const limitState = policyEngine.getLimitState();

  // Calculate actual limit values
  // Note: Max values should ideally come from the policy configuration
  const maxTxPerHour = 50; // Default from testnet policy
  const maxTxPerDay = 200; // Default from testnet policy
  const maxDailyVolumeXrp = 10000; // Default from testnet policy

  const limits = {
    daily_volume_used_drops: String(Math.floor(limitState.daily.totalVolumeXrp * 1_000_000)),
    daily_volume_limit_drops: String(maxDailyVolumeXrp * 1_000_000),
    hourly_tx_used: limitState.hourly.transactions.length,
    hourly_tx_limit: maxTxPerHour,
    daily_tx_used: limitState.daily.transactionCount,
    daily_tx_limit: maxTxPerDay,
  };

  return {
    would_approve: policyResult.tier === 1,
    tier: policyResult.tier,
    warnings: policyResult.warnings || [],
    violations: policyResult.violations || [],
    limits,
    transaction_details: {
      type: transactionType as any, // Cast to match expected transaction type enum
      ...(destination ? { destination } : {}),
      ...(amountDrops ? { amount_drops: amountDrops } : {}),
    },
  };
}
