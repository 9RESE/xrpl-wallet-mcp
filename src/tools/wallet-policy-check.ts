/**
 * wallet_policy_check Tool Implementation
 *
 * Dry-run policy evaluation without signing.
 *
 * @module tools/wallet-policy-check
 * @version 1.0.0
 */

import { decode } from 'xrpl';
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

  // Get current limit status (TEMP: mock data)
  const limits = {
    daily_volume_used_drops: '0',
    daily_volume_limit_drops: '10000000000', // 10,000 XRP
    hourly_tx_used: 0,
    hourly_tx_limit: 10,
    daily_tx_used: 0,
    daily_tx_limit: 100,
  };

  return {
    would_approve: policyResult.tier === 1,
    tier: policyResult.tier,
    warnings: policyResult.warnings || [],
    violations: policyResult.violations || [],
    limits,
    transaction_details: {
      type: decoded.TransactionType,
      destination: 'Destination' in decoded ? (decoded.Destination as string) : undefined,
      amount_drops: 'Amount' in decoded && typeof decoded.Amount === 'string' ? decoded.Amount : undefined,
    },
  };
}
