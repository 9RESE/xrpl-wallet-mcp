/**
 * wallet_fund Tool Implementation
 *
 * Funds wallet from testnet/devnet faucet.
 *
 * @module tools/wallet-fund
 * @version 1.0.0
 */

import type { ServerContext } from '../server.js';
import type { WalletFundInput, WalletFundOutput } from '../schemas/index.js';

/**
 * Handle wallet_fund tool invocation.
 *
 * Requests test XRP from faucet for testnet/devnet wallets.
 * Only available on non-mainnet networks.
 *
 * @param context - Service instances
 * @param input - Validated fund request
 * @returns Funding result
 */
export async function handleWalletFund(
  context: ServerContext,
  input: WalletFundInput
): Promise<WalletFundOutput> {
  const { xrplClient, auditLogger } = context;

  // Ensure not on mainnet
  if (input.network === 'mainnet') {
    throw new Error('Faucet not available on mainnet');
  }

  try {
    // Request funding from faucet
    const fundResult = await xrplClient.fundWallet(input.network, input.wallet_address);

    // Audit funding event
    await auditLogger.log({
      event: 'wallet_created', // Using existing event type
      seq: 0,
      timestamp: new Date().toISOString(),
      wallet_address: input.wallet_address,
      context: `Funded from ${input.network} faucet`,
      prev_hash: '',
      hash: '',
    });

    return {
      status: 'funded',
      amount_drops: fundResult.amount,
      tx_hash: fundResult.hash,
      new_balance_drops: fundResult.balance,
    };
  } catch (error) {
    return {
      status: 'failed',
      error: error instanceof Error ? error.message : 'Unknown faucet error',
    };
  }
}
