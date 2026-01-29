/**
 * wallet_history Tool Implementation
 *
 * Retrieves transaction history from XRPL.
 *
 * @module tools/wallet-history
 * @version 1.0.0
 */

import type { ServerContext } from '../server.js';
import type { WalletHistoryInput, WalletHistoryOutput } from '../schemas/index.js';

/**
 * Handle wallet_history tool invocation.
 *
 * Queries XRPL for transaction history and returns
 * formatted entries with policy tier information.
 *
 * @param context - Service instances
 * @param input - Validated history request
 * @returns Transaction history entries
 */
export async function handleWalletHistory(
  context: ServerContext,
  input: WalletHistoryInput
): Promise<WalletHistoryOutput> {
  const { keystore, xrplClient } = context;

  // Get wallet entry to find network
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);

  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }

  // Query XRPL for transaction history
  const txHistory = await xrplClient.getTransactionHistory(
    wallet.network,
    input.wallet_address,
    {
      limit: input.limit || 20,
      marker: input.marker,
    }
  );

  // Map to output format
  const transactions = txHistory.transactions.map((tx) => ({
    hash: tx.hash,
    type: tx.tx.TransactionType,
    amount_drops: 'Amount' in tx.tx && typeof tx.tx.Amount === 'string' ? tx.tx.Amount : undefined,
    destination: 'Destination' in tx.tx ? (tx.tx.Destination as string) : undefined,
    timestamp: new Date((tx.close_time_iso || '')).toISOString(),
    policy_tier: 1 as const, // TEMP: Would come from audit log
    context: undefined, // TEMP: Would come from audit log
    ledger_index: tx.ledger_index || 0,
    success: tx.meta?.TransactionResult === 'tesSUCCESS',
  }));

  return {
    address: input.wallet_address,
    transactions,
    marker: txHistory.marker,
    has_more: !!txHistory.marker,
  };
}
