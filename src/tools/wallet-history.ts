/**
 * wallet_history Tool Implementation
 *
 * Retrieves transaction history from XRPL.
 *
 * @module tools/wallet-history
 * @version 1.0.0
 */

import type { ServerContext } from '../server.js';
import type { WalletHistoryInput, WalletHistoryOutput, TransactionHistoryEntry } from '../schemas/index.js';

/**
 * Handle wallet_history tool invocation.
 *
 * Queries XRPL for transaction history and returns
 * formatted entries with available information.
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

  // Query XRPL for transaction history using getAccountTransactions
  const rawTransactions = await xrplClient.getAccountTransactions(
    input.wallet_address,
    {
      limit: input.limit || 20,
    }
  );

  // Map to output format
  const transactions: TransactionHistoryEntry[] = rawTransactions.map((tx: any) => {
    // Extract transaction details
    const txData = tx.tx || tx;
    const meta = tx.meta || {};

    // Determine transaction result
    const resultCode = typeof meta === 'object' && meta.TransactionResult
      ? meta.TransactionResult
      : 'unknown';

    return {
      hash: txData.hash || tx.hash || '',
      type: txData.TransactionType || 'Unknown',
      amount_drops: 'Amount' in txData && typeof txData.Amount === 'string'
        ? txData.Amount
        : undefined,
      destination: 'Destination' in txData
        ? (txData.Destination as string)
        : undefined,
      timestamp: txData.date
        ? new Date((txData.date + 946684800) * 1000).toISOString() // XRPL epoch starts 2000-01-01
        : new Date().toISOString(),
      policy_tier: 1 as const, // Historical transactions don't have policy tier info
      context: undefined, // Would need to cross-reference with audit log
      ledger_index: txData.ledger_index || tx.ledger_index || 0,
      success: resultCode === 'tesSUCCESS',
    };
  });

  // Note: XRPL pagination uses markers, but getAccountTransactions
  // may not return a marker in all cases
  return {
    address: input.wallet_address,
    transactions,
    marker: undefined, // Pagination marker if available
    has_more: transactions.length >= (input.limit || 20),
  };
}
