/**
 * wallet_list Tool Implementation
 *
 * Lists all managed wallets.
 *
 * @module tools/wallet-list
 * @version 1.0.0
 */

import type { ServerContext } from '../server.js';
import type { WalletListInput, WalletListOutput } from '../schemas/index.js';

/**
 * Handle wallet_list tool invocation.
 *
 * Returns all wallets managed by this MCP instance,
 * optionally filtered by network.
 *
 * @param context - Service instances
 * @param input - Validated list request (optional network filter)
 * @returns List of wallet summaries
 */
export async function handleWalletList(
  context: ServerContext,
  input: WalletListInput
): Promise<WalletListOutput> {
  const { keystore } = context;

  // Query keystore for wallets
  const walletSummaries = await keystore.listWallets(input.network);

  // Map to output format
  const wallets = walletSummaries.map((w) => ({
    wallet_id: w.walletId,
    address: w.address,
    name: w.name,
    network: w.network,
    policy_id: w.policyId,
    created_at: w.createdAt,
  }));

  return {
    wallets,
    total: wallets.length,
  };
}
