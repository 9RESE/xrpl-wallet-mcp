/**
 * wallet_balance Tool Implementation
 *
 * Queries wallet balance and status from XRPL.
 *
 * @module tools/wallet-balance
 * @version 1.0.0
 */

import { dropsToXrp } from 'xrpl';
import type { ServerContext } from '../server.js';
import type { WalletBalanceInput, WalletBalanceOutput } from '../schemas/index.js';

/**
 * Handle wallet_balance tool invocation.
 *
 * Process:
 * 1. Query XRPL for account info
 * 2. Calculate reserves (base + owner count)
 * 3. Return balance, reserves, and available funds
 *
 * @param context - Service instances
 * @param input - Validated balance query
 * @returns Wallet balance and status
 */
export async function handleWalletBalance(
  context: ServerContext,
  input: WalletBalanceInput
): Promise<WalletBalanceOutput> {
  const { keystore, xrplClient } = context;

  // Get wallet entry to find network and policy
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);

  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }

  // Query XRPL for account info
  const accountInfo = await xrplClient.getAccountInfo(wallet.network, input.wallet_address);

  // Calculate reserves (TEMP: using hardcoded values - should query from XRPL)
  const baseReserve = BigInt('1000000'); // 1 XRP
  const ownerReserve = BigInt('200000'); // 0.2 XRP per object
  const ownerCount = BigInt(accountInfo.OwnerCount || 0);
  const totalReserve = baseReserve + ownerReserve * ownerCount;

  const balance = BigInt(accountInfo.Balance);
  const available = balance > totalReserve ? balance - totalReserve : BigInt(0);

  return {
    address: input.wallet_address,
    balance_drops: balance.toString(),
    balance_xrp: dropsToXrp(balance.toString()),
    reserve_drops: totalReserve.toString(),
    available_drops: available.toString(),
    sequence: accountInfo.Sequence,
    regular_key_set: !!accountInfo.RegularKey,
    signer_list: null, // TEMP: Would parse SignerList from account objects
    policy_id: wallet.policyId,
    network: wallet.network,
    queried_at: new Date().toISOString(),
  };
}
