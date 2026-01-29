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
 * 1. Query XRPL for account info and server info
 * 2. Calculate reserves using network-specific values
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
  const accountInfo = await xrplClient.getAccountInfo(input.wallet_address);

  // Query server info for current reserve requirements
  let baseReserve = BigInt('10000000'); // 10 XRP default
  let ownerReserve = BigInt('2000000'); // 2 XRP per object default

  try {
    const serverInfo = await xrplClient.getServerInfo();
    if (serverInfo.validated_ledger) {
      // Convert XRP to drops
      baseReserve = BigInt(Math.floor(serverInfo.validated_ledger.reserve_base_xrp * 1_000_000));
      ownerReserve = BigInt(Math.floor(serverInfo.validated_ledger.reserve_inc_xrp * 1_000_000));
    }
  } catch (error) {
    // Use defaults if server info unavailable
    console.warn('Could not fetch server info for reserves, using defaults');
  }

  // Calculate total reserve based on owner count
  const ownerCount = BigInt(accountInfo.ownerCount || 0);
  const totalReserve = baseReserve + ownerReserve * ownerCount;

  const balance = BigInt(accountInfo.balance);
  const available = balance > totalReserve ? balance - totalReserve : BigInt(0);

  return {
    address: input.wallet_address,
    balance_drops: balance.toString(),
    balance_xrp: dropsToXrp(balance.toString()),
    reserve_drops: totalReserve.toString(),
    available_drops: available.toString(),
    sequence: accountInfo.sequence,
    regular_key_set: !!(accountInfo as any).regularKey,
    signer_list: null, // SignerList would require separate account_objects query
    policy_id: wallet.policyId,
    network: wallet.network,
    queried_at: new Date().toISOString(),
  };
}
