/**
 * wallet_balance Tool Implementation
 *
 * Queries wallet balance and status from XRPL.
 * Returns ledger_index for consistency verification.
 *
 * @module tools/wallet-balance
 * @version 2.0.0
 */

import * as xrpl from 'xrpl';
import type { ServerContext } from '../server.js';
import type { WalletBalanceInput, WalletBalanceOutput } from '../schemas/index.js';

/**
 * Sleep utility for wait_after_tx delay
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Handle wallet_balance tool invocation.
 *
 * Process:
 * 1. Optional: Wait for specified delay (for post-transaction timing)
 * 2. Query XRPL for account info and server info
 * 3. Calculate reserves using network-specific values
 * 4. Return balance, reserves, available funds, and ledger_index
 *
 * @param context - Service instances
 * @param input - Validated balance query
 * @returns Wallet balance, status, and ledger_index
 */
export async function handleWalletBalance(
  context: ServerContext,
  input: WalletBalanceInput
): Promise<WalletBalanceOutput> {
  const { keystore, xrplClient } = context;

  // Optional delay for post-transaction balance queries
  // This helps avoid stale balance reads after a transaction
  if (input.wait_after_tx && input.wait_after_tx > 0) {
    await sleep(input.wait_after_tx);
  }

  // Get wallet entry to find network and policy
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);

  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }

  // Query XRPL for account info
  const accountInfo = await xrplClient.getAccountInfo(input.wallet_address);

  // Query current ledger index for consistency verification
  const currentLedgerIndex = await xrplClient.getCurrentLedgerIndex();

  // Query server info for current reserve requirements
  // Defaults updated Dec 2024: 1 XRP base, 0.2 XRP per object
  let baseReserve = BigInt('1000000'); // 1 XRP default
  let ownerReserve = BigInt('200000'); // 0.2 XRP per object default

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
    balance_xrp: String(xrpl.dropsToXrp(balance.toString())), // Ensure string type
    reserve_drops: totalReserve.toString(),
    available_drops: available.toString(),
    sequence: accountInfo.sequence, // Keep as number per schema
    regular_key_set: !!(accountInfo as { regularKey?: string }).regularKey,
    signer_list: null, // SignerList would require separate account_objects query
    policy_id: wallet.policyId,
    network: wallet.network,
    ledger_index: currentLedgerIndex,
    queried_at: new Date().toISOString(),
  };
}
