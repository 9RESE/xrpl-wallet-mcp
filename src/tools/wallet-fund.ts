/**
 * wallet_fund Tool Implementation
 *
 * Funds wallet from testnet/devnet faucet with automatic retry
 * until account is queryable on validated ledger.
 *
 * @module tools/wallet-fund
 * @version 2.0.0
 */

import { Client } from 'xrpl';
import type { ServerContext } from '../server.js';
import type { WalletFundInput, WalletFundOutput } from '../schemas/index.js';
import { getWebSocketUrl, getFaucetUrl } from '../xrpl/config.js';

/**
 * Configuration for faucet retry behavior
 */
const FAUCET_CONFIG = {
  /** Maximum retries for account confirmation */
  maxRetries: 15,
  /** Delay between retries in milliseconds */
  retryDelayMs: 2000,
  /** Initial wait after faucet request before first check */
  initialWaitMs: 3000,
} as const;

/**
 * Sleep utility
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Handle wallet_fund tool invocation.
 *
 * Requests test XRP from faucet for testnet/devnet wallets.
 * Implements retry logic to wait until account is queryable.
 *
 * Process:
 * 1. Request funding from network faucet
 * 2. Wait for account to appear on validated ledger (if wait_for_confirmation)
 * 3. Return initial balance and account_ready status
 *
 * @param context - Service instances
 * @param input - Validated fund request
 * @returns Funding result with initial_balance_drops and account_ready
 */
export async function handleWalletFund(
  context: ServerContext,
  input: WalletFundInput
): Promise<WalletFundOutput> {
  const { auditLogger } = context;
  const waitForConfirmation = input.wait_for_confirmation ?? true;

  // Get faucet URL
  const faucetUrl = getFaucetUrl(input.network);
  if (!faucetUrl) {
    return {
      status: 'failed',
      error: `No faucet available for network: ${input.network}`,
    };
  }

  // Get WebSocket URL for the network
  const wsUrl = getWebSocketUrl(input.network);

  // Create a temporary client for this operation
  const client = new Client(wsUrl);

  try {
    // Connect to XRPL
    await client.connect();

    // Audit funding attempt
    await auditLogger.log({
      event: 'wallet_created', // Using existing event type for audit
      wallet_address: input.wallet_address,
      context: `Faucet funding requested for ${input.network}`,
    });

    // Use xrpl.js fundWallet method which handles the faucet API
    // Note: fundWallet can either create a new wallet or fund an existing address
    // We're funding an existing address here
    let fundResult: { balance: number; wallet?: unknown };

    try {
      // Try to fund using the wallet address
      // xrpl.js fundWallet accepts either a Wallet object or creates one
      // For existing addresses, we need to use the faucet API directly
      const faucetResponse = await fetch(faucetUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          destination: input.wallet_address,
        }),
      });

      if (!faucetResponse.ok) {
        const errorText = await faucetResponse.text();
        throw new Error(`Faucet request failed: ${faucetResponse.status} - ${errorText}`);
      }

      const faucetData = await faucetResponse.json() as {
        account?: { address: string };
        balance?: number;
        amount?: number;
      };

      fundResult = {
        balance: faucetData.balance ?? faucetData.amount ?? 0,
      };
    } catch (faucetError) {
      // Disconnect and return error
      await client.disconnect();
      return {
        status: 'failed',
        error: faucetError instanceof Error ? faucetError.message : 'Faucet request failed',
        faucet_url: faucetUrl,
      };
    }

    // If not waiting for confirmation, return immediately
    if (!waitForConfirmation) {
      await client.disconnect();
      return {
        status: 'pending',
        account_ready: false,
        faucet_url: faucetUrl,
        message: 'Funding submitted. Account may take 5-20 seconds to appear on validated ledger.',
      };
    }

    // Wait for account to be queryable on validated ledger
    // Faucet funding takes time to propagate (5-20 seconds on testnet)
    await sleep(FAUCET_CONFIG.initialWaitMs);

    let accountReady = false;
    let finalBalance = '0';
    let ledgerIndex: number | undefined;

    for (let attempt = 0; attempt < FAUCET_CONFIG.maxRetries; attempt++) {
      try {
        const accountInfo = await client.request({
          command: 'account_info',
          account: input.wallet_address,
          ledger_index: 'validated',
        });

        // Account exists and is queryable
        finalBalance = accountInfo.result.account_data.Balance;
        ledgerIndex = accountInfo.result.ledger_index;
        accountReady = true;
        break;
      } catch (error: unknown) {
        // Check if it's "account not found" error - this is expected while waiting
        const errorData = error as { data?: { error?: string } };
        if (errorData.data?.error === 'actNotFound') {
          // Account not yet on validated ledger, continue waiting
          await sleep(FAUCET_CONFIG.retryDelayMs);
          continue;
        }
        // Other errors should be logged but we continue trying
        console.warn(`[wallet_fund] Attempt ${attempt + 1} failed:`, error);
        await sleep(FAUCET_CONFIG.retryDelayMs);
      }
    }

    // Disconnect client
    await client.disconnect();

    if (!accountReady) {
      return {
        status: 'pending',
        account_ready: false,
        faucet_url: faucetUrl,
        message: `Account not confirmed after ${FAUCET_CONFIG.maxRetries * FAUCET_CONFIG.retryDelayMs / 1000}s. It may still appear later.`,
      };
    }

    // Success - account is funded and queryable
    return {
      status: 'funded',
      amount_drops: finalBalance,
      initial_balance_drops: finalBalance,
      new_balance_drops: finalBalance, // Deprecated but kept for compatibility
      account_ready: true,
      ledger_index: ledgerIndex,
      faucet_url: faucetUrl,
    };
  } catch (error) {
    // Ensure client is disconnected on error
    try {
      if (client.isConnected()) {
        await client.disconnect();
      }
    } catch {
      // Ignore disconnect errors
    }

    return {
      status: 'failed',
      error: error instanceof Error ? error.message : 'Unknown faucet error',
      faucet_url: faucetUrl,
    };
  }
}
