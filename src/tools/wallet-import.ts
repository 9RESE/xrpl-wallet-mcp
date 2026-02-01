/**
 * wallet_import Tool Implementation
 *
 * Imports an existing XRPL wallet from a seed with a simple default policy.
 * This provides an easy way to use an existing wallet without configuring
 * the full policy schema.
 *
 * @module tools/wallet-import
 * @version 1.0.0
 */

import * as xrpl from 'xrpl';
import type { ServerContext } from '../server.js';
import type { Network, WalletImportInput } from '../schemas/index.js';
import { getWalletPassword } from '../utils/env.js';
import { SecureBuffer } from '../keystore/secure-buffer.js';
import { createTestPolicy } from '../policy/engine.js';

// Re-export the input type for server.ts
export type { WalletImportInput } from '../schemas/index.js';

/**
 * Output from wallet_import tool
 */
export interface WalletImportOutput {
  /** XRPL address */
  address: string;
  /** Public key */
  public_key: string;
  /** Wallet ID for future operations */
  wallet_id: string;
  /** Network the wallet is on */
  network: Network;
  /** Policy ID applied */
  policy_id: string;
  /** When the wallet was imported */
  imported_at: string;
}

/**
 * Handle wallet_import tool invocation.
 *
 * Imports an existing wallet from a seed:
 * 1. Derive address from seed
 * 2. Store encrypted seed in keystore
 * 3. Apply simple default policy
 * 4. Return wallet details
 *
 * @param context - Service instances
 * @param input - Seed and network
 * @returns Imported wallet details
 */
export async function handleWalletImport(
  context: ServerContext,
  input: WalletImportInput
): Promise<WalletImportOutput> {
  const { keystore, auditLogger } = context;

  // Validate seed format
  if (!input.seed.startsWith('s')) {
    throw new Error('Invalid seed format: must start with "s"');
  }

  // Derive wallet from seed to get address
  let wallet: xrpl.Wallet;
  try {
    wallet = xrpl.Wallet.fromSeed(input.seed);
  } catch (error) {
    throw new Error(`Invalid seed: ${error instanceof Error ? error.message : 'unknown error'}`);
  }

  // Get password for encryption
  const password = getWalletPassword();

  // Create a simple default policy for this network
  const policy = createTestPolicy(input.network);
  const policyId = `${input.network}-default-${Date.now()}`;

  // Store the seed securely
  const seedBuffer = Buffer.from(input.seed, 'utf-8');
  const secureKey = SecureBuffer.from(seedBuffer);

  // Zero the source buffer
  seedBuffer.fill(0);

  // Generate wallet ID
  const walletId = input.wallet_name || `imported-${wallet.address.slice(0, 8)}-${Date.now()}`;

  // Store in keystore
  await keystore.storeKey(
    walletId,
    secureKey,
    password,
    {
      address: wallet.address,
      publicKey: wallet.publicKey,
      network: input.network,
      policyId,
      policyVersion: policy.version,
      name: input.wallet_name,
    }
  );

  // Clean up secure buffer
  secureKey.dispose();

  const importedAt = new Date().toISOString();

  // Audit the import
  await auditLogger.log({
    event: 'wallet_created',
    wallet_id: walletId,
    wallet_address: wallet.address,
    context: `Imported with default policy: ${policyId}`,
  });

  return {
    address: wallet.address,
    public_key: wallet.publicKey,
    wallet_id: walletId,
    network: input.network,
    policy_id: policyId,
    imported_at: importedAt,
  };
}
