/**
 * wallet_create Tool Implementation
 *
 * Creates a new XRPL wallet with policy controls and encrypted key storage.
 *
 * @module tools/wallet-create
 * @version 1.0.0
 */

import type { ServerContext } from '../server.js';
import type { WalletCreateInput, WalletCreateOutput } from '../schemas/index.js';
import { getWalletPassword } from '../utils/env.js';

/**
 * Handle wallet_create tool invocation.
 *
 * Creates a new agent wallet:
 * 1. Generate wallet keys via keystore
 * 2. Store policy configuration
 * 3. Audit wallet creation event
 * 4. Return wallet details (no private keys)
 *
 * @param context - Service instances
 * @param input - Validated wallet creation parameters
 * @returns Wallet creation result with address and public key
 */
export async function handleWalletCreate(
  context: ServerContext,
  input: WalletCreateInput
): Promise<WalletCreateOutput> {
  const { keystore, policyEngine, auditLogger } = context;

  // Store policy configuration
  await policyEngine.setPolicy(input.policy);

  // Get wallet password (throws if not set)
  const password = getWalletPassword();

  // Create wallet with policy reference
  const walletEntry = await keystore.createWallet(
    input.network,
    {
      policyId: input.policy.policy_id,
      policyVersion: input.policy.policy_version,
    },
    {
      name: input.wallet_name,
      password,
      algorithm: 'ed25519', // Recommended for XRPL
    }
  );

  // Generate master key backup (encrypted)
  const backup = await keystore.exportBackup(
    walletEntry.walletId,
    password,
    'encrypted-json'
  );

  // Audit wallet creation
  await auditLogger.log({
    event: 'wallet_created',
    wallet_id: walletEntry.walletId,
    wallet_address: walletEntry.address,
    context: `Policy: ${input.policy.policy_id}`,
  });

  return {
    address: walletEntry.address,
    regular_key_public: walletEntry.publicKey,
    master_key_backup: JSON.stringify(backup),
    policy_id: input.policy.policy_id,
    wallet_id: walletEntry.walletId,
    network: input.network,
    created_at: walletEntry.createdAt,
  };
}
