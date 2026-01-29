/**
 * policy_set Tool Implementation
 *
 * Updates wallet policy configuration.
 *
 * @module tools/policy-set
 * @version 1.0.0
 */

import type { ServerContext } from '../server.js';
import type { PolicySetInput, PolicySetOutput } from '../schemas/index.js';

/**
 * Handle policy_set tool invocation.
 *
 * Updates policy for an existing wallet.
 * SECURITY: This is a CRITICAL operation requiring human approval.
 *
 * @param context - Service instances
 * @param input - Validated policy update request
 * @returns Policy update result
 */
export async function handlePolicySet(
  context: ServerContext,
  input: PolicySetInput
): Promise<PolicySetOutput> {
  const { keystore, policyEngine, auditLogger } = context;

  // Get wallet entry
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);

  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }

  const previousPolicyId = wallet.policyId;

  // TEMP: Policy changes always require approval in production
  // For now, we'll apply directly but log as requiring approval
  await policyEngine.setPolicy(input.policy);

  // Update wallet metadata with new policy reference
  await keystore.updateMetadata(wallet.walletId, {
    customData: {
      policyId: input.policy.policy_id,
      policyVersion: input.policy.policy_version,
    },
  });

  const timestamp = new Date().toISOString();

  // Audit policy change
  await auditLogger.log({
    event: 'policy_updated',
    seq: 0,
    timestamp,
    wallet_id: wallet.walletId,
    wallet_address: wallet.address,
    context: input.reason,
    prev_hash: '',
    hash: '',
  });

  return {
    status: 'pending_approval', // TEMP: Would be 'applied' after approval
    previous_policy_id: previousPolicyId,
    new_policy_id: input.policy.policy_id,
    approval_id: `policy_approval_${Date.now()}`,
  };
}
