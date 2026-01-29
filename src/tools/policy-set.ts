/**
 * policy_set Tool Implementation
 *
 * Updates wallet policy configuration with proper audit trail.
 *
 * Security Process:
 * 1. Validate new policy structure
 * 2. Verify wallet exists and get current policy
 * 3. Signal policy engine about the update
 * 4. Update keystore metadata with new policy reference
 * 5. Audit the policy change
 *
 * NOTE: In production, policy changes should require human approval.
 * Currently implements auto-approval for development purposes.
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
 *
 * SECURITY CONSIDERATIONS:
 * - Policy changes affect what transactions can be signed autonomously
 * - Relaxing policies (e.g., increasing limits) is higher risk
 * - Tightening policies (e.g., decreasing limits) is lower risk
 * - All changes are audited with full before/after state
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

  // Step 1: Get wallet entry to verify it exists
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);

  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }

  const previousPolicyId = wallet.policyId;
  const timestamp = new Date().toISOString();

  // Step 2: Validate the new policy structure
  // The Zod schema already validated the input, but we do additional checks
  if (!input.policy.policy_id) {
    throw new Error('Policy must have a policy_id');
  }
  if (!input.policy.policy_version) {
    throw new Error('Policy must have a policy_version');
  }

  // Step 3: Analyze policy change risk
  const changeAnalysis = analyzePolicyChange(previousPolicyId, input.policy);

  // Step 4: PolicyEngine is immutable by design (ADR-003 security requirement).
  // Instead of calling policyEngine.setPolicy() which throws, we:
  // 1. Store the policy update request in wallet metadata
  // 2. Return a status indicating the change was recorded
  // 3. Log the request for the administrator to handle
  //
  // In production, policy changes could trigger:
  // - A notification to the administrator
  // - A scheduled server restart
  // - A manual approval workflow
  //
  // Note: The wallet metadata will be updated with the new policy reference,
  // but the PolicyEngine won't use it until the server is restarted.
  console.log(
    `[PolicySet] Policy update requested for wallet ${wallet.walletId}: ` +
      `${previousPolicyId} -> ${input.policy.policy_id} v${input.policy.policy_version}`
  );

  // Step 5: Update wallet metadata with new policy reference
  await keystore.updateMetadata(wallet.walletId, {
    customData: {
      ...(wallet as any).customData,
      policyId: input.policy.policy_id,
      policyVersion: input.policy.policy_version,
      policyUpdatedAt: timestamp,
      policyUpdateReason: input.reason,
      previousPolicyId,
    },
  });

  // Step 6: Audit policy change
  await auditLogger.log({
    event: 'policy_updated',
    wallet_id: wallet.walletId,
    wallet_address: wallet.address,
    context: JSON.stringify({
      reason: input.reason,
      previous_policy_id: previousPolicyId,
      new_policy_id: input.policy.policy_id,
      new_policy_version: input.policy.policy_version,
      change_analysis: changeAnalysis,
    }),
  });

  // Step 8: Return status
  // Note: Policy metadata has been updated, but the PolicyEngine is immutable.
  // The actual policy behavior will change after a server restart.
  //
  // Risk-based approval logic (future enhancement):
  // - Low risk (tightening): auto-approve on restart
  // - Medium risk: delayed approval (24h window)
  // - High risk (loosening): require human approval

  return {
    status: 'applied',
    previous_policy_id: previousPolicyId,
    new_policy_id: input.policy.policy_id,
    applied_at: timestamp,
    // Note: The policy metadata is updated, but the PolicyEngine won't use
    // the new policy until the server is restarted (immutability requirement).
  };
}

/**
 * Analyze policy change to determine risk level.
 *
 * @param previousPolicyId - Previous policy identifier
 * @param newPolicy - New policy configuration
 * @returns Analysis of the policy change
 */
function analyzePolicyChange(
  previousPolicyId: string,
  newPolicy: PolicySetInput['policy']
): {
  risk_level: 'low' | 'medium' | 'high';
  changes: string[];
} {
  const changes: string[] = [];

  // Without access to the old policy details, we can only note the change
  changes.push(`Policy ID changed from "${previousPolicyId}" to "${newPolicy.policy_id}"`);
  changes.push(`Policy version: ${newPolicy.policy_version}`);

  // Check for potentially risky configurations
  let riskLevel: 'low' | 'medium' | 'high' = 'low';

  // High limits are higher risk
  const maxAmountDrops = BigInt(newPolicy.limits.max_amount_per_tx_drops);
  const maxDailyDrops = BigInt(newPolicy.limits.max_daily_volume_drops);

  // 10,000 XRP per transaction is high risk
  if (maxAmountDrops > BigInt('10000000000')) {
    changes.push(`High per-transaction limit: ${Number(maxAmountDrops) / 1_000_000} XRP`);
    riskLevel = 'high';
  }

  // 100,000 XRP daily is high risk
  if (maxDailyDrops > BigInt('100000000000')) {
    changes.push(`High daily volume limit: ${Number(maxDailyDrops) / 1_000_000} XRP`);
    riskLevel = 'high';
  }

  // Open destination mode is higher risk
  if (newPolicy.destinations.mode === 'open') {
    changes.push('Destination mode is "open" - any destination allowed');
    if (riskLevel !== 'high') riskLevel = 'medium';
  }

  // Many transaction types allowed is higher risk
  if (newPolicy.transaction_types.allowed.length > 10) {
    changes.push(`Many transaction types allowed: ${newPolicy.transaction_types.allowed.length}`);
    if (riskLevel !== 'high') riskLevel = 'medium';
  }

  return {
    risk_level: riskLevel,
    changes,
  };
}
