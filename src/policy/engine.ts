/**
 * Policy Engine Implementation
 *
 * The core policy engine that evaluates transactions against declarative
 * policies before allowing signing operations. Implements an OPA-inspired
 * rule evaluation system entirely in TypeScript.
 *
 * @module policy/engine
 * @version 1.0.0
 */

import { createHash } from 'crypto';
import type {
  PolicyContext,
  PolicyResult,
  PolicyInfo,
  InternalPolicy,
  PolicyEngineOptions,
  Tier,
  TierFactor,
  LimitState,
  PolicyRule,
} from './types.js';
import {
  PolicyError,
  PolicyLoadError,
  PolicyValidationError,
  PolicyEvaluationError,
  tierToNumeric,
} from './types.js';
import { RuleEvaluator, checkBlocklist, isInAllowlist, type RuleEvaluatorOptions } from './evaluator.js';
import { LimitTracker, type LimitTrackerOptions } from './limits.js';
import type { AgentWalletPolicy, ApprovalTier } from '../schemas/index.js';

// ============================================================================
// POLICY ENGINE INTERFACE
// ============================================================================

/**
 * Core policy engine interface.
 * All evaluation methods are synchronous and deterministic.
 */
export interface IPolicyEngine {
  /**
   * Evaluate a transaction against the loaded policy.
   * This is the primary entry point for all transaction authorization.
   */
  evaluate(context: PolicyContext): PolicyResult;

  /**
   * Get the SHA-256 hash of the currently loaded policy.
   * Used for integrity verification and audit logging.
   */
  getPolicyHash(): string;

  /**
   * Get policy metadata without exposing internal rules.
   */
  getPolicyInfo(): PolicyInfo;

  /**
   * Verify policy integrity against stored hash.
   * Should be called periodically and before signing operations.
   */
  verifyIntegrity(): boolean;

  /**
   * Get current limit state for monitoring/debugging.
   * Does not expose sensitive policy details.
   */
  getLimitState(): LimitState;

  /**
   * Reset limit counters. Only for testing or administrative override.
   * Requires explicit confirmation and is logged.
   */
  resetLimits(confirmation: string): void;

  /**
   * Record a successful transaction for limit tracking.
   */
  recordTransaction(context: PolicyContext): void;

  /**
   * Clean up resources (intervals, etc).
   */
  dispose(): void;
}

// ============================================================================
// POLICY ENGINE IMPLEMENTATION
// ============================================================================

/**
 * Policy Engine - Security boundary for transaction authorization.
 *
 * Features:
 * - Immutable policy after loading
 * - Priority-based rule evaluation
 * - 4-tier classification (autonomous, delayed, co-sign, prohibited)
 * - Blocklist/allowlist support
 * - Memo pattern detection for prompt injection
 * - Rate and volume limiting
 * - Policy integrity verification
 *
 * Security Guarantees:
 * - LLM/agent cannot modify policies at runtime
 * - Policy integrity verified on each evaluation
 * - Fail-secure: any error results in denial
 * - Hard limits enforce absolute ceilings
 */
export class PolicyEngine implements IPolicyEngine {
  /** Frozen policy data */
  private readonly policy: Readonly<InternalPolicy>;
  /** SHA-256 hash of serialized policy */
  private readonly policyHash: string;
  /** When policy was loaded */
  private readonly loadedAt: Date;
  /** Rule evaluator */
  private readonly ruleEvaluator: RuleEvaluator;
  /** Limit tracker */
  private readonly limitTracker: LimitTracker;
  /** Custom clock for testing */
  private readonly clock: () => Date;
  /** Regex cache for blocklist patterns */
  private readonly regexCache: Map<string, RegExp> = new Map();

  constructor(policy: InternalPolicy, options?: PolicyEngineOptions) {
    this.clock = options?.clock ?? (() => new Date());
    this.loadedAt = this.clock();

    // Compute hash before freezing
    this.policyHash = this.computeHash(policy);

    // Deep freeze the policy to prevent modifications
    this.policy = this.deepFreeze(policy);

    // Initialize rule evaluator
    const evaluatorOptions: RuleEvaluatorOptions = {};
    if (options?.regexTimeoutMs !== undefined) {
      evaluatorOptions.regexTimeoutMs = options.regexTimeoutMs;
    }
    this.ruleEvaluator = new RuleEvaluator(evaluatorOptions);

    // Compile rules
    this.ruleEvaluator.compileRules(this.policy.rules);

    // Initialize limit tracker
    const limitTrackerOptions: LimitTrackerOptions = {
      config: {
        dailyResetHour: this.policy.limits.daily_reset_utc_hour ?? 0,
        maxTransactionsPerHour: this.policy.limits.max_transactions_per_hour,
        maxTransactionsPerDay: this.policy.limits.max_transactions_per_day,
        maxTotalVolumeXrpPerDay: this.policy.limits.max_total_volume_xrp_per_day,
        maxUniqueDestinationsPerDay:
          this.policy.limits.max_unique_destinations_per_day,
        cooldownAfterHighValue: this.policy.limits.cooldown_after_high_value
          ? {
              enabled: this.policy.limits.cooldown_after_high_value.enabled,
              thresholdXrp:
                this.policy.limits.cooldown_after_high_value.threshold_xrp,
              cooldownSeconds:
                this.policy.limits.cooldown_after_high_value.cooldown_seconds,
            }
          : undefined,
      },
      clock: this.clock,
    };
    this.limitTracker = new LimitTracker(limitTrackerOptions);
  }

  /**
   * Evaluate a transaction against the loaded policy.
   */
  evaluate(context: PolicyContext): PolicyResult {
    const startTime = performance.now();

    try {
      // Step 1: Verify policy integrity
      if (!this.verifyIntegrity()) {
        return this.createProhibitedResult(
          'Policy integrity check failed',
          'integrity-check',
          startTime
        );
      }

      // Step 2: Check if policy is enabled
      if (this.policy.enabled === false) {
        return this.createProhibitedResult(
          'Policy is disabled',
          'policy-disabled',
          startTime
        );
      }

      // Step 3: Check global limits first (hard ceiling)
      const limitResult = this.checkGlobalLimits(context);
      if (limitResult) {
        return {
          ...limitResult,
          evaluationTimeMs: performance.now() - startTime,
        };
      }

      // Step 4: Check blocklist (highest priority)
      const blocklistResult = checkBlocklist(context, this.policy, this.regexCache);
      if (blocklistResult.blocked) {
        return this.createProhibitedResult(
          blocklistResult.reason!,
          blocklistResult.matchedRule!,
          startTime,
          blocklistResult.injectionDetected
        );
      }

      // Step 5: Check transaction type restrictions
      const typeResult = this.checkTransactionType(context);
      if (typeResult) {
        return {
          ...typeResult,
          evaluationTimeMs: performance.now() - startTime,
        };
      }

      // Step 6: Evaluate rules in priority order
      const ruleResult = this.ruleEvaluator.evaluate(context, this.policy);

      // Step 7: Apply tier-specific constraints and amount escalation
      const finalResult = this.applyTierConstraints(ruleResult, context);

      return {
        ...finalResult,
        evaluationTimeMs: performance.now() - startTime,
      };
    } catch (error) {
      // Log error with full details
      console.error('Policy evaluation error:', {
        correlationId: context.correlationId,
        error,
        transactionType: context.transaction.type,
      });

      // Fail-secure: return prohibited on any error
      if (error instanceof PolicyError) {
        return this.createProhibitedResult(
          `Policy error: ${error.code}`,
          'error-handler',
          startTime
        );
      }

      return this.createProhibitedResult(
        'Internal policy engine error',
        'error-handler',
        startTime
      );
    }
  }

  /**
   * Check global limits.
   */
  private checkGlobalLimits(context: PolicyContext): PolicyResult | null {
    const limitCheck = this.limitTracker.checkLimits(context);

    if (limitCheck.exceeded) {
      return {
        allowed: false,
        tier: 'prohibited',
        tierNumeric: 4,
        reason: limitCheck.reason!,
        matchedRule: `limit-${limitCheck.limitType}`,
        factors: [
          {
            source: 'limit_exceeded',
            tier: 'prohibited',
            reason: limitCheck.reason!,
          },
        ],
      };
    }

    return null;
  }

  /**
   * Check transaction type restrictions.
   */
  private checkTransactionType(context: PolicyContext): PolicyResult | null {
    const txType = context.transaction.type;

    // Check prohibited transaction types
    const prohibitedTypes =
      this.policy.tiers.prohibited?.prohibited_transaction_types ?? [];
    if (prohibitedTypes.includes(txType)) {
      return {
        allowed: false,
        tier: 'prohibited',
        tierNumeric: 4,
        reason: `Transaction type ${txType} is prohibited`,
        matchedRule: 'prohibited-type',
        factors: [
          {
            source: 'prohibited_type',
            tier: 'prohibited',
            reason: `Transaction type ${txType} is prohibited`,
          },
        ],
      };
    }

    // Check per-type configuration
    const typeConfig = this.policy.transaction_types?.[txType];
    if (typeConfig?.enabled === false) {
      return {
        allowed: false,
        tier: 'prohibited',
        tierNumeric: 4,
        reason: `Transaction type ${txType} is disabled`,
        matchedRule: 'type-disabled',
        factors: [
          {
            source: 'transaction_type',
            tier: 'prohibited',
            reason: `Transaction type ${txType} is disabled`,
          },
        ],
      };
    }

    return null;
  }

  /**
   * Apply tier-specific constraints and amount escalation.
   */
  private applyTierConstraints(
    ruleResult: {
      matched: boolean;
      ruleId: string;
      ruleName: string;
      tier: Tier;
      reason: string;
      overrideDelaySeconds?: number | undefined;
      notify?: boolean | undefined;
    },
    context: PolicyContext
  ): PolicyResult {
    let tier: Tier = ruleResult.tier;
    const factors: TierFactor[] = [
      {
        source: 'rule',
        tier: ruleResult.tier,
        reason: ruleResult.reason,
      },
    ];

    // Check per-type configuration for require_cosign
    const typeConfig = this.policy.transaction_types?.[context.transaction.type];
    if (typeConfig?.require_cosign && tier !== 'prohibited') {
      tier = this.compareTiers('cosign', tier);
      if (tier === 'cosign') {
        factors.push({
          source: 'transaction_type',
          tier: 'cosign',
          reason: `Type ${context.transaction.type} requires co-sign`,
        });
      }
    }

    // Apply amount-based tier escalation
    tier = this.applyAmountEscalation(tier, context, factors);

    // Check new destination escalation
    tier = this.applyNewDestinationEscalation(tier, context, factors);

    // Build final result
    const result: PolicyResult = {
      allowed: tier !== 'prohibited',
      tier,
      tierNumeric: tierToNumeric(tier),
      reason: factors.find((f) => f.tier === tier)?.reason ?? ruleResult.reason,
      matchedRule: ruleResult.ruleId,
      factors,
    };

    // Add tier-specific details
    switch (tier) {
      case 'delayed':
        result.delaySeconds =
          ruleResult.overrideDelaySeconds ??
          this.policy.tiers.delayed?.delay_seconds ??
          300;
        result.vetoEnabled = this.policy.tiers.delayed?.veto_enabled ?? true;
        result.notify =
          ruleResult.notify ?? this.policy.tiers.delayed?.notify_on_queue ?? true;
        break;

      case 'cosign':
        result.signerQuorum = this.policy.tiers.cosign?.signer_quorum ?? 2;
        result.approvalTimeoutHours =
          this.policy.tiers.cosign?.approval_timeout_hours ?? 24;
        result.signerAddresses = this.policy.tiers.cosign?.signer_addresses ?? [];
        result.notify = ruleResult.notify ?? true;
        break;

      case 'autonomous':
        result.notify = ruleResult.notify ?? false;
        break;
    }

    return result;
  }

  /**
   * Apply amount-based tier escalation.
   */
  private applyAmountEscalation(
    currentTier: Tier,
    context: PolicyContext,
    factors: TierFactor[]
  ): Tier {
    const amountXrp = context.transaction.amount_xrp ?? 0;
    const tiers = this.policy.tiers;

    // Check if amount exceeds delayed tier max -> escalate to cosign
    if (
      tiers.delayed?.max_amount_xrp !== undefined &&
      amountXrp > tiers.delayed.max_amount_xrp
    ) {
      if (currentTier === 'autonomous' || currentTier === 'delayed') {
        factors.push({
          source: 'amount_limit',
          tier: 'cosign',
          reason: `Amount ${amountXrp} XRP exceeds delayed tier max (${tiers.delayed.max_amount_xrp})`,
        });
        return 'cosign';
      }
    }

    // Check if amount exceeds autonomous tier max -> escalate to delayed
    if (
      tiers.autonomous?.max_amount_xrp !== undefined &&
      amountXrp > tiers.autonomous.max_amount_xrp
    ) {
      if (currentTier === 'autonomous') {
        // Check if within delayed range
        if (
          tiers.delayed?.max_amount_xrp === undefined ||
          amountXrp <= tiers.delayed.max_amount_xrp
        ) {
          factors.push({
            source: 'amount_limit',
            tier: 'delayed',
            reason: `Amount ${amountXrp} XRP exceeds autonomous tier max (${tiers.autonomous.max_amount_xrp})`,
          });
          return 'delayed';
        }
      }
    }

    // Check per-type amount limits
    const typeConfig = this.policy.transaction_types?.[context.transaction.type];
    if (typeConfig?.max_amount_xrp !== undefined && amountXrp > typeConfig.max_amount_xrp) {
      if (currentTier === 'autonomous') {
        factors.push({
          source: 'amount_limit',
          tier: 'delayed',
          reason: `Amount ${amountXrp} XRP exceeds ${context.transaction.type} limit (${typeConfig.max_amount_xrp})`,
        });
        return 'delayed';
      }
    }

    return currentTier;
  }

  /**
   * Apply new destination escalation.
   */
  private applyNewDestinationEscalation(
    currentTier: Tier,
    context: PolicyContext,
    factors: TierFactor[]
  ): Tier {
    // Skip if no destination or already prohibited
    if (!context.transaction.destination || currentTier === 'prohibited') {
      return currentTier;
    }

    // Check if destination is in allowlist
    if (isInAllowlist(context, this.policy)) {
      return currentTier;
    }

    let resultTier = currentTier;

    // Check if autonomous tier requires known destination
    if (
      resultTier === 'autonomous' &&
      this.policy.tiers.autonomous?.require_known_destination
    ) {
      factors.push({
        source: 'new_destination',
        tier: 'delayed',
        reason: 'Destination not in allowlist (require_known_destination enabled)',
      });
      resultTier = 'delayed';
    }

    // Check if cosign always required for new destinations
    // This can further escalate from autonomous or delayed to cosign
    if (this.policy.tiers.cosign?.new_destination_always) {
      // Check if destination is known from today's transactions
      const isKnown = this.limitTracker.isDestinationKnown(
        context.transaction.destination
      );

      if (!isKnown) {
        const newTier = this.compareTiers('cosign', resultTier);
        if (newTier === 'cosign' && resultTier !== 'cosign') {
          factors.push({
            source: 'new_destination',
            tier: 'cosign',
            reason: 'First transaction to new destination',
          });
          resultTier = 'cosign';
        }
      }
    }

    return resultTier;
  }

  /**
   * Compare two tiers and return the more restrictive one.
   */
  private compareTiers(tier1: Tier, tier2: Tier): Tier {
    const tierOrder: Record<Tier, number> = {
      autonomous: 1,
      delayed: 2,
      cosign: 3,
      prohibited: 4,
    };

    return tierOrder[tier1] > tierOrder[tier2] ? tier1 : tier2;
  }

  /**
   * Create a prohibited result.
   */
  private createProhibitedResult(
    reason: string,
    matchedRule: string,
    startTime: number,
    injectionDetected?: boolean
  ): PolicyResult {
    const result: PolicyResult = {
      allowed: false,
      tier: 'prohibited',
      tierNumeric: 4,
      reason,
      matchedRule,
      evaluationTimeMs: performance.now() - startTime,
    };
    if (injectionDetected !== undefined) {
      result.injectionDetected = injectionDetected;
    }
    return result;
  }

  // ============================================================================
  // PUBLIC METHODS
  // ============================================================================

  /**
   * Get policy hash.
   */
  getPolicyHash(): string {
    return this.policyHash;
  }

  /**
   * Get policy info.
   */
  getPolicyInfo(): PolicyInfo {
    const info: PolicyInfo = {
      name: this.policy.name,
      version: this.policy.version,
      network: this.policy.network,
      enabled: this.policy.enabled,
      loadedAt: this.loadedAt,
      hash: this.policyHash.slice(0, 16),
      ruleCount: this.policy.rules.length,
      enabledRuleCount: this.ruleEvaluator.getRuleCount(),
    };
    if (this.policy.description !== undefined) {
      info.description = this.policy.description;
    }
    return info;
  }

  /**
   * Verify policy integrity.
   */
  verifyIntegrity(): boolean {
    const currentHash = this.computeHash(this.policy);
    return currentHash === this.policyHash;
  }

  /**
   * Get limit state.
   */
  getLimitState(): LimitState {
    return this.limitTracker.getState();
  }

  /**
   * Reset limits.
   */
  resetLimits(confirmation: string): void {
    this.limitTracker.reset(confirmation);
  }

  /**
   * Record a successful transaction.
   */
  recordTransaction(context: PolicyContext): void {
    this.limitTracker.recordTransaction(context);
  }

  /**
   * Dispose of resources.
   */
  dispose(): void {
    this.limitTracker.dispose();
  }

  // ============================================================================
  // PRIVATE HELPERS
  // ============================================================================

  /**
   * Compute SHA-256 hash of policy.
   */
  private computeHash(policy: InternalPolicy | Readonly<InternalPolicy>): string {
    const content = JSON.stringify(policy);
    return createHash('sha256').update(content).digest('hex');
  }

  /**
   * Deep freeze an object.
   */
  private deepFreeze<T extends object>(obj: T): Readonly<T> {
    const propNames = Object.getOwnPropertyNames(obj);

    for (const name of propNames) {
      const value = (obj as Record<string, unknown>)[name];
      if (value && typeof value === 'object') {
        this.deepFreeze(value as object);
      }
    }

    return Object.freeze(obj);
  }
}

// ============================================================================
// FACTORY FUNCTIONS
// ============================================================================

/**
 * Create a PolicyEngine from an AgentWalletPolicy.
 */
export function createPolicyEngine(
  policy: AgentWalletPolicy,
  options?: PolicyEngineOptions
): PolicyEngine {
  // Convert AgentWalletPolicy to InternalPolicy format
  const internalPolicy: InternalPolicy = {
    version: policy.policy_version,
    name: policy.policy_id,
    network: 'mainnet', // Default, should be provided externally
    enabled: true,
    tiers: {
      autonomous: {
        max_amount_xrp: dropsToXrp(policy.limits.max_amount_per_tx_drops),
        daily_limit_xrp: dropsToXrp(policy.limits.max_daily_volume_drops),
        require_known_destination:
          policy.destinations.mode === 'allowlist' ||
          !policy.destinations.allow_new_destinations,
        allowed_transaction_types: policy.transaction_types.allowed,
      },
      delayed: {
        max_amount_xrp: dropsToXrp(policy.escalation.amount_threshold_drops),
        delay_seconds: policy.escalation.delay_seconds ?? 300,
        veto_enabled: true,
        notify_on_queue: true,
      },
      cosign: {
        signer_quorum: 2,
        new_destination_always: policy.escalation.new_destination === 3,
        approval_timeout_hours: 24,
      },
      prohibited: {
        prohibited_transaction_types: policy.transaction_types.blocked ?? [],
      },
    },
    rules: buildRulesFromPolicy(policy),
    blocklist: {
      addresses: policy.destinations.blocklist ?? [],
    },
    allowlist: {
      addresses:
        policy.destinations.mode === 'allowlist'
          ? policy.destinations.allowlist ?? []
          : [],
    },
    limits: {
      daily_reset_utc_hour: 0,
      max_transactions_per_hour: policy.limits.max_tx_per_hour,
      max_transactions_per_day: policy.limits.max_tx_per_day,
      max_total_volume_xrp_per_day: dropsToXrp(policy.limits.max_daily_volume_drops),
    },
  };

  return new PolicyEngine(internalPolicy, options);
}

/**
 * Convert drops string to XRP number.
 */
function dropsToXrp(drops: string): number {
  return Number(BigInt(drops)) / 1_000_000;
}

/**
 * Build rules from AgentWalletPolicy.
 */
function buildRulesFromPolicy(policy: AgentWalletPolicy): PolicyRule[] {
  const rules: PolicyRule[] = [];
  let priority = 1;

  // Rule: Check blocklist first
  if (policy.destinations.blocklist && policy.destinations.blocklist.length > 0) {
    rules.push({
      id: 'blocklist-check',
      name: 'Blocklist Check',
      priority: priority++,
      condition: {
        field: 'destination',
        operator: 'in',
        value: { ref: 'blocklist.addresses' },
      },
      action: {
        tier: 'prohibited',
        reason: 'Destination is blocklisted',
      },
    });
  }

  // Rule: Check blocked transaction types
  if (policy.transaction_types.blocked && policy.transaction_types.blocked.length > 0) {
    for (const txType of policy.transaction_types.blocked) {
      rules.push({
        id: `block-${txType.toLowerCase()}`,
        name: `Block ${txType}`,
        priority: priority++,
        condition: {
          field: 'transaction_type',
          operator: '==',
          value: txType,
        },
        action: {
          tier: 'prohibited',
          reason: `Transaction type ${txType} is not allowed`,
        },
      });
    }
  }

  // Rule: Require approval transaction types
  if (
    policy.transaction_types.require_approval &&
    policy.transaction_types.require_approval.length > 0
  ) {
    for (const txType of policy.transaction_types.require_approval) {
      rules.push({
        id: `require-approval-${txType.toLowerCase()}`,
        name: `Require Approval for ${txType}`,
        priority: priority++,
        condition: {
          field: 'transaction_type',
          operator: '==',
          value: txType,
        },
        action: {
          tier: 'cosign',
          reason: `Transaction type ${txType} requires approval`,
        },
      });
    }
  }

  // Rule: High value transactions
  const thresholdXrp = dropsToXrp(policy.escalation.amount_threshold_drops);
  rules.push({
    id: 'high-value-cosign',
    name: 'High Value Transaction',
    priority: priority++,
    condition: {
      field: 'amount_xrp',
      operator: '>=',
      value: thresholdXrp,
    },
    action: {
      tier: policy.escalation.new_destination === 3 ? 'cosign' : 'delayed',
      reason: `Amount exceeds ${thresholdXrp} XRP threshold`,
    },
  });

  // Rule: New destination handling
  if (
    policy.destinations.mode === 'allowlist' ||
    !policy.destinations.allow_new_destinations
  ) {
    rules.push({
      id: 'new-destination-check',
      name: 'New Destination Check',
      priority: priority++,
      condition: {
        not: {
          field: 'destination',
          operator: 'in',
          value: { ref: 'allowlist.addresses' },
        },
      },
      action: {
        tier:
          policy.destinations.new_destination_tier === 3
            ? 'cosign'
            : policy.destinations.new_destination_tier === 2
              ? 'delayed'
              : 'prohibited',
        reason: 'Destination not in allowlist',
      },
    });
  }

  // Rule: Default allow for configured types
  rules.push({
    id: 'default-allow',
    name: 'Default Allow',
    priority: 999,
    condition: {
      always: true,
    },
    action: {
      tier: 'autonomous',
      reason: 'Transaction within policy limits',
    },
  });

  return rules;
}

/**
 * Create a simple test policy for development.
 */
export function createTestPolicy(
  network: 'mainnet' | 'testnet' | 'devnet' = 'testnet',
  overrides?: Partial<InternalPolicy>
): InternalPolicy {
  const basePolicy: InternalPolicy = {
    version: '1.0',
    name: `${network}-test-policy`,
    description: 'Test policy for development',
    network,
    enabled: true,
    tiers: {
      autonomous: {
        max_amount_xrp: network === 'mainnet' ? 100 : 10000,
        daily_limit_xrp: network === 'mainnet' ? 1000 : 100000,
        require_known_destination: network === 'mainnet',
        allowed_transaction_types: ['Payment', 'EscrowFinish', 'EscrowCancel'],
      },
      delayed: {
        max_amount_xrp: network === 'mainnet' ? 1000 : 100000,
        delay_seconds: network === 'mainnet' ? 300 : 60,
        veto_enabled: true,
        notify_on_queue: true,
      },
      cosign: {
        signer_quorum: 2,
        new_destination_always: network === 'mainnet',
        approval_timeout_hours: 24,
      },
      prohibited: {
        prohibited_transaction_types: ['Clawback'],
      },
    },
    rules: [
      {
        id: 'default-allow',
        name: 'Default Allow',
        priority: 999,
        condition: { always: true },
        action: { tier: 'autonomous', reason: 'Within policy limits' },
      },
    ],
    blocklist: {
      addresses: [],
      memo_patterns: ['ignore.*previous', '\\[INST\\]', '<<SYS>>'],
    },
    allowlist: {
      addresses: [],
    },
    limits: {
      daily_reset_utc_hour: 0,
      max_transactions_per_hour: network === 'mainnet' ? 50 : 1000,
      max_transactions_per_day: network === 'mainnet' ? 200 : 10000,
      max_unique_destinations_per_day: network === 'mainnet' ? 20 : 500,
      max_total_volume_xrp_per_day: network === 'mainnet' ? 5000 : 10000000,
    },
  };

  // Merge overrides
  if (overrides) {
    return deepMerge(basePolicy, overrides) as InternalPolicy;
  }

  return basePolicy;
}

/**
 * Deep merge two objects.
 */
function deepMerge<T extends object>(target: T, source: Partial<T>): T {
  const result = { ...target };

  for (const key of Object.keys(source) as (keyof T)[]) {
    const sourceValue = source[key];
    const targetValue = target[key];

    if (
      sourceValue !== undefined &&
      typeof sourceValue === 'object' &&
      sourceValue !== null &&
      !Array.isArray(sourceValue) &&
      typeof targetValue === 'object' &&
      targetValue !== null &&
      !Array.isArray(targetValue)
    ) {
      (result as Record<string, unknown>)[key as string] = deepMerge(
        targetValue as object,
        sourceValue as object
      );
    } else if (sourceValue !== undefined) {
      (result as Record<string, unknown>)[key as string] = sourceValue;
    }
  }

  return result;
}
