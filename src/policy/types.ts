/**
 * Policy Engine Type Definitions
 *
 * Core types for policy evaluation, rule matching, and tier classification.
 * These types support the OPA-inspired policy engine for the XRPL Agent Wallet.
 *
 * @module policy/types
 * @version 1.0.0
 */

import { z } from 'zod';
import type {
  TransactionType,
  ApprovalTier,
  AgentWalletPolicy,
} from '../schemas/index.js';

// ============================================================================
// TIER TYPES
// ============================================================================

/**
 * String representation of approval tiers for policy engine internal use.
 * Maps to ApprovalTier (1-4) for external API.
 */
export type Tier = 'autonomous' | 'delayed' | 'cosign' | 'prohibited';

/**
 * Convert string tier to numeric ApprovalTier
 */
export function tierToNumeric(tier: Tier): ApprovalTier {
  const map: Record<Tier, ApprovalTier> = {
    autonomous: 1,
    delayed: 2,
    cosign: 3,
    prohibited: 4,
  };
  return map[tier];
}

/**
 * Convert numeric ApprovalTier to string tier
 */
export function numericToTier(tier: ApprovalTier): Tier {
  const map: Record<ApprovalTier, Tier> = {
    1: 'autonomous',
    2: 'delayed',
    3: 'cosign',
    4: 'prohibited',
  };
  return map[tier];
}

// ============================================================================
// POLICY CONTEXT
// ============================================================================

/**
 * Transaction context for policy evaluation.
 * Contains all fields that can be used in policy conditions.
 */
export interface TransactionContext {
  /** XRPL transaction type */
  type: TransactionType;
  /** Destination address (if applicable) */
  destination?: string;
  /** Amount in XRP */
  amount_xrp?: number;
  /** Amount in drops */
  amount_drops?: bigint;
  /** Memo content (text) */
  memo?: string;
  /** Memo type field */
  memo_type?: string;
  /** Transaction fee in drops */
  fee_drops?: number;
  /** Destination tag */
  destination_tag?: number;
  /** Source tag */
  source_tag?: number;
  /** Currency code (for issued currencies) */
  currency?: string;
  /** Token issuer address */
  issuer?: string;
}

/**
 * Wallet context for policy evaluation.
 */
export interface WalletContext {
  /** Wallet's XRPL address */
  address: string;
  /** Network the wallet operates on */
  network: 'mainnet' | 'testnet' | 'devnet';
}

/**
 * Complete context for policy evaluation.
 */
export interface PolicyContext {
  /** Transaction being evaluated */
  transaction: TransactionContext;
  /** Wallet making the transaction */
  wallet: WalletContext;
  /** Evaluation timestamp */
  timestamp: Date;
  /** Correlation ID for audit trail */
  correlationId: string;
}

// ============================================================================
// POLICY RESULT TYPES
// ============================================================================

/**
 * Factor that contributed to tier determination.
 */
export interface TierFactor {
  /** What triggered this factor */
  source:
    | 'rule'
    | 'transaction_type'
    | 'amount_limit'
    | 'new_destination'
    | 'prohibited_type'
    | 'blocklist'
    | 'limit_exceeded'
    | 'time_control';
  /** Tier this factor suggests */
  tier: Tier;
  /** Explanation */
  reason: string;
}

/**
 * Complete policy evaluation result.
 */
export interface PolicyResult {
  /** Whether transaction can proceed (in some form) */
  allowed: boolean;
  /** Assigned tier determining approval workflow */
  tier: Tier;
  /** Numeric tier for API responses */
  tierNumeric: ApprovalTier;
  /** Human-readable explanation */
  reason: string;
  /** ID of the rule that matched */
  matchedRule: string;
  /** Contributing factors to tier determination */
  factors?: TierFactor[];
  /** Evaluation duration in milliseconds */
  evaluationTimeMs?: number;

  // Tier-specific fields

  /** Delay in seconds (for delayed tier) */
  delaySeconds?: number;
  /** Whether veto is possible (for delayed tier) */
  vetoEnabled?: boolean;
  /** Required signatures (for cosign tier) */
  signerQuorum?: number;
  /** Approval timeout (for cosign tier) */
  approvalTimeoutHours?: number;
  /** Authorized signer addresses (for cosign tier) */
  signerAddresses?: string[];
  /** Whether to send notification */
  notify?: boolean;
  /** Prompt injection detected in memo */
  injectionDetected?: boolean;
}

// ============================================================================
// RULE TYPES
// ============================================================================

/**
 * Operators for condition evaluation.
 */
export type Operator =
  | '=='
  | '!='
  | '>'
  | '>='
  | '<'
  | '<='
  | 'in'
  | 'not_in'
  | 'matches'
  | 'contains'
  | 'starts_with'
  | 'ends_with'
  | 'in_category';

/**
 * Reference to a policy list (blocklist/allowlist).
 */
export interface ValueReference {
  ref: string;
}

/**
 * Simple field condition.
 */
export interface FieldCondition {
  field: string;
  operator: Operator;
  value: unknown | ValueReference;
}

/**
 * Logical AND condition.
 */
export interface AndCondition {
  and: Condition[];
}

/**
 * Logical OR condition.
 */
export interface OrCondition {
  or: Condition[];
}

/**
 * Logical NOT condition.
 */
export interface NotCondition {
  not: Condition;
}

/**
 * Always-true condition (for default rules).
 */
export interface AlwaysCondition {
  always: true;
}

/**
 * Union of all condition types.
 */
export type Condition =
  | FieldCondition
  | AndCondition
  | OrCondition
  | NotCondition
  | AlwaysCondition;

/**
 * Rule action - what tier to assign.
 */
export interface RuleAction {
  tier: Tier;
  reason?: string;
  override_delay_seconds?: number;
  notify?: boolean;
  log_level?: 'info' | 'warn' | 'error';
}

/**
 * Policy rule definition.
 */
export interface PolicyRule {
  id: string;
  name: string;
  description?: string;
  priority: number;
  enabled?: boolean;
  condition: Condition;
  action: RuleAction;
}

// ============================================================================
// LIMIT TYPES
// ============================================================================

/**
 * Limit check result.
 */
export interface LimitCheckResult {
  /** Whether limit was exceeded */
  exceeded: boolean;
  /** Human-readable reason */
  reason?: string;
  /** Type of limit exceeded */
  limitType?:
    | 'daily_count'
    | 'hourly_count'
    | 'daily_volume'
    | 'unique_destinations'
    | 'cooldown'
    | 'per_tx_amount';
  /** Current value */
  currentValue?: number;
  /** Limit value */
  limitValue?: number;
  /** Requested amount (if volume limit) */
  requestedAmount?: number;
  /** When limit resets */
  expiresAt?: Date;
}

/**
 * Current limit state for monitoring.
 */
export interface LimitState {
  daily: {
    date: string;
    transactionCount: number;
    totalVolumeXrp: number;
    uniqueDestinations: Set<string>;
    lastTransactionTime: Date | null;
  };
  hourly: {
    transactions: Array<{
      timestamp: Date;
      amountXrp: number;
      destination: string;
    }>;
  };
  cooldown: {
    active: boolean;
    reason: string | null;
    expiresAt: Date | null;
    triggeredBy: string | null;
  };
}

/**
 * Limit configuration.
 */
export interface LimitConfig {
  dailyResetHour: number;
  maxTransactionsPerHour: number;
  maxTransactionsPerDay: number;
  maxUniqueDestinationsPerDay?: number | undefined;
  maxTotalVolumeXrpPerDay: number;
  maxAmountPerTxXrp?: number | undefined;
  cooldownAfterHighValue?: {
    enabled: boolean;
    thresholdXrp: number;
    cooldownSeconds: number;
  } | undefined;
}

// ============================================================================
// POLICY INFO & METADATA
// ============================================================================

/**
 * Policy metadata (safe to expose).
 */
export interface PolicyInfo {
  name: string;
  version: string;
  network: string;
  description?: string | undefined;
  enabled: boolean;
  loadedAt: Date;
  hash: string;
  ruleCount: number;
  enabledRuleCount: number;
}

// ============================================================================
// COMPILED RULE TYPE
// ============================================================================

/**
 * Function type for condition evaluation.
 */
export type ConditionEvaluator = (
  context: PolicyContext,
  policy: InternalPolicy
) => boolean;

/**
 * Compiled rule for efficient evaluation.
 */
export interface CompiledRule {
  id: string;
  name: string;
  priority: number;
  evaluator: ConditionEvaluator;
  action: RuleAction;
}

// ============================================================================
// INTERNAL POLICY STRUCTURE
// ============================================================================

/**
 * Internal policy structure used by the engine.
 * Extended from AgentWalletPolicy with additional fields.
 */
export interface InternalPolicy {
  version: string;
  name: string;
  description?: string;
  network: 'mainnet' | 'testnet' | 'devnet';
  enabled: boolean;

  tiers: {
    autonomous?: {
      max_amount_xrp: number;
      daily_limit_xrp?: number;
      require_known_destination?: boolean;
      allowed_transaction_types?: TransactionType[];
      max_fee_drops?: number;
    };
    delayed?: {
      max_amount_xrp: number;
      daily_limit_xrp?: number;
      delay_seconds: number;
      veto_enabled?: boolean;
      notify_on_queue?: boolean;
    };
    cosign?: {
      min_amount_xrp?: number;
      new_destination_always?: boolean;
      signer_quorum: number;
      approval_timeout_hours?: number;
      notify_signers?: boolean;
      signer_addresses?: string[];
    };
    prohibited?: {
      reasons?: string[];
      prohibited_transaction_types?: TransactionType[];
    };
  };

  rules: PolicyRule[];

  blocklist?: {
    addresses?: string[];
    memo_patterns?: string[];
    currency_issuers?: string[];
  };

  allowlist?: {
    addresses?: string[];
    trusted_tags?: number[];
    auto_learn?: boolean;
    exchange_addresses?: Array<{
      address: string;
      name?: string;
      require_tag?: boolean;
    }>;
  };

  limits: {
    daily_reset_utc_hour?: number;
    max_transactions_per_hour: number;
    max_transactions_per_day: number;
    max_unique_destinations_per_day?: number;
    max_total_volume_xrp_per_day: number;
    cooldown_after_high_value?: {
      enabled: boolean;
      threshold_xrp: number;
      cooldown_seconds: number;
    };
  };

  transaction_types?: Record<
    TransactionType,
    {
      enabled?: boolean;
      default_tier?: Tier;
      max_amount_xrp?: number;
      require_cosign?: boolean;
    }
  >;
}

// ============================================================================
// POLICY ENGINE OPTIONS
// ============================================================================

/**
 * Options for PolicyEngine constructor.
 */
export interface PolicyEngineOptions {
  /** Path for persisting limit state across restarts */
  limitPersistencePath?: string;
  /** Watch policy file for changes and log warnings */
  watchForChanges?: boolean;
  /** Custom clock for testing time-dependent logic */
  clock?: () => Date;
  /** Maximum regex execution time in milliseconds (ReDoS protection) */
  regexTimeoutMs?: number;
}

// ============================================================================
// ERROR TYPES
// ============================================================================

/**
 * Base error for policy-related failures.
 */
export class PolicyError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly recoverable: boolean = false
  ) {
    super(message);
    this.name = 'PolicyError';
  }

  toJSON(): object {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      recoverable: this.recoverable,
    };
  }
}

/**
 * Policy file loading failed.
 */
export class PolicyLoadError extends PolicyError {
  constructor(message: string) {
    super(message, 'POLICY_LOAD_ERROR', false);
    this.name = 'PolicyLoadError';
  }
}

/**
 * Policy validation against schema failed.
 */
export class PolicyValidationError extends PolicyError {
  constructor(
    message: string,
    public readonly issues: z.ZodIssue[]
  ) {
    super(message, 'POLICY_VALIDATION_ERROR', false);
    this.name = 'PolicyValidationError';
  }
}

/**
 * Error during policy evaluation.
 */
export class PolicyEvaluationError extends PolicyError {
  constructor(message: string) {
    super(message, 'POLICY_EVALUATION_ERROR', true);
    this.name = 'PolicyEvaluationError';
  }
}

/**
 * Policy integrity check failed.
 */
export class PolicyIntegrityError extends PolicyError {
  constructor() {
    super('Policy integrity verification failed', 'POLICY_INTEGRITY_ERROR', false);
    this.name = 'PolicyIntegrityError';
  }
}

/**
 * Limit exceeded error.
 */
export class LimitExceededError extends PolicyError {
  constructor(
    message: string,
    public readonly limitType: string,
    public readonly currentValue: number,
    public readonly limitValue: number
  ) {
    super(message, 'LIMIT_EXCEEDED', true);
    this.name = 'LimitExceededError';
  }
}
