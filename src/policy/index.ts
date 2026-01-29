/**
 * Policy Engine Module
 *
 * Exports the policy engine components for transaction authorization.
 *
 * @module policy
 * @version 1.0.0
 */

// ============================================================================
// TYPES
// ============================================================================

export type {
  // Core types
  Tier,
  PolicyContext,
  TransactionContext,
  WalletContext,
  PolicyResult,
  TierFactor,
  PolicyInfo,

  // Rule types
  Operator,
  Condition,
  FieldCondition,
  AndCondition,
  OrCondition,
  NotCondition,
  AlwaysCondition,
  ValueReference,
  RuleAction,
  PolicyRule,
  CompiledRule,
  ConditionEvaluator,

  // Limit types
  LimitConfig,
  LimitState,
  LimitCheckResult,

  // Policy types
  InternalPolicy,
  PolicyEngineOptions,
} from './types.js';

// ============================================================================
// CLASSES & FUNCTIONS
// ============================================================================

// Type utilities
export { tierToNumeric, numericToTier } from './types.js';

// Error types
export {
  PolicyError,
  PolicyLoadError,
  PolicyValidationError,
  PolicyEvaluationError,
  PolicyIntegrityError,
  LimitExceededError,
} from './types.js';

// Engine
export {
  PolicyEngine,
  createPolicyEngine,
  createTestPolicy,
  type IPolicyEngine,
} from './engine.js';

// Evaluator
export {
  RuleEvaluator,
  checkBlocklist,
  isInAllowlist,
  getTransactionCategory,
  type RuleResult,
  type RuleEvaluatorOptions,
  type BlocklistCheckResult,
} from './evaluator.js';

// Limits
export {
  LimitTracker,
  createLimitTracker,
  type LimitTrackerOptions,
} from './limits.js';
