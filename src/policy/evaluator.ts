/**
 * Rule Evaluator Implementation
 *
 * Priority-based rule matching with condition compilation for
 * efficient policy evaluation.
 *
 * @module policy/evaluator
 * @version 1.0.0
 */

import type {
  PolicyContext,
  InternalPolicy,
  PolicyRule,
  Condition,
  FieldCondition,
  AndCondition,
  OrCondition,
  NotCondition,
  AlwaysCondition,
  ValueReference,
  Operator,
  ConditionEvaluator,
  CompiledRule,
  RuleAction,
  Tier,
} from './types.js';
import { PolicyEvaluationError } from './types.js';
import type { TransactionType } from '../schemas/index.js';

// ============================================================================
// TRANSACTION CATEGORIES
// ============================================================================

/**
 * Map transaction types to categories for in_category operator.
 */
const TRANSACTION_CATEGORIES: Record<string, string> = {
  // Payments
  Payment: 'payments',

  // Trustlines
  TrustSet: 'trustlines',

  // DEX
  OfferCreate: 'dex',
  OfferCancel: 'dex',

  // Escrow
  EscrowCreate: 'escrow',
  EscrowFinish: 'escrow',
  EscrowCancel: 'escrow',

  // Payment Channels
  PaymentChannelCreate: 'paychan',
  PaymentChannelFund: 'paychan',
  PaymentChannelClaim: 'paychan',

  // Account
  AccountSet: 'account',
  AccountDelete: 'account',
  SetRegularKey: 'account',
  SignerListSet: 'account',
  DepositPreauth: 'account',

  // NFT
  NFTokenMint: 'nft',
  NFTokenBurn: 'nft',
  NFTokenCreateOffer: 'nft',
  NFTokenCancelOffer: 'nft',
  NFTokenAcceptOffer: 'nft',

  // AMM
  AMMCreate: 'amm',
  AMMDeposit: 'amm',
  AMMWithdraw: 'amm',
  AMMVote: 'amm',
  AMMBid: 'amm',
  AMMDelete: 'amm',

  // Checks
  CheckCreate: 'checks',
  CheckCash: 'checks',
  CheckCancel: 'checks',

  // Tickets
  TicketCreate: 'tickets',

  // Clawback
  Clawback: 'clawback',

  // DID
  DIDSet: 'did',
  DIDDelete: 'did',

  // Cross-chain
  XChainAccountCreateCommit: 'xchain',
  XChainAddClaimAttestation: 'xchain',
  XChainClaim: 'xchain',
  XChainCommit: 'xchain',
  XChainCreateBridge: 'xchain',
  XChainCreateClaimID: 'xchain',
  XChainModifyBridge: 'xchain',
};

/**
 * Get transaction category for a transaction type.
 */
export function getTransactionCategory(type: string): string {
  return TRANSACTION_CATEGORIES[type] ?? 'unknown';
}

// ============================================================================
// RULE EVALUATOR
// ============================================================================

/**
 * Result of rule evaluation.
 */
export interface RuleResult {
  matched: boolean;
  ruleId: string;
  ruleName: string;
  tier: Tier;
  reason: string;
  overrideDelaySeconds?: number | undefined;
  notify?: boolean | undefined;
  logLevel?: 'info' | 'warn' | 'error' | undefined;
}

/**
 * Options for RuleEvaluator.
 */
export interface RuleEvaluatorOptions {
  /** Maximum regex execution time in ms (ReDoS protection) */
  regexTimeoutMs?: number;
  /** Maximum input length for regex matching */
  maxRegexInputLength?: number;
}

/**
 * Evaluates policy rules in priority order.
 *
 * Features:
 * - Rule compilation for efficient repeated evaluation
 * - Priority-based evaluation (lower = higher priority)
 * - Logical operators (AND, OR, NOT)
 * - Field comparisons with multiple operators
 * - Reference resolution for blocklist/allowlist
 * - Regex caching with ReDoS protection
 */
export class RuleEvaluator {
  private readonly compiledRules: Map<string, CompiledRule> = new Map();
  private readonly regexCache: Map<string, RegExp> = new Map();
  private readonly options: Required<RuleEvaluatorOptions>;

  constructor(options?: RuleEvaluatorOptions) {
    this.options = {
      regexTimeoutMs: options?.regexTimeoutMs ?? 100,
      maxRegexInputLength: options?.maxRegexInputLength ?? 10000,
    };
  }

  /**
   * Compile rules for efficient evaluation.
   * Rules are sorted by priority (lower = higher priority).
   */
  compileRules(rules: PolicyRule[]): void {
    this.compiledRules.clear();

    // Filter enabled rules and sort by priority
    const enabledRules = rules
      .filter((rule) => rule.enabled !== false)
      .sort((a, b) => a.priority - b.priority);

    for (const rule of enabledRules) {
      const compiled = this.compileRule(rule);
      this.compiledRules.set(rule.id, compiled);
    }
  }

  /**
   * Compile a single rule.
   */
  private compileRule(rule: PolicyRule): CompiledRule {
    return {
      id: rule.id,
      name: rule.name,
      priority: rule.priority,
      evaluator: this.compileCondition(rule.condition),
      action: rule.action,
    };
  }

  /**
   * Compile a condition into an evaluator function.
   */
  private compileCondition(condition: Condition): ConditionEvaluator {
    // Always condition
    if (this.isAlwaysCondition(condition)) {
      return () => true;
    }

    // Logical AND
    if (this.isAndCondition(condition)) {
      const subEvaluators = condition.and.map((c) => this.compileCondition(c));
      return (ctx, policy) => subEvaluators.every((evaluator) => evaluator(ctx, policy));
    }

    // Logical OR
    if (this.isOrCondition(condition)) {
      const subEvaluators = condition.or.map((c) => this.compileCondition(c));
      return (ctx, policy) => subEvaluators.some((evaluator) => evaluator(ctx, policy));
    }

    // Logical NOT
    if (this.isNotCondition(condition)) {
      const subEvaluator = this.compileCondition(condition.not);
      return (ctx, policy) => !subEvaluator(ctx, policy);
    }

    // Field condition
    if (this.isFieldCondition(condition)) {
      return this.compileFieldCondition(condition);
    }

    throw new PolicyEvaluationError(
      `Unknown condition type: ${JSON.stringify(condition)}`
    );
  }

  /**
   * Compile a field condition.
   */
  private compileFieldCondition(condition: FieldCondition): ConditionEvaluator {
    const { field, operator, value } = condition;

    return (context: PolicyContext, policy: InternalPolicy) => {
      // Extract field value from context
      const fieldValue = this.extractFieldValue(field, context, policy);

      // Resolve value (may be a reference to policy lists)
      const compareValue = this.resolveValue(value, policy);

      // Evaluate operator
      return this.evaluateOperator(operator, fieldValue, compareValue);
    };
  }

  /**
   * Extract a field value from the policy context.
   */
  private extractFieldValue(
    field: string,
    context: PolicyContext,
    policy: InternalPolicy
  ): unknown {
    switch (field) {
      // Transaction fields
      case 'destination':
        return context.transaction.destination;
      case 'amount_xrp':
        return context.transaction.amount_xrp ?? 0;
      case 'amount_drops':
        return context.transaction.amount_drops ?? 0n;
      case 'transaction_type':
        return context.transaction.type;
      case 'transaction_category':
        return getTransactionCategory(context.transaction.type);
      case 'memo':
        return context.transaction.memo ?? '';
      case 'memo_type':
        return context.transaction.memo_type ?? '';
      case 'fee_drops':
        return context.transaction.fee_drops ?? 0;
      case 'destination_tag':
        return context.transaction.destination_tag;
      case 'source_tag':
        return context.transaction.source_tag;
      case 'currency':
        return context.transaction.currency;
      case 'issuer':
        return context.transaction.issuer;

      // Wallet fields
      case 'wallet_address':
        return context.wallet.address;
      case 'network':
        return context.wallet.network;

      // Derived fields
      case 'is_new_destination':
        // This requires limit tracker integration
        // For now, check against allowlist
        if (!context.transaction.destination) return false;
        const allowlist = policy.allowlist?.addresses ?? [];
        return !allowlist.includes(context.transaction.destination);

      default:
        throw new PolicyEvaluationError(`Unknown field: ${field}`);
    }
  }

  /**
   * Resolve a value (may be a reference to policy lists).
   */
  private resolveValue(value: unknown, policy: InternalPolicy): unknown {
    // Check if value is a reference
    if (this.isValueReference(value)) {
      return this.resolveReference(value.ref, policy);
    }
    return value;
  }

  /**
   * Resolve a reference to a policy list.
   */
  private resolveReference(ref: string, policy: InternalPolicy): unknown {
    switch (ref) {
      case 'blocklist.addresses':
        return policy.blocklist?.addresses ?? [];
      case 'blocklist.memo_patterns':
        return policy.blocklist?.memo_patterns ?? [];
      case 'blocklist.currency_issuers':
        return policy.blocklist?.currency_issuers ?? [];
      case 'allowlist.addresses':
        return policy.allowlist?.addresses ?? [];
      case 'allowlist.trusted_tags':
        return policy.allowlist?.trusted_tags ?? [];
      default:
        throw new PolicyEvaluationError(`Unknown reference: ${ref}`);
    }
  }

  /**
   * Evaluate an operator.
   */
  private evaluateOperator(
    operator: Operator,
    fieldValue: unknown,
    compareValue: unknown
  ): boolean {
    switch (operator) {
      // Equality operators
      case '==':
        return fieldValue === compareValue;
      case '!=':
        return fieldValue !== compareValue;

      // Numeric comparison operators
      case '>':
        return this.asNumber(fieldValue) > this.asNumber(compareValue);
      case '>=':
        return this.asNumber(fieldValue) >= this.asNumber(compareValue);
      case '<':
        return this.asNumber(fieldValue) < this.asNumber(compareValue);
      case '<=':
        return this.asNumber(fieldValue) <= this.asNumber(compareValue);

      // Array operators
      case 'in':
        return this.asArray(compareValue).includes(fieldValue);
      case 'not_in':
        return !this.asArray(compareValue).includes(fieldValue);

      // String operators
      case 'matches':
        return this.matchesRegex(this.asString(fieldValue), this.asString(compareValue));
      case 'contains':
        return this.asString(fieldValue).includes(this.asString(compareValue));
      case 'starts_with':
        return this.asString(fieldValue).startsWith(this.asString(compareValue));
      case 'ends_with':
        return this.asString(fieldValue).endsWith(this.asString(compareValue));

      // Category operator
      case 'in_category':
        return this.isInCategory(this.asString(fieldValue), this.asString(compareValue));

      default:
        throw new PolicyEvaluationError(`Unknown operator: ${operator}`);
    }
  }

  /**
   * Check if a regex pattern is potentially vulnerable to ReDoS.
   *
   * Detects common ReDoS patterns:
   * - Nested quantifiers: (a+)+, (a*)*
   * - Overlapping alternation: (a|a)+
   * - Exponential backtracking patterns
   */
  private isReDoSVulnerable(pattern: string): boolean {
    // Patterns that indicate potential ReDoS vulnerability
    const dangerousPatterns = [
      /\([^)]*[+*][^)]*\)[+*]/, // Nested quantifiers: (a+)+, (.*)*
      /\([^)]*\|[^)]*\)[+*]{2,}/, // Alternation with repeated quantifiers
      /\(\.\*\)[+*]/, // (.*)+
      /\(\.\+\)[+*]/, // (.+)+
      /\[[^\]]*\][+*]{2,}[^\s]*\[[^\]]*\][+*]{2,}/, // Multiple char classes with quantifiers
    ];

    for (const dangerous of dangerousPatterns) {
      if (dangerous.test(pattern)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Match a value against a regex pattern.
   */
  private matchesRegex(value: string, pattern: string): boolean {
    // Get or compile regex
    let regex = this.regexCache.get(pattern);
    if (!regex) {
      // Check for ReDoS vulnerability before compiling
      if (this.isReDoSVulnerable(pattern)) {
        throw new PolicyEvaluationError(
          `Regex pattern rejected due to potential ReDoS vulnerability: ${pattern}`
        );
      }

      try {
        regex = new RegExp(pattern, 'i');
        this.regexCache.set(pattern, regex);
      } catch (error) {
        throw new PolicyEvaluationError(`Invalid regex pattern: ${pattern}`);
      }
    }

    // Limit input length for ReDoS protection
    const truncatedValue =
      value.length > this.options.maxRegexInputLength
        ? value.slice(0, this.options.maxRegexInputLength)
        : value;

    return regex.test(truncatedValue);
  }

  /**
   * Check if a transaction type is in a category.
   */
  private isInCategory(txType: string, category: string): boolean {
    return getTransactionCategory(txType) === category;
  }

  // ============================================================================
  // TYPE GUARDS
  // ============================================================================

  private isAlwaysCondition(condition: Condition): condition is AlwaysCondition {
    return 'always' in condition && condition.always === true;
  }

  private isAndCondition(condition: Condition): condition is AndCondition {
    return 'and' in condition;
  }

  private isOrCondition(condition: Condition): condition is OrCondition {
    return 'or' in condition;
  }

  private isNotCondition(condition: Condition): condition is NotCondition {
    return 'not' in condition;
  }

  private isFieldCondition(condition: Condition): condition is FieldCondition {
    return 'field' in condition;
  }

  private isValueReference(value: unknown): value is ValueReference {
    return (
      typeof value === 'object' &&
      value !== null &&
      'ref' in value &&
      typeof (value as ValueReference).ref === 'string'
    );
  }

  // ============================================================================
  // TYPE CONVERSIONS
  // ============================================================================

  private asNumber(value: unknown): number {
    if (typeof value === 'number') return value;
    if (typeof value === 'bigint') return Number(value);
    if (typeof value === 'string') {
      const parsed = parseFloat(value);
      if (isNaN(parsed)) {
        throw new PolicyEvaluationError(`Cannot convert "${value}" to number`);
      }
      return parsed;
    }
    throw new PolicyEvaluationError(`Cannot convert ${typeof value} to number`);
  }

  private asString(value: unknown): string {
    if (typeof value === 'string') return value;
    if (value === null || value === undefined) return '';
    return String(value);
  }

  private asArray(value: unknown): unknown[] {
    if (Array.isArray(value)) return value;
    throw new PolicyEvaluationError(`Expected array, got ${typeof value}`);
  }

  // ============================================================================
  // PUBLIC EVALUATION METHODS
  // ============================================================================

  /**
   * Evaluate rules against a context.
   * Returns the first matching rule's result.
   */
  evaluate(context: PolicyContext, policy: InternalPolicy): RuleResult {
    // Rules are pre-sorted by priority during compilation
    for (const [ruleId, compiled] of this.compiledRules) {
      try {
        const matches = compiled.evaluator(context, policy);

        if (matches) {
          return {
            matched: true,
            ruleId: compiled.id,
            ruleName: compiled.name,
            tier: compiled.action.tier,
            reason: compiled.action.reason ?? `Matched rule: ${compiled.name}`,
            overrideDelaySeconds: compiled.action.override_delay_seconds,
            notify: compiled.action.notify,
            logLevel: compiled.action.log_level,
          };
        }
      } catch (error) {
        // Log error but continue to next rule
        // Fail-secure: if rule evaluation errors, don't match it
        console.error(`Rule evaluation error for ${ruleId}:`, error);
      }
    }

    // No rule matched - default deny
    return {
      matched: false,
      ruleId: 'default-deny',
      ruleName: 'No matching rule',
      tier: 'prohibited',
      reason: 'No matching rule (default deny)',
    };
  }

  /**
   * Get the number of compiled rules.
   */
  getRuleCount(): number {
    return this.compiledRules.size;
  }

  /**
   * Clear compiled rules and caches.
   */
  clear(): void {
    this.compiledRules.clear();
    this.regexCache.clear();
  }
}

// ============================================================================
// BLOCKLIST CHECKER
// ============================================================================

/**
 * Check if a transaction matches blocklist criteria.
 */
export interface BlocklistCheckResult {
  blocked: boolean;
  reason?: string;
  matchedRule?: string;
  injectionDetected?: boolean;
}

/**
 * Check transaction against blocklist.
 *
 * This is a separate check from rule evaluation because
 * blocklist should ALWAYS be checked first, regardless of rules.
 */
export function checkBlocklist(
  context: PolicyContext,
  policy: InternalPolicy,
  regexCache?: Map<string, RegExp>
): BlocklistCheckResult {
  const blocklist = policy.blocklist;
  if (!blocklist) {
    return { blocked: false };
  }

  // Check destination address
  if (
    context.transaction.destination &&
    blocklist.addresses?.includes(context.transaction.destination)
  ) {
    return {
      blocked: true,
      reason: 'Destination address is blocklisted',
      matchedRule: 'blocklist-address',
    };
  }

  // Check currency issuer
  if (
    context.transaction.issuer &&
    blocklist.currency_issuers?.includes(context.transaction.issuer)
  ) {
    return {
      blocked: true,
      reason: 'Token issuer is blocklisted',
      matchedRule: 'blocklist-issuer',
    };
  }

  // Check memo patterns (prompt injection detection)
  if (context.transaction.memo && blocklist.memo_patterns?.length) {
    const cache = regexCache ?? new Map<string, RegExp>();

    for (const pattern of blocklist.memo_patterns) {
      let regex = cache.get(pattern);
      if (!regex) {
        try {
          regex = new RegExp(pattern, 'i');
          cache.set(pattern, regex);
        } catch {
          // Invalid regex pattern - skip
          continue;
        }
      }

      // Limit memo length for ReDoS protection
      const memo =
        context.transaction.memo.length > 10000
          ? context.transaction.memo.slice(0, 10000)
          : context.transaction.memo;

      if (regex.test(memo)) {
        return {
          blocked: true,
          reason: 'Memo contains blocked pattern (potential injection)',
          matchedRule: 'blocklist-memo-pattern',
          injectionDetected: true,
        };
      }
    }
  }

  return { blocked: false };
}

/**
 * Check if a destination is in the allowlist.
 */
export function isInAllowlist(
  context: PolicyContext,
  policy: InternalPolicy
): boolean {
  const allowlist = policy.allowlist;
  if (!allowlist) return false;

  // Check if destination is in allowlist
  if (
    context.transaction.destination &&
    allowlist.addresses?.includes(context.transaction.destination)
  ) {
    return true;
  }

  // Check exchange addresses with special handling
  if (context.transaction.destination && allowlist.exchange_addresses) {
    const exchange = allowlist.exchange_addresses.find(
      (ex) => ex.address === context.transaction.destination
    );
    if (exchange) {
      // Exchange addresses may require destination tag
      if (exchange.require_tag && !context.transaction.destination_tag) {
        return false; // Missing required tag
      }
      return true;
    }
  }

  // Check trusted tags
  if (
    context.transaction.destination_tag !== undefined &&
    allowlist.trusted_tags?.includes(context.transaction.destination_tag)
  ) {
    return true;
  }

  return false;
}
