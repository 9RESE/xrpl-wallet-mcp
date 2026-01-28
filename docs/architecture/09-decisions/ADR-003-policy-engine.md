# ADR-003: Policy Engine Design

**Status:** Accepted
**Date:** 2026-01-28
**Decision Makers:** Tech Lead, Security Specialist

---

## Context

AI agents operating the XRPL wallet must be constrained by policies that define what transactions they can sign autonomously. The policy engine is the critical security boundary between agent intent and actual signing operations.

Key requirements:
1. **LLM Isolation**: The LLM/agent cannot modify policies at runtime - policies are immutable during execution
2. **Declarative Rules**: Policies should be human-readable and auditable
3. **Deterministic Evaluation**: Same inputs must always produce same outputs
4. **Testability**: Policies must be testable before deployment
5. **Version Control**: Policies should integrate with standard VCS workflows
6. **No Runtime Dependencies**: Avoid external services for policy evaluation
7. **Extensibility**: Support new transaction types and rule types over time

The policy engine must prevent prompt injection attacks (T-001) and policy bypass attempts (T-003).

## Decision

**We will implement an OPA-inspired JSON policy engine with declarative rules, evaluated by a pure TypeScript engine with no external runtime.**

### Policy Structure

```json
{
  "version": "1.0",
  "name": "default-agent-policy",
  "description": "Standard policy for AI agent operations",

  "tiers": {
    "autonomous": {
      "max_amount_xrp": 100,
      "daily_limit_xrp": 1000,
      "require_known_destination": true,
      "allowed_transaction_types": ["Payment", "TrustSet"]
    },
    "delayed": {
      "max_amount_xrp": 1000,
      "daily_limit_xrp": 10000,
      "delay_seconds": 300,
      "veto_enabled": true
    },
    "cosign": {
      "min_amount_xrp": 1000,
      "new_destination_always": true,
      "signer_quorum": 2,
      "approval_timeout_hours": 24
    },
    "prohibited": {
      "reasons": ["blocklist", "daily_limit_exceeded", "unknown_type"]
    }
  },

  "rules": [
    {
      "id": "rule-001",
      "name": "blocklist-check",
      "priority": 1,
      "condition": {
        "field": "destination",
        "operator": "in",
        "value": { "ref": "blocklist.addresses" }
      },
      "action": { "tier": "prohibited", "reason": "Destination is blocklisted" }
    },
    {
      "id": "rule-002",
      "name": "high-value-cosign",
      "priority": 10,
      "condition": {
        "and": [
          { "field": "amount_xrp", "operator": ">=", "value": 1000 },
          { "field": "transaction_type", "operator": "==", "value": "Payment" }
        ]
      },
      "action": { "tier": "cosign", "reason": "High-value payment requires co-signature" }
    },
    {
      "id": "rule-003",
      "name": "new-destination-cosign",
      "priority": 20,
      "condition": {
        "field": "destination",
        "operator": "not_in",
        "value": { "ref": "allowlist.addresses" }
      },
      "action": { "tier": "cosign", "reason": "New destination requires approval" }
    },
    {
      "id": "rule-004",
      "name": "medium-value-delayed",
      "priority": 30,
      "condition": {
        "and": [
          { "field": "amount_xrp", "operator": ">=", "value": 100 },
          { "field": "amount_xrp", "operator": "<", "value": 1000 }
        ]
      },
      "action": { "tier": "delayed", "reason": "Medium-value transaction, delay for review" }
    },
    {
      "id": "rule-999",
      "name": "default-autonomous",
      "priority": 999,
      "condition": { "always": true },
      "action": { "tier": "autonomous", "reason": "Within autonomous limits" }
    }
  ],

  "blocklist": {
    "addresses": [],
    "memo_patterns": ["ignore.*previous", "\\[INST\\]"]
  },

  "allowlist": {
    "addresses": [],
    "trusted_tags": []
  },

  "limits": {
    "daily_reset_utc_hour": 0,
    "max_transactions_per_hour": 100,
    "max_transactions_per_day": 1000
  }
}
```

### Evaluation Engine

```typescript
interface PolicyContext {
  transaction: {
    type: string;
    destination?: string;
    amount_xrp?: number;
    memo?: string;
    fee_drops?: number;
  };
  wallet: {
    address: string;
    daily_spent_xrp: number;
    hourly_transaction_count: number;
  };
  timestamp: string;
}

interface PolicyResult {
  allowed: boolean;
  tier: 'autonomous' | 'delayed' | 'cosign' | 'prohibited';
  reason: string;
  matched_rule: string;
  delay_seconds?: number;
}

function evaluatePolicy(policy: Policy, context: PolicyContext): PolicyResult {
  // Sort rules by priority (lower = higher priority)
  const sortedRules = [...policy.rules].sort((a, b) => a.priority - b.priority);

  for (const rule of sortedRules) {
    if (evaluateCondition(rule.condition, context, policy)) {
      return {
        allowed: rule.action.tier !== 'prohibited',
        tier: rule.action.tier,
        reason: rule.action.reason,
        matched_rule: rule.id,
        delay_seconds: rule.action.tier === 'delayed' ? policy.tiers.delayed.delay_seconds : undefined
      };
    }
  }

  // Default deny (should never reach here with proper default rule)
  return {
    allowed: false,
    tier: 'prohibited',
    reason: 'No matching rule (default deny)',
    matched_rule: 'none'
  };
}
```

### Policy Isolation

The policy engine runs in isolation from the LLM context:

```
+------------------+     +------------------+     +------------------+
|   MCP Request    |     |  Policy Engine   |     |  Signing Layer   |
|                  |     |                  |     |                  |
| Transaction data | --> | Pure evaluation  | --> | Sign if allowed  |
| from LLM/Agent   |     | No side effects  |     | Reject otherwise |
|                  |     | Immutable policy |     |                  |
+------------------+     +------------------+     +------------------+
```

## Consequences

### Positive

- **Human Readable**: JSON policies are easily reviewed by non-programmers
- **Auditable**: Complete decision trace available for every evaluation
- **Version Controlled**: Policies are files, work with Git, PR reviews
- **Testable**: Policy can be tested with mock transactions before deployment
- **No External Runtime**: No OPA server, network calls, or external dependencies
- **Deterministic**: Same inputs always produce same outputs
- **Fast Evaluation**: Pure TypeScript, no IPC or network overhead (<1ms typical)
- **LLM-Proof**: Policies loaded at startup, not modifiable via MCP tools
- **Extensible**: New operators and conditions can be added to engine

### Negative

- **Less Expressive Than Rego**: Cannot express complex conditional logic as elegantly as OPA's Rego
- **Custom Implementation**: We maintain the evaluation engine (vs using battle-tested OPA)
- **Schema Evolution**: Policy format changes require migration tooling
- **No Built-in Testing Framework**: Must build policy testing tools

### Neutral

- Policy changes require service restart or explicit reload command
- Policies are per-network (mainnet/testnet may have different rules)
- Policy size limited by reasonable JSON file size

## Alternatives Considered

| Option | Pros | Cons | Why Not Chosen |
|--------|------|------|----------------|
| **OPA with Rego** | Mature, expressive, battle-tested | Requires separate OPA server, Rego learning curve, adds latency | Operational complexity, external dependency |
| **YAML Policies** | Familiar to ops teams | Less precise, ambiguous semantics, harder to parse | JSON better for programmatic handling |
| **Hardcoded Rules** | Simple, fast, no parsing | Not configurable, requires code changes | Inflexible, poor DX |
| **CEL (Common Expression Language)** | Google-backed, embedded | Less mature ecosystem, complex expressions | OPA ecosystem more developed |
| **JavaScript Policies** | Maximum flexibility | Security risk (code execution), harder to audit | Unacceptable security properties |

## Implementation Notes

### Policy Loading

```typescript
class PolicyEngine {
  private policy: Policy;
  private policyHash: string;

  constructor(policyPath: string) {
    this.loadPolicy(policyPath);
  }

  private loadPolicy(path: string): void {
    const content = fs.readFileSync(path, 'utf8');
    this.policy = JSON.parse(content);
    this.policyHash = crypto.createHash('sha256').update(content).digest('hex');
    this.validatePolicy(this.policy);
    console.log(`Policy loaded: ${this.policy.name} (hash: ${this.policyHash.slice(0, 8)})`);
  }

  // No public method to modify policy - immutable by design
  getPolicyHash(): string {
    return this.policyHash;
  }
}
```

### Condition Operators

```typescript
type Operator = '==' | '!=' | '>' | '>=' | '<' | '<=' | 'in' | 'not_in' | 'matches' | 'contains';

function evaluateOperator(
  operator: Operator,
  fieldValue: unknown,
  compareValue: unknown
): boolean {
  switch (operator) {
    case '==': return fieldValue === compareValue;
    case '!=': return fieldValue !== compareValue;
    case '>':  return (fieldValue as number) > (compareValue as number);
    case '>=': return (fieldValue as number) >= (compareValue as number);
    case '<':  return (fieldValue as number) < (compareValue as number);
    case '<=': return (fieldValue as number) <= (compareValue as number);
    case 'in': return (compareValue as unknown[]).includes(fieldValue);
    case 'not_in': return !(compareValue as unknown[]).includes(fieldValue);
    case 'matches': return new RegExp(compareValue as string).test(fieldValue as string);
    case 'contains': return (fieldValue as string).includes(compareValue as string);
    default: throw new Error(`Unknown operator: ${operator}`);
  }
}
```

### Policy Validation Schema

```typescript
const PolicySchema = z.object({
  version: z.string(),
  name: z.string(),
  description: z.string().optional(),
  tiers: z.object({
    autonomous: TierConfigSchema,
    delayed: TierConfigSchema,
    cosign: TierConfigSchema,
    prohibited: z.object({ reasons: z.array(z.string()) })
  }),
  rules: z.array(RuleSchema),
  blocklist: BlocklistSchema,
  allowlist: AllowlistSchema,
  limits: LimitsSchema
});
```

### Decision Logging

Every policy evaluation is logged:

```typescript
function evaluateWithLogging(
  policy: Policy,
  context: PolicyContext,
  correlationId: string
): PolicyResult {
  const startTime = Date.now();
  const result = evaluatePolicy(policy, context);
  const duration = Date.now() - startTime;

  auditLog.record({
    eventType: 'POLICY_EVALUATION',
    correlationId,
    input: {
      transactionType: context.transaction.type,
      destination: context.transaction.destination,
      amountXrp: context.transaction.amount_xrp,
      // Note: Never log full transaction or sensitive data
    },
    output: result,
    duration,
    policyHash: policyEngine.getPolicyHash()
  });

  return result;
}
```

## Security Considerations

### Prompt Injection Defense

The policy engine defends against prompt injection by:

1. **Immutable Policies**: LLM cannot modify policy via any MCP tool
2. **Memo Pattern Matching**: Blocklisted patterns in memos trigger rejection
3. **Separate Evaluation**: Policy evaluation has no access to LLM context
4. **Hard Limits**: Tier thresholds cannot be bypassed regardless of input

### Policy Integrity

```typescript
// On policy load, hash is computed and logged
// On each evaluation, policy is checked against stored hash
function verifyPolicyIntegrity(): boolean {
  const currentHash = crypto.createHash('sha256')
    .update(JSON.stringify(this.policy))
    .digest('hex');
  return currentHash === this.policyHash;
}
```

### Compliance Mapping

| Requirement | Implementation |
|-------------|----------------|
| AUTHZ-006 | Immutable policy engine, no MCP modification |
| AUTHZ-002 | Tiered approval in policy structure |
| AUTHZ-003 | Allowlist support in policy |
| AUTHZ-007 | Blocklist enforcement in rules |
| VAL-004 | Memo pattern checking for injection |
| AUDIT-002 | Every evaluation logged |

## References

- [Open Policy Agent](https://www.openpolicyagent.org/) - Inspiration for declarative policy approach
- [Rego Language](https://www.openpolicyagent.org/docs/latest/policy-language/) - Reference for policy expressiveness
- Security Requirements: AUTHZ-002, AUTHZ-003, AUTHZ-006, AUTHZ-007, VAL-004

## Related ADRs

- [ADR-004: XRPL Key Strategy](ADR-004-xrpl-key-strategy.md) - Multi-sign for cosign tier
- [ADR-005: Audit Logging](ADR-005-audit-logging.md) - Policy decision logging
- [ADR-009: Transaction Scope](ADR-009-transaction-scope.md) - Supported transaction types

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Tech Lead | Initial ADR |
