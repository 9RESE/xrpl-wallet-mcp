# Understanding the Policy Engine

**Document Type:** Explanation (Diataxis)
**Last Updated:** 2026-01-28
**Audience:** Developers, security architects, system administrators

---

## What is the Policy Engine?

The Policy Engine is the critical security boundary that stands between AI agents and your XRPL wallet. Every transaction request from an agent must pass through this component before any signing operation can occur. Think of it as an intelligent gatekeeper that evaluates each transaction against a comprehensive set of rules, limits, and constraints you have defined.

The policy engine is inspired by the Open Policy Agent (OPA) design philosophy, but implemented entirely in TypeScript with no external runtime dependencies. This means faster evaluation, simpler deployment, and predictable behavior without network calls or external service availability concerns.

### The Role in the Security Model

In traditional wallet management, a human reviews each transaction before signing. When AI agents operate wallets, we need a mechanism that can make consistent, auditable decisions at machine speed while preserving human control over high-risk operations. The policy engine fills this role by:

1. **Classifying every transaction** into one of four tiers based on risk
2. **Enforcing hard limits** that no agent can exceed
3. **Detecting potential attacks** through pattern matching and anomaly detection
4. **Routing high-value operations** to human approval workflows
5. **Maintaining complete audit trails** of every decision

---

## Why Policies are Immutable at Runtime

A fundamental design principle of the policy engine is that policies cannot be modified while the system is running. This immutability is not a limitation but a deliberate security feature.

### The Threat Model

Consider what could happen if an AI agent could modify its own governance rules:

- A compromised or manipulated agent could gradually relax limits
- Prompt injection attacks could instruct the agent to remove blocklist entries
- Social engineering through transaction memos could trick the agent into expanding allowlists
- An attacker who gains temporary control could permanently weaken defenses

By making policies immutable at runtime, we establish a clear separation of concerns: the policy defines what is allowed, and the agent operates within those boundaries. Neither can influence the other.

### How Policy Changes Work

Policies are loaded from disk at server startup. The policy file is read, validated against the schema, and then frozen in memory. Any changes to the policy require:

1. Modifying the policy file on disk
2. Restarting the MCP server (or explicitly calling reload during a maintenance window)
3. Re-verification of the policy hash

The SHA-256 hash of the loaded policy is computed and stored. Before every transaction evaluation, this hash is verified to ensure the in-memory policy has not been tampered with. Any integrity failure results in immediate denial of all transactions.

### The Tradeoff

This design trades operational flexibility for security. You cannot make emergency policy changes without a restart. However, this tradeoff is appropriate because:

- Policy changes should be deliberate, reviewed, and tested
- Emergency situations should use the co-sign tier, not policy modifications
- The delay in changing policies is measured in seconds, not hours
- Audit trails become cleaner when policy changes are explicit events

---

## Rule Evaluation Explained

The policy engine uses a rule-based system where rules are evaluated in a specific order to determine how each transaction should be handled.

### Priority-Based Evaluation

Rules are assigned priority numbers, and lower numbers are evaluated first. This creates a deterministic, predictable evaluation order. Consider this conceptual example:

```
Priority 1: Block all transactions to blocklisted addresses
Priority 10: Allow small payments to known addresses
Priority 20: Delay medium payments for review
Priority 100: Require co-sign for everything else
Priority 999: Default deny (catch-all)
```

The engine evaluates rules sequentially. The moment a rule's condition matches, that rule's action determines the outcome, and evaluation stops. This "first match wins" approach means:

- High-priority security rules (blocklists) are checked before permissive rules
- Specific exceptions can be placed before general rules
- A catch-all default rule at the end ensures no transaction slips through undefined

### Condition Evaluation

Each rule has a condition that determines when it applies. Conditions can be simple field comparisons or complex logical combinations.

**Simple conditions** compare a transaction field against a value:
- "Is the amount greater than 1000 XRP?"
- "Is the destination in the blocklist?"
- "Does the memo contain a suspicious pattern?"

**Compound conditions** combine simple conditions with logical operators:
- **AND**: All sub-conditions must be true (used for multiple criteria)
- **OR**: At least one sub-condition must be true (used for alternatives)
- **NOT**: The sub-condition must be false (used for exclusions)

These can be nested to express complex policies. For example: "Block this transaction if (the amount exceeds 5000 XRP) AND (the destination is new OR the memo mentions 'urgent')."

### Action Determination

When a rule matches, its action specifies:

1. **The tier** the transaction should be assigned to
2. **A reason** explaining why (for audit logs and user feedback)
3. **Optional overrides** like custom delay periods or notification flags

The tier determines what happens next: autonomous transactions proceed immediately, delayed transactions enter a queue, co-sign transactions await human approval, and prohibited transactions are rejected.

### The Default Deny Principle

If no rule matches a transaction, it is denied by default. This fail-secure behavior ensures that policy gaps result in rejection rather than unauthorized access. Every policy should include a catch-all rule at the lowest priority to handle this explicitly, but the engine enforces denial even if such a rule is missing.

---

## Limit Tracking Explained

Beyond rule-based evaluation, the policy engine enforces hard limits on transaction volume, frequency, and scope. These limits operate independently of rules and cannot be bypassed.

### Rolling Windows

Some limits use rolling time windows rather than fixed periods. The hourly transaction count limit, for example, counts transactions in the past 60 minutes, not "since the top of the hour."

With a rolling window:
- At 2:30 PM, the window includes transactions from 1:30 PM to 2:30 PM
- At 2:31 PM, the window includes transactions from 1:31 PM to 2:31 PM
- Transactions "age out" as they pass the window boundary

This prevents the "reset exploit" where an attacker times high-volume activity around limit boundaries. With fixed hourly resets at the top of each hour, an attacker could execute 100 transactions at 12:59 PM and another 100 at 1:01 PM. Rolling windows prevent this pattern.

### Daily Resets

Daily limits do use fixed reset times because:
- Rolling 24-hour windows would be computationally expensive to maintain
- Daily budgets align with business operations and reporting
- The reset time is configurable (default: midnight UTC)

When the configured reset hour arrives:
- Daily transaction counts return to zero
- Daily volume accumulators reset
- Unique destination sets are cleared
- The limit tracker logs the previous day's totals

### Multi-Limit Interactions

A transaction must satisfy all applicable limits to proceed. The engine checks in this order:

1. **Cooldown status**: Is the wallet in a mandatory pause period?
2. **Daily transaction count**: Have we exceeded the daily transaction limit?
3. **Hourly transaction count**: Have we exceeded the rolling hourly limit?
4. **Daily volume**: Would this transaction exceed the daily XRP volume cap?
5. **Unique destinations**: Would this add a new destination beyond the daily unique destination limit?

Any limit failure results in immediate denial with a specific reason indicating which limit was exceeded. The transaction is not queued for later; the agent must wait for limits to reset or adjust its approach.

### Why Limits Cannot Be Rule-Overridden

Rules can only assign tiers; they cannot bypass limits. This design ensures that even with permissive rules, fundamental safety boundaries remain intact. A rule might classify a transaction as "autonomous," but if the daily volume limit has been reached, that transaction is still denied.

This separation means:
- Rules express policy intent (what kind of transaction is this?)
- Limits enforce absolute boundaries (how much can happen?)
- Neither can subvert the other

---

## Tier Classification Logic

Every transaction is ultimately classified into one of four tiers. Understanding how this classification works is essential for designing effective policies.

### The Four Tiers

| Tier | Name | What Happens |
|------|------|--------------|
| 1 | Autonomous | Transaction proceeds immediately without human involvement |
| 2 | Delayed | Transaction is queued for a review period; humans can veto |
| 3 | Co-Sign | Transaction requires explicit human approval (signatures) |
| 4 | Prohibited | Transaction is rejected; cannot proceed under any circumstances |

### How Tiers Are Determined

Tier determination is a multi-factor process:

1. **Rule evaluation** provides the initial tier assignment
2. **Transaction type defaults** may escalate the tier
3. **Amount thresholds** may further escalate based on value
4. **New destination status** may trigger escalation
5. **Multiple factors** combine via "most restrictive wins"

For example, a 500 XRP payment might:
- Match a rule assigning it to "delayed" tier (priority 20)
- But the co-sign tier is configured to require approval for amounts over 100 XRP
- The final tier is "co-sign" because it is more restrictive

### The "Most Restrictive Wins" Principle

When multiple factors suggest different tiers, the most restrictive tier is always selected. The tier hierarchy from most to least restrictive is:

```
Prohibited > Co-Sign > Delayed > Autonomous
```

This ensures that:
- A single high-risk factor can elevate a transaction's tier
- Permissive rules cannot override restrictive type defaults
- Security measures compose additively

### Tier Factors

The policy result includes a list of factors that contributed to the tier determination. This provides transparency for:
- Debugging policy behavior
- Explaining decisions to users
- Audit trail documentation

A transaction might show factors like:
- Rule "medium-payment-delay" contributed tier "delayed"
- Amount 500 XRP exceeded autonomous max 100 XRP, escalated to "delayed"
- New destination triggered co-sign requirement
- Final tier: co-sign

---

## Allowlist and Blocklist Behavior

The policy engine maintains two special lists that receive expedited treatment in evaluation.

### Blocklist: Absolute Denial

The blocklist is checked before any rule evaluation. If a transaction matches any blocklist criterion, it is immediately classified as "prohibited" with no further evaluation. This ensures:

- Known bad addresses are always blocked
- Prompt injection patterns are caught before rules process the memo
- Blocked token issuers cannot be interacted with

Blocklist matching includes:
- **Destination addresses**: Exact match against known scam/sanctioned addresses
- **Memo patterns**: Regular expression matching for injection attempts
- **Currency issuers**: Exact match for blocked token issuers

The blocklist check happens at the start of evaluation, making it impossible for rules to "allow" a blocklisted address.

### Allowlist: Trust but Verify

The allowlist identifies pre-approved destinations that may receive favorable treatment. Unlike the blocklist, the allowlist does not automatically approve transactions. Instead:

- Allowlisted addresses may qualify for autonomous tier (if `require_known_destination` is true)
- Allowlisted addresses are not considered "new destinations" for escalation
- Exchange addresses on the allowlist can have special requirements (like mandatory destination tags)

The allowlist is a "softening" factor, not an override. A transaction to an allowlisted address still must:
- Pass all rules
- Stay within all limits
- Comply with tier-specific amount thresholds

### Auto-Learn (and Why It Is Dangerous)

Some policies support auto-learning, where addresses that receive co-signed approval are automatically added to the allowlist. This feature exists for convenience but carries significant risk:

- Social engineering attacks can trick co-signers into approving a bad address
- Once allowlisted, that address receives favorable treatment
- The allowlist pollution persists until manually cleaned

Auto-learn is disabled by default and should remain disabled for mainnet deployments. If enabled, it operates by emitting an event that external systems can process to update the policy file, preserving the immutability principle.

---

## Policy Versioning

Policies include a version field that supports schema evolution and migration.

### Version Field Purpose

The version field (e.g., "1.0") indicates which schema version the policy conforms to. This enables:

- Validation against the correct schema
- Migration tooling that upgrades policies to newer schemas
- Backward compatibility detection

### How Versioning Works

When the policy engine loads a policy:
1. It reads the version field
2. It selects the appropriate schema validator
3. It validates the policy structure
4. For older versions, it may apply automatic migrations

### Schema Evolution Strategy

The schema is designed for forward-compatible evolution:
- New optional fields can be added without breaking existing policies
- Required fields are minimized to essentials
- Semantic changes are avoided; new behaviors use new fields
- Major version changes indicate breaking changes requiring migration

---

## Common Policy Patterns

Understanding common patterns helps in designing effective policies.

### The Defense-in-Depth Pattern

Multiple overlapping controls provide layered security:

```
Layer 1: Blocklist blocks known bad actors
Layer 2: Rules classify by risk factors
Layer 3: Tiers add human oversight
Layer 4: Limits enforce absolute ceilings
```

No single layer needs to be perfect. If one layer fails to catch an attack, another layer provides protection.

### The Principle of Least Privilege

Policies should grant the minimum necessary permissions:

- Start with everything prohibited
- Add specific rules for needed operations
- Keep autonomous tier thresholds low
- Escalate to human oversight liberally

It is easier to relax a restrictive policy than to tighten a permissive one after an incident.

### The Escalation Ladder

Design policies with clear escalation paths:

```
Small routine transactions  -> Autonomous
Medium operational needs    -> Delayed with veto window
Large or unusual requests   -> Co-sign with human approval
Dangerous or forbidden ops  -> Prohibited
```

Each step up the ladder adds oversight appropriate to the risk.

### The Quarantine Pattern

For new agent deployments, use a quarantine period:

1. Deploy with maximally restrictive policy (everything co-sign)
2. Monitor behavior and approval patterns
3. Gradually relax restrictions as confidence grows
4. Maintain audit logs for anomaly detection

This pattern treats new agents as untrusted until they demonstrate reliable behavior.

### The Emergency Stop Pattern

Include mechanisms for rapid shutdown:

- A policy-level `enabled: false` flag stops all transactions
- High-priority rules can prohibit specific operation types
- Cooldown periods after high-value transactions create mandatory pauses

These mechanisms provide human override capability even when the agent is operating autonomously.

---

## Summary

The policy engine is the foundation of safe AI agent wallet operation. Its key concepts are:

1. **Immutability** prevents runtime manipulation of governance rules
2. **Priority-based evaluation** provides deterministic, auditable decisions
3. **Tier classification** routes transactions to appropriate approval workflows
4. **Limit tracking** enforces absolute boundaries independent of rules
5. **Allowlists and blocklists** provide expedited handling for known addresses
6. **Defense in depth** means multiple layers must all agree before execution

By understanding these concepts, you can design policies that balance operational efficiency with security, enabling AI agents to perform useful work while maintaining human control over critical decisions.

---

## Related Documents

- [Policy Schema Reference](../../api/policy-schema.md) - Complete field documentation
- [Policy Engine Specification](../../development/features/policy-engine-spec.md) - Implementation details
- [ADR-003: Policy Engine Design](../../architecture/09-decisions/ADR-003-policy-engine.md) - Architectural rationale
- [Security Requirements](../../security/security-requirements.md) - Broader security context

---

*This document explains concepts and rationale. For step-by-step configuration instructions, see the Policy Configuration How-To Guide.*
