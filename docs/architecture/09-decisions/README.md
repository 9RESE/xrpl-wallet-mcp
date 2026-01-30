# Architecture Decision Records (ADRs)

**Project:** XRPL Agent Wallet MCP Server
**Last Updated:** 2026-01-28

---

## Overview

This directory contains Architecture Decision Records (ADRs) documenting the key architectural decisions for the XRPL Agent Wallet MCP server. ADRs capture the context, decision, and consequences of significant technical choices.

## ADR Index

| ADR | Title | Status | Summary |
|-----|-------|--------|---------|
| [ADR-001](ADR-001-key-storage.md) | Key Storage (Phase 1) | Accepted | Local AES-256-GCM encrypted files for key storage |
| [ADR-002](ADR-002-key-derivation.md) | Key Derivation Function | Accepted | Argon2id with 64MB memory, 3 iterations, 4 parallelism |
| [ADR-003](ADR-003-policy-engine.md) | Policy Engine Design | Accepted | OPA-inspired JSON policies with declarative rules |
| [ADR-004](ADR-004-xrpl-key-strategy.md) | XRPL Key Strategy | Accepted | Regular Keys for agent, Master Key cold storage, Multi-Sign for Tier 3 |
| [ADR-005](ADR-005-audit-logging.md) | Audit Logging | Accepted | HMAC-SHA256 hash chains with tamper detection |
| [ADR-006](ADR-006-input-validation.md) | Input Validation | Accepted | Zod schemas for all MCP tool inputs |
| [ADR-007](ADR-007-rate-limiting.md) | Rate Limiting | Accepted | Token bucket with sliding window |
| [ADR-008](ADR-008-integration-design.md) | Integration Design | Accepted | Composable MCP ecosystem (unsigned TX to signed TX pattern) |
| [ADR-009](ADR-009-transaction-scope.md) | Transaction Scope | Accepted | Support ALL XRPL transaction types |
| [ADR-010](ADR-010-network-isolation.md) | Network Isolation | Accepted | Separate keystores per network (mainnet/testnet/devnet) |
| [ADR-011](ADR-011-security-remediation.md) | Security Remediation | Accepted | Phase 1 security hardening (19 issues fixed) |
| [ADR-012](ADR-012-escrow-integration-improvements.md) | Escrow Integration | Accepted | Timing-aware parameters for MCP-to-MCP workflows |
| [ADR-013](ADR-013-sequence-autofill.md) | Sequence Autofill | Accepted | Local sequence tracking to prevent tefPAST_SEQ race conditions |

## ADR Status Definitions

| Status | Definition |
|--------|------------|
| **Proposed** | Under discussion, not yet approved |
| **Accepted** | Approved and ready for implementation |
| **Deprecated** | No longer valid, superseded by another ADR |
| **Superseded** | Replaced by a newer ADR |

## Decision Relationships

```
ADR-001 (Key Storage)
    |
    +-- uses --> ADR-002 (Argon2id KDF)
    |
    +-- uses --> ADR-006 (Zod) for keystore format validation
    |
    +-- constrained by --> ADR-010 (Network Isolation)

ADR-003 (Policy Engine)
    |
    +-- evaluates --> ADR-009 (All TX Types)
    |
    +-- enforces --> ADR-004 (Multi-Sign) for Tier 3
    |
    +-- logs to --> ADR-005 (Audit Logging)

ADR-004 (XRPL Key Strategy)
    |
    +-- keys stored via --> ADR-001 (Key Storage)
    |
    +-- isolated by --> ADR-010 (Network Isolation)

ADR-006 (Input Validation)
    |
    +-- validates --> ADR-009 (Transaction Types)
    |
    +-- runs before --> ADR-007 (Rate Limiting)

ADR-008 (Integration Design)
    |
    +-- validates via --> ADR-006 (Input Validation)
    |
    +-- evaluates via --> ADR-003 (Policy Engine)
    |
    +-- supports --> ADR-009 (All TX Types)
    |
    +-- enhanced by --> ADR-012 (Escrow Integration)

ADR-012 (Escrow Integration)
    |
    +-- addresses --> ADR-013 (Sequence Autofill) for multi-tx workflows
    |
    +-- extends --> ADR-008 (Integration Design)

ADR-013 (Sequence Autofill)
    |
    +-- prevents --> tefPAST_SEQ race conditions
    |
    +-- uses --> SequenceTracker singleton
    |
    +-- tracks in --> wallet_sign, tx_submit
```

## Security Requirements Mapping

Each ADR addresses specific security requirements from the [Security Requirements Specification](../../security/security-requirements.md):

| ADR | Primary Requirements |
|-----|---------------------|
| ADR-001 | ENC-001, ENC-002, ENC-003, ENC-005, ENC-006, KEY-005, KEY-006 |
| ADR-002 | AUTH-001 |
| ADR-003 | AUTHZ-002, AUTHZ-003, AUTHZ-006, AUTHZ-007, VAL-004 |
| ADR-004 | AUTHZ-002, KEY-001, KEY-002 |
| ADR-005 | AUDIT-001, AUDIT-002, AUDIT-003, AUDIT-004, AUDIT-005, AUDIT-006, AUDIT-007 |
| ADR-006 | VAL-001, VAL-002, VAL-003, VAL-004, VAL-005, VAL-006, VAL-007 |
| ADR-007 | RATE-001, RATE-002, RATE-003, RATE-004, RATE-005, RATE-006 |
| ADR-008 | Integration patterns |
| ADR-009 | Transaction type policies |
| ADR-010 | Network safety guardrails |
| ADR-011 | AUTH-001, KEY-002, AUDIT-001, VAL-004 (security hardening) |
| ADR-012 | Integration timing, ledger consistency |
| ADR-013 | Sequence management, race condition prevention |

## Creating New ADRs

Use the following template when creating new ADRs:

```markdown
# ADR-NNN: [Title]

**Status:** Proposed | Accepted | Deprecated | Superseded
**Date:** YYYY-MM-DD
**Decision Makers:** [Names/Roles]

---

## Context

[Why is this decision needed? What problem are we solving?]

## Decision

[What is the decision? Be specific.]

## Consequences

### Positive
- [Benefit 1]
- [Benefit 2]

### Negative
- [Tradeoff 1]
- [Tradeoff 2]

### Neutral
- [Observation]

## Alternatives Considered

| Option | Pros | Cons | Why Not Chosen |
|--------|------|------|----------------|
| [Alt 1] | ... | ... | ... |
| [Alt 2] | ... | ... | ... |

## Implementation Notes

[Any specific implementation guidance]

## Security Considerations

[Security implications of this decision]

## References

- [Link 1]
- [Link 2]

## Related ADRs

- ADR-XXX: [Related decision]

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | YYYY-MM-DD | [Author] | Initial ADR |
```

## References

- [Arc42 Template - Section 09: Architecture Decisions](https://arc42.org/overview)
- [Michael Nygard's ADR Template](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
- [Security Architecture](../../security/SECURITY-ARCHITECTURE.md)
- [Solution Strategy](../04-solution-strategy.md)

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Tech Lead | Initial ADR index with 10 ADRs |
| 1.1.0 | 2026-01-28 | Code Review Agent | Added ADR-011 Security Remediation |
| 1.2.0 | 2026-01-29 | - | Added ADR-012 Escrow Integration, ADR-013 Sequence Autofill |
