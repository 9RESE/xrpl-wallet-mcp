# XRPL Agent Wallet MCP Documentation

## Project Status: ✅ PHASE 1 IMPLEMENTATION COMPLETE

This documentation provides the complete technical specification and implementation details for the XRPL Agent Wallet MCP server - a secure, policy-controlled wallet infrastructure for AI agents operating on the XRP Ledger.

**Implementation Plan:** `xrpl-wallet-mcp-impl-2026-01-28`
**Version:** 1.0.0
**Date:** 2026-01-28
**Tests:** 222 passing

---

## Documentation Status

| Section | Status | Documents |
|---------|--------|-----------|
| Research | **COMPLETE** | 1 |
| Security | **COMPLETE** | 6 |
| Architecture (Arc42) | **COMPLETE** | 9 + 10 ADRs |
| API Reference | **COMPLETE** | 13 |
| User Documentation (Diataxis) | **COMPLETE** | 11 |
| Development Specifications | **COMPLETE** | 11 |
| C4 Diagrams | **COMPLETE** | 3 |

**Total Documentation Files:** 64

---

## Quick Links

### Architecture (Arc42)

| Document | Description |
|----------|-------------|
| [01 - Introduction](architecture/01-introduction.md) | Goals, stakeholders, requirements |
| [02 - Constraints](architecture/02-constraints.md) | Technical and organizational constraints |
| [03 - Context](architecture/03-context.md) | System context and external interfaces |
| [04 - Solution Strategy](architecture/04-solution-strategy.md) | Key design decisions overview |
| [05 - Building Blocks](architecture/05-building-blocks.md) | Component decomposition |
| [06 - Runtime View](architecture/06-runtime-view.md) | Transaction signing flows |
| [07 - Deployment View](architecture/07-deployment-view.md) | Infrastructure and deployment |
| [08 - Crosscutting Concepts](architecture/08-crosscutting.md) | Security, error handling, logging |
| [09 - Architecture Decisions](architecture/09-decisions/README.md) | ADR index (10 decisions) |
| [Architecture Review Report](architecture/architecture-review-report.md) | Complete architecture review |

#### Architecture Decision Records (ADRs)

| ADR | Title |
|-----|-------|
| [ADR-001](architecture/09-decisions/ADR-001-key-storage.md) | Encrypted Local Key Storage |
| [ADR-002](architecture/09-decisions/ADR-002-key-derivation.md) | Argon2id Key Derivation |
| [ADR-003](architecture/09-decisions/ADR-003-policy-engine.md) | Multi-Tier Policy Engine |
| [ADR-004](architecture/09-decisions/ADR-004-xrpl-key-strategy.md) | XRPL Key Management Strategy |
| [ADR-005](architecture/09-decisions/ADR-005-audit-logging.md) | Tamper-Evident Audit Logging |
| [ADR-006](architecture/09-decisions/ADR-006-input-validation.md) | Input Validation Strategy |
| [ADR-007](architecture/09-decisions/ADR-007-rate-limiting.md) | Rate Limiting Architecture |
| [ADR-008](architecture/09-decisions/ADR-008-integration-design.md) | MCP Integration Design |
| [ADR-009](architecture/09-decisions/ADR-009-transaction-scope.md) | Transaction Type Scope |
| [ADR-010](architecture/09-decisions/ADR-010-network-isolation.md) | Network Isolation Design |

### Security

| Document | Description |
|----------|-------------|
| [Security Architecture](security/SECURITY-ARCHITECTURE.md) | Complete security architecture |
| [Threat Model](security/threat-model.md) | STRIDE analysis, attack trees |
| [Security Requirements](security/security-requirements.md) | Functional and non-functional requirements |
| [Compliance Mapping](security/compliance-mapping.md) | OWASP, NIST, SOC2 alignment |
| [OWASP LLM Mitigations](security/owasp-llm-mitigations.md) | AI-specific threat mitigations |
| [Security Review Report](security/security-review-report.md) | Complete security review |

### API Reference

| Document | Description |
|----------|-------------|
| [Policy Schema](api/policy-schema.md) | JSON Schema for policy configuration |
| [Network Configuration](api/network-config.md) | Network settings and isolation |

#### MCP Tools (11)

| Tool | Description |
|------|-------------|
| [wallet_balance](api/tools/wallet-balance.md) | Query wallet balance |
| [wallet_policy_check](api/tools/wallet-policy-check.md) | Pre-validate transactions |
| [wallet_create](api/tools/wallet-create.md) | Create new wallet |
| [wallet_sign](api/tools/wallet-sign.md) | Sign transactions |
| [wallet_history](api/tools/wallet-history.md) | Query transaction history |
| [wallet_rotate](api/tools/wallet-rotate.md) | Rotate keys |
| [wallet_list](api/tools/wallet-list.md) | List wallets |
| [wallet_fund](api/tools/wallet-fund.md) | Fund from testnet/devnet faucet |
| [policy_set](api/tools/policy-set.md) | Configure policies |
| [tx_decode](api/tools/tx-decode.md) | Decode transaction blobs |
| [tx_submit](api/tools/tx-submit.md) | Submit signed transactions |

### User Documentation (Diataxis)

#### Tutorials
| Document | Description |
|----------|-------------|
| [Getting Started](user/tutorials/getting-started.md) | First steps with the wallet |
| [Escrow Workflow](user/tutorials/escrow-workflow.md) | End-to-end escrow tutorial |

#### How-To Guides
| Document | Description |
|----------|-------------|
| [Configure Policies](user/how-to/configure-policies.md) | Policy configuration guide |
| [Rotate Keys](user/how-to/rotate-keys.md) | Key rotation procedures |
| [Network Configuration](user/how-to/network-configuration.md) | Network setup guide |
| [Escrow MCP Integration](user/how-to/escrow-mcp-integration.md) | Cross-MCP integration |

#### Reference
| Document | Description |
|----------|-------------|
| [API Reference](user/reference/api.md) | Quick API reference |
| [Supported Transactions](user/reference/supported-transactions.md) | Transaction type reference |

#### Explanation
| Document | Description |
|----------|-------------|
| [Security Model](user/explanation/security-model.md) | Security architecture explained |
| [Policy Engine](user/explanation/policy-engine.md) | Policy system concepts |
| [Network Isolation](user/explanation/network-isolation.md) | Network separation explained |

### Development

#### Implementation Status
| Document | Description |
|----------|-------------|
| [Implementation Status](development/features/implementation-status.md) | Current implementation status and metrics |

#### Feature Specifications
| Document | Description |
|----------|-------------|
| [Keystore Interface](development/features/keystore-interface.md) | Abstract keystore specification |
| [Local Keystore](development/features/local-keystore-spec.md) | File-based keystore implementation |
| [Policy Engine](development/features/policy-engine-spec.md) | Policy engine specification |
| [Audit Logger](development/features/audit-logger-spec.md) | Audit logging specification |
| [XRPL Client](development/features/xrpl-client-spec.md) | XRPL client wrapper specification |
| [Multi-Sign](development/features/multi-sign-spec.md) | Multi-signature specification |

#### Test Specifications
| Document | Description |
|----------|-------------|
| [Test Coverage Requirements](development/features/test-coverage-requirements.md) | Coverage targets and strategy |
| [Unit Test Patterns](development/features/test-patterns-unit.md) | Unit testing patterns |
| [Integration Test Patterns](development/features/test-patterns-integration.md) | Integration testing patterns |
| [Security Test Patterns](development/features/test-patterns-security.md) | Security testing patterns |
| [E2E Test Scenarios](development/features/test-scenarios-e2e.md) | End-to-end test scenarios |

### C4 Diagrams

| Document | Description |
|----------|-------------|
| [Context Diagram](c4-diagrams/context.md) | System context (Level 1) |
| [Container Diagram](c4-diagrams/containers.md) | Container architecture (Level 2) |
| [Component Diagram](c4-diagrams/components.md) | Component breakdown (Level 3) |

### Research

| Document | Description |
|----------|-------------|
| [AI Agent Wallet Security 2025-2026](research/ai-agent-wallet-security-2025-2026.md) | Industry research and analysis |

---

## Project Overview

### Problem Statement

AI agents interacting with the XRP Ledger need to:
1. **Hold XRP** for transaction fees and operations
2. **Sign transactions** autonomously within defined boundaries
3. **Operate within safety guardrails** to prevent unauthorized actions
4. **Keep private keys secure** from exposure or theft

**Current State:** Agents must store raw seeds in environment variables with no policy enforcement, human oversight for high-risk operations, or proper key management.

### Solution

A secure MCP server providing:

- **Policy-Controlled Signing** - Three-tier approval system (auto-approve, require-review, deny) with configurable rules
- **XRPL-Native Security** - Regular Keys for operational signing, Master Key protection, Multi-Sign support
- **Encrypted Key Storage** - AES-256-GCM encryption with Argon2id key derivation
- **Audit Logging** - Tamper-evident logs with hash chains and integrity verification
- **Defense in Depth** - Input validation, rate limiting, network isolation, prompt injection defenses

### Design Priorities

1. **Security** - Never compromise key safety or transaction integrity
2. **Agent Autonomy** - Maximize operational capability within policy bounds
3. **Usability** - Simple MCP API with excellent developer experience

### Architecture Highlights

```
+------------------+     +------------------------+     +-------------+
|    AI Agent      |---->|  XRPL Wallet MCP       |---->|    XRPL     |
|  (Claude, etc.)  |     |  Server                |     |   Network   |
+------------------+     +------------------------+     +-------------+
                               |
                               v
                    +--------------------+
                    |  Encrypted         |
                    |  Key Storage       |
                    +--------------------+
```

**Key Components:**
- **MCP Tool Layer** - 11 tools for wallet operations
- **Policy Engine** - Transaction validation and approval
- **Keystore** - Encrypted key management
- **Audit Logger** - Comprehensive activity logging
- **XRPL Client** - Network communication wrapper
- **Signing Service** - Transaction signing with multi-sig support

---

## Getting Started

### For Specification Review

1. **Start with Research:** [AI Agent Wallet Security Research](research/ai-agent-wallet-security-2025-2026.md)
2. **Review Security:** [Security Architecture](security/SECURITY-ARCHITECTURE.md)
3. **Understand Architecture:** [Arc42 Introduction](architecture/01-introduction.md)
4. **Check ADRs:** [Architecture Decisions](architecture/09-decisions/README.md)
5. **Review API:** [Policy Schema](api/policy-schema.md) and tool specifications

### For Implementation

1. **Tutorial:** [Getting Started Guide](user/tutorials/getting-started.md)
2. **Feature Specs:** Start with [Keystore Interface](development/features/keystore-interface.md)
3. **Test Specs:** Review [Test Coverage Requirements](development/features/test-coverage-requirements.md)
4. **Implementation Order:**
   - Core: Keystore -> Policy Engine -> Audit Logger
   - Tools: wallet_create -> wallet_balance -> wallet_sign
   - Advanced: Multi-Sign -> Key Rotation -> Network Config

### Security Policy

See [SECURITY.md](/SECURITY.md) for:
- Vulnerability reporting procedures
- Security contact information
- Responsible disclosure policy

---

## Contributing

See [CONTRIBUTING.md](/CONTRIBUTING.md) for:
- Development setup
- Code style guidelines
- Pull request process
- Testing requirements

---

## Implementation Status

Phase 1 (MVP) implementation is **COMPLETE**.

### Implementation Metrics
- **Source Files:** 33 TypeScript files
- **Lines of Code:** ~12,000
- **Test Suites:** 3
- **Tests Passing:** 222

### Included
- Full security architecture with threat modeling
- Complete API specification for 11 MCP tools
- Detailed component specifications
- Comprehensive test specifications
- User documentation following Diataxis framework
- Architecture documentation following Arc42 template
- 10 Architecture Decision Records

### Implementation Highlights
- All specifications implemented in TypeScript
- 222 tests passing across 3 test suites
- All 10 ADRs implemented as specified
- Build output: 159 KB ESM bundle

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0.0 | 2026-01-28 | Initial complete specification |
| 1.0.1 | 2026-01-28 | Phase 1 implementation complete (222 tests) |

---

*Documentation Index - XRPL Agent Wallet MCP*
*Implementation Complete: 2026-01-28*
*Total Documents: 66*
