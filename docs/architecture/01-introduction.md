# 1. Introduction and Goals

**Document Version**: 1.0.0
**Last Updated**: 2026-01-28
**Status**: Draft
**Arc42 Section**: 01 - Introduction and Goals

---

## Table of Contents

1. [Requirements Overview](#1-requirements-overview)
2. [Quality Goals](#2-quality-goals)
3. [Stakeholders](#3-stakeholders)
4. [Project Scope](#4-project-scope)
5. [Document Conventions](#5-document-conventions)

---

## 1. Requirements Overview

### 1.1 Business Context

The XRPL Agent Wallet MCP server addresses a critical gap in AI agent infrastructure: the absence of secure, policy-controlled wallet operations for autonomous agents operating on the XRP Ledger. As AI agents increasingly perform financial operations, they require wallet infrastructure that balances autonomy with security and human oversight.

### 1.2 Business Goals

| Goal | Description | Success Metric |
|------|-------------|----------------|
| **Enable Agent Autonomy** | Allow AI agents to autonomously operate on XRPL within defined parameters | Agents can execute 95%+ of routine transactions without human intervention |
| **Secure Key Infrastructure** | Provide secure wallet infrastructure for agent-initiated transactions | Zero key exposure incidents; keys never leave encrypted storage unprotected |
| **Policy-Controlled Signing** | Implement configurable policy engine with tiered approval workflows | Policies block 100% of out-of-bounds transactions |
| **Human Oversight** | Enable human intervention for high-value or anomalous operations | All transactions exceeding thresholds require human approval |
| **Ecosystem Integration** | Support integration with xrpl-escrow-mcp and other XRPL MCP servers | Seamless interoperability with existing XRPL MCP ecosystem |
| **Audit Compliance** | Provide tamper-evident audit trail for all agent activities | Complete traceability of every operation with cryptographic proof |

### 1.3 Key Problems Solved

The XRPL Agent Wallet MCP directly addresses the following critical problems in current AI agent deployments:

#### Problem 1: Insecure Key Storage

**Current State**: Agents store raw seeds or private keys in environment variables, configuration files, or plaintext storage.

**Risks**:
- Environment variable exposure through process inspection
- Configuration file leaks via version control or backups
- Memory dumps revealing key material
- Lateral movement attacks accessing stored credentials

**Solution**: Encrypted keystore with AES-256-GCM encryption, Argon2id key derivation, and defense-in-depth protections. Keys are never exposed in plaintext outside the signing context.

#### Problem 2: No Policy Enforcement

**Current State**: Agents have unrestricted access to wallet operations with no guardrails on transaction parameters.

**Risks**:
- Prompt injection attacks triggering unauthorized transactions
- Runaway agents draining wallet balances
- No limits on transaction amounts, destinations, or frequency
- Inability to enforce compliance requirements

**Solution**: Comprehensive policy engine supporting transaction limits, destination allowlists, time-based restrictions, and tiered approval workflows based on transaction risk profile.

#### Problem 3: Missing Human Oversight

**Current State**: High-value or sensitive operations execute without human review.

**Risks**:
- Large unauthorized transfers
- Transactions to suspicious destinations
- Pattern-based attacks (e.g., structuring)
- No circuit breaker for anomalous behavior

**Solution**: Tiered approval system with configurable thresholds. High-value transactions route to human approval queues. Anomaly detection triggers automatic holds.

#### Problem 4: No Audit Trail

**Current State**: Agent activities lack comprehensive logging or have mutable logs that cannot prove integrity.

**Risks**:
- Inability to investigate incidents
- Non-compliance with regulatory requirements
- No forensic capability post-breach
- Disputed transactions without evidence

**Solution**: Tamper-evident logging with cryptographic hash chains. Every operation is logged with sufficient detail for forensic analysis while protecting sensitive data.

### 1.4 Core Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-01 | Create and manage XRPL wallets with encrypted key storage | Must Have |
| FR-02 | Sign transactions with policy validation | Must Have |
| FR-03 | Configure transaction limits and allowlists | Must Have |
| FR-04 | Support tiered approval workflows | Must Have |
| FR-05 | Generate tamper-evident audit logs | Must Have |
| FR-06 | Integrate with XRPL network (mainnet, testnet, devnet) | Must Have |
| FR-07 | Support XRPL Regular Keys for key rotation | Should Have |
| FR-08 | Support XRPL Multi-Sign for multi-party approval | Should Have |
| FR-09 | Export audit reports for compliance | Should Have |
| FR-10 | Integrate with xrpl-escrow-mcp | Could Have |

---

## 2. Quality Goals

The following quality goals are prioritized to guide architectural decisions. When conflicts arise, higher-priority goals take precedence.

| Priority | Quality Goal | Description | Architectural Approach |
|----------|--------------|-------------|------------------------|
| 1 | **Security** | Private keys are never exposed; defense in depth protects all operations | Encrypted keystore, input validation, policy enforcement, secure memory handling, fail-secure defaults |
| 2 | **Reliability** | 99.9% availability for signing operations; no transaction loss | Idempotent operations, transaction persistence, graceful degradation, comprehensive error handling |
| 3 | **Agent Autonomy** | Maximize autonomous operation within policy bounds | Configurable policies, automatic approval for low-risk transactions, minimal friction for compliant operations |
| 4 | **Auditability** | Tamper-evident logging of all operations; forensic capability | Hash-chained logs, comprehensive event capture, immutable storage, compliance reporting |
| 5 | **Usability** | Simple MCP interface; easy configuration; clear error messages | Standard MCP protocol, declarative policy configuration, actionable error responses |

### 2.1 Quality Scenarios

#### QS-1: Security - Key Protection Under Attack

**Scenario**: An attacker gains access to the host system and attempts to extract private keys.

**Expected Behavior**:
- Keys remain encrypted at rest (AES-256-GCM)
- Key derivation requires master password (Argon2id with high memory cost)
- File permissions prevent unauthorized read access
- Memory is zeroed after cryptographic operations
- Audit log records suspicious access attempts

**Metric**: Zero key extraction possible without master password

#### QS-2: Security - Prompt Injection Attack

**Scenario**: A malicious prompt injection attempts to trigger an unauthorized transaction.

**Expected Behavior**:
- Input validation rejects malformed requests
- Policy engine blocks transactions outside permitted parameters
- Transaction requires appropriate approval tier
- Attempt is logged with full context
- System remains operational for legitimate requests

**Metric**: 100% of out-of-policy transactions blocked

#### QS-3: Reliability - System Recovery

**Scenario**: The MCP server crashes during transaction signing.

**Expected Behavior**:
- Pending transaction state is recoverable
- No duplicate transactions on restart
- Wallet state remains consistent
- Operations resume within 30 seconds

**Metric**: Zero transaction loss or duplication

#### QS-4: Auditability - Incident Investigation

**Scenario**: A compliance officer needs to investigate a transaction from 90 days ago.

**Expected Behavior**:
- Complete transaction history available
- Hash chain integrity verifiable
- All context (policy evaluation, approval, signing) reconstructable
- Export in standard format for analysis

**Metric**: 100% of operations traceable with integrity proof

#### QS-5: Usability - Agent Integration

**Scenario**: A developer integrates the wallet MCP with an existing AI agent.

**Expected Behavior**:
- Standard MCP protocol requires no custom code
- Configuration via declarative YAML/JSON
- Clear documentation with examples
- Meaningful error messages guide troubleshooting

**Metric**: Integration achievable in under 4 hours

---

## 3. Stakeholders

### 3.1 Stakeholder Overview

| Role | Representative | Expectations |
|------|----------------|--------------|
| AI Agent Developers | Development teams building XRPL agents | Simple API, clear documentation, reliable operations |
| Security Officers | Security team leads | Robust key protection, compliance, audit capability |
| Operations Teams | DevOps/SRE engineers | Easy deployment, monitoring, maintenance |
| Compliance Officers | Legal/compliance leads | Audit trails, regulatory alignment, reporting |
| Open Source Contributors | Community developers | Clean codebase, contribution guidelines, extensibility |

### 3.2 Detailed Stakeholder Analysis

#### AI Agent Developers

**Role Description**: Software engineers and teams building AI agents that need to interact with XRPL for payments, escrows, NFTs, or other on-ledger operations.

**Expectations**:
- Clean, well-documented MCP interface
- Predictable behavior with clear error handling
- Fast transaction signing (< 100ms for routine operations)
- Support for all common XRPL transaction types
- Easy local development and testing

**How Architecture Addresses Needs**:
- Standard MCP protocol with comprehensive tool definitions
- Detailed API documentation with code examples
- Input validation with actionable error messages
- Testnet/devnet support for development
- Docker-based local deployment option

**Interaction Pattern**: Primary consumers of MCP tools; integrate wallet into agent workflows

---

#### Security Officers

**Role Description**: Security professionals responsible for reviewing and approving the wallet infrastructure, ensuring it meets organizational security requirements.

**Expectations**:
- Defense-in-depth security architecture
- No exposure of private key material
- Configurable security policies
- Incident response capability
- Regular security audits and updates

**How Architecture Addresses Needs**:
- Multi-layer security (encryption, validation, authorization, audit)
- Keys encrypted at rest with Argon2id-derived keys
- Policy engine with fine-grained controls
- Comprehensive audit logging with tamper detection
- Security-focused development practices (SAST, dependency scanning)

**Interaction Pattern**: Review architecture and policies; approve deployment; audit operations

---

#### Operations Teams

**Role Description**: DevOps and SRE engineers responsible for deploying, monitoring, and maintaining the MCP server in production environments.

**Expectations**:
- Simple deployment process
- Health checks and monitoring endpoints
- Log aggregation compatibility
- Graceful shutdown and restart
- Configuration management

**How Architecture Addresses Needs**:
- Container-based deployment (Docker, Cloud Run)
- Health check endpoints for orchestration
- Structured logging (JSON format) for aggregation
- Signal handling for graceful shutdown
- Environment-based configuration with validation

**Interaction Pattern**: Deploy and maintain infrastructure; respond to alerts; perform upgrades

---

#### Compliance Officers

**Role Description**: Legal and compliance professionals responsible for ensuring operations meet regulatory requirements and can withstand audits.

**Expectations**:
- Tamper-proof audit trails
- Regulatory compliance (SOC 2, MiCA considerations)
- Report generation capability
- Data retention compliance
- Evidence for investigations

**How Architecture Addresses Needs**:
- Hash-chained audit logs with integrity verification
- Comprehensive event capture (who, what, when, why)
- Export tools for compliance reporting
- Configurable retention policies
- Forensic-ready log format

**Interaction Pattern**: Review audit logs; generate compliance reports; investigate incidents

---

#### Open Source Contributors

**Role Description**: Community developers who want to extend, improve, or adapt the wallet MCP for their use cases.

**Expectations**:
- Clean, readable codebase
- Comprehensive documentation
- Contribution guidelines
- Responsive maintainers
- Extension points for customization

**How Architecture Addresses Needs**:
- Modular architecture with clear boundaries
- Arc42 documentation for architectural understanding
- CONTRIBUTING.md with clear process
- Plugin architecture for custom policy providers
- MIT/Apache licensing for broad use

**Interaction Pattern**: Review code; submit issues and PRs; extend functionality

---

### 3.3 Stakeholder Communication

| Stakeholder | Documentation | Communication Channel |
|-------------|---------------|----------------------|
| AI Agent Developers | API Reference, Tutorials, Examples | GitHub Issues, Discussions |
| Security Officers | Security Architecture, Threat Model | Security advisories, private disclosure |
| Operations Teams | Deployment Guide, Runbook | GitHub Issues, monitoring alerts |
| Compliance Officers | Compliance Mapping, Audit Guide | Compliance reports, documentation |
| Open Source Contributors | Contributing Guide, Architecture Docs | GitHub Discussions, PRs |

---

## 4. Project Scope

### 4.1 In Scope

The XRPL Agent Wallet MCP specification covers:

#### Core Wallet Operations
- Wallet creation with secure key generation
- Key import from seed/mnemonic (with secure handling)
- Transaction signing for all XRPL transaction types
- Balance and account information queries
- Transaction history retrieval

#### Policy Engine
- Transaction amount limits (per-transaction, daily, velocity)
- Destination address allowlists and blocklists
- Time-based restrictions (business hours, rate limits)
- Tiered approval routing based on risk profile
- Custom policy rules via configuration

#### Security Infrastructure
- AES-256-GCM encrypted keystore
- Argon2id key derivation from master password
- Secure memory handling for key material
- Input validation and sanitization
- Rate limiting and abuse prevention

#### Audit System
- Tamper-evident logging with hash chains
- Comprehensive event capture
- Integrity verification
- Export for compliance reporting

#### XRPL Integration
- Network connectivity (mainnet, testnet, devnet)
- Regular Key support for key rotation
- Multi-Sign support for multi-party approval
- Integration with xrpl-escrow-mcp

#### MCP Interface
- Standard MCP protocol implementation
- Tool definitions for all wallet operations
- Resource exposure for wallet state
- Error handling and reporting

### 4.2 Out of Scope

The following are explicitly excluded from this specification:

#### Full Implementation
This document is a **specification only**. While it provides implementation guidance and code examples, the actual implementation is a separate effort that will follow this specification.

#### Cloud KMS Integration (Phase 2)
Direct integration with cloud key management services (AWS KMS, Google Cloud KMS, Azure Key Vault) is planned for Phase 2. The initial specification focuses on local encrypted keystore.

**Rationale**: Local keystore provides a foundation that works in all environments. Cloud KMS integration requires additional infrastructure and may not be needed for all deployments.

#### TEE Deployment (Phase 3)
Trusted Execution Environment (TEE) deployment using AWS Nitro Enclaves or similar is planned for Phase 3.

**Rationale**: TEE provides the highest security guarantees but requires specialized infrastructure. The architecture is designed to support TEE deployment as a future enhancement.

#### Mobile/Desktop UI
No graphical user interface is included. The wallet is accessed exclusively through the MCP protocol.

**Rationale**: The target users are AI agents and developers, not end users. A CLI tool may be provided for administrative operations.

#### Fiat On/Off Ramp
No integration with fiat currency systems (banking, payment processors).

**Rationale**: Out of scope for an XRPL wallet. May be addressed by separate MCP servers.

#### Token Issuance
Creating or managing XRPL tokens (IOUs) is not in scope for the initial specification.

**Rationale**: Token issuance has different security requirements. May be addressed in future versions.

#### DeFi Protocol Integration
Direct integration with specific DeFi protocols (AMMs, lending) is not included.

**Rationale**: DeFi integration is protocol-specific and can be built on top of the base wallet functionality.

### 4.3 Future Considerations

The architecture is designed to accommodate future extensions:

| Future Capability | Design Consideration |
|-------------------|----------------------|
| Cloud KMS | Abstracted key storage interface allows pluggable backends |
| TEE Deployment | Signing logic isolated for extraction to enclave |
| Multi-chain | Core architecture not XRPL-specific; can support additional chains |
| Advanced Policies | Policy engine supports custom rule providers |
| DAO Governance | Multi-sign foundation supports governance workflows |

---

## 5. Document Conventions

### 5.1 Arc42 Structure

This documentation follows the [Arc42](https://arc42.org/) architecture documentation template, which provides a structured approach to describing software architecture.

| Section | Content |
|---------|---------|
| 01 - Introduction | Goals, stakeholders, scope (this document) |
| 02 - Constraints | Technical and organizational constraints |
| 03 - Context | System context and external interfaces |
| 04 - Solution Strategy | Key architectural decisions |
| 05 - Building Blocks | Component decomposition |
| 06 - Runtime View | Key scenarios and interactions |
| 07 - Deployment View | Infrastructure and deployment |
| 08 - Crosscutting | Security, logging, error handling concepts |
| 09 - Decisions | Architecture Decision Records (ADRs) |

### 5.2 Version Numbering

Documentation versions follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Incompatible architectural changes
- **MINOR**: Backwards-compatible additions
- **PATCH**: Backwards-compatible fixes and clarifications

**Current Version**: 1.0.0 (Initial specification)

### 5.3 Document Status

Each document includes a status indicator:

| Status | Meaning |
|--------|---------|
| Draft | Under active development; subject to change |
| Review | Ready for stakeholder review |
| Approved | Reviewed and approved; changes require ADR |
| Deprecated | Superseded by newer version |

### 5.4 Requirement Notation

Requirements use RFC 2119 keywords:

- **MUST** / **REQUIRED**: Absolute requirement
- **MUST NOT** / **SHALL NOT**: Absolute prohibition
- **SHOULD** / **RECOMMENDED**: Strong recommendation with valid exceptions
- **SHOULD NOT** / **NOT RECOMMENDED**: Strong discouragement with valid exceptions
- **MAY** / **OPTIONAL**: Truly optional

### 5.5 Change Management

#### Minor Changes
- Clarifications, typo fixes, formatting
- Do not require ADR
- Documented in commit history

#### Significant Changes
- Architectural modifications
- Requirement changes
- Interface changes
- **Require ADR** in `/docs/architecture/09-decisions/`

#### ADR Format
Architecture Decision Records follow the format:
- **Title**: Short descriptive name
- **Status**: Proposed, Accepted, Deprecated, Superseded
- **Context**: What is the issue?
- **Decision**: What is the change?
- **Consequences**: What are the impacts?

### 5.6 Diagram Conventions

Diagrams in this documentation use:

- **C4 Model**: Context, Container, Component, Code diagrams
- **Sequence Diagrams**: UML sequence notation
- **Mermaid**: Text-based diagram rendering where possible

### 5.7 Code Examples

Code examples are illustrative and may not represent final implementation:

- TypeScript/JavaScript for MCP server code
- Python for client examples
- YAML for configuration examples

---

## References

### Internal Documents
- [Security Architecture](/docs/security/SECURITY-ARCHITECTURE.md)
- [Research Report](/docs/research/ai-agent-wallet-security-2025-2026.md)
- [Threat Model](/docs/security/threat-model.md)

### External Standards
- [Arc42 Template](https://arc42.org/)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
- [XRPL Documentation](https://xrpl.org/docs.html)
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/)

---

**Document Metadata**
- **Author**: Tech Lead Agent
- **Reviewers**: Pending
- **Approval**: Pending
- **Next Review**: 2026-04-28
