# Arc42 Section 2: Architecture Constraints

**Project:** XRPL Agent Wallet MCP Server
**Version:** 1.0.0
**Date:** 2026-01-28
**Author:** Tech Lead
**Status:** Draft

---

## Table of Contents

1. [Overview](#1-overview)
2. [Technical Constraints](#2-technical-constraints)
3. [Organizational Constraints](#3-organizational-constraints)
4. [Regulatory and Compliance Constraints](#4-regulatory-and-compliance-constraints)
5. [Development Conventions](#5-development-conventions)
6. [Security Constraints](#6-security-constraints)
7. [XRPL Protocol Constraints](#7-xrpl-protocol-constraints)
8. [Constraint Impact Analysis](#8-constraint-impact-analysis)
9. [References](#9-references)

---

## 1. Overview

This document catalogs all constraints affecting the architecture of the XRPL Agent Wallet MCP Server. Constraints are fixed conditions that limit architectural freedom and must be accommodated in the system design. They differ from requirements in that they are typically non-negotiable boundaries imposed by technology choices, organizational policies, regulatory bodies, or external protocols.

### 1.1 Constraint Categories

| Category | Description | Count |
|----------|-------------|-------|
| **Technical (TC)** | Technology platform and implementation restrictions | 8 |
| **Organizational (OC)** | Project structure and resource limitations | 4 |
| **Regulatory (RC)** | Compliance and legal requirements | 4 |
| **Conventions (CV)** | Development standards and practices | 4 |
| **Security (SC)** | Cryptographic and security implementation requirements | 8 |
| **XRPL Protocol (XC)** | XRP Ledger protocol limitations | 5 |

---

## 2. Technical Constraints

Technical constraints define the technology choices and implementation boundaries for the system.

| ID | Constraint | Rationale | Impact |
|----|------------|-----------|--------|
| **TC-01** | TypeScript/Node.js 20+ runtime | MCP SDK is TypeScript-native; Node.js 20+ provides LTS stability, security updates until April 2026, and required cryptographic APIs (crypto.subtle, randomUUID) | All source code must be TypeScript; deployment requires Node.js 20+ runtime |
| **TC-02** | MCP Protocol 1.x compatibility | Standard interface for AI agent tool communication; ensures interoperability with Claude, GPT, and other LLM systems | All wallet operations exposed as MCP tools; must implement MCP server specification |
| **TC-03** | XRPL WebSocket API (rippled) | Primary communication channel with XRP Ledger; required for transaction submission, account queries, and ledger subscriptions | Must handle WebSocket connection lifecycle; reconnection logic required |
| **TC-04** | AES-256-GCM encryption | NIST-approved authenticated encryption; industry standard for data-at-rest protection; provides confidentiality and integrity | Key material storage, keystore encryption |
| **TC-05** | Argon2id key derivation | GPU-resistant memory-hard KDF; PHC (Password Hashing Competition) winner 2015; superior to PBKDF2/bcrypt | Password-based key derivation; minimum 500ms derivation time |
| **TC-06** | 96-bit (12-byte) IV for GCM | NIST SP 800-38D recommendation for deterministic IV construction; optimal performance and security balance | IV generation for all encryption operations |
| **TC-07** | Zod schema validation | Type-safe runtime validation with excellent TypeScript inference; better developer experience than alternatives (Joi, Yup) | All MCP tool inputs validated against Zod schemas |
| **TC-08** | JSON policy format | Human-readable, version-controllable, widely supported; enables policy-as-code workflows | Transaction policies, rate limits, allowlists stored as JSON |

### 2.1 Technology Stack Rationale

```
┌─────────────────────────────────────────────────────────────────────┐
│                         MCP Client (AI Agent)                        │
└────────────────────────────────┬────────────────────────────────────┘
                                 │ MCP Protocol (JSON-RPC)
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    MCP Server (TypeScript/Node.js)                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │
│  │   Zod       │  │   Policy    │  │   Crypto    │  │   xrpl.js  │  │
│  │ Validation  │  │   Engine    │  │  (Argon2id) │  │   Client   │  │
│  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘  │
└────────────────────────────────┬────────────────────────────────────┘
                                 │ WebSocket (TLS 1.3)
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         XRP Ledger (rippled)                         │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Node.js Version Requirements

| Feature | Minimum Version | Used For |
|---------|-----------------|----------|
| `crypto.randomUUID()` | 14.17.0 | Correlation IDs |
| `crypto.subtle` | 15.0.0 | WebCrypto API |
| `--experimental-permission` | 20.0.0 | Process sandboxing |
| `fs.promises` with signals | 20.0.0 | Cancellable file operations |
| LTS Security Support | 20.x | Security patches until 2026-04 |

---

## 3. Organizational Constraints

Organizational constraints reflect the project's operational context and resource limitations.

| ID | Constraint | Rationale | Impact |
|----|------------|-----------|--------|
| **OC-01** | Open source (MIT license) | Maximize community adoption; enable commercial use; standard for MCP ecosystem tools | All source code publicly available; no proprietary dependencies |
| **OC-02** | Single developer initially | Resource constraint; bootstrap phase before community growth | Prioritize automation, testing, documentation over manual processes |
| **OC-03** | Documentation-first approach | Specification before implementation; enables review before code; reduces rework | Arc42 architecture docs, ADRs, threat model complete before implementation |
| **OC-04** | npm package distribution | Standard Node.js distribution channel; easy installation via `npx` | Package must be publishable to npm registry; semver versioning required |

### 3.1 Project Timeline Constraints

Given OC-02 (single developer), the project must:

1. **Automate extensively** - CI/CD, testing, documentation generation
2. **Prioritize security** - Cannot rely on security-in-depth from multiple reviewers
3. **Build incrementally** - Phase-based delivery (see Security Requirements Phase 1-3)
4. **Document thoroughly** - Enable future contributors to onboard quickly

### 3.2 Distribution Model

```
┌─────────────────────────────────────────────────────────────────┐
│                        npm Registry                              │
│                                                                  │
│   @xrpl-wallet-mcp/server                                        │
│   ├── bin/xrpl-wallet-mcp (CLI entry point)                      │
│   ├── dist/ (compiled TypeScript)                                │
│   └── package.json (dependencies, scripts)                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Installation Methods                         │
│                                                                  │
│   npx @xrpl-wallet-mcp/server              (direct execution)    │
│   npm install -g @xrpl-wallet-mcp/server   (global install)      │
│   npm install @xrpl-wallet-mcp/server      (local dependency)    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Regulatory and Compliance Constraints

Regulatory constraints address legal and compliance requirements for financial software handling digital assets.

| ID | Constraint | Rationale | Impact |
|----|------------|-----------|--------|
| **RC-01** | SOC 2 Type II alignment | Enterprise adoption requirement; demonstrates security controls for institutional users | Audit logging, access controls, encryption standards must meet SOC 2 criteria |
| **RC-02** | MiCA (Markets in Crypto-Assets) awareness | EU regulatory framework effective 2025; may affect European users/deployments | Monitor regulatory developments; design for compliance adaptability |
| **RC-03** | OWASP LLM Top 10 2025 compliance | Standard for AI application security; addresses prompt injection, training data poisoning | Implement defenses for all OWASP LLM risks applicable to agent wallets |
| **RC-04** | 7-year log retention capability | Financial services compliance requirement; enables audit trail reconstruction | Audit logs must support long-term storage and integrity verification |

### 4.1 SOC 2 Trust Services Criteria Mapping

| TSC Category | Relevant Requirements | System Implementation |
|--------------|----------------------|----------------------|
| **Security** | CC6.1-CC6.8 | Encryption (ENC-*), Authentication (AUTH-*) |
| **Availability** | CC7.1-CC7.5 | Rate limiting (RATE-*), Error handling (ERR-*) |
| **Processing Integrity** | CC8.1 | Input validation (VAL-*), Audit logging (AUDIT-*) |
| **Confidentiality** | CC9.1-CC9.2 | Key management (KEY-*), Encryption (ENC-*) |

### 4.2 OWASP LLM Top 10 2025 Relevance

| Risk | Applicability | Mitigation |
|------|---------------|------------|
| **LLM01: Prompt Injection** | Critical - Primary attack vector | VAL-004, VAL-006, AUTHZ-006 |
| **LLM02: Insecure Output Handling** | High - Transaction parameters | Input validation, policy enforcement |
| **LLM03: Training Data Poisoning** | Low - No model training | N/A |
| **LLM04: Model DoS** | Medium - KDF computation | RATE-006, AUTH-002 |
| **LLM05: Supply Chain** | Medium - npm dependencies | SBOM, dependency scanning |
| **LLM06: Sensitive Info Disclosure** | Critical - Key material | KEY-*, AUDIT-003 |
| **LLM07: Insecure Plugin Design** | Critical - MCP tools | AUTHZ-001, AUTHZ-005 |
| **LLM08: Excessive Agency** | Critical - Transaction signing | AUTHZ-002, tiered approval |
| **LLM09: Overreliance** | Low - User responsibility | Documentation, warnings |
| **LLM10: Model Theft** | N/A - No proprietary models | N/A |

---

## 5. Development Conventions

Development conventions ensure code quality, maintainability, and collaboration.

| ID | Convention | Details | Enforcement |
|----|------------|---------|-------------|
| **CV-01** | Semantic versioning | MAJOR.MINOR.PATCH per semver.org; breaking changes increment MAJOR | npm version scripts, CI/CD validation |
| **CV-02** | Conventional commits | Format: `type(scope): description`; types: feat, fix, docs, style, refactor, perf, test, chore | commitlint, husky pre-commit hook |
| **CV-03** | ESLint + Prettier | TypeScript ESLint with strict rules; Prettier for formatting | Pre-commit hooks, CI checks |
| **CV-04** | Vitest testing framework | Fast native TypeScript testing; compatible with Jest API; built-in coverage | Minimum 80% coverage, CI enforcement |

### 5.1 Commit Message Convention

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation only
- `style` - Formatting (no code change)
- `refactor` - Code change (no feature/fix)
- `perf` - Performance improvement
- `test` - Adding/fixing tests
- `chore` - Build process, tooling

**Scopes:**
- `core` - Core wallet functionality
- `mcp` - MCP protocol handling
- `crypto` - Cryptographic operations
- `policy` - Policy engine
- `audit` - Audit logging
- `cli` - Command-line interface

### 5.2 Code Quality Standards

```typescript
// ESLint configuration (eslint.config.js)
export default [
  {
    rules: {
      // Security-critical rules
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/strict-boolean-expressions': 'error',

      // Code quality
      '@typescript-eslint/no-unused-vars': 'error',
      '@typescript-eslint/explicit-function-return-type': 'warn',
      'prefer-const': 'error',
    }
  }
];
```

### 5.3 Testing Requirements

| Test Type | Coverage Target | Purpose |
|-----------|-----------------|---------|
| Unit tests | 80% line coverage | Individual function verification |
| Integration tests | Critical paths | Component interaction verification |
| Security tests | All security requirements | Security control verification |
| Fuzz tests | Input validation | Malformed input handling |

---

## 6. Security Constraints

Security constraints are derived from the Security Requirements Specification (v1.0.0). These are non-negotiable implementation requirements.

| ID | Constraint | Requirement Reference | Details |
|----|------------|----------------------|---------|
| **SC-01** | Minimum 64MB Argon2id memory cost | AUTH-001 | Prevents GPU-accelerated brute force; minimum 500ms derivation time |
| **SC-02** | Unique IV per encryption operation | ENC-002 | IV reuse breaks AES-GCM security completely |
| **SC-03** | Keys zeroed from memory after use | KEY-002, KEY-004 | Prevents key extraction via memory dumps; <100ms key lifetime |
| **SC-04** | 5 failed auth attempts triggers lockout | AUTH-002 | 30-minute initial lockout; progressive doubling to 24h max |
| **SC-05** | Rate limits on all sensitive operations | RATE-001 | CRITICAL tier: 5 requests/5 minutes; no burst allowed |
| **SC-06** | Tamper-evident audit log hash chain | AUDIT-001 | HMAC-SHA256 chain; deletion/modification detectable |
| **SC-07** | No secrets in logs | AUDIT-003 | Private keys, seed phrases, passwords never logged |
| **SC-08** | Fail-secure on all errors | ERR-001 | Authorization errors default to deny; no fail-open paths |

### 6.1 Cryptographic Parameter Constraints

```typescript
// Immutable cryptographic parameters
const CRYPTO_PARAMS = {
  // AES-256-GCM (TC-04)
  encryption: {
    algorithm: 'aes-256-gcm',
    keyLength: 32,        // 256 bits
    ivLength: 12,         // 96 bits (TC-06)
    authTagLength: 16,    // 128 bits
  },

  // Argon2id (TC-05, SC-01)
  kdf: {
    algorithm: 'argon2id',
    memoryCost: 65536,    // 64 MB minimum
    timeCost: 3,          // 3 iterations minimum
    parallelism: 4,       // 4 threads
    hashLength: 32,       // 256-bit output
    saltLength: 32,       // 256-bit salt
  },

  // Session tokens (AUTH-003)
  session: {
    tokenLength: 32,      // 256 bits
    idleTimeout: 1800,    // 30 minutes
    absoluteTimeout: 28800, // 8 hours
  },
} as const;
```

### 6.2 Security Constraint Dependencies

```
SC-01 (Argon2id memory) ───► Prevents T-010 (Brute force)
         │
         ▼
SC-04 (Lockout) ───────────► Prevents T-014 (KDF DoS)
         │
         ▼
SC-05 (Rate limits) ───────► Prevents T-013 (Rate limit DoS)


SC-02 (Unique IV) ─────────► Prevents keystream reuse
         │
         ▼
SC-03 (Key zeroing) ───────► Prevents T-002 (Memory exposure)
         │
         ▼
SC-07 (No log secrets) ────► Prevents T-011 (Log leakage)


SC-06 (Audit chain) ───────► Prevents T-012 (Log tampering)
         │
         ▼
SC-08 (Fail-secure) ───────► Prevents all authorization bypass
```

---

## 7. XRPL Protocol Constraints

XRPL protocol constraints are imposed by the XRP Ledger consensus rules and cannot be changed by this system.

| ID | Constraint | Details | Impact |
|----|------------|---------|--------|
| **XC-01** | 1 XRP base reserve | Minimum balance to activate an account on XRPL mainnet (updated Dec 2024) | New wallets require 1 XRP funding before use |
| **XC-02** | 0.2 XRP owner reserve per object | Additional reserve for owned objects (trustlines, offers, signer lists, escrows) | Multi-sig setup increases reserve by 0.2 XRP |
| **XC-03** | Monotonic sequence numbers | Each account has a sequence number that must increment by 1 for each transaction | Must track sequence numbers; cannot reuse or skip |
| **XC-04** | 10 drops minimum transaction fee | Base transaction cost (1 XRP = 1,000,000 drops) | Fee must be >= 10 drops; open ledger cost may be higher |
| **XC-05** | Maximum 32 signers in signer list | Multi-signature quorum limited to 32 participants | Enterprise multi-sig designs limited by this |

### 7.1 XRPL Reserve Calculation

```
Account Reserve = Base Reserve + (Owner Count × Owner Reserve)

Where (as of December 2024):
- Base Reserve = 1 XRP (XC-01)
- Owner Reserve = 0.2 XRP (XC-02)
- Owner Count = number of owned ledger objects

Example:
- Basic account: 1 XRP
- Account with 1 escrow: 1 + (1 × 0.2) = 1.2 XRP
- Account with 5 escrows: 1 + (5 × 0.2) = 2 XRP
- Account with signer list: 1 + (1 × 0.2) = 1.2 XRP
- Account with escrow + signer list: 1 + (2 × 0.2) = 1.4 XRP
```

### 7.2 Sequence Number Management

```
┌─────────────────────────────────────────────────────────────────┐
│                    Sequence Number Lifecycle                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Account Created (Seq: 1)                                        │
│          │                                                       │
│          ▼                                                       │
│  ┌───────────────┐                                               │
│  │   Seq: 1      │──► Transaction 1 submitted (uses Seq 1)       │
│  │   (available) │                                               │
│  └───────────────┘                                               │
│          │                                                       │
│          ▼ (after validation)                                    │
│  ┌───────────────┐                                               │
│  │   Seq: 2      │──► Transaction 2 submitted (uses Seq 2)       │
│  │   (available) │                                               │
│  └───────────────┘                                               │
│          │                                                       │
│          ▼                                                       │
│         ...                                                      │
│                                                                  │
│  CONSTRAINT: Sequences MUST be used in order                     │
│  CONSTRAINT: Cannot skip sequences                               │
│  CONSTRAINT: Cannot reuse sequences                              │
└─────────────────────────────────────────────────────────────────┘
```

### 7.3 Transaction Fee Dynamics

| Fee Type | Value | When Used |
|----------|-------|-----------|
| Minimum fee | 10 drops | Absolute floor |
| Base fee | 10-12 drops | Normal network load |
| Open ledger fee | Variable | High network load |
| Queue fee | Calculated | Transaction queuing |

**Fee Escalation Protection (AUTHZ-002 + VAL-003):**
- Maximum fee policy enforced
- Tier-based approval for high fees
- Automatic fee rejection above configured threshold

---

## 8. Constraint Impact Analysis

### 8.1 Architectural Decisions Forced by Constraints

| Constraint | Architectural Impact |
|------------|---------------------|
| TC-01 (Node.js) | Single runtime; no polyglot architecture |
| TC-02 (MCP Protocol) | Tool-based API design; JSON-RPC interface |
| TC-04 (AES-256-GCM) | Authenticated encryption; no separate MAC |
| SC-01 (Argon2id 64MB) | High memory per auth; limits concurrent auths |
| SC-08 (Fail-secure) | Defensive coding; explicit allow patterns |
| XC-03 (Sequence numbers) | Stateful transaction tracking required |

### 8.2 Trade-offs Accepted

| Constraint | Trade-off | Mitigation |
|------------|-----------|------------|
| SC-01 (64MB memory) | Limits concurrent authentications | Rate limiting; async processing |
| TC-08 (JSON policies) | Larger file size vs binary | Compression optional; readability prioritized |
| XC-01 (1 XRP reserve) | Low barrier for testing | Testnet/devnet faucets provide ~100 XRP |
| RC-04 (7-year retention) | Storage costs | Log rotation; archival storage |

### 8.3 Constraint Validation Matrix

| Constraint | Validation Method | Frequency |
|------------|-------------------|-----------|
| TC-01 | engines field in package.json | Build time |
| TC-04 | Cryptographic audit | Release |
| TC-05 | Parameter verification unit tests | CI/CD |
| SC-01 | Integration test timing | CI/CD |
| SC-02 | IV uniqueness statistical test | CI/CD |
| SC-03 | Memory forensics | Security audit |
| SC-06 | Hash chain verification | Runtime + audit |
| XC-01-05 | XRPL testnet validation | Integration tests |

---

## 9. References

### 9.1 Related Documents

| Document | Path | Description |
|----------|------|-------------|
| Security Requirements | `docs/security/security-requirements.md` | Detailed security requirements with acceptance criteria |
| Threat Model | `docs/security/threat-model.md` | Threat identification and risk assessment |
| ADR Template | `docs/architecture/09-decisions/ADR-000-template.md` | Architecture Decision Record template |

### 9.2 External Standards

| Standard | Version | URL |
|----------|---------|-----|
| NIST SP 800-38D | Current | https://csrc.nist.gov/publications/detail/sp/800-38d/final |
| Argon2 RFC | RFC 9106 | https://www.rfc-editor.org/rfc/rfc9106 |
| OWASP LLM Top 10 | 2025 | https://genai.owasp.org/llmrisk/ |
| MCP Specification | 1.x | https://modelcontextprotocol.io/specification |
| XRPL Documentation | Current | https://xrpl.org/docs.html |
| SOC 2 TSC | 2017 | https://www.aicpa.org/soc2 |

### 9.3 Technology Documentation

| Technology | Documentation |
|------------|---------------|
| Node.js 20 | https://nodejs.org/docs/latest-v20.x/api/ |
| TypeScript | https://www.typescriptlang.org/docs/ |
| Zod | https://zod.dev/ |
| xrpl.js | https://js.xrpl.org/ |
| Vitest | https://vitest.dev/ |

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Tech Lead | Initial constraints specification |

**Next Review Date:** 2026-04-28 (or upon significant technology/regulatory changes)

**Cross-References:**
- Arc42 Section 1: Introduction and Goals
- Arc42 Section 3: Context and Scope
- Arc42 Section 4: Solution Strategy (derives from these constraints)

---

*This document is part of the Arc42 architecture documentation. Constraints documented here are non-negotiable boundaries that must be respected by all architectural decisions.*
