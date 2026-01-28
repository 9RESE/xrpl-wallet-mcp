# 04 - Solution Strategy

**Arc42 Section**: Solution Strategy
**Version**: 1.0.0
**Date**: 2026-01-28
**Status**: Draft

---

## Table of Contents

1. [Solution Approach](#1-solution-approach)
2. [Key Architectural Decisions](#2-key-architectural-decisions)
3. [Quality Goals Achievement](#3-quality-goals-achievement)
4. [Tiered Security Model](#4-tiered-security-model)
5. [Technology Selection](#5-technology-selection)
6. [Implementation Phases](#6-implementation-phases)

---

## 1. Solution Approach

The XRPL Agent Wallet MCP server is built on four foundational pillars that define our approach to secure, autonomous AI agent operations on the XRP Ledger.

### 1.1 Security-First Design

**Security is the #1 priority** - above features, performance, and developer experience. Every architectural decision is evaluated first through a security lens.

#### Core Principles

| Principle | Implementation |
|-----------|----------------|
| **Defense in Depth** | 8 distinct security layers, each providing independent protection |
| **Default-Deny** | All operations rejected unless explicitly permitted by policy |
| **Fail-Secure** | Errors result in denied access, never in bypassed controls |
| **Least Privilege** | Components receive minimum permissions required |
| **Zero Trust** | Every request validated regardless of source |

#### Eight Security Layers

```
Layer 1: Transport Security
         TLS 1.3, certificate validation

Layer 2: Input Validation
         Zod schema validation, sanitization, length limits

Layer 3: Rate Limiting
         Token bucket algorithm, tier-based limits

Layer 4: Authentication
         Wallet unlock verification, session management

Layer 5: Policy Engine
         Declarative JSON policies, immutable evaluation

Layer 6: Authorization
         Tool-level permissions, sensitivity classification

Layer 7: Cryptographic Operations
         AES-256-GCM encryption, Argon2id key derivation

Layer 8: Audit Trail
         HMAC hash-chained logs, tamper detection
```

#### Error Handling Philosophy

```typescript
// Fail-secure: On ANY error, deny access
try {
  return await evaluatePolicy(transaction);
} catch (error) {
  await auditLog.record('policy_evaluation_error', { error });
  return { allowed: false, reason: 'Policy evaluation failed' };
}
```

### 1.2 Policy-Controlled Autonomy

AI agents operate autonomously **within defined policy boundaries**. The policy engine is the central control point for all signing operations.

#### Key Characteristics

| Aspect | Description |
|--------|-------------|
| **Declarative Policies** | JSON-based rules, human-readable and auditable |
| **Immutable Evaluation** | LLM cannot modify policy engine or rules at runtime |
| **Tiered Approval** | Risk-proportionate escalation to human oversight |
| **Transparent Decisions** | Every policy decision logged with full reasoning |

#### Policy Engine Isolation

```
+------------------+     +------------------+
|   LLM Agent      |     |  Policy Engine   |
|                  |     |                  |
| - Can request    | --> | - Evaluates      |
|   transactions   |     |   independently  |
| - Cannot modify  |     | - Immutable      |
|   policies       |     |   rules          |
+------------------+     +------------------+
                               |
                               v
                    +------------------+
                    |  Signing Layer   |
                    +------------------+
```

#### Human-in-the-Loop Integration

The system supports configurable human oversight:

- **Tier 1 (Autonomous)**: Agent signs immediately, no human involvement
- **Tier 2 (Delayed)**: Agent signs after delay, human can veto
- **Tier 3 (Co-Sign)**: Agent requests, human must approve
- **Tier 4 (Prohibited)**: Automatic rejection, human cannot override

### 1.3 XRPL-Native Security

The architecture leverages XRPL's native security features rather than reimplementing them.

#### Regular Keys for Agent Operations

```
+------------------+     +------------------+
|   Master Key     |     |   Regular Key    |
|                  |     |                  |
| - Cold storage   |     | - Agent signing  |
| - Never online   |     | - Rotatable      |
| - Recovery only  |     | - Revocable      |
+------------------+     +------------------+
```

**Benefits**:
- Master key kept offline/cold - never exposed to agent operations
- Regular key can be rotated without moving funds
- Compromised regular key can be revoked instantly via SetRegularKey
- Account remains secure even if agent is compromised

#### Multi-Sign for Co-Sign Tier

For high-value transactions requiring human approval:

```
Transaction requires M-of-N signatures:
  - Agent provides 1 signature (Regular Key)
  - Human approves via separate key(s)
  - XRPL validates threshold before execution
```

**XRPL Multi-Sign Configuration**:
```json
{
  "SignerQuorum": 2,
  "SignerEntries": [
    { "SignerEntry": { "Account": "rAgent...", "SignerWeight": 1 }},
    { "SignerEntry": { "Account": "rHuman...", "SignerWeight": 1 }}
  ]
}
```

#### Network-Isolated Keystores

Each XRPL network (mainnet, testnet, devnet) maintains completely separate keystores:

| Network | Keystore Path | Purpose |
|---------|---------------|---------|
| mainnet | `~/.xrpl-wallet-mcp/mainnet/keystore.enc` | Production operations |
| testnet | `~/.xrpl-wallet-mcp/testnet/keystore.enc` | Testing and development |
| devnet | `~/.xrpl-wallet-mcp/devnet/keystore.enc` | Development only |

**Safety Guardrails**:
- Testnet keys cannot sign mainnet transactions
- Network mismatch results in immediate rejection
- Cross-network operations require explicit confirmation

### 1.4 Composable MCP Ecosystem

The wallet MCP is designed to integrate with other XRPL MCP servers through a clean, composable interface.

#### Ecosystem Integration

```
+------------------+     +------------------+
| xrpl-escrow-mcp  |     | xrpl-amm-mcp     |
|                  |     | (future)         |
| Creates unsigned | --> |                  |
| escrow TXs       |     | Creates unsigned |
+--------+---------+     | AMM TXs          |
         |               +--------+---------+
         |                        |
         v                        v
+----------------------------------------+
|        xrpl-wallet-mcp                 |
|                                        |
| - Receives unsigned transactions       |
| - Evaluates against policy             |
| - Signs if permitted                   |
| - Returns signed TX or rejection       |
+----------------------------------------+
```

#### Standard Transaction Flow

1. **Upstream MCP** creates unsigned transaction
2. **Wallet MCP** receives via `sign_transaction` tool
3. **Policy Engine** evaluates transaction against rules
4. **Signing Layer** produces signature (if permitted)
5. **Audit Log** records decision and outcome
6. **Response** returns signed TX blob or rejection reason

#### Future Extensibility

The architecture supports:
- Additional XRPL MCPs (AMM, NFT, DEX)
- Custom transaction type handlers
- Plugin-based policy extensions
- Third-party audit integrations

---

## 2. Key Architectural Decisions

The following Architecture Decision Records (ADRs) define the foundational choices for this system.

| ADR | Decision | Rationale |
|-----|----------|-----------|
| **ADR-001** | Local AES-256-GCM keystore | Simple, portable, no external dependencies. Encrypted file storage provides security without cloud vendor lock-in. Enterprise users can upgrade to Cloud KMS in Phase 2. |
| **ADR-002** | Argon2id key derivation | GPU-resistant, memory-hard, PHC competition winner. Provides superior protection against brute-force attacks compared to PBKDF2 or bcrypt. |
| **ADR-003** | OPA-inspired JSON policies | Declarative policies are human-readable, auditable, and testable. JSON format enables tooling integration and version control. No separate runtime required. |
| **ADR-004** | Regular Keys + Multi-Sign | Leverages XRPL's native security model. Master key cold storage eliminates single point of compromise. Multi-sign enables human oversight without blocking agent autonomy. |
| **ADR-005** | HMAC hash chain audit logs | Tamper-evident logging using cryptographic hash chains. Each entry includes hash of previous entry, enabling detection of any modification or deletion. |
| **ADR-006** | Zod schema validation | Type-safe, composable validation with excellent TypeScript inference. Provides runtime validation with compile-time type safety. Better DX than alternatives. |
| **ADR-007** | Token bucket rate limiting | Allows controlled bursting while enforcing average limits. More flexible than fixed windows, prevents both sustained abuse and burst attacks. |
| **ADR-008** | Composable MCP design | Wallet MCP focuses solely on signing. Other MCPs (escrow, AMM) handle transaction construction. Clean separation enables ecosystem growth. |
| **ADR-009** | All XRPL TX types supported | Not limited to escrow transactions. Supports Payment, TrustSet, OfferCreate, EscrowCreate, NFT operations, and all future XRPL transaction types. |
| **ADR-010** | Network-isolated keystores | Separate keystore per network prevents accidental mainnet operations with test keys. Physical isolation eliminates cross-network vulnerabilities. |

### Decision Relationships

```
ADR-001 (Local Keystore)
    |
    +-- uses --> ADR-002 (Argon2id) for password-based encryption
    |
    +-- uses --> ADR-006 (Zod) for keystore format validation
    |
    +-- constrained by --> ADR-010 (Network Isolation)

ADR-003 (JSON Policies)
    |
    +-- evaluated for --> ADR-009 (All TX Types)
    |
    +-- enforces --> ADR-004 (Regular Keys + Multi-Sign) tiers

ADR-005 (Audit Logs)
    |
    +-- records --> All policy decisions
    |
    +-- protected by --> HMAC with separate key
```

---

## 3. Quality Goals Achievement

This section maps how the architecture achieves the project's quality goals.

### Quality Goal Matrix

| Quality Goal | Priority | Solution Approach | Verification Method |
|--------------|----------|-------------------|---------------------|
| **Security** | 1 | 8-layer defense, encrypted storage, policy engine, fail-secure design | Security audit, penetration testing, threat modeling |
| **Reliability** | 2 | Fail-secure design, audit trail for recovery, atomic operations | Integration tests, chaos testing, recovery drills |
| **Agent Autonomy** | 3 | Tier 1 autonomous signing, wide policy bounds, minimal latency | Performance benchmarks, autonomy metrics |
| **Auditability** | 4 | Hash-chained logs, compliance evidence export, full traceability | Audit log verification, compliance review |
| **Usability** | 5 | Simple MCP interface, good defaults, clear error messages | User testing, DX feedback, documentation review |

### Security Quality Goal

**Target**: Prevent unauthorized signing, protect private keys, detect compromise attempts

| Security Measure | Implementation |
|------------------|----------------|
| Key Protection | AES-256-GCM encryption, Argon2id derivation, memory zeroing |
| Access Control | Policy engine, tiered approval, rate limiting |
| Attack Prevention | Input validation, prompt injection defense, output sanitization |
| Compromise Detection | Audit logging, anomaly detection, hash chain verification |
| Recovery | Master key cold storage, regular key rotation, audit-based forensics |

### Reliability Quality Goal

**Target**: System operates correctly under normal and error conditions

| Reliability Measure | Implementation |
|--------------------|----------------|
| Fail-Secure | All errors result in denied operations |
| Atomic Operations | Signing either completes fully or not at all |
| State Recovery | Audit log enables transaction replay analysis |
| Graceful Degradation | Read-only mode if signing becomes unavailable |
| Self-Healing | Automatic reconnection to XRPL nodes |

### Agent Autonomy Quality Goal

**Target**: Maximize agent operational capability within security bounds

| Autonomy Measure | Implementation |
|------------------|----------------|
| Low Latency | Tier 1 signing < 100ms |
| Wide Bounds | Configurable limits up to 100 XRP autonomous |
| Self-Service | Agents can check policies, balances, transaction status |
| Predictable | Clear policy rules, no ambiguous decisions |
| Minimal Friction | No human intervention for routine operations |

### Auditability Quality Goal

**Target**: Complete, verifiable record of all operations

| Audit Measure | Implementation |
|---------------|----------------|
| Completeness | Every operation logged (success and failure) |
| Integrity | HMAC hash chain prevents tampering |
| Accessibility | JSON format, standard query interface |
| Retention | Configurable retention (default: 7 years) |
| Compliance | Export formats for SOC 2, MiCA requirements |

### Usability Quality Goal

**Target**: Simple, intuitive interface for both agents and operators

| Usability Measure | Implementation |
|-------------------|----------------|
| Simple API | 10 MCP tools, consistent patterns |
| Good Defaults | Secure-by-default configuration |
| Clear Errors | Structured error codes, actionable messages |
| Documentation | Complete API reference, tutorials, examples |
| Tooling | CLI for key management, policy testing |

---

## 4. Tiered Security Model

The tiered approval system provides risk-proportionate security controls.

### Tier Definitions

| Tier | Name | Criteria | Agent Action | Human Action | Latency |
|------|------|----------|--------------|--------------|---------|
| **1** | Autonomous | < 100 XRP, known destination, within daily limit | Sign immediately | None | < 100ms |
| **2** | Delayed | 100-1000 XRP, or elevated risk indicators | Sign after 5-min delay | Can veto during delay | 5+ min |
| **3** | Co-Sign | > 1000 XRP, new destination, or policy flag | Request approval | Must approve | Variable |
| **4** | Prohibited | Policy violation, blocklisted destination, exceeded limits | Reject immediately | N/A | < 50ms |

### Tier Decision Flow

```
Transaction Request
        |
        v
+------------------+
| Policy Evaluation|
+------------------+
        |
        +-- Blocklist/Violation? --> Tier 4 (Reject)
        |
        +-- > 1000 XRP or New Dest? --> Tier 3 (Co-Sign)
        |
        +-- 100-1000 XRP or Risk Flag? --> Tier 2 (Delayed)
        |
        +-- < 100 XRP, Known Dest, Within Limits? --> Tier 1 (Auto)
```

### Tier 1: Autonomous Operations

**Purpose**: Enable efficient agent operations for routine, low-risk transactions

**Default Criteria**:
- Amount: < 100 XRP (configurable)
- Destination: In allowlist or previously used
- Daily volume: Within 1,000 XRP limit
- Transaction type: Payment, standard operations
- Time: No unusual patterns

**Agent Capabilities**:
- Immediate signing without human involvement
- Full transaction lifecycle management
- Real-time status updates

### Tier 2: Delayed Signing

**Purpose**: Allow time for human review while not blocking agent operations

**Default Criteria**:
- Amount: 100-1000 XRP
- Destination: Known but infrequent
- Daily volume: 50-100% of limit
- Transaction type: Any supported type

**Process**:
1. Agent submits transaction
2. System acknowledges with delay notification
3. 5-minute countdown begins
4. Human receives notification with veto option
5. If no veto: transaction signed after delay
6. If vetoed: transaction rejected, agent notified

**Veto Mechanism**:
- Email/SMS notification to designated approvers
- Dashboard access for review
- One-click veto within delay window
- Audit log of veto decisions

### Tier 3: Co-Sign Required

**Purpose**: Ensure human oversight for high-value or unusual transactions

**Default Criteria**:
- Amount: > 1000 XRP
- Destination: Never used before
- Transaction type: AccountSet, SetRegularKey (account changes)
- Policy flag: Manual review required

**Process**:
1. Agent submits transaction with justification
2. System queues for human approval
3. Designated approver(s) receive notification
4. Approver reviews transaction details
5. If approved: Multi-sign process initiated
6. If rejected: Agent receives rejection with reason

**Multi-Sign Integration**:
- Agent holds Regular Key (weight: 1)
- Human holds approval key (weight: 1)
- SignerQuorum: 2 (both required)
- XRPL validates before execution

### Tier 4: Prohibited Operations

**Purpose**: Hard stops for policy violations

**Automatic Rejection Triggers**:
- Destination in blocklist
- Amount exceeds maximum allowed
- Daily/hourly limits exceeded
- Transaction type not permitted
- Suspicious patterns detected
- Rate limit exceeded

**Response**:
- Immediate rejection (no delay)
- Clear error message with reason
- Audit log entry
- Optional alert to security team

### Policy Configuration Example

```json
{
  "version": "1.0",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 100,
      "daily_limit_xrp": 1000,
      "require_known_destination": true,
      "allowed_transaction_types": ["Payment", "TrustSet"]
    },
    "delayed": {
      "max_amount_xrp": 1000,
      "delay_seconds": 300,
      "daily_limit_xrp": 10000,
      "veto_channels": ["email", "dashboard"]
    },
    "cosign": {
      "min_amount_xrp": 1000,
      "new_destination_always": true,
      "signer_quorum": 2,
      "approval_timeout_hours": 24
    }
  },
  "blocklist": {
    "addresses": [],
    "memo_patterns": []
  },
  "allowlist": {
    "addresses": [],
    "trusted_tags": []
  }
}
```

---

## 5. Technology Selection

### Technology Stack Summary

| Component | Technology | Version | Alternatives Considered | Decision Rationale |
|-----------|------------|---------|------------------------|-------------------|
| **Runtime** | Node.js | 20+ LTS | Deno, Bun | MCP SDK official support, ecosystem maturity, production stability |
| **Language** | TypeScript | 5.x | JavaScript, Rust | Type safety, excellent tooling, MCP SDK compatibility |
| **Validation** | Zod | 3.x | Joi, Yup, io-ts | Best TypeScript inference, composable schemas, excellent DX |
| **Encryption** | Node.js crypto | Native | libsodium, WebCrypto | No native dependencies, FIPS mode available, well-audited |
| **KDF** | Argon2 (argon2 npm) | 0.40+ | scrypt, bcrypt, PBKDF2 | Memory-hard, GPU-resistant, PHC winner, modern standard |
| **Policy** | JSON + Custom Engine | - | Rego (OPA), YAML, CEL | No separate runtime, simple tooling, auditable |
| **XRPL** | xrpl.js | 3.x+ | ripple-lib (deprecated) | Official SDK, full feature support, active maintenance |
| **Logging** | pino | 8.x | winston, bunyan | Fastest JSON logger, low overhead, structured output |
| **Testing** | Vitest | 1.x | Jest, Mocha | Fast, native ESM, excellent TypeScript support |

### Runtime: Node.js 20+

**Selection Criteria**:
- MCP SDK officially supports Node.js
- LTS version ensures long-term stability
- Native crypto module is well-audited
- Excellent ecosystem for security tooling

**Key Features Used**:
- Native `crypto` module for AES-256-GCM
- `buffer` for secure memory handling
- ES Modules for modern import/export
- Native fetch for HTTP operations

### Language: TypeScript 5.x

**Benefits for Security**:
- Compile-time type checking catches errors early
- Exhaustive pattern matching prevents missed cases
- Discriminated unions for transaction type handling
- Strict null checks prevent undefined behavior

**Configuration (tsconfig.json)**:
```json
{
  "compilerOptions": {
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true
  }
}
```

### Validation: Zod

**Why Zod Over Alternatives**:

| Feature | Zod | Joi | io-ts |
|---------|-----|-----|-------|
| TypeScript Inference | Excellent | Manual | Good |
| Bundle Size | 12KB | 150KB | 45KB |
| Composability | Excellent | Good | Excellent |
| Error Messages | Clear | Verbose | Technical |
| Schema Transforms | Built-in | Plugin | Complex |

**Example Usage**:
```typescript
const XRPLAddressSchema = z.string()
  .regex(/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/)
  .refine(isValidChecksum, 'Invalid checksum');

const PaymentSchema = z.object({
  destination: XRPLAddressSchema,
  amount: z.string().regex(/^\d+$/),
  memo: z.string().max(1024).optional()
});

// TypeScript type inferred automatically
type Payment = z.infer<typeof PaymentSchema>;
```

### Encryption: Node.js Crypto

**Advantages**:
- No native compilation required
- FIPS 140-2 validated mode available
- Consistent cross-platform behavior
- Well-audited implementation

**No libsodium Because**:
- Requires native module compilation
- Adds deployment complexity
- Node.js crypto is sufficient for our needs
- Reduces supply chain attack surface

### Key Derivation: Argon2id

**Why Argon2id**:
- Winner of Password Hashing Competition (PHC)
- Hybrid approach: resistant to both side-channel and GPU attacks
- Memory-hard: expensive to parallelize
- Recommended by OWASP for new systems

**Parameters**:
```typescript
const ARGON2_CONFIG = {
  type: argon2.argon2id,
  memoryCost: 65536,  // 64 MB
  timeCost: 3,        // 3 iterations
  parallelism: 4,     // 4 threads
  hashLength: 32      // 256-bit output
};
```

### Policy Engine: Custom JSON

**Why Not OPA/Rego**:
- OPA requires separate runtime process
- Rego has learning curve
- Our policy needs are focused and specific
- JSON enables easy tooling integration

**Policy Engine Design**:
- Pure TypeScript evaluation
- JSON policy files, version controlled
- No external dependencies
- Deterministic, testable evaluation

---

## 6. Implementation Phases

### Phase Overview

| Phase | Scope | Focus | Timeline |
|-------|-------|-------|----------|
| **Phase 1 (MVP)** | Local keystore, policy engine, core tools | Security foundation | Specification + 8 weeks |
| **Phase 2** | Cloud KMS, HSM support, enterprise features | Enterprise readiness | Future |
| **Phase 3** | TEE deployment, advanced compliance | Maximum security | Future |

### Phase 1: Minimum Viable Product

**Scope**: Complete, secure, production-ready MCP server for individual and small team use.

**Deliverables**:

| Component | Description |
|-----------|-------------|
| **Local Keystore** | AES-256-GCM encrypted file storage with Argon2id KDF |
| **Policy Engine** | JSON-based policies, tiered approval evaluation |
| **Core MCP Tools** | 10 tools for wallet operations |
| **Audit Logging** | HMAC hash-chained log files |
| **CLI Utilities** | Key management, policy testing |

**Core MCP Tools**:
1. `create_wallet` - Generate new XRPL wallet
2. `import_wallet` - Import existing seed/secret
3. `list_wallets` - List managed wallet addresses
4. `get_balance` - Query wallet balance
5. `sign_transaction` - Sign transaction (policy-controlled)
6. `get_transaction_status` - Check transaction result
7. `set_regular_key` - Configure regular key
8. `setup_multisign` - Configure multi-signature
9. `get_policy` - Retrieve current policy
10. `check_policy` - Evaluate transaction against policy (dry-run)

**Security Features**:
- All 8 security layers implemented
- Rate limiting per tool
- Input validation on all parameters
- Fail-secure error handling
- Network-isolated keystores

### Phase 2: Enterprise Features

**Scope**: Cloud integration and enterprise deployment options.

**Planned Features**:

| Feature | Description |
|---------|-------------|
| **Cloud KMS Integration** | AWS KMS, Google Cloud KMS, Azure Key Vault |
| **HSM Support** | PKCS#11 interface for hardware security modules |
| **Multi-Tenant** | Organization-level isolation and policies |
| **RBAC** | Role-based access control for operators |
| **Advanced Audit** | SIEM integration, compliance exports |
| **High Availability** | Clustered deployment, failover support |

**Cloud KMS Architecture**:
```
+------------------+     +------------------+
|   Wallet MCP     |     |   Cloud KMS      |
|                  |     |                  |
| Master key       | --> | Key encryption   |
| encrypted by     |     | key (KEK)        |
| KEK from KMS     |     | stored in KMS    |
+------------------+     +------------------+
```

### Phase 3: Maximum Security

**Scope**: Trusted Execution Environment deployment for highest security requirements.

**Planned Features**:

| Feature | Description |
|---------|-------------|
| **TEE Deployment** | AWS Nitro Enclaves, Azure Confidential Computing |
| **Remote Attestation** | Cryptographic proof of enclave integrity |
| **Hardware Root of Trust** | Keys never exist outside TEE |
| **Regulatory Compliance** | MiCA, SOC 2 Type II, ISO 27001 |
| **Agent Identity (KYA)** | Know Your Agent attestation support |

**TEE Architecture**:
```
+------------------------------------------+
|              Nitro Enclave               |
|  +------------------------------------+  |
|  |         Signing Operations         |  |
|  |  - Key never leaves enclave       |  |
|  |  - Remote attestation on request  |  |
|  |  - Policy evaluation inside TEE   |  |
|  +------------------------------------+  |
|              |           |               |
|         KMS API      vsock              |
|              |           |               |
+------------------------------------------+
              |           |
        AWS KMS       MCP Server
```

### Migration Path

Each phase builds on the previous:

```
Phase 1: Local Keystore
    |
    +-- Policy format remains constant
    |
    v
Phase 2: Cloud KMS
    |
    +-- Same MCP API
    +-- Keystore backend swappable
    |
    v
Phase 3: TEE
    |
    +-- Same MCP API
    +-- Same policy format
    +-- Enhanced security guarantees
```

**Backward Compatibility**:
- MCP tool interfaces remain stable
- Policy file format versioned
- Keystore migration tools provided
- Audit log format unchanged

---

## Related Documents

- [01 - Introduction](01-introduction.md)
- [02 - Constraints](02-constraints.md)
- [03 - Context](03-context.md)
- [05 - Building Blocks](05-building-blocks.md)
- [Security Architecture](../security/SECURITY-ARCHITECTURE.md)
- [Research Report](../research/ai-agent-wallet-security-2025-2026.md)

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Tech Lead | Initial version |

---

*Arc42 Template - Section 04: Solution Strategy*
