# XRPL Agent Wallet MCP - Project Guide

## Project Overview

**Purpose**: Secure, policy-controlled wallet infrastructure for AI agents on the XRP Ledger.

**Status**: Specification Complete (v1.0.0) - Implementation Phase Beginning

**Companion Project**: [xrpl-escrow-mcp](https://github.com/9RESE/xrpl-escrow-mcp) - This wallet MCP signs transactions built by escrow-mcp (and any other TX builder).

---

## Design Philosophy

### Priority Order (Non-Negotiable)
1. **Security** - Never compromise key safety or transaction integrity
2. **Agent Autonomy** - Maximize operational capability within policy bounds
3. **Usability** - Simple MCP API with excellent developer experience

### Core Principle
> "Keys never exposed, policies never bypassed, actions always audited."

---

## Architecture Decisions (ADRs)

| ADR | Decision | Rationale |
|-----|----------|-----------|
| **ADR-001** | AES-256-GCM local keystore | Industry standard, NIST approved, hardware acceleration |
| **ADR-002** | Argon2id KDF (64MB, 3 iterations, 4 parallelism) | Memory-hard, OWASP recommended for 2024+ |
| **ADR-003** | OPA-inspired JSON policy engine | Declarative, auditable, immutable at runtime |
| **ADR-004** | Regular Keys + Multi-Sign | XRPL-native security, master key stays cold |
| **ADR-005** | HMAC-SHA256 hash-chained audit logs | Tamper-evident, compliance-ready |
| **ADR-006** | Zod schema validation | Type-safe, composable, excellent error messages |
| **ADR-007** | Token bucket rate limiting | Per-tool, per-wallet, burst-tolerant |
| **ADR-008** | Composable MCP design | Works standalone or with xrpl-escrow-mcp |
| **ADR-009** | All 32 XRPL TX types supported | Future-proof, not limited to escrow |
| **ADR-010** | Network-isolated keystores | Prevents mainnet/testnet accidents |

Full ADRs: `docs/architecture/09-decisions/`

---

## Security Model

### 8-Layer Defense in Depth

| Layer | Protection | Implementation |
|-------|------------|----------------|
| **Transport** | TLS 1.3 | xrpl.js with certificate pinning |
| **Input** | Schema validation | Zod with injection detection |
| **Authentication** | Password-based | Argon2id, progressive lockout |
| **Authorization** | Tool sensitivity | Rate limiting per sensitivity level |
| **Policy** | Transaction rules | Immutable JSON policies, priority evaluation |
| **Cryptographic** | Key protection | AES-256-GCM, SecureBuffer memory handling |
| **XRPL Native** | Protocol security | Regular Keys, Multi-Sign, network isolation |
| **Audit** | Accountability | HMAC hash chains, tamper detection |

### Tiered Approval Model

| Tier | Criteria | Agent Behavior | Human Involvement |
|------|----------|----------------|-------------------|
| **Autonomous** | < 100 XRP, allowlisted destination | Sign immediately | None |
| **Delayed** | 100-1000 XRP | Sign after 5-min delay | Can veto within window |
| **Co-Sign** | > 1000 XRP, new destination | Request approval | Must provide co-signature |
| **Prohibited** | Blocklist, policy violation | Reject with reason | N/A |

### Prompt Injection Defenses
- Memo field pattern matching (`blocklist.memo_patterns`)
- Context sanitization before logging
- Policies immutable at runtime (agent cannot self-modify)

---

## MCP Tools Reference

| Tool | Sensitivity | Purpose |
|------|-------------|---------|
| `wallet_create` | HIGH | Create wallet with policy |
| `wallet_sign` | CRITICAL | Sign transaction (policy-controlled) |
| `wallet_balance` | LOW | Query balance and reserves |
| `wallet_policy_check` | LOW | Dry-run policy evaluation |
| `wallet_rotate` | DESTRUCTIVE | Rotate regular key |
| `wallet_list` | LOW | List managed wallets |
| `wallet_history` | LOW | Query transaction history |
| `policy_set` | CRITICAL | Update policy configuration |
| `tx_submit` | HIGH | Submit signed transaction |
| `tx_decode` | LOW | Decode transaction blob |

### Critical Tool: `wallet_sign`

Returns discriminated union:
```typescript
type SignResult =
  | { tier: 'autonomous'; signed_blob: string; hash: string }
  | { tier: 'delayed'; delay_id: string; expires_at: string }
  | { tier: 'cosign'; request_id: string; partial_blob: string }
  | { tier: 'prohibited'; reason: string; policy_ref: string };
```

Agent must handle all four outcomes appropriately.

---

## Key Implementation Patterns

### SecureBuffer (Memory-Safe Keys)
```typescript
class SecureBuffer {
  private buffer: Buffer;

  constructor(data: Buffer) {
    this.buffer = Buffer.alloc(data.length);
    data.copy(this.buffer);
    data.fill(0); // Zero source immediately
  }

  use<T>(fn: (buf: Buffer) => T): T {
    try { return fn(this.buffer); }
    finally { /* buffer stays alive */ }
  }

  dispose(): void {
    this.buffer.fill(0); // Cryptographic zeroing
  }
}
```

### Policy Rule Evaluation
```
1. Sort rules by priority (highest first)
2. For each rule:
   a. Check conditions against transaction
   b. If all conditions match -> return rule.action
3. If no rules match -> return default_action
```

### Hash-Chained Audit Logs
```
Entry N: {
  data: {...},
  prev_hash: hash(Entry N-1),
  hash: HMAC-SHA256(data + prev_hash)
}
```

---

## Development Guidelines

### Test Coverage Requirements

| Module | Target | Rationale |
|--------|--------|-----------|
| `src/keystore/` | 95% | Security-critical |
| `src/policy/` | 95% | Security-critical |
| `src/signing/` | 95% | Security-critical |
| `src/validators/` | 95% | Security-critical |
| **Overall** | 90% | High-assurance requirement |

### Test Categories
1. **Unit Tests**: Isolated component behavior
2. **Integration Tests**: Component interactions, XRPL testnet
3. **E2E Tests**: Full signing workflows
4. **Security Tests**: Injection, timing attacks, key exposure

### Code Standards
- TypeScript strict mode
- Zod for all external input validation
- No `any` types in security-critical code
- All async operations must handle timeouts
- Secrets never in logs (even at DEBUG level)

---

## File Structure

```
xrpl-wallet-mcp/
├── src/
│   ├── keystore/          # Key storage implementations
│   │   ├── interface.ts   # IKeystore abstract interface
│   │   └── local.ts       # File-based AES-256-GCM storage
│   ├── policy/            # Policy engine
│   │   ├── engine.ts      # Rule evaluation
│   │   └── schema.ts      # Policy Zod schemas
│   ├── signing/           # Transaction signing
│   │   ├── service.ts     # Sign orchestration
│   │   └── multisig.ts    # Multi-sign support
│   ├── audit/             # Audit logging
│   │   └── logger.ts      # Hash-chained logger
│   ├── xrpl/              # XRPL client wrapper
│   │   └── client.ts      # Connection management
│   ├── tools/             # MCP tool implementations
│   │   ├── wallet-create.ts
│   │   ├── wallet-sign.ts
│   │   └── ...
│   ├── validators/        # Input validation
│   │   └── injection.ts   # Prompt injection detection
│   └── index.ts           # MCP server entry
├── docs/
│   ├── architecture/      # Arc42 (01-08) + ADRs (09-decisions/)
│   ├── security/          # Threat model, requirements, compliance
│   ├── api/               # Tool specs, policy schema
│   ├── user/              # Diataxis: tutorials, how-to, reference, explanation
│   └── development/       # Implementation specs, test patterns
├── policies/              # Default policy configurations
│   ├── schema.json        # JSON Schema for policies
│   ├── conservative.json  # Low-risk defaults
│   └── testnet.json       # Testnet defaults
└── tests/
    ├── unit/
    ├── integration/
    ├── e2e/
    └── security/
```

---

## Network Configuration

### Environment Variables
```bash
XRPL_NETWORK=testnet              # mainnet | testnet | devnet
XRPL_WALLET_PASSWORD=<secret>     # Master encryption password
XRPL_WALLET_KEYSTORE_PATH=~/.xrpl-wallet-mcp  # Optional
XRPL_WALLET_POLICY=/path/to/policy.json       # Optional
```

### Network Isolation
- Separate keystore directories per network
- Keys created on testnet cannot sign mainnet transactions
- Network mismatch = immediate rejection

```
~/.xrpl-wallet-mcp/
├── mainnet/
│   ├── wallets/
│   └── audit/
├── testnet/
│   ├── wallets/
│   └── audit/
└── devnet/
    ├── wallets/
    └── audit/
```

---

## Integration with xrpl-escrow-mcp

```
xrpl-escrow-mcp              xrpl-wallet-mcp              XRPL
----------------              ---------------              ----
escrow_create_prepare()  ->  wallet_sign()            ->  validate()
  └─ unsigned TX blob          └─ policy check              └─ consensus
                                 └─ sign if allowed
                                 └─ return signed blob
```

### Shared Conventions
- Network enum: `mainnet | testnet | devnet`
- Zod validation schemas
- Structured error responses with recovery suggestions

---

## Security Checklist (Before Each Release)

- [ ] All security tests pass
- [ ] No secrets in logs (verify with DEBUG level)
- [ ] Argon2id parameters unchanged (64MB, 3 iter, 4 parallel)
- [ ] AES-256-GCM with unique IV per encryption
- [ ] SecureBuffer used for all key material
- [ ] Policy immutability verified (no runtime modification)
- [ ] Audit log hash chain integrity test passes
- [ ] Rate limiting active on all HIGH/CRITICAL tools
- [ ] Network isolation test passes (testnet key rejects mainnet TX)
- [ ] Prompt injection patterns updated in blocklist

---

## Documentation Index

| Category | Location | Framework |
|----------|----------|-----------|
| Architecture | `docs/architecture/` | Arc42 |
| Security | `docs/security/` | STRIDE, OWASP |
| API Reference | `docs/api/` | OpenAPI-style |
| User Guides | `docs/user/` | Diataxis |
| Implementation | `docs/development/` | Feature specs |
| Research | `docs/research/` | Industry analysis |

**Key Documents**:
- [Threat Model](docs/security/threat-model.md) - 20 threats analyzed
- [Security Requirements](docs/security/security-requirements.md) - 52 testable requirements
- [Policy Schema](docs/api/policy-schema.md) - Complete policy format
- [Getting Started](docs/user/tutorials/getting-started.md) - First wallet tutorial

---

## Quick Commands

```bash
# Development
npm install
npm run build
npm test                    # Watch mode
npm run test:coverage       # Coverage report

# Security testing
npm run test:security       # Security-specific tests

# Linting
npm run lint
npm run lint:fix
```

---

## Agent Guidelines

When working on this codebase:

1. **Security changes require ADR** - Any modification to crypto, auth, or policy requires a new ADR
2. **Test before commit** - 90% coverage is mandatory, not aspirational
3. **No shortcuts on validation** - All external input goes through Zod
4. **Audit log everything** - Operations on keys, policies, and signing must be logged
5. **Network awareness** - Always verify network context before operations
6. **Memory hygiene** - Use SecureBuffer for keys, zero after use

---

*Specification Version: 1.0.0*
*Last Updated: 2026-01-28*
