# XRPL Agent Wallet MCP

[![Build Status](https://img.shields.io/github/actions/workflow/status/9RESE/xrpl-agent-wallet-mcp/ci.yml?branch=main)](https://github.com/9RESE/xrpl-agent-wallet-mcp/actions)
[![Coverage](https://img.shields.io/codecov/c/github/9RESE/xrpl-agent-wallet-mcp)](https://codecov.io/gh/9RESE/xrpl-agent-wallet-mcp)
[![npm version](https://img.shields.io/npm/v/xrpl-agent-wallet-mcp)](https://www.npmjs.com/package/xrpl-agent-wallet-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22.0.0-brightgreen)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)](https://www.typescriptlang.org/)

**Secure, policy-controlled wallet infrastructure for AI agents operating on the XRP Ledger.**

This MCP (Model Context Protocol) server enables AI agents to autonomously manage XRPL wallets and sign transactions within configurable policy boundaries. It implements a tiered security model where low-risk operations execute immediately while high-value transactions require human oversight.

> **Project Status**: ✅ **Phase 1 Implementation Complete** - All core modules implemented and tested (222 tests passing)

## The Problem

AI agents need to transact on XRPL, but current approaches are insecure:
- Raw seeds stored in environment variables
- No policy enforcement on agent-initiated transactions
- No human oversight for high-value operations
- No audit trail for compliance

## The Solution

A security-first MCP server that provides:
- **Encrypted key storage** - Keys never exposed in plaintext
- **Policy engine** - Declarative rules control what agents can do
- **Tiered approval** - Human oversight scales with transaction risk
- **Full audit trail** - Tamper-evident logging for compliance

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                     XRPL Agent Wallet MCP Server                     │
├─────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │ Input Validation │  │  Policy Engine   │  │ Signing Service  │  │
│  │   (Zod schemas)  │─▶│  (Tier routing)  │─▶│  (AES-256-GCM)   │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
│                              │                        │             │
│                              ▼                        ▼             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │   Rate Limiter   │  │  Audit Logger    │  │   XRPL Client    │  │
│  │  (Token bucket)  │  │  (Hash chains)   │  │    (xrpl.js)     │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────────────────┤
│                         11 MCP Tools                                 │
│  wallet_create │ wallet_sign │ wallet_balance │ wallet_policy_check │
│  wallet_rotate │ wallet_list │ wallet_history │ wallet_fund         │
│  policy_set    │ tx_submit   │ tx_decode                            │
└─────────────────────────────────────────────────────────────────────┘
```

## Key Features

### Security-First Design

| Layer | Protection |
|-------|------------|
| **Transport** | TLS 1.3 for XRPL connections |
| **Input** | Zod schema validation, injection detection |
| **Authentication** | Argon2id (64MB), progressive lockout |
| **Authorization** | Tool sensitivity levels, rate limiting |
| **Policy** | Immutable rules engine, tier classification |
| **Cryptographic** | AES-256-GCM, SecureBuffer memory handling |
| **XRPL Native** | Regular Keys, Multi-Sign, network isolation |
| **Audit** | HMAC-SHA256 hash-chained logs |

### Tiered Approval Model

| Tier | Criteria | Agent Action | Human Action |
|------|----------|--------------|--------------|
| **Autonomous** | < 100 XRP, known destination | Sign immediately | None |
| **Delayed** | 100-1000 XRP | Sign after 5-min delay | Can veto |
| **Co-Sign** | > 1000 XRP, new destination | Request approval | Must approve |
| **Prohibited** | Policy violation, blocklist | Reject | N/A |

### Companion to xrpl-escrow-mcp

This wallet MCP is designed as the **signing layer** for [xrpl-escrow-mcp](https://github.com/9RESE/xrpl-escrow-mcp):

```
xrpl-escrow-mcp              xrpl-wallet-mcp              XRPL Network
(builds unsigned TX)    →    (signs with policy)     →    (validates)
```

But it's not limited to escrow - it supports **all 32 XRPL transaction types**.

## Quick Start

### 1. Install

```bash
npm install -g xrpl-agent-wallet-mcp
```

### 2. Configure Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "xrpl-wallet": {
      "command": "xrpl-agent-wallet-mcp",
      "env": {
        "XRPL_NETWORK": "testnet",
        "XRPL_WALLET_PASSWORD": "your-secure-password"
      }
    }
  }
}
```

### 3. Create Your First Wallet

Ask Claude: *"Create a new XRPL wallet on testnet for my AI agent"*

## MCP Tools

| Tool | Purpose | Sensitivity |
|------|---------|-------------|
| `wallet_create` | Create new wallet with policy | HIGH |
| `wallet_sign` | Sign transaction (policy-controlled) | CRITICAL |
| `wallet_balance` | Query balance and reserves | LOW |
| `wallet_policy_check` | Dry-run policy evaluation | LOW |
| `wallet_rotate` | Rotate regular key | DESTRUCTIVE |
| `wallet_list` | List managed wallets | LOW |
| `wallet_history` | Query transaction history | LOW |
| `wallet_fund` | Fund wallet from testnet/devnet faucet | HIGH |
| `policy_set` | Update policy configuration | CRITICAL |
| `tx_submit` | Submit signed transaction | HIGH |
| `tx_decode` | Decode transaction blob | LOW |

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `XRPL_NETWORK` | Yes | - | `mainnet`, `testnet`, or `devnet` |
| `XRPL_WALLET_PASSWORD` | Yes | - | Master encryption password |
| `XRPL_WALLET_KEYSTORE_PATH` | No | `~/.xrpl-wallet-mcp` | Keystore location |
| `XRPL_WALLET_POLICY` | No | Built-in | Path to policy JSON |
| `LOG_LEVEL` | No | `info` | `debug`, `info`, `warn`, `error` |

### Policy Configuration

Policies are JSON files controlling agent behavior:

```json
{
  "version": "1.0.0",
  "name": "conservative",
  "network": "testnet",
  "tiers": {
    "autonomous": { "max_amount_drops": "100000000" },
    "delayed": { "max_amount_drops": "1000000000", "delay_seconds": 300 },
    "cosign": { "quorum": 2 }
  },
  "limits": {
    "daily_volume_drops": "1000000000",
    "max_tx_per_hour": 10
  },
  "destinations": {
    "mode": "allowlist",
    "addresses": ["rKnownExchange...", "rTrustedPartner..."]
  },
  "blocklist": {
    "addresses": [],
    "memo_patterns": ["ignore previous", "system prompt"]
  }
}
```

## Security Model

### XRPL Native Security

- **Regular Keys**: Agent signs with rotatable key; master key stays cold
- **Multi-Sign**: Tier 3 transactions require human co-signature (2-of-N)
- **Network Isolation**: Separate keystores per network prevent accidents

### Key Protection

```
User Password
     │
     ▼ Argon2id (64MB, 3 iterations)
Master Key
     │
     ▼ AES-256-GCM
Encrypted Wallet Keys
     │
     ▼ File (0600 permissions)
~/.xrpl-wallet-mcp/{network}/wallets/
```

### Prompt Injection Defense

The policy engine includes defenses against prompt injection:
- Memo field pattern matching blocks common attack vectors
- Policy rules are immutable at runtime (agent cannot self-modify)
- Context field sanitized before audit logging

## Documentation

### Architecture (Arc42)
- [Introduction](./docs/architecture/01-introduction.md) - Goals, stakeholders, scope
- [Constraints](./docs/architecture/02-constraints.md) - Technical and regulatory
- [Context](./docs/architecture/03-context.md) - System boundaries (C4 Level 1)
- [Solution Strategy](./docs/architecture/04-solution-strategy.md) - Key decisions
- [Building Blocks](./docs/architecture/05-building-blocks.md) - Components (C4 Level 2/3)
- [Runtime View](./docs/architecture/06-runtime-view.md) - Sequence diagrams
- [Deployment](./docs/architecture/07-deployment-view.md) - Infrastructure
- [Crosscutting](./docs/architecture/08-crosscutting.md) - Security, logging, errors
- [ADRs](./docs/architecture/09-decisions/) - 10 architecture decisions

### Security
- [Threat Model](./docs/security/threat-model.md) - STRIDE analysis, 20 threats
- [Security Requirements](./docs/security/security-requirements.md) - 52 requirements
- [Compliance Mapping](./docs/security/compliance-mapping.md) - SOC 2, MiCA
- [OWASP LLM Mitigations](./docs/security/owasp-llm-mitigations.md) - Top 10 coverage

### API Reference
- [Tool Specifications](./docs/api/tools/) - All 11 MCP tools
- [Policy Schema](./docs/api/policy-schema.md) - Complete policy format
- [Network Configuration](./docs/api/network-config.md) - Network setup

### User Guides (Diataxis)
- **Tutorials**: [Getting Started](./docs/user/tutorials/getting-started.md), [Escrow Workflow](./docs/user/tutorials/escrow-workflow.md)
- **How-To**: [Configure Policies](./docs/user/how-to/configure-policies.md), [Rotate Keys](./docs/user/how-to/rotate-keys.md), [Network Config](./docs/user/how-to/network-configuration.md)
- **Reference**: [API](./docs/user/reference/api.md), [Transaction Types](./docs/user/reference/supported-transactions.md)
- **Explanation**: [Security Model](./docs/user/explanation/security-model.md), [Policy Engine](./docs/user/explanation/policy-engine.md)

## Development

### Prerequisites

- Node.js 22+
- npm 10+

### Setup

```bash
git clone https://github.com/9RESE/xrpl-agent-wallet-mcp.git
cd xrpl-agent-wallet-mcp
npm install
npm run build
```

### Testing

```bash
npm test                    # Watch mode
npm run test:run           # Single run
npm run test:coverage      # Coverage report (90% target)
npm run test:security      # Security tests
```

### Test Coverage Requirements

| Module | Target |
|--------|--------|
| `src/keystore/` | 95% |
| `src/policy/` | 95% |
| `src/signing/` | 95% |
| `src/validators/` | 95% |
| Overall | 90% |

## Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| **1 (MVP)** | Local keystore, policy engine, 11 MCP tools | ✅ **Complete** |
| **2** | Cloud KMS (AWS/GCP), HSM integration | Planned |
| **3** | TEE deployment (AWS Nitro), KYA identity | Future |

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

Security vulnerabilities: See [SECURITY.md](./SECURITY.md) - do NOT open public issues.

## License

MIT License - see [LICENSE](./LICENSE)

## Acknowledgments

- [XRPL Foundation](https://xrpl.org/) - XRP Ledger and xrpl.js
- [Anthropic](https://anthropic.com/) - Model Context Protocol
- [xrpl-escrow-mcp](https://github.com/9RESE/xrpl-escrow-mcp) - Companion project
- Security research from AWS Nitro, OWASP, and the agent wallet community

---

**Questions?** [Open an issue](https://github.com/9RESE/xrpl-agent-wallet-mcp/issues) or start a [discussion](https://github.com/9RESE/xrpl-agent-wallet-mcp/discussions)
