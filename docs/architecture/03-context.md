# Arc42 Section 03: System Context

**Version:** 1.0.0
**Date:** 2026-01-28
**Status:** Complete

---

## Table of Contents

1. [Overview](#overview)
2. [Business Context](#business-context)
3. [Technical Context](#technical-context)
4. [External Dependencies](#external-dependencies)
5. [Context Boundaries](#context-boundaries)

---

## Overview

This document describes the system context for the XRPL Agent Wallet MCP server, showing how it interacts with external actors and systems. The wallet MCP serves as secure signing infrastructure enabling AI agents to autonomously execute XRP Ledger transactions within policy-controlled boundaries.

**System Purpose:** Provide secure, policy-controlled wallet infrastructure for AI agents operating on the XRP Ledger.

**Core Value Proposition:**
- Enable AI agent autonomy for XRP transactions
- Enforce security policies without human intervention for low-risk operations
- Provide human oversight for high-risk operations
- Maintain comprehensive audit trails for compliance

---

## Business Context

The business context identifies all external actors that interact with the XRPL Agent Wallet MCP and their communication relationships.

### Human Actors

#### Agent Developer

| Attribute | Description |
|-----------|-------------|
| **Role** | Technical implementer who integrates AI agents with the wallet MCP |
| **Responsibility** | Configure agents, define initial policies, deploy infrastructure |
| **Interaction Frequency** | Setup phase: High; Operational: Low |
| **Communication Channel** | Configuration files, environment variables, CLI tools |

**Key Activities:**
- Install and configure the MCP server
- Define wallet creation parameters
- Set up policy files for transaction control
- Configure agent-to-MCP communication
- Monitor system health and logs
- Troubleshoot integration issues

#### Security Officer

| Attribute | Description |
|-----------|-------------|
| **Role** | Security governance and policy authority |
| **Responsibility** | Approve policy changes, review audit logs, assess security posture |
| **Interaction Frequency** | Periodic reviews, incident response |
| **Communication Channel** | Policy approval workflows, audit dashboards |

**Key Activities:**
- Review and approve policy modifications
- Audit transaction logs for anomalies
- Assess compliance with security standards
- Respond to security incidents
- Approve key rotation schedules
- Define tiered approval thresholds

#### Operations Team

| Attribute | Description |
|-----------|-------------|
| **Role** | System administrators ensuring operational reliability |
| **Responsibility** | Deploy, monitor, and maintain the MCP server infrastructure |
| **Interaction Frequency** | Continuous monitoring, periodic maintenance |
| **Communication Channel** | Monitoring dashboards, alerting systems, deployment pipelines |

**Key Activities:**
- Deploy MCP server instances
- Monitor system health and performance
- Manage infrastructure scaling
- Execute backup and recovery procedures
- Apply security patches and updates
- Rotate encryption keys per schedule

#### Human Approver

| Attribute | Description |
|-----------|-------------|
| **Role** | Authorized signer for high-value or high-risk transactions |
| **Responsibility** | Review and co-sign Tier 3 transactions requiring human oversight |
| **Interaction Frequency** | On-demand based on transaction volume |
| **Communication Channel** | Notifications (webhook, email, mobile), approval interface |

**Key Activities:**
- Receive approval requests for high-value transactions
- Review transaction details and context
- Provide cryptographic co-signature
- Reject suspicious or unauthorized requests
- Escalate anomalous patterns to Security Officer

### System Actors

#### AI Agent (Primary User)

| Attribute | Description |
|-----------|-------------|
| **Type** | LLM-powered autonomous agent (Claude, GPT, custom) |
| **Role** | Primary consumer of wallet MCP services |
| **Responsibility** | Request wallet operations within authorized scope |
| **Communication Protocol** | Model Context Protocol (MCP) over stdio/SSE |

**Key Interactions:**
- `wallet_create` - Create new wallets for agent operations
- `wallet_list` - Enumerate available wallets
- `wallet_get_balance` - Query account balances
- `wallet_sign` - Sign transactions (policy-controlled)
- `wallet_submit` - Submit signed transactions to XRPL
- `wallet_get_status` - Check transaction status

**Trust Level:** Untrusted input source - all requests subject to validation and policy enforcement

#### xrpl-escrow-mcp (Companion MCP)

| Attribute | Description |
|-----------|-------------|
| **Type** | MCP server providing escrow transaction building |
| **Role** | Supply unsigned escrow transactions for signing |
| **Responsibility** | Construct valid EscrowCreate/EscrowFinish transactions |
| **Communication Pattern** | Output unsigned TX blob, wallet MCP signs and submits |

**Transaction Types:**
- `EscrowCreate` - Create time-locked or condition-based escrows
- `EscrowFinish` - Complete escrow conditions
- `EscrowCancel` - Cancel expired escrows

**Integration Pattern:**
```
[AI Agent] --> [xrpl-escrow-mcp] --> Unsigned TX
                                          |
                                          v
[AI Agent] --> [xrpl-wallet-mcp] --> Sign & Submit
```

#### Other XRPL MCPs (Future)

| Attribute | Description |
|-----------|-------------|
| **Type** | Future MCP servers for specialized XRPL operations |
| **Role** | Provide unsigned transactions for various XRPL features |
| **Examples** | AMM operations, DEX trading, NFT minting, Hooks deployment |

**Anticipated Transaction Types:**
- Payment transactions
- TrustSet operations
- OfferCreate/OfferCancel (DEX)
- NFTokenMint/NFTokenBurn
- AMMCreate/AMMDeposit/AMMWithdraw
- SetHook (when Hooks launch on mainnet)

#### XRPL Network

| Attribute | Description |
|-----------|-------------|
| **Type** | Distributed ledger network |
| **Role** | Transaction validation and consensus |
| **Networks** | Mainnet, Testnet, Devnet, AMM-Devnet |
| **Communication Protocol** | WebSocket (WSS) or JSON-RPC (HTTPS) |

**Interaction Types:**
- Transaction submission (`submit` command)
- Account information queries (`account_info`, `account_lines`)
- Transaction status tracking (`tx`, `ledger_entry`)
- Network status monitoring (`server_info`, `fee`)

**Network Endpoints:**
| Network | WebSocket Endpoint | Purpose |
|---------|-------------------|---------|
| Mainnet | `wss://xrplcluster.com/` | Production transactions |
| Mainnet | `wss://s1.ripple.com/` | Alternative mainnet |
| Testnet | `wss://s.altnet.rippletest.net/` | Integration testing |
| Devnet | `wss://s.devnet.rippletest.net/` | Development |

---

## Technical Context

### Interface Specifications

| Interface | Protocol | Direction | Format | Purpose |
|-----------|----------|-----------|--------|---------|
| MCP Tools | MCP/JSON-RPC 2.0 | Agent --> Wallet | JSON | Tool invocations for wallet operations |
| XRPL WebSocket | WSS | Wallet --> XRPL | JSON | Transaction submission and queries |
| XRPL JSON-RPC | HTTPS | Wallet --> XRPL | JSON | Alternative API (fallback) |
| File System | Local FS | Wallet <--> Disk | JSON/Binary | Keystore, policies, audit logs |
| Notifications | Webhook | Wallet --> Approver | JSON | Tier 2/3 approval requests |
| Notifications | Email/SMTP | Wallet --> Approver | Text/HTML | Backup notification channel |
| Monitoring | Prometheus | Wallet --> Ops | Metrics | Operational telemetry |

### MCP Tool Interface

**Transport Options:**
- **stdio** (recommended): Standard input/output streams, lowest latency
- **SSE**: Server-Sent Events over HTTP for web-based hosts

**Request Format:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "wallet_sign",
    "arguments": {
      "wallet_id": "agent-wallet-001",
      "transaction": {
        "TransactionType": "Payment",
        "Destination": "rDestination...",
        "Amount": "1000000"
      }
    }
  },
  "id": 1
}
```

**Response Format:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"signed_tx_blob\": \"...\", \"tx_hash\": \"...\"}"
      }
    ]
  },
  "id": 1
}
```

### XRPL WebSocket Interface

**Connection Management:**
- Persistent WebSocket connection with automatic reconnection
- Connection pooling for high-throughput scenarios
- Health checks via `ping` command

**Transaction Submission:**
```json
{
  "command": "submit",
  "tx_blob": "1200002280000000240000000361..."
}
```

**Response Handling:**
- `tesSUCCESS`: Transaction accepted
- `tec*`: Transaction executed but claimed fee only
- `tef*`/`tem*`/`ter*`: Transaction rejected

### File System Interface

**Directory Structure:**
```
~/.xrpl-wallet-mcp/
|-- config/
|   |-- server.json          # Server configuration
|   `-- networks.json         # XRPL network endpoints
|-- wallets/
|   |-- agent-wallet-001.enc  # Encrypted wallet file
|   `-- agent-wallet-002.enc
|-- policies/
|   |-- default.json          # Default policy
|   `-- agent-wallet-001.json # Wallet-specific policy
|-- audit/
|   |-- 2026-01-28.log        # Daily audit log
|   `-- chain.json            # Hash chain for integrity
`-- keys/
    `-- master.key.enc        # Encrypted master key (or KMS reference)
```

**File Permissions:**
- Wallet files: `0600` (owner read/write only)
- Directories: `0700` (owner full access only)
- Audit logs: `0600` (append-only via process permissions)

### Notification Interface

**Webhook Payload (Approval Request):**
```json
{
  "event": "approval_required",
  "timestamp": "2026-01-28T14:30:00Z",
  "request_id": "req_abc123",
  "tier": 3,
  "wallet_id": "agent-wallet-001",
  "transaction": {
    "type": "Payment",
    "destination": "rDestination...",
    "amount_xrp": "5000",
    "memo": "Agent-initiated payment"
  },
  "policy_evaluation": {
    "matched_rule": "high_value_transfer",
    "required_approvers": 1,
    "timeout_minutes": 60
  },
  "approval_url": "https://approvals.example.com/req_abc123"
}
```

---

## External Dependencies

### Required Dependencies

| Dependency | Type | Purpose | Availability Impact |
|------------|------|---------|---------------------|
| XRPL Network | Infrastructure | Transaction validation | Cannot submit transactions |
| npm Registry | Build-time | Package installation | Cannot install/update |
| Node.js Runtime | Runtime | Server execution | Cannot operate |

### Optional Dependencies (Phase 2+)

| Dependency | Type | Purpose | Phase |
|------------|------|---------|-------|
| AWS KMS | Cloud Service | Hardware-backed key encryption | Phase 2 |
| AWS Nitro Enclaves | TEE Infrastructure | Isolated signing environment | Phase 3 |
| Google Cloud KMS | Cloud Service | Alternative key management | Phase 2 |
| HashiCorp Vault | Secret Management | Enterprise key storage | Phase 2 |

### Network Dependency Analysis

**XRPL Network:**
- **Redundancy:** Multiple endpoint fallback
- **Monitoring:** Health check before critical operations
- **Degradation Strategy:** Queue transactions, retry with backoff
- **Offline Capability:** Can sign transactions offline, submit when available

**npm Registry:**
- **Redundancy:** Registry mirrors, offline package cache
- **Impact:** Build-time only, no runtime impact
- **Mitigation:** Lockfile pinning, vendor dependencies for air-gapped deployments

---

## Context Boundaries

### What is INSIDE the System

| Component | Responsibility |
|-----------|---------------|
| MCP Server | Protocol handling, tool routing |
| Wallet Manager | Wallet lifecycle, key storage |
| Policy Engine | Transaction authorization |
| Signing Module | Cryptographic operations |
| Audit Logger | Compliance logging |
| XRPL Client | Network communication |

### What is OUTSIDE the System

| External Entity | Relationship |
|-----------------|-------------|
| AI Agent | Consumer (untrusted input) |
| XRPL Network | Infrastructure dependency |
| Human Approvers | Authorization authority |
| Transaction Builders (other MCPs) | Upstream providers |
| Monitoring Systems | Observability consumers |

### Trust Boundaries

```
+----------------------------------------------------------+
|                    UNTRUSTED ZONE                          |
|  +------------------+    +------------------+              |
|  |    AI Agent      |    | Other MCPs       |              |
|  | (Prompt-injectable) | (Unsigned TX source)|            |
|  +--------+---------+    +--------+---------+              |
|           |                       |                        |
+----------------------------------------------------------+
            |                       |
            v                       v
+----------------------------------------------------------+
|                    VALIDATION BOUNDARY                     |
|  +--------------------------------------------------+     |
|  |              Input Validation Layer               |     |
|  |  - Schema validation (zod)                       |     |
|  |  - Prompt injection detection                    |     |
|  |  - Rate limiting                                 |     |
|  +--------------------------------------------------+     |
+----------------------------------------------------------+
            |
            v
+----------------------------------------------------------+
|                    POLICY BOUNDARY                         |
|  +--------------------------------------------------+     |
|  |              Policy Engine                        |     |
|  |  - Transaction limits                            |     |
|  |  - Destination allowlist                         |     |
|  |  - Tiered approval routing                       |     |
|  +--------------------------------------------------+     |
+----------------------------------------------------------+
            |
            v
+----------------------------------------------------------+
|                    CRYPTOGRAPHIC BOUNDARY                  |
|  +--------------------------------------------------+     |
|  |              Signing Module (TEE in Phase 3)      |     |
|  |  - Key storage (encrypted)                       |     |
|  |  - Transaction signing                           |     |
|  |  - Never exports private keys                    |     |
|  +--------------------------------------------------+     |
+----------------------------------------------------------+
            |
            v
+----------------------------------------------------------+
|                    EXTERNAL BOUNDARY                       |
|  +------------------+    +------------------+              |
|  |  XRPL Network    |    | Human Approvers  |              |
|  | (Trusted infra)  |    | (Authorization)  |              |
|  +------------------+    +------------------+              |
+----------------------------------------------------------+
```

### Data Flow Summary

1. **Inbound (Agent --> Wallet MCP)**
   - All input treated as untrusted
   - Validated against schemas
   - Checked for injection patterns
   - Rate limited per agent

2. **Internal Processing**
   - Policy evaluation
   - Tier routing (auto/manual approval)
   - Cryptographic signing
   - Audit logging

3. **Outbound (Wallet MCP --> XRPL)**
   - Signed transaction submission
   - Result tracking
   - Status reporting back to agent

4. **Side Channels**
   - Approval requests to humans (Tier 2/3)
   - Audit logs to storage
   - Metrics to monitoring

---

## Related Documents

- [C4 Context Diagram](../c4-diagrams/context.md) - Visual representation
- [04 - Solution Strategy](04-solution-strategy.md) - Architectural approach
- [Security Architecture](../security/SECURITY-ARCHITECTURE.md) - Security details
- [Threat Model](../security/threat-model.md) - Security threats

---

*Document generated: 2026-01-28*
*Arc42 Template Section: 03 - System Scope and Context*
