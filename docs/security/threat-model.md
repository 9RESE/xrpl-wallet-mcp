# XRPL Agent Wallet MCP Server - Threat Model

**Version:** 1.0.0
**Date:** 2026-01-28
**Author:** Security Specialist
**Methodology:** STRIDE
**Classification:** Internal/Public
**Review Cycle:** Quarterly

---

## Table of Contents

1. [Overview](#1-overview)
2. [System Description](#2-system-description)
3. [Assets and Data Flows](#3-assets-and-data-flows)
4. [Threat Actors](#4-threat-actors)
5. [Attack Surface Analysis](#5-attack-surface-analysis)
6. [STRIDE Analysis](#6-stride-analysis)
7. [Threat Matrix](#7-threat-matrix)
8. [Attack Trees](#8-attack-trees)
9. [Residual Risks](#9-residual-risks)
10. [References](#10-references)

---

## 1. Overview

### 1.1 Purpose

This threat model provides a comprehensive security analysis of the XRPL Agent Wallet MCP (Model Context Protocol) server. The analysis identifies threats, vulnerabilities, and attack vectors specific to AI agent-controlled cryptocurrency wallets operating on the XRP Ledger.

### 1.2 Scope

**In Scope:**
- MCP server implementation and tool interfaces
- Cryptographic key storage and management
- Transaction signing and submission
- Policy engine and access controls
- Audit logging and monitoring
- Integration with XRPL network
- Agent authentication and authorization

**Out of Scope:**
- XRPL network protocol vulnerabilities
- LLM/AI model internal security
- Client application security (beyond MCP interface)
- Physical security of hosting infrastructure
- Network infrastructure beyond application boundary

### 1.3 Threat Model Objectives

1. Identify and categorize all significant threats to the system
2. Assess likelihood and impact of each threat
3. Prioritize threats for mitigation
4. Document attack trees for critical threats
5. Identify residual risks requiring acceptance or monitoring

### 1.4 Methodology

This threat model uses the **STRIDE** methodology developed by Microsoft:

| Category | Description | Security Property |
|----------|-------------|-------------------|
| **S**poofing | Impersonating something or someone else | Authentication |
| **T**ampering | Modifying data or code | Integrity |
| **R**epudiation | Claiming to have not performed an action | Non-repudiation |
| **I**nformation Disclosure | Exposing information to unauthorized parties | Confidentiality |
| **D**enial of Service | Denying or degrading service | Availability |
| **E**levation of Privilege | Gaining capabilities without authorization | Authorization |

---

## 2. System Description

### 2.1 Architecture Overview

```
                                    TRUST BOUNDARY
                    ┌─────────────────────────────────────────────────────┐
                    │                  MCP SERVER                          │
┌─────────────┐     │  ┌──────────────┐   ┌──────────────┐                │     ┌─────────────┐
│             │     │  │    Input     │   │    Policy    │                │     │             │
│  LLM/Agent  │────────│  Validation  │──▶│    Engine    │                │     │    XRPL     │
│   Client    │     │  │   Layer      │   │              │                │     │   Network   │
│             │     │  └──────────────┘   └──────┬───────┘                │     │             │
└─────────────┘     │                            │                        │     └─────────────┘
                    │                    ┌───────▼───────┐                │            │
                    │                    │   Tool        │                │            │
                    │                    │   Executor    │                │            │
                    │                    └───────┬───────┘                │            │
                    │         ┌─────────────────┼─────────────────┐       │            │
                    │         │                 │                 │       │            │
                    │  ┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐│            │
                    │  │   Wallet    │   │  Signing    │   │   Network   │─────────────┘
                    │  │   Manager   │   │   Service   │   │   Client    ││
                    │  └──────┬──────┘   └──────┬──────┘   └─────────────┘│
                    │         │                 │                         │
                    │  ┌──────▼─────────────────▼──────┐                  │
                    │  │      Encrypted Keystore       │                  │
                    │  │      (File System)            │                  │
                    │  └───────────────────────────────┘                  │
                    │                                                     │
                    │  ┌───────────────────────────────┐                  │
                    │  │      Audit Log Store          │                  │
                    │  │      (Tamper-Evident)         │                  │
                    │  └───────────────────────────────┘                  │
                    └─────────────────────────────────────────────────────┘
```

### 2.2 Component Descriptions

| Component | Description | Security Function |
|-----------|-------------|-------------------|
| **Input Validation Layer** | Validates all MCP tool inputs | First line of defense, sanitization |
| **Policy Engine** | Enforces transaction limits and rules | Authorization, rate limiting |
| **Tool Executor** | Executes MCP tool operations | Sandboxing, timeout enforcement |
| **Wallet Manager** | Manages wallet creation and import | Key generation, wallet lifecycle |
| **Signing Service** | Signs XRPL transactions | Secure key access, memory protection |
| **Network Client** | Communicates with XRPL network | TLS, connection management |
| **Encrypted Keystore** | Stores encrypted private keys | Encryption at rest, file permissions |
| **Audit Log Store** | Tamper-evident operation logging | Non-repudiation, forensics |

### 2.3 Technology Stack

| Layer | Technology | Security Relevance |
|-------|------------|-------------------|
| Runtime | Node.js 20+ | Memory model, async handling |
| Protocol | MCP (Model Context Protocol) | Tool interface security |
| Encryption | AES-256-GCM | Data at rest protection |
| Key Derivation | Argon2id | Password-based key protection |
| Cryptographic Signing | Ed25519 (secp256k1) | XRPL transaction signing |
| Validation | Zod schemas | Input validation framework |
| Network | WebSocket/TLS 1.3 | XRPL communication |

---

## 3. Assets and Data Flows

### 3.1 Asset Inventory

#### 3.1.1 Critical Assets (Highest Protection Required)

| Asset ID | Asset Name | Description | Classification |
|----------|------------|-------------|----------------|
| A-001 | **XRPL Master Keys** | Primary signing keys for wallets | CRITICAL |
| A-002 | **XRPL Regular Keys** | Secondary signing keys | CRITICAL |
| A-003 | **Seed Phrases** | BIP-39 mnemonic recovery phrases | CRITICAL |
| A-004 | **Master Encryption Key** | Key derived from user password | CRITICAL |

#### 3.1.2 High-Value Assets

| Asset ID | Asset Name | Description | Classification |
|----------|------------|-------------|----------------|
| A-005 | **Encrypted Keystore Files** | AES-256-GCM encrypted wallet data | HIGH |
| A-006 | **Policy Configurations** | Transaction limits, allowlists | HIGH |
| A-007 | **User Passwords** | Password used for key derivation | HIGH |
| A-008 | **Session Credentials** | Active authentication tokens | HIGH |

#### 3.1.3 Sensitive Assets

| Asset ID | Asset Name | Description | Classification |
|----------|------------|-------------|----------------|
| A-009 | **Audit Logs** | Tamper-evident operation history | SENSITIVE |
| A-010 | **XRPL Account Addresses** | Public wallet identifiers | SENSITIVE |
| A-011 | **Transaction History** | Record of signed transactions | SENSITIVE |
| A-012 | **Rate Limit State** | Current rate limiting counters | SENSITIVE |

### 3.2 Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DATA FLOWS                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  [DF-1] MCP Tool Request                                                    │
│  ┌─────────┐    JSON-RPC     ┌─────────────┐                               │
│  │  Agent  │ ───────────────▶│ Input Layer │                               │
│  └─────────┘                 └─────────────┘                               │
│                                                                             │
│  [DF-2] Policy Evaluation                                                   │
│  ┌─────────────┐  validated   ┌─────────────┐                              │
│  │ Input Layer │ ────────────▶│Policy Engine│                              │
│  └─────────────┘   request    └─────────────┘                              │
│                                                                             │
│  [DF-3] Key Access                                                          │
│  ┌─────────────┐  auth'd req  ┌─────────────┐                              │
│  │Policy Engine│ ────────────▶│Signing Svc  │                              │
│  └─────────────┘              └──────┬──────┘                              │
│                                      │                                      │
│  [DF-4] Key Decryption               │ encrypted                           │
│  ┌─────────────┐              ┌──────▼──────┐                              │
│  │  Keystore   │◀─────────────│Signing Svc  │                              │
│  └─────────────┘   key req    └─────────────┘                              │
│                                                                             │
│  [DF-5] Transaction Signing (in-memory)                                     │
│  ┌─────────────┐  plaintext   ┌─────────────┐                              │
│  │ Decrypted   │ ────────────▶│   Sign &    │                              │
│  │    Key      │     key      │   Zero Mem  │                              │
│  └─────────────┘              └─────────────┘                              │
│                                                                             │
│  [DF-6] Network Submission                                                  │
│  ┌─────────────┐  signed tx   ┌─────────────┐                              │
│  │Signing Svc  │ ────────────▶│XRPL Network │                              │
│  └─────────────┘    TLS 1.3   └─────────────┘                              │
│                                                                             │
│  [DF-7] Audit Logging (all operations)                                      │
│  ┌─────────────┐   log entry  ┌─────────────┐                              │
│  │ All Layers  │ ────────────▶│ Audit Store │                              │
│  └─────────────┘              └─────────────┘                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Trust Boundaries

| Boundary ID | Description | Crossing Points |
|-------------|-------------|-----------------|
| **TB-1** | External to MCP Server | MCP tool interface |
| **TB-2** | MCP Server to Keystore | File system access |
| **TB-3** | MCP Server to XRPL Network | WebSocket connection |
| **TB-4** | Encrypted to Decrypted Key Space | In-memory signing |

---

## 4. Threat Actors

### 4.1 Threat Actor Profiles

#### TA-001: External Attacker (Remote)

| Attribute | Description |
|-----------|-------------|
| **Motivation** | Financial gain, cryptocurrency theft |
| **Capability** | High - Sophisticated attack tools, exploit development |
| **Access** | Network-based, no prior access |
| **Resources** | Moderate to high (organized crime, state-sponsored) |
| **Target Assets** | Private keys, wallet funds, credentials |
| **Attack Vectors** | Network attacks, supply chain, zero-days |

#### TA-002: Malicious Agent (Compromised LLM)

| Attribute | Description |
|-----------|-------------|
| **Motivation** | Execute unauthorized transactions via prompt injection |
| **Capability** | Medium - Limited by MCP interface constraints |
| **Access** | Authorized MCP interface access |
| **Resources** | Low (leveraging existing access) |
| **Target Assets** | Transaction authorization, policy bypass |
| **Attack Vectors** | Prompt injection, input manipulation |

#### TA-003: Insider Threat (Compromised Operator)

| Attribute | Description |
|-----------|-------------|
| **Motivation** | Financial gain, sabotage, coercion |
| **Capability** | High - System knowledge, privileged access |
| **Access** | Administrative access, configuration control |
| **Resources** | Low to moderate |
| **Target Assets** | Keys, configurations, audit logs |
| **Attack Vectors** | Privilege abuse, configuration tampering |

#### TA-004: Supply Chain Attacker

| Attribute | Description |
|-----------|-------------|
| **Motivation** | Mass compromise, backdoor installation |
| **Capability** | Very high - Advanced persistence, stealth |
| **Access** | Via compromised dependencies |
| **Resources** | High (nation-state level) |
| **Target Assets** | Code integrity, key material, all data |
| **Attack Vectors** | Malicious packages, dependency confusion |

#### TA-005: Network Adversary (MITM)

| Attribute | Description |
|-----------|-------------|
| **Motivation** | Transaction interception, data theft |
| **Capability** | Medium - Network position required |
| **Access** | Network path between client and XRPL |
| **Resources** | Moderate |
| **Target Assets** | Transactions, account information |
| **Attack Vectors** | TLS downgrade, certificate spoofing |

---

## 5. Attack Surface Analysis

### 5.1 MCP Tool Interface

**Entry Points:**

| Entry Point | Tools Exposed | Risk Level |
|-------------|---------------|------------|
| `create_wallet` | Key generation, seed phrase | HIGH |
| `import_wallet` | Seed phrase input, key storage | CRITICAL |
| `export_wallet` | Key material output | CRITICAL |
| `sign_transaction` | Key access, signing | CRITICAL |
| `submit_transaction` | Network communication | HIGH |
| `get_balance` | Account enumeration | MEDIUM |
| `get_account_info` | Information disclosure | MEDIUM |
| `set_policy` | Policy modification | HIGH |

**Attack Considerations:**
- All inputs come from potentially compromised LLM
- Prompt injection can manipulate tool parameters
- Rate limiting essential for all sensitive operations
- Schema validation required before any processing

### 5.2 Keystore File System

**Attack Surface:**

| Vector | Description | Risk Level |
|--------|-------------|------------|
| File path traversal | Accessing arbitrary files | HIGH |
| Permission escalation | Reading protected files | HIGH |
| Symbolic link attacks | Redirecting file operations | MEDIUM |
| Temp file exposure | Plaintext in temp files | HIGH |
| Backup file leakage | Unencrypted backups | HIGH |

**Mitigations Required:**
- Strict path canonicalization
- File permission enforcement (0600)
- No symlink following
- Secure temp file handling
- Encrypted backups only

### 5.3 Memory During Signing

**Attack Surface:**

| Vector | Description | Risk Level |
|--------|-------------|------------|
| Memory dump | Key extraction from RAM | CRITICAL |
| Core dump exposure | Crash dumps containing keys | CRITICAL |
| Swap file leakage | Keys paged to disk | HIGH |
| Memory scanning | Process memory inspection | HIGH |
| JavaScript GC delay | Keys persist in memory | MEDIUM |

**Mitigations Required:**
- Immediate memory zeroing after use
- Disable core dumps
- Memory-locked allocations where possible
- Minimize key lifetime in memory
- Consider TEE for signing operations

### 5.4 Network Communications (XRPL)

**Attack Surface:**

| Vector | Description | Risk Level |
|--------|-------------|------------|
| TLS downgrade | Forcing weak encryption | HIGH |
| Certificate spoofing | Fake XRPL server | HIGH |
| DNS hijacking | Redirecting connections | HIGH |
| Connection hijacking | Taking over sessions | MEDIUM |
| Traffic analysis | Transaction correlation | LOW |

**Mitigations Required:**
- TLS 1.3 minimum, certificate pinning
- DNS over HTTPS/TLS
- Connection integrity verification
- Multiple XRPL node validation

### 5.5 Dependencies (npm Packages)

**Attack Surface:**

| Vector | Description | Risk Level |
|--------|-------------|------------|
| Malicious package | Backdoored dependency | CRITICAL |
| Dependency confusion | Wrong package resolution | HIGH |
| Typosquatting | Similar package names | HIGH |
| Compromised maintainer | Account takeover | HIGH |
| Transitive vulnerabilities | Nested dependency issues | MEDIUM |

**Mitigations Required:**
- Lockfile enforcement
- Package integrity verification
- SBOM generation and tracking
- Regular dependency audits
- Minimal dependency footprint

---

## 6. STRIDE Analysis

### 6.1 Spoofing (Identity Attacks)

#### S-001: Agent Identity Spoofing

| Attribute | Value |
|-----------|-------|
| **Description** | Malicious entity impersonates authorized AI agent |
| **Attack Vector** | Forged MCP client credentials, session hijacking |
| **Target Assets** | A-008 Session Credentials |
| **Likelihood** | Medium |
| **Impact** | Critical |
| **Mitigations** | Agent attestation (KYA), cryptographic identity, session binding |

#### S-002: XRPL Node Spoofing

| Attribute | Value |
|-----------|-------|
| **Description** | Attacker presents fake XRPL node to intercept transactions |
| **Attack Vector** | DNS hijacking, certificate spoofing |
| **Target Assets** | Signed transactions, account information |
| **Likelihood** | Low |
| **Impact** | High |
| **Mitigations** | Certificate pinning, multiple node validation, TLS 1.3 |

#### S-003: Tool Response Spoofing

| Attribute | Value |
|-----------|-------|
| **Description** | Injected responses make agent believe operations succeeded |
| **Attack Vector** | MITM on MCP communication, response injection |
| **Target Assets** | Transaction state, wallet state |
| **Likelihood** | Low |
| **Impact** | Medium |
| **Mitigations** | Response signing, integrity verification |

### 6.2 Tampering (Data Modification)

#### T-001: Keystore File Tampering

| Attribute | Value |
|-----------|-------|
| **Description** | Modification of encrypted keystore files |
| **Attack Vector** | File system access, backup replacement |
| **Target Assets** | A-005 Encrypted Keystore Files |
| **Likelihood** | Medium |
| **Impact** | Critical |
| **Mitigations** | HMAC integrity verification, file checksums, backup validation |

#### T-002: Policy Configuration Tampering

| Attribute | Value |
|-----------|-------|
| **Description** | Unauthorized modification of policy rules |
| **Attack Vector** | Insider threat, configuration injection |
| **Target Assets** | A-006 Policy Configurations |
| **Likelihood** | Medium |
| **Impact** | High |
| **Mitigations** | Signed configurations, change audit logging, multi-party approval |

#### T-003: Audit Log Tampering

| Attribute | Value |
|-----------|-------|
| **Description** | Modification or deletion of audit records |
| **Attack Vector** | Insider threat, compromised storage |
| **Target Assets** | A-009 Audit Logs |
| **Likelihood** | Medium |
| **Impact** | High |
| **Mitigations** | Hash chains, append-only storage, external backup |

#### T-004: Transaction Tampering

| Attribute | Value |
|-----------|-------|
| **Description** | Modification of transaction parameters before signing |
| **Attack Vector** | Memory manipulation, input injection |
| **Target Assets** | Transaction data |
| **Likelihood** | Low |
| **Impact** | Critical |
| **Mitigations** | Transaction verification before signing, parameter binding |

### 6.3 Repudiation (Deniability Attacks)

#### R-001: Transaction Non-Repudiation Failure

| Attribute | Value |
|-----------|-------|
| **Description** | Agent or user denies authorizing a transaction |
| **Attack Vector** | Insufficient logging, log tampering |
| **Target Assets** | A-009 Audit Logs, A-011 Transaction History |
| **Likelihood** | Medium |
| **Impact** | High |
| **Mitigations** | Cryptographic audit logs, transaction signatures, timestamps |

#### R-002: Policy Change Repudiation

| Attribute | Value |
|-----------|-------|
| **Description** | Operator denies making policy changes |
| **Attack Vector** | Insufficient change tracking |
| **Target Assets** | A-006 Policy Configurations |
| **Likelihood** | Medium |
| **Impact** | Medium |
| **Mitigations** | Signed change requests, version control, approval workflows |

### 6.4 Information Disclosure (Key Leakage)

#### I-001: Private Key Extraction via Memory

| Attribute | Value |
|-----------|-------|
| **Description** | Extraction of decrypted private keys from memory |
| **Attack Vector** | Memory dump, debugging, core dump |
| **Target Assets** | A-001 Master Keys, A-002 Regular Keys |
| **Likelihood** | Medium |
| **Impact** | Critical |
| **Mitigations** | Memory zeroing, TEE, disable debugging, no core dumps |

#### I-002: Seed Phrase Leakage

| Attribute | Value |
|-----------|-------|
| **Description** | Exposure of seed phrases through logs or errors |
| **Attack Vector** | Verbose logging, error messages, stack traces |
| **Target Assets** | A-003 Seed Phrases |
| **Likelihood** | Medium |
| **Impact** | Critical |
| **Mitigations** | Secret filtering in logs, structured error handling |

#### I-003: Keystore File Theft

| Attribute | Value |
|-----------|-------|
| **Description** | Unauthorized access to encrypted keystore files |
| **Attack Vector** | File system access, backup theft, cloud storage breach |
| **Target Assets** | A-005 Encrypted Keystore Files |
| **Likelihood** | Medium |
| **Impact** | High (enables offline brute force) |
| **Mitigations** | Strong encryption, file permissions, access monitoring |

#### I-004: Password Exposure

| Attribute | Value |
|-----------|-------|
| **Description** | Leakage of user password via various channels |
| **Attack Vector** | Logging, memory, command line history |
| **Target Assets** | A-007 User Passwords |
| **Likelihood** | Medium |
| **Impact** | Critical |
| **Mitigations** | Never log passwords, secure input handling, memory protection |

#### I-005: Account Enumeration

| Attribute | Value |
|-----------|-------|
| **Description** | Disclosure of wallet addresses and balances |
| **Attack Vector** | Unauthorized queries, side-channel timing |
| **Target Assets** | A-010 XRPL Account Addresses |
| **Likelihood** | High |
| **Impact** | Low |
| **Mitigations** | Rate limiting, authentication for all queries |

### 6.5 Denial of Service (Resource Exhaustion)

#### D-001: Rate Limit Exhaustion

| Attribute | Value |
|-----------|-------|
| **Description** | Consuming all available rate limit tokens |
| **Attack Vector** | Rapid repeated requests |
| **Target Assets** | Service availability |
| **Likelihood** | High |
| **Impact** | Medium |
| **Mitigations** | Per-client rate limiting, backoff strategies |

#### D-002: Computational Exhaustion (KDF)

| Attribute | Value |
|-----------|-------|
| **Description** | Triggering expensive key derivation operations |
| **Attack Vector** | Repeated authentication attempts |
| **Target Assets** | CPU resources, service availability |
| **Likelihood** | High |
| **Impact** | Medium |
| **Mitigations** | Authentication lockout, request throttling |

#### D-003: Memory Exhaustion

| Attribute | Value |
|-----------|-------|
| **Description** | Filling memory with large payloads |
| **Attack Vector** | Large transaction data, many concurrent operations |
| **Target Assets** | Memory resources, service availability |
| **Likelihood** | Medium |
| **Impact** | High |
| **Mitigations** | Input size limits, memory quotas, concurrent operation limits |

#### D-004: XRPL Connection Exhaustion

| Attribute | Value |
|-----------|-------|
| **Description** | Exhausting connections to XRPL nodes |
| **Attack Vector** | Many concurrent network requests |
| **Target Assets** | Network connectivity |
| **Likelihood** | Medium |
| **Impact** | Medium |
| **Mitigations** | Connection pooling, request queuing, multiple nodes |

### 6.6 Elevation of Privilege (Policy Bypass)

#### E-001: Prompt Injection for Unauthorized Transactions

| Attribute | Value |
|-----------|-------|
| **Description** | Manipulating LLM to authorize transactions beyond policy |
| **Attack Vector** | Crafted prompts in transaction memos, external content |
| **Target Assets** | Transaction authorization |
| **Likelihood** | High |
| **Impact** | Critical |
| **Mitigations** | Policy engine enforcement, input sanitization, human-in-the-loop |

#### E-002: Policy Bypass via Input Manipulation

| Attribute | Value |
|-----------|-------|
| **Description** | Crafted inputs that bypass policy checks |
| **Attack Vector** | Edge cases, type confusion, encoding tricks |
| **Target Assets** | A-006 Policy Configurations |
| **Likelihood** | Medium |
| **Impact** | Critical |
| **Mitigations** | Strict schema validation, canonical form processing |

#### E-003: Tool Privilege Escalation

| Attribute | Value |
|-----------|-------|
| **Description** | Using low-privilege tools to gain high-privilege access |
| **Attack Vector** | Chained tool calls, race conditions |
| **Target Assets** | Tool authorization |
| **Likelihood** | Low |
| **Impact** | High |
| **Mitigations** | Per-operation authorization, no privilege inheritance |

#### E-004: Insider Privilege Abuse

| Attribute | Value |
|-----------|-------|
| **Description** | Operator using access for unauthorized operations |
| **Attack Vector** | Administrative access abuse |
| **Target Assets** | All assets |
| **Likelihood** | Low |
| **Impact** | Critical |
| **Mitigations** | Separation of duties, multi-party authorization, audit logging |

---

## 7. Threat Matrix

### 7.1 Complete Threat Registry

| ID | Threat | STRIDE | Threat Actor | Likelihood | Impact | Risk Score | Priority |
|----|--------|--------|--------------|------------|--------|------------|----------|
| **T-001** | Prompt injection triggering unauthorized transactions | E | TA-002 | High | Critical | **CRITICAL** | P0 |
| **T-002** | Key extraction via memory exposure | I | TA-001 | Medium | Critical | **HIGH** | P1 |
| **T-003** | Policy bypass through input manipulation | E | TA-002 | Medium | Critical | **HIGH** | P1 |
| **T-004** | Insider threat from compromised operator | E | TA-003 | Low | Critical | **HIGH** | P1 |
| **T-005** | Supply chain attack via malicious dependency | T | TA-004 | Low | Critical | **HIGH** | P1 |
| **T-006** | MITM attack on XRPL communication | S, I | TA-005 | Low | High | **MEDIUM** | P2 |
| **T-007** | Sequence manipulation attack | T | TA-001 | Low | High | **MEDIUM** | P2 |
| **T-008** | Fee escalation attack | T | TA-002 | Medium | Medium | **MEDIUM** | P2 |
| **T-009** | Keystore file theft | I | TA-001 | Medium | High | **HIGH** | P1 |
| **T-010** | Brute force password attack | I | TA-001 | Medium | Critical | **HIGH** | P1 |
| **T-011** | Seed phrase logging exposure | I | TA-001 | Medium | Critical | **HIGH** | P1 |
| **T-012** | Audit log tampering | R | TA-003 | Medium | High | **MEDIUM** | P2 |
| **T-013** | Rate limit exhaustion DoS | D | TA-001 | High | Medium | **MEDIUM** | P2 |
| **T-014** | KDF computational DoS | D | TA-001 | High | Medium | **MEDIUM** | P2 |
| **T-015** | Agent identity spoofing | S | TA-001 | Medium | Critical | **HIGH** | P1 |
| **T-016** | Configuration injection | T | TA-003 | Low | High | **MEDIUM** | P2 |
| **T-017** | Memory exhaustion DoS | D | TA-001 | Medium | High | **MEDIUM** | P2 |
| **T-018** | Transaction parameter tampering | T | TA-002 | Low | Critical | **HIGH** | P1 |
| **T-019** | Tool chaining privilege escalation | E | TA-002 | Low | High | **MEDIUM** | P2 |
| **T-020** | Backup file leakage | I | TA-001 | Medium | High | **MEDIUM** | P2 |

### 7.2 Risk Scoring Methodology

**Likelihood Scale:**
- **High**: Expected to occur, multiple attack paths
- **Medium**: Feasible attack, requires specific conditions
- **Low**: Difficult to execute, requires significant resources

**Impact Scale:**
- **Critical**: Complete key compromise, total fund loss
- **High**: Significant fund loss, system compromise
- **Medium**: Service disruption, information disclosure
- **Low**: Minor inconvenience, limited exposure

**Risk Score Matrix:**

|              | Low Impact | Medium Impact | High Impact | Critical Impact |
|--------------|------------|---------------|-------------|-----------------|
| **High Likelihood** | Medium | Medium | High | Critical |
| **Medium Likelihood** | Low | Medium | Medium/High | High |
| **Low Likelihood** | Low | Low | Medium | High |

### 7.3 Mitigation Summary

| Threat ID | Primary Mitigation | Secondary Mitigation | Status |
|-----------|-------------------|---------------------|--------|
| T-001 | Policy engine with hard limits | Human-in-the-loop for high value | Required |
| T-002 | TEE signing environment | Memory zeroing, SecureBuffer | Required |
| T-003 | Strict zod schema validation | Canonical input processing | Required |
| T-004 | Multi-party authorization | Separation of duties | Required |
| T-005 | Lockfile enforcement, SBOM | Dependency auditing | Required |
| T-006 | TLS 1.3, certificate pinning | Multiple node validation | Required |
| T-007 | Sequence tracking, account monitoring | Transaction verification | Required |
| T-008 | Fee limits in policy | Fee reasonableness checks | Required |
| T-009 | File permissions (0600) | Access monitoring | Required |
| T-010 | Argon2id with high params | Account lockout | Required |
| T-011 | Secret filtering in logs | Structured error handling | Required |
| T-012 | Hash chain integrity | Append-only storage | Required |
| T-013 | Per-client rate limiting | Backoff strategies | Required |
| T-014 | Authentication lockout | Request throttling | Required |
| T-015 | KYA agent attestation | Cryptographic identity | Planned |
| T-016 | Signed configurations | Version control | Required |
| T-017 | Input size limits | Memory quotas | Required |
| T-018 | Pre-sign verification | Parameter binding | Required |
| T-019 | Per-operation authorization | No privilege inheritance | Required |
| T-020 | Encrypted backups only | Backup access controls | Required |

---

## 8. Attack Trees

### 8.1 Attack Tree: T-001 - Prompt Injection for Unauthorized Transactions

```
[ROOT] Unauthorized Transaction Execution
│
├── [AND] Bypass Policy Engine
│   │
│   ├── [OR] Inject malicious prompt content
│   │   ├── Via transaction memo field
│   │   ├── Via external website content
│   │   ├── Via email/message content
│   │   └── Via document content
│   │
│   └── [OR] Exploit policy gaps
│       ├── Transaction splitting (stay under limits)
│       ├── Time-based policy gaps
│       └── Allowlist exploitation
│
├── [AND] Manipulate Transaction Parameters
│   │
│   ├── [OR] Modify destination address
│   │   ├── Substitute with attacker address
│   │   └── Exploit address parsing
│   │
│   ├── [OR] Modify amount
│   │   ├── Increase beyond authorized
│   │   └── Decimal manipulation
│   │
│   └── [OR] Add unauthorized fields
│       └── Inject malicious memo
│
└── [AND] Circumvent Human Review
    │
    ├── [OR] Social engineering via injected content
    │   ├── Urgent language in transaction context
    │   └── Authority impersonation
    │
    └── [OR] Review fatigue exploitation
        └── Flood with legitimate-looking requests

MITIGATIONS:
[M1] Strict input sanitization at MCP boundary
[M2] Policy engine with immutable limits
[M3] Transaction parameter binding and verification
[M4] Human-in-the-loop for transactions above threshold
[M5] Rate limiting and anomaly detection
[M6] Allowlist-only destinations for high values
```

### 8.2 Attack Tree: T-002 - Key Extraction via Memory

```
[ROOT] Extract Private Keys from Memory
│
├── [OR] Direct Memory Access
│   │
│   ├── Memory dump attack
│   │   ├── Process memory read
│   │   ├── /proc/[pid]/mem access
│   │   └── Debugger attachment
│   │
│   ├── Core dump capture
│   │   ├── Crash triggering
│   │   └── SIGABRT injection
│   │
│   └── Swap file analysis
│       └── Disk forensics
│
├── [OR] JavaScript Runtime Exploitation
│   │
│   ├── V8 heap exploitation
│   │   ├── Heap spray attacks
│   │   └── Use-after-free
│   │
│   ├── GC timing attacks
│   │   └── Key persists longer than expected
│   │
│   └── String interning
│       └── Key converted to string
│
└── [OR] Side Channel Attacks
    │
    ├── Timing attacks
    │   └── Key-dependent timing
    │
    └── Cache attacks
        └── Cache line analysis

MITIGATIONS:
[M1] TEE-based signing (Nitro Enclaves)
[M2] Immediate memory zeroing via SecureBuffer
[M3] Disable core dumps (ulimit -c 0)
[M4] mlock for key memory (where possible)
[M5] Minimize key lifetime in memory
[M6] Never convert keys to strings
[M7] Consider native signing module (Rust/C++)
```

### 8.3 Attack Tree: T-005 - Supply Chain Attack

```
[ROOT] Compromise via Malicious Dependency
│
├── [OR] Direct Dependency Attack
│   │
│   ├── Typosquatting
│   │   ├── Similar package name (xrp1-lib)
│   │   └── Common typo variants
│   │
│   ├── Package hijacking
│   │   ├── Maintainer account compromise
│   │   └── Abandoned package takeover
│   │
│   └── Malicious update
│       └── Trusted package goes rogue
│
├── [OR] Transitive Dependency Attack
│   │
│   ├── Deep dependency compromise
│   │   └── Attack low-visibility package
│   │
│   └── Dependency confusion
│       └── Internal package name collision
│
├── [OR] Build/Publish Attack
│   │
│   ├── CI/CD compromise
│   │   └── Inject code during build
│   │
│   └── Registry compromise
│       └── npm registry attack
│
└── [OR] Execution Vector
    │
    ├── Install script execution
    │   └── postinstall hook
    │
    ├── Runtime code execution
    │   └── require() evaluation
    │
    └── Data exfiltration
        └── Key material to C2

MITIGATIONS:
[M1] Lockfile enforcement (npm ci)
[M2] Package integrity verification
[M3] ignore-scripts=true in .npmrc
[M4] SBOM generation and tracking
[M5] Regular dependency audits (snyk, npm audit)
[M6] Minimal dependency footprint
[M7] Pin exact versions (no ranges)
[M8] Private registry mirror
```

### 8.4 Attack Tree: T-010 - Brute Force Password Attack

```
[ROOT] Compromise Encryption Password
│
├── [OR] Online Attack (against running service)
│   │
│   ├── Credential stuffing
│   │   └── Known password lists
│   │
│   ├── Dictionary attack
│   │   └── Common passwords
│   │
│   └── Rate limit bypass
│       ├── Distributed attack
│       └── Slowloris-style attack
│
├── [OR] Offline Attack (against keystore file)
│   │
│   ├── [AND] Obtain keystore file
│   │   ├── File system access
│   │   ├── Backup theft
│   │   └── Cloud storage breach
│   │
│   └── [AND] Brute force password
│       ├── GPU-accelerated attack
│       ├── ASIC attack
│       └── Rainbow table (if salt weak)
│
└── [OR] Password Interception
    │
    ├── Keylogger
    │   └── Compromise operator system
    │
    ├── Shoulder surfing
    │   └── Physical observation
    │
    └── Phishing
        └── Fake MCP interface

MITIGATIONS:
[M1] Argon2id with high memory cost (64MB+)
[M2] Account lockout after failed attempts
[M3] Progressive lockout duration
[M4] Strong password requirements
[M5] File permissions (0600)
[M6] Encrypted backup storage
[M7] Two-factor authentication (future)
[M8] Hardware security key support (future)
```

---

## 9. Residual Risks

### 9.1 Accepted Risks

| Risk ID | Description | Residual Risk | Acceptance Rationale |
|---------|-------------|---------------|---------------------|
| RR-001 | JavaScript memory model limitations | Medium | Node.js constraints; mitigated by SecureBuffer and short key lifetime |
| RR-002 | Dependency on XRPL network availability | Low | Outside system control; multiple node connections mitigate |
| RR-003 | LLM inherent unpredictability | Medium | Fundamental to use case; policy engine provides hard limits |
| RR-004 | Password strength variation | Medium | User responsibility; guidance provided, minimum requirements enforced |

### 9.2 Risks Requiring Monitoring

| Risk ID | Description | Monitoring Approach | Escalation Trigger |
|---------|-------------|--------------------|--------------------|
| RM-001 | Emerging prompt injection techniques | Security research monitoring, OWASP updates | New bypass discovered |
| RM-002 | New cryptographic vulnerabilities | CVE monitoring, security advisories | AES-GCM or Ed25519 weakness |
| RM-003 | Supply chain attack patterns | npm security advisories, threat intel | New attack vector identified |
| RM-004 | Regulatory changes | Legal monitoring | New compliance requirements |

### 9.3 Risks Requiring Future Mitigation

| Risk ID | Description | Planned Mitigation | Target Timeline |
|---------|-------------|-------------------|-----------------|
| RF-001 | No TEE implementation | AWS Nitro Enclaves integration | Phase 2 |
| RF-002 | No KYA agent identity | Agent attestation framework | Phase 2 |
| RF-003 | Limited multi-party authorization | Multi-signature workflow | Phase 2 |
| RF-004 | No hardware key support | HSM/hardware wallet integration | Phase 3 |

### 9.4 Risk Treatment Summary

```
                    Risk Treatment Distribution
    ┌────────────────────────────────────────────────────┐
    │                                                    │
    │   Mitigated ██████████████████████████░░░░  75%    │
    │                                                    │
    │   Monitored ████████░░░░░░░░░░░░░░░░░░░░░░  15%    │
    │                                                    │
    │   Accepted  ███░░░░░░░░░░░░░░░░░░░░░░░░░░░   7%    │
    │                                                    │
    │   Future    █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   3%    │
    │                                                    │
    └────────────────────────────────────────────────────┘
```

---

## 10. References

### 10.1 Threat Modeling Standards

- [Microsoft STRIDE](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- [NIST SP 800-154 Guide to Data-Centric Threat Modeling](https://csrc.nist.gov/publications/detail/sp/800-154/draft)

### 10.2 AI/LLM Security

- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llmrisk/)
- [MITRE ATLAS (Adversarial Threat Landscape for AI Systems)](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)

### 10.3 Cryptocurrency Wallet Security

- [Bitcoin Wallet Security](https://bitcoin.org/en/secure-your-wallet)
- [Ethereum Key Management](https://ethereum.org/en/developers/docs/smart-contracts/security/)
- [XRPL Security Guidelines](https://xrpl.org/security.html)

### 10.4 Supply Chain Security

- [CISA Software Supply Chain Security](https://www.cisa.gov/supply-chain-compromise)
- [OpenSSF Security Scorecards](https://securityscorecards.dev/)
- [npm Security Best Practices](https://docs.npmjs.com/packages-and-modules/securing-your-code)

### 10.5 Cryptographic Standards

- [NIST SP 800-38D (GCM Mode)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [NIST SP 800-132 (Key Derivation)](https://csrc.nist.gov/publications/detail/sp/800-132/final)
- [Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106)

### 10.6 Related Project Documents

- [Security Architecture](./SECURITY-ARCHITECTURE.md)
- [AI Agent Wallet Security Research](../research/ai-agent-wallet-security-2025-2026.md)

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Security Specialist | Initial threat model |

**Next Review Date:** 2026-04-28

**Approval Required From:**
- [ ] Security Lead
- [ ] Technical Lead
- [ ] Product Owner

---

*This threat model is a living document and should be updated whenever significant changes are made to the system architecture, new threats are identified, or after security incidents.*
