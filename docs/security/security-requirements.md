# XRPL Agent Wallet MCP Server - Security Requirements Specification

**Version:** 1.0.0
**Date:** 2026-01-28
**Author:** Security Specialist
**Classification:** Internal/Public
**Status:** Draft
**Review Cycle:** Quarterly

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Requirements Categories](#2-requirements-categories)
   - [2.1 Authentication (AUTH)](#21-authentication-auth)
   - [2.2 Authorization (AUTHZ)](#22-authorization-authz)
   - [2.3 Encryption (ENC)](#23-encryption-enc)
   - [2.4 Key Management (KEY)](#24-key-management-key)
   - [2.5 Input Validation (VAL)](#25-input-validation-val)
   - [2.6 Audit Logging (AUDIT)](#26-audit-logging-audit)
   - [2.7 Rate Limiting (RATE)](#27-rate-limiting-rate)
   - [2.8 Error Handling (ERR)](#28-error-handling-err)
3. [Traceability Matrix](#3-traceability-matrix)
4. [Verification Methods Table](#4-verification-methods-table)
5. [Implementation Priority Matrix](#5-implementation-priority-matrix)
6. [References](#6-references)

---

## 1. Executive Summary

### 1.1 Purpose

This document specifies security requirements for the XRPL Agent Wallet MCP (Model Context Protocol) server. These requirements are derived from the threat model (v1.0.0) and establish testable, measurable security controls to protect against identified threats.

### 1.2 Scope

These requirements cover:
- Authentication mechanisms for wallet access
- Authorization controls for MCP tool operations
- Cryptographic protections for data at rest and in transit
- Key generation, storage, and lifecycle management
- Input validation and prompt injection defense
- Tamper-evident audit logging
- Rate limiting and denial-of-service protection
- Secure error handling practices

### 1.3 Requirement Priorities

| Priority | Definition | SLA |
|----------|------------|-----|
| **Critical** | Must be implemented before production deployment | Phase 1 |
| **High** | Must be implemented within 30 days of production | Phase 1-2 |
| **Medium** | Should be implemented within 90 days of production | Phase 2 |
| **Low** | Recommended for future releases | Phase 3 |

### 1.4 Requirement Format

Each requirement includes:
- **ID**: Unique identifier (CATEGORY-NNN)
- **Title**: Brief descriptive title
- **Description**: Detailed requirement specification
- **Rationale**: Why this requirement exists
- **Mitigates**: Threat IDs from threat model
- **Priority**: Critical/High/Medium/Low
- **Verification**: How to test compliance
- **Acceptance Criteria**: Specific measurable outcomes

---

## 2. Requirements Categories

### 2.1 Authentication (AUTH)

#### AUTH-001: Password-Based Key Derivation with Argon2id

| Attribute | Value |
|-----------|-------|
| **Title** | Argon2id Key Derivation for Password Authentication |
| **Description** | The system SHALL derive encryption keys from user passwords using Argon2id with the following minimum parameters: memory cost of 64MB (65,536 KB), time cost of 3 iterations, parallelism of 4 threads, and output key length of 256 bits. |
| **Rationale** | Argon2id provides resistance against both side-channel and GPU-based attacks, making offline password cracking computationally infeasible. |
| **Mitigates** | T-010 (Brute force password attack) |
| **Priority** | Critical |
| **Verification** | Unit test verifying Argon2id parameters; security audit of KDF implementation |
| **Acceptance Criteria** | - Argon2id is used (not Argon2i or Argon2d alone)<br>- Memory cost >= 64MB<br>- Time cost >= 3<br>- Key derivation takes >= 500ms on reference hardware<br>- Salt is 32 bytes, cryptographically random |

#### AUTH-002: Progressive Account Lockout

| Attribute | Value |
|-----------|-------|
| **Title** | Progressive Lockout After Failed Authentication Attempts |
| **Description** | The system SHALL implement progressive account lockout: after 5 failed authentication attempts within 15 minutes, the account SHALL be locked for 30 minutes. Subsequent lockouts SHALL double in duration (30 min, 60 min, 120 min, max 24 hours). |
| **Rationale** | Prevents online brute force attacks while limiting impact on legitimate users who mistype passwords. |
| **Mitigates** | T-010 (Brute force password attack), T-014 (KDF computational DoS) |
| **Priority** | Critical |
| **Verification** | Integration test simulating failed login attempts; verify lockout triggers and durations |
| **Acceptance Criteria** | - Lockout after exactly 5 failures in 15-minute window<br>- Initial lockout duration is 30 minutes<br>- Lockout duration doubles each time (verified up to 24h max)<br>- Successful login resets failure counter<br>- Lockout events are logged |

#### AUTH-003: Secure Session Management

| Attribute | Value |
|-----------|-------|
| **Title** | Cryptographically Secure Session Token Management |
| **Description** | The system SHALL generate session tokens using cryptographically secure random number generation (256 bits minimum entropy). Sessions SHALL expire after 30 minutes of inactivity and have a maximum lifetime of 8 hours. |
| **Rationale** | Prevents session hijacking and limits exposure window for compromised sessions. |
| **Mitigates** | T-015 (Agent identity spoofing), S-001 (Agent Identity Spoofing) |
| **Priority** | High |
| **Verification** | Security audit of session token generation; automated tests for expiration |
| **Acceptance Criteria** | - Session tokens are 256 bits, generated via crypto.randomBytes<br>- Idle timeout enforced at 30 minutes<br>- Absolute timeout enforced at 8 hours<br>- Session invalidation on logout is immediate<br>- Expired sessions cannot be reused |

#### AUTH-004: Password Complexity Requirements

| Attribute | Value |
|-----------|-------|
| **Title** | Minimum Password Complexity Enforcement |
| **Description** | The system SHALL enforce minimum password requirements: length >= 12 characters, containing at least one uppercase letter, one lowercase letter, one digit, and one special character. Passwords SHALL be checked against known breached password lists. |
| **Rationale** | Weak passwords significantly reduce the effectiveness of Argon2id protection. |
| **Mitigates** | T-010 (Brute force password attack) |
| **Priority** | High |
| **Verification** | Unit tests for password validation logic; integration with HaveIBeenPwned API |
| **Acceptance Criteria** | - Passwords < 12 characters are rejected<br>- Missing character class requirements cause rejection<br>- Known breached passwords are rejected<br>- Password strength meter provided in UI |

#### AUTH-005: Password Never Stored

| Attribute | Value |
|-----------|-------|
| **Title** | Zero Password Storage Policy |
| **Description** | The system SHALL NOT store user passwords in any form (plaintext, hashed, or encrypted). Only the derived key material necessary for decryption operations SHALL be held in memory for the minimum required duration. |
| **Rationale** | Eliminates password database as an attack target. |
| **Mitigates** | I-004 (Password Exposure), T-010 (Brute force password attack) |
| **Priority** | Critical |
| **Verification** | Code review; memory forensics testing; static analysis for password storage patterns |
| **Acceptance Criteria** | - No database tables or files contain passwords<br>- Password variable is zeroed after KDF completes<br>- Memory dump analysis shows no password strings |

#### AUTH-006: Password Input Security

| Attribute | Value |
|-----------|-------|
| **Title** | Secure Password Input Handling |
| **Description** | The system SHALL NOT accept passwords via command line arguments, environment variables, or URL parameters. Passwords SHALL only be accepted via secure input mechanisms (stdin with echo disabled or secure API endpoints over TLS). |
| **Rationale** | Command line arguments and environment variables are visible in process listings and logs. |
| **Mitigates** | I-004 (Password Exposure), T-011 (Seed phrase logging exposure) |
| **Priority** | High |
| **Verification** | Code review; penetration test verifying password not in process args or env |
| **Acceptance Criteria** | - CLI tools use password prompt with hidden input<br>- API endpoints only accept password in request body<br>- Password not logged at any log level<br>- Password not visible in shell history |

---

### 2.2 Authorization (AUTHZ)

#### AUTHZ-001: Tool Permission Classification

| Attribute | Value |
|-----------|-------|
| **Title** | MCP Tool Sensitivity Classification System |
| **Description** | The system SHALL classify all MCP tools into three sensitivity levels: READ_ONLY (balance queries, account info), SENSITIVE (transaction signing, key export), and DESTRUCTIVE (wallet deletion, key rotation). Each tool operation SHALL verify the caller has appropriate authorization for the tool's sensitivity level. |
| **Rationale** | Different operations require different levels of scrutiny and authorization. |
| **Mitigates** | T-003 (Policy bypass), E-003 (Tool Privilege Escalation) |
| **Priority** | Critical |
| **Verification** | Authorization matrix test; attempt to call SENSITIVE tools without authorization |
| **Acceptance Criteria** | - All tools assigned sensitivity classification<br>- READ_ONLY tools succeed with basic authentication<br>- SENSITIVE tools require explicit confirmation<br>- DESTRUCTIVE tools require confirmation + additional verification<br>- Tool classification is documented |

#### AUTHZ-002: Tiered Transaction Signing Approval

| Attribute | Value |
|-----------|-------|
| **Title** | Tiered Approval System Based on Transaction Value |
| **Description** | The system SHALL implement tiered approval for transaction signing:<br>- Tier 1 (< 100 XRP): Automatic after policy check<br>- Tier 2 (100-1,000 XRP): Single confirmation required<br>- Tier 3 (1,000-10,000 XRP): Multi-factor confirmation<br>- Tier 4 (> 10,000 XRP): Human-in-the-loop approval with 24h time-lock |
| **Rationale** | High-value transactions require additional scrutiny to prevent catastrophic loss. |
| **Mitigates** | T-001 (Prompt injection), T-008 (Fee escalation attack), E-001 (Prompt injection for unauthorized transactions) |
| **Priority** | Critical |
| **Verification** | Integration tests for each tier boundary; attempt tier bypass attacks |
| **Acceptance Criteria** | - Transaction amount is calculated before signing<br>- Correct tier is determined for transaction<br>- Tier escalation cannot be bypassed via input manipulation<br>- Time-lock is enforced for Tier 4 transactions<br>- Tier thresholds are configurable |

#### AUTHZ-003: Destination Address Allowlisting

| Attribute | Value |
|-----------|-------|
| **Title** | Configurable Destination Address Allowlist |
| **Description** | The system SHALL support an optional destination address allowlist. When enabled, transactions to addresses not on the allowlist SHALL be rejected. The allowlist SHALL support both explicit addresses and address patterns (e.g., exchange addresses). |
| **Rationale** | Limits transaction destinations to pre-approved addresses, preventing fund extraction to attacker wallets. |
| **Mitigates** | T-001 (Prompt injection), E-001 (Prompt injection for unauthorized transactions) |
| **Priority** | High |
| **Verification** | Test transactions to allowlisted and non-allowlisted addresses |
| **Acceptance Criteria** | - Allowlist can be enabled/disabled<br>- Transactions to non-allowlisted addresses are rejected<br>- Allowlist supports individual addresses<br>- Allowlist supports regex patterns<br>- Allowlist changes are logged |

#### AUTHZ-004: Daily Transaction Limits

| Attribute | Value |
|-----------|-------|
| **Title** | Configurable Daily Transaction Limits |
| **Description** | The system SHALL enforce configurable daily transaction limits per wallet. Default limits SHALL be: 1,000 XRP per day for Tier 1, 10,000 XRP per day for Tier 2, 100,000 XRP per day for Tier 3. Limits reset at midnight UTC. |
| **Rationale** | Limits aggregate extraction even if individual transaction limits are not exceeded. |
| **Mitigates** | T-001 (Prompt injection), E-001 (Prompt injection for unauthorized transactions) |
| **Priority** | High |
| **Verification** | Integration tests exceeding daily limits across multiple transactions |
| **Acceptance Criteria** | - Daily totals tracked per wallet<br>- Transactions exceeding daily limit are rejected<br>- Limit reset occurs at 00:00 UTC<br>- Current usage queryable via tool<br>- Limits are configurable per wallet |

#### AUTHZ-005: Per-Operation Authorization Checks

| Attribute | Value |
|-----------|-------|
| **Title** | No Authorization Inheritance Between Operations |
| **Description** | The system SHALL perform authorization checks for EACH tool operation independently. Authorization for one operation SHALL NOT grant implicit authorization for subsequent operations. Session tokens SHALL NOT inherit elevated privileges. |
| **Rationale** | Prevents privilege escalation through chained operations. |
| **Mitigates** | E-003 (Tool Privilege Escalation), T-019 (Tool chaining privilege escalation) |
| **Priority** | Critical |
| **Verification** | Test chained operations; verify each requires separate authorization |
| **Acceptance Criteria** | - Each tool call performs authorization check<br>- Previous tool success does not bypass next check<br>- Elevated permissions expire immediately after use<br>- No privilege caching between requests |

#### AUTHZ-006: Policy Engine Enforcement

| Attribute | Value |
|-----------|-------|
| **Title** | Immutable Policy Engine with Hard Limits |
| **Description** | The system SHALL implement a policy engine that enforces hard limits regardless of input or context. Policy limits SHALL NOT be modifiable via MCP tool calls. Policy changes SHALL require administrative access and SHALL be logged. |
| **Rationale** | Policy engine provides defense against prompt injection by enforcing limits the LLM cannot override. |
| **Mitigates** | T-001 (Prompt injection), T-003 (Policy bypass), T-016 (Configuration injection) |
| **Priority** | Critical |
| **Verification** | Attempt policy bypass via prompt injection; verify policy immutability |
| **Acceptance Criteria** | - Policy limits enforced for all transactions<br>- No MCP tool can modify policy<br>- Policy changes require separate administrative interface<br>- All policy changes logged with timestamp and actor |

#### AUTHZ-007: Blocklist Enforcement

| Attribute | Value |
|-----------|-------|
| **Title** | Known Malicious Address Blocklist |
| **Description** | The system SHALL maintain a blocklist of known malicious addresses. Transactions to blocklisted addresses SHALL be rejected. The blocklist SHALL be updateable without service restart. |
| **Rationale** | Prevents transactions to known scam or sanctioned addresses. |
| **Mitigates** | T-001 (Prompt injection), E-001 (Prompt injection for unauthorized transactions) |
| **Priority** | High |
| **Verification** | Attempt transaction to blocklisted address; verify rejection |
| **Acceptance Criteria** | - Blocklist is configurable<br>- Hot-reload of blocklist updates supported<br>- Transactions to blocklisted addresses fail<br>- Blocklist match logged with reason |

---

### 2.3 Encryption (ENC)

#### ENC-001: AES-256-GCM for Data at Rest

| Attribute | Value |
|-----------|-------|
| **Title** | AES-256-GCM Encryption for Keystore Files |
| **Description** | The system SHALL encrypt all keystore files using AES-256-GCM with 12-byte (96-bit) initialization vectors and 16-byte (128-bit) authentication tags. Each encryption operation SHALL use a unique IV. |
| **Rationale** | AES-256-GCM provides authenticated encryption, ensuring both confidentiality and integrity. |
| **Mitigates** | T-009 (Keystore file theft), I-003 (Keystore File Theft), T-001 (Keystore File Tampering) |
| **Priority** | Critical |
| **Verification** | Cryptographic audit; verify encrypted file format; attempt decryption with wrong key |
| **Acceptance Criteria** | - Algorithm is aes-256-gcm<br>- IV is 12 bytes, unique per encryption<br>- Auth tag is 16 bytes<br>- Auth tag verification fails for tampered data<br>- Decryption fails for wrong key |

#### ENC-002: Unique IV per Encryption Operation

| Attribute | Value |
|-----------|-------|
| **Title** | Cryptographically Random Unique IVs |
| **Description** | The system SHALL generate a unique, cryptographically random 12-byte IV for every encryption operation using Node.js crypto.randomBytes(). IV SHALL never be reused with the same key. |
| **Rationale** | IV reuse with AES-GCM completely breaks security, allowing ciphertext manipulation and key recovery. |
| **Mitigates** | T-009 (Keystore file theft), T-001 (Keystore File Tampering) |
| **Priority** | Critical |
| **Verification** | Code review for IV generation; statistical analysis of IVs across multiple encryptions |
| **Acceptance Criteria** | - IV generated via crypto.randomBytes(12)<br>- IV stored alongside ciphertext<br>- No IV reuse detected in 10,000 encryption operations<br>- Counter-based IV generation prohibited |

#### ENC-003: Authenticated Encryption Verification

| Attribute | Value |
|-----------|-------|
| **Title** | Mandatory Authentication Tag Verification |
| **Description** | The system SHALL verify the GCM authentication tag BEFORE returning any decrypted data. Decryption operations SHALL fail completely if the auth tag verification fails - no partial data SHALL be returned. |
| **Rationale** | Auth tag verification prevents ciphertext tampering attacks. |
| **Mitigates** | T-001 (Keystore File Tampering), T-018 (Transaction parameter tampering) |
| **Priority** | Critical |
| **Verification** | Modify ciphertext bytes; verify decryption fails; verify no partial data returned |
| **Acceptance Criteria** | - Modified ciphertext causes decryption failure<br>- Modified auth tag causes decryption failure<br>- No plaintext bytes returned on failure<br>- Clear error indicating tampering detected |

#### ENC-004: TLS 1.3 for Data in Transit

| Attribute | Value |
|-----------|-------|
| **Title** | TLS 1.3 Minimum for XRPL Network Communication |
| **Description** | The system SHALL use TLS 1.3 as the minimum version for all XRPL network communication. TLS 1.2 and earlier SHALL be explicitly disabled. Only secure cipher suites SHALL be permitted. |
| **Rationale** | TLS 1.3 provides improved security and performance over earlier versions. |
| **Mitigates** | T-006 (MITM attack), S-002 (XRPL Node Spoofing) |
| **Priority** | High |
| **Verification** | TLS scanner (sslyze/testssl); verify TLS 1.2 connection rejected |
| **Acceptance Criteria** | - TLS 1.3 connections succeed<br>- TLS 1.2 connections rejected<br>- Only AEAD cipher suites accepted<br>- Certificate validation enabled |

#### ENC-005: Key Wrapping for Stored Keys

| Attribute | Value |
|-----------|-------|
| **Title** | Key Wrapping with Derived Encryption Key |
| **Description** | The system SHALL use a key wrapping scheme where private keys are encrypted with a Key Encryption Key (KEK) derived from the user password. The KEK SHALL never be stored - only derived on demand. |
| **Rationale** | Key wrapping provides defense in depth for stored keys. |
| **Mitigates** | T-009 (Keystore file theft), I-001 (Private Key Extraction via Memory) |
| **Priority** | Critical |
| **Verification** | Verify KEK derivation flow; verify KEK not persisted |
| **Acceptance Criteria** | - KEK derived from password via AUTH-001 KDF<br>- KEK used only for key encryption/decryption<br>- KEK zeroed from memory after use<br>- Private keys double-encrypted (KEK then storage key) |

#### ENC-006: Encryption Salt Storage

| Attribute | Value |
|-----------|-------|
| **Title** | Secure Salt Generation and Storage |
| **Description** | The system SHALL generate a unique 32-byte cryptographically random salt for each keystore. The salt SHALL be stored alongside the encrypted data but SHALL NOT be encrypted. |
| **Rationale** | Per-keystore salts prevent rainbow table attacks and ensure unique derived keys. |
| **Mitigates** | T-010 (Brute force password attack) |
| **Priority** | Critical |
| **Verification** | Verify salt uniqueness; verify salt stored in cleartext |
| **Acceptance Criteria** | - Salt is 32 bytes<br>- Salt generated via crypto.randomBytes<br>- Each keystore has unique salt<br>- Salt stored in keystore metadata |

---

### 2.4 Key Management (KEY)

#### KEY-001: Cryptographically Secure Key Generation

| Attribute | Value |
|-----------|-------|
| **Title** | CSPRNG-Based Key Generation |
| **Description** | The system SHALL generate all cryptographic keys using Node.js crypto.randomBytes() or equivalent CSPRNG. Ed25519 and secp256k1 keys SHALL be generated using established cryptographic libraries with proper entropy sources. |
| **Rationale** | Weak random number generation leads to predictable keys. |
| **Mitigates** | I-001 (Private Key Extraction via Memory), General key compromise |
| **Priority** | Critical |
| **Verification** | Code review; entropy testing (NIST SP 800-22 tests); verify no Math.random usage |
| **Acceptance Criteria** | - All key generation uses crypto.randomBytes<br>- No Math.random in security-critical code<br>- Entropy source verified functional<br>- Generated keys pass randomness tests |

#### KEY-002: SecureBuffer for Key Handling

| Attribute | Value |
|-----------|-------|
| **Title** | Memory-Safe Key Handling with SecureBuffer |
| **Description** | The system SHALL implement a SecureBuffer class that provides: explicit memory zeroing on disposal, prevention of buffer copying, try-finally patterns ensuring cleanup, and minimum key lifetime in memory. |
| **Rationale** | JavaScript's garbage collector does not guarantee timely memory cleanup, risking key exposure. |
| **Mitigates** | T-002 (Key extraction via memory exposure), I-001 (Private Key Extraction via Memory) |
| **Priority** | Critical |
| **Verification** | Code review; memory dump analysis during signing; verify zeroing |
| **Acceptance Criteria** | - SecureBuffer.zero() overwrites with 0x00<br>- Keys held in memory < 100ms during signing<br>- Memory dump during operation shows no plaintext key<br>- All key operations use SecureBuffer pattern |

#### KEY-003: Key Never Converted to String

| Attribute | Value |
|-----------|-------|
| **Title** | Binary-Only Key Representation |
| **Description** | The system SHALL maintain keys exclusively as Buffer objects. Keys SHALL NOT be converted to strings (hex, base64, or otherwise) except during export operations initiated by explicit user request. |
| **Rationale** | String interning in JavaScript can cause keys to persist indefinitely in memory. |
| **Mitigates** | T-002 (Key extraction via memory exposure), I-001 (Private Key Extraction via Memory) |
| **Priority** | High |
| **Verification** | Static analysis for toString/encoding calls on key buffers; code review |
| **Acceptance Criteria** | - No key.toString() calls in signing path<br>- No Buffer.from(key).toString() patterns<br>- Export explicitly converts with user confirmation<br>- Internal logging never converts keys |

#### KEY-004: Seed Phrase Immediate Zeroing

| Attribute | Value |
|-----------|-------|
| **Title** | Immediate Seed Phrase Memory Zeroing |
| **Description** | The system SHALL zero seed phrase memory immediately after key derivation. Seed phrases SHALL be accepted as arrays (not concatenated strings) and each word SHALL be individually zeroed after processing. |
| **Rationale** | Seed phrases are highest-value targets and must have minimum memory lifetime. |
| **Mitigates** | T-011 (Seed phrase logging exposure), I-002 (Seed Phrase Leakage) |
| **Priority** | Critical |
| **Verification** | Memory forensics during import; verify word array zeroing |
| **Acceptance Criteria** | - Seed phrase accepted as string[] not string<br>- Each word zeroed after processing<br>- Array.fill('') + length=0 applied<br>- Seed phrase in memory < 50ms |

#### KEY-005: Keystore File Permissions

| Attribute | Value |
|-----------|-------|
| **Title** | Restrictive Keystore File Permissions |
| **Description** | The system SHALL create keystore files with mode 0600 (owner read/write only). Keystore directories SHALL have mode 0700 (owner read/write/execute only). File permissions SHALL be verified before reading. |
| **Rationale** | Restricts keystore access to the owner, preventing other users from reading encrypted keys. |
| **Mitigates** | T-009 (Keystore file theft), I-003 (Keystore File Theft) |
| **Priority** | High |
| **Verification** | Verify file mode after creation; attempt read as different user |
| **Acceptance Criteria** | - Keystore files created with 0600<br>- Directory created with 0700<br>- Read operation verifies permissions<br>- Insecure permissions cause operation failure |

#### KEY-006: Atomic Keystore Writes

| Attribute | Value |
|-----------|-------|
| **Title** | Atomic File Operations for Keystore Updates |
| **Description** | The system SHALL use atomic write operations for keystore updates: write to temporary file, verify integrity, then rename. This prevents data corruption from interrupted writes. |
| **Rationale** | Non-atomic writes risk corrupted keystores that cannot be recovered. |
| **Mitigates** | T-001 (Keystore File Tampering), Data corruption |
| **Priority** | High |
| **Verification** | Simulate interrupted write; verify original file intact |
| **Acceptance Criteria** | - Write goes to .tmp file first<br>- Integrity verified before rename<br>- Atomic rename replaces original<br>- Failed write leaves original intact |

#### KEY-007: No Core Dumps

| Attribute | Value |
|-----------|-------|
| **Title** | Disable Core Dump Generation |
| **Description** | The system SHALL disable core dump generation via ulimit -c 0 equivalent. The system SHALL verify core dumps are disabled at startup and warn if they cannot be disabled. |
| **Rationale** | Core dumps may contain decrypted keys in memory. |
| **Mitigates** | T-002 (Key extraction via memory exposure), I-001 (Private Key Extraction via Memory) |
| **Priority** | High |
| **Verification** | Trigger crash; verify no core dump created; verify startup warning |
| **Acceptance Criteria** | - process.setrlimit('core', {soft: 0, hard: 0}) called<br>- Startup logs core dump status<br>- Warning if cannot disable<br>- No core file created on SIGABRT |

---

### 2.5 Input Validation (VAL)

#### VAL-001: Zod Schema Validation for All Inputs

| Attribute | Value |
|-----------|-------|
| **Title** | Mandatory Zod Schema Validation |
| **Description** | The system SHALL validate ALL MCP tool inputs against Zod schemas before any processing. Schema validation failure SHALL reject the request immediately with a generic error message. |
| **Rationale** | Schema validation prevents malformed input from reaching business logic. |
| **Mitigates** | T-003 (Policy bypass through input manipulation), E-002 (Policy Bypass via Input Manipulation) |
| **Priority** | Critical |
| **Verification** | Fuzz testing with malformed inputs; verify all tools have schemas |
| **Acceptance Criteria** | - Every MCP tool has defined Zod schema<br>- Validation occurs before any processing<br>- Invalid input returns error without processing<br>- No input bypasses validation |

#### VAL-002: XRPL Address Checksum Verification

| Attribute | Value |
|-----------|-------|
| **Title** | XRPL Address Format and Checksum Validation |
| **Description** | The system SHALL validate XRPL addresses against the format regex ^r[1-9A-HJ-NP-Za-km-z]{24,34}$ AND SHALL verify the address checksum using the XRPL base58check algorithm. |
| **Rationale** | Invalid addresses cause transaction failures; typos could send funds to unrecoverable addresses. |
| **Mitigates** | T-003 (Policy bypass through input manipulation), Transaction errors |
| **Priority** | Critical |
| **Verification** | Test with valid addresses, invalid format, valid format with bad checksum |
| **Acceptance Criteria** | - Valid addresses pass<br>- Invalid format rejected<br>- Valid format with wrong checksum rejected<br>- Rejection message does not reveal checksum details |

#### VAL-003: XRP Amount Range Validation

| Attribute | Value |
|-----------|-------|
| **Title** | XRP Amount Bounds Checking |
| **Description** | The system SHALL validate XRP amounts are within the valid range: minimum 1 drop (0.000001 XRP), maximum 100 billion XRP (100,000,000,000,000,000 drops). Negative amounts SHALL be rejected. |
| **Rationale** | Out-of-range amounts cause transaction failures or unexpected behavior. |
| **Mitigates** | T-008 (Fee escalation attack), E-002 (Policy Bypass via Input Manipulation) |
| **Priority** | Critical |
| **Verification** | Test boundary values: 0, 1, max, max+1, negative |
| **Acceptance Criteria** | - 0 drops rejected<br>- 1 drop accepted<br>- Max drops accepted<br>- Max+1 drops rejected<br>- Negative values rejected |

#### VAL-004: Prompt Injection Pattern Detection

| Attribute | Value |
|-----------|-------|
| **Title** | Prompt Injection Attack Pattern Detection |
| **Description** | The system SHALL detect and reject inputs containing prompt injection patterns including: instruction override attempts ([INST], <<SYS>>), role confusion attempts, ignore previous instructions patterns, and excessive special characters. |
| **Rationale** | Prompt injection is the primary attack vector for LLM-controlled wallets. |
| **Mitigates** | T-001 (Prompt injection), E-001 (Prompt injection for unauthorized transactions) |
| **Priority** | Critical |
| **Verification** | Test known prompt injection patterns; fuzzing with attack payloads |
| **Acceptance Criteria** | - [INST] patterns rejected<br>- <<SYS>> patterns rejected<br>- "ignore previous" patterns rejected<br>- Rejection logged as security event<br>- Legitimate similar-looking data handled |

#### VAL-005: Input Sanitization

| Attribute | Value |
|-----------|-------|
| **Title** | Control Character and Special Character Sanitization |
| **Description** | The system SHALL sanitize all string inputs by removing control characters (0x00-0x1F, 0x7F), trimming whitespace, and enforcing maximum length limits per field. |
| **Rationale** | Control characters can cause unexpected behavior; length limits prevent resource exhaustion. |
| **Mitigates** | T-017 (Memory exhaustion DoS), E-002 (Policy Bypass via Input Manipulation) |
| **Priority** | High |
| **Verification** | Submit inputs with control characters; verify removal |
| **Acceptance Criteria** | - Control characters stripped<br>- Leading/trailing whitespace trimmed<br>- Length limits enforced per field<br>- Sanitization logged for audit |

#### VAL-006: Memo Field Sanitization

| Attribute | Value |
|-----------|-------|
| **Title** | Transaction Memo Field Content Filtering |
| **Description** | The system SHALL sanitize transaction memo fields to prevent prompt injection via memo content. Memos SHALL be truncated to 1KB, encoded as hex or plain ASCII, and checked for injection patterns. |
| **Rationale** | Memo fields are user-controlled and could be used to inject instructions via transaction context. |
| **Mitigates** | T-001 (Prompt injection), E-001 (Prompt injection for unauthorized transactions) |
| **Priority** | Critical |
| **Verification** | Submit transactions with malicious memo content |
| **Acceptance Criteria** | - Memos > 1KB truncated<br>- Injection patterns in memo rejected<br>- Memo content logged separately from instructions<br>- Memo encoding normalized |

#### VAL-007: Canonical Input Processing

| Attribute | Value |
|-----------|-------|
| **Title** | Input Canonicalization Before Validation |
| **Description** | The system SHALL canonicalize inputs before validation: Unicode normalization (NFC), case normalization where applicable, and duplicate field detection. |
| **Rationale** | Different representations of the same data could bypass validation. |
| **Mitigates** | T-003 (Policy bypass through input manipulation), E-002 (Policy Bypass via Input Manipulation) |
| **Priority** | High |
| **Verification** | Submit Unicode variants; verify canonical form validated |
| **Acceptance Criteria** | - Unicode normalized to NFC<br>- Address case handled consistently<br>- Duplicate JSON fields cause rejection<br>- Whitespace variants normalized |

---

### 2.6 Audit Logging (AUDIT)

#### AUDIT-001: Tamper-Evident Hash Chain

| Attribute | Value |
|-----------|-------|
| **Title** | HMAC-SHA256 Hash Chain for Audit Logs |
| **Description** | The system SHALL implement a hash chain where each audit log entry includes the HMAC-SHA256 hash of the previous entry. The HMAC key SHALL be stored securely separate from logs. |
| **Rationale** | Hash chains allow detection of log tampering or deletion. |
| **Mitigates** | T-012 (Audit log tampering), R-001 (Transaction Non-Repudiation Failure) |
| **Priority** | Critical |
| **Verification** | Modify log entry; verify chain validation fails; verify deletion detected |
| **Acceptance Criteria** | - Each entry includes previousHash field<br>- HMAC-SHA256 used (not plain SHA256)<br>- Chain validation detects modification<br>- Chain validation detects deletion<br>- Genesis entry has known hash |

#### AUDIT-002: Required Logged Events

| Attribute | Value |
|-----------|-------|
| **Title** | Mandatory Security Event Logging |
| **Description** | The system SHALL log the following events: all authentication attempts (success/failure), all transaction signing requests, all transaction submissions, all policy violations, all rate limit triggers, all key operations, all configuration changes. |
| **Rationale** | Complete audit trail required for forensics and compliance. |
| **Mitigates** | R-001 (Transaction Non-Repudiation Failure), R-002 (Policy Change Repudiation) |
| **Priority** | Critical |
| **Verification** | Perform each operation; verify corresponding log entry |
| **Acceptance Criteria** | - Auth success/failure logged<br>- Transaction operations logged<br>- Policy violations logged<br>- Rate limit events logged<br>- Key operations logged<br>- Config changes logged |

#### AUDIT-003: Prohibited Logged Data

| Attribute | Value |
|-----------|-------|
| **Title** | Sensitive Data Exclusion from Logs |
| **Description** | The system SHALL NEVER log: private keys, seed phrases, passwords, encryption keys, full transaction payloads (only hash), decrypted keystore contents. Logs SHALL be automatically scanned for accidental secret inclusion. |
| **Rationale** | Logged secrets become a high-value attack target. |
| **Mitigates** | T-011 (Seed phrase logging exposure), I-002 (Seed Phrase Leakage), I-004 (Password Exposure) |
| **Priority** | Critical |
| **Verification** | Static analysis for logging patterns; log output review; secret scanning |
| **Acceptance Criteria** | - No hex strings matching key length in logs<br>- No mnemonic word sequences in logs<br>- Password fields redacted<br>- Automated secret scanner on log output |

#### AUDIT-004: Monotonic Sequence Numbers

| Attribute | Value |
|-----------|-------|
| **Title** | Strictly Monotonic Log Sequence Numbers |
| **Description** | The system SHALL assign a strictly monotonic increasing sequence number to each log entry. Sequence gaps SHALL be detected and flagged as potential tampering. |
| **Rationale** | Sequence numbers allow detection of deleted entries. |
| **Mitigates** | T-012 (Audit log tampering), R-001 (Transaction Non-Repudiation Failure) |
| **Priority** | High |
| **Verification** | Delete log entry; verify sequence gap detected |
| **Acceptance Criteria** | - Sequence starts at 1<br>- Each entry increments by 1<br>- Gap detection implemented<br>- Gap triggers security alert |

#### AUDIT-005: Timestamp Integrity

| Attribute | Value |
|-----------|-------|
| **Title** | Cryptographically Bound Timestamps |
| **Description** | The system SHALL include ISO 8601 timestamps with timezone in all log entries. Timestamps SHALL be included in the hash chain. Clock drift > 5 seconds from NTP SHALL trigger a warning. |
| **Rationale** | Reliable timestamps are essential for forensics and compliance. |
| **Mitigates** | R-001 (Transaction Non-Repudiation Failure), Forensics requirements |
| **Priority** | High |
| **Verification** | Verify timestamp format; verify included in hash; test clock drift |
| **Acceptance Criteria** | - Timestamp in ISO 8601 format<br>- Timezone included (UTC preferred)<br>- Timestamp in hash calculation<br>- NTP sync verified at startup |

#### AUDIT-006: Correlation ID Tracking

| Attribute | Value |
|-----------|-------|
| **Title** | Request Correlation ID Propagation |
| **Description** | The system SHALL generate a unique correlation ID (UUID v4) for each incoming request and include it in all related log entries. Correlation IDs SHALL be returned in error responses to support incident investigation. |
| **Rationale** | Enables tracing of multi-step operations and error debugging. |
| **Mitigates** | R-001 (Transaction Non-Repudiation Failure), Operational requirements |
| **Priority** | High |
| **Verification** | Submit request; verify correlation ID in all related logs |
| **Acceptance Criteria** | - UUID v4 generated per request<br>- Propagated to all log entries<br>- Included in error responses<br>- Searchable in log system |

#### AUDIT-007: Append-Only Log Storage

| Attribute | Value |
|-----------|-------|
| **Title** | Write-Once-Read-Many Log Storage |
| **Description** | The system SHALL write audit logs to append-only storage. Delete operations on log entries SHALL be prohibited at the application level. Archive and rotation SHALL preserve original entries. |
| **Rationale** | Append-only storage prevents log tampering. |
| **Mitigates** | T-012 (Audit log tampering), R-001 (Transaction Non-Repudiation Failure) |
| **Priority** | High |
| **Verification** | Attempt to delete or modify log entry via API; verify failure |
| **Acceptance Criteria** | - No delete operation exposed<br>- No update operation exposed<br>- Rotation creates new file, preserves old<br>- File permissions prevent modification |

---

### 2.7 Rate Limiting (RATE)

#### RATE-001: Tiered Rate Limit Configuration

| Attribute | Value |
|-----------|-------|
| **Title** | Operation-Based Rate Limit Tiers |
| **Description** | The system SHALL implement three rate limit tiers:<br>- STANDARD (read operations): 100 requests/minute, burst 10<br>- STRICT (write operations): 20 requests/minute, burst 2<br>- CRITICAL (sensitive operations): 5 requests/5 minutes, no burst |
| **Rationale** | Different operation types require different rate limits based on risk and resource consumption. |
| **Mitigates** | T-013 (Rate limit exhaustion DoS), T-014 (KDF computational DoS), D-001 (Rate Limit Exhaustion) |
| **Priority** | Critical |
| **Verification** | Exceed each tier's limit; verify rejection; verify tier boundaries |
| **Acceptance Criteria** | - Each tier has defined limits<br>- Each tool assigned to tier<br>- Limits enforced correctly<br>- Tier documentation complete |

#### RATE-002: Sliding Window Implementation

| Attribute | Value |
|-----------|-------|
| **Title** | Sliding Window Rate Limit Algorithm |
| **Description** | The system SHALL use a sliding window algorithm for rate limiting, providing smooth rate enforcement without hard edges at window boundaries. |
| **Rationale** | Fixed windows allow burst attacks at window boundaries. |
| **Mitigates** | T-013 (Rate limit exhaustion DoS), D-001 (Rate Limit Exhaustion) |
| **Priority** | High |
| **Verification** | Test requests spanning window boundaries; verify smooth limiting |
| **Acceptance Criteria** | - No burst allowed at window boundary<br>- Rate calculated across sliding period<br>- Requests evenly distributed across window<br>- Edge case at exactly window size handled |

#### RATE-003: Token Bucket for Burst Allowance

| Attribute | Value |
|-----------|-------|
| **Title** | Token Bucket Algorithm for Controlled Bursts |
| **Description** | The system SHALL implement token bucket rate limiting for tiers that allow bursts. Tokens refill at the configured rate. Maximum bucket size limits burst capacity. |
| **Rationale** | Allows legitimate burst usage while maintaining overall rate limits. |
| **Mitigates** | T-013 (Rate limit exhaustion DoS), D-001 (Rate Limit Exhaustion) |
| **Priority** | High |
| **Verification** | Use burst allowance; verify refill; verify max capacity |
| **Acceptance Criteria** | - Burst allowed up to bucket size<br>- Tokens refill at configured rate<br>- Bucket never exceeds max size<br>- Empty bucket causes rejection |

#### RATE-004: Rate Limit Headers in Responses

| Attribute | Value |
|-----------|-------|
| **Title** | Standard Rate Limit Response Headers |
| **Description** | The system SHALL include rate limit headers in all responses: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset. Rate-limited responses SHALL include Retry-After header. |
| **Rationale** | Enables clients to implement backoff and monitor their usage. |
| **Mitigates** | D-001 (Rate Limit Exhaustion), Client integration |
| **Priority** | Medium |
| **Verification** | Inspect response headers; verify accuracy |
| **Acceptance Criteria** | - All three headers present<br>- Remaining count accurate<br>- Reset time accurate<br>- Retry-After on 429 response |

#### RATE-005: Per-Client Rate Limiting

| Attribute | Value |
|-----------|-------|
| **Title** | Client-Isolated Rate Limit Tracking |
| **Description** | The system SHALL track rate limits per client identifier (session token or API key). One client exhausting their limit SHALL NOT affect other clients. |
| **Rationale** | Prevents one misbehaving client from causing denial of service for others. |
| **Mitigates** | T-013 (Rate limit exhaustion DoS), D-001 (Rate Limit Exhaustion) |
| **Priority** | High |
| **Verification** | Exhaust limit for client A; verify client B unaffected |
| **Acceptance Criteria** | - Rate limits tracked per client<br>- Client A exhaustion does not affect B<br>- Client identifier extracted securely<br>- Rate limit state isolated |

#### RATE-006: Authentication Rate Limiting

| Attribute | Value |
|-----------|-------|
| **Title** | Stricter Rate Limits for Authentication |
| **Description** | The system SHALL apply stricter rate limits to authentication attempts: maximum 10 attempts per IP per hour, maximum 5 attempts per account per 15 minutes. |
| **Rationale** | Authentication is computationally expensive (Argon2id) and a common attack target. |
| **Mitigates** | T-010 (Brute force password attack), T-014 (KDF computational DoS), D-002 (Computational Exhaustion) |
| **Priority** | Critical |
| **Verification** | Exceed auth rate limits; verify rejection |
| **Acceptance Criteria** | - IP-based limiting at 10/hour<br>- Account-based limiting at 5/15min<br>- Both limits enforced independently<br>- Rate-limited auth returns 429 |

---

### 2.8 Error Handling (ERR)

#### ERR-001: Fail-Secure Default Behavior

| Attribute | Value |
|-----------|-------|
| **Title** | Default-Deny on Error Conditions |
| **Description** | The system SHALL default to denying access when any error occurs during authorization checks. Errors during policy evaluation SHALL result in operation rejection, not bypass. |
| **Rationale** | Fail-open errors create security vulnerabilities. |
| **Mitigates** | T-003 (Policy bypass through input manipulation), All authorization bypass |
| **Priority** | Critical |
| **Verification** | Inject errors in auth path; verify access denied |
| **Acceptance Criteria** | - Exception in auth check = denied<br>- Timeout in policy check = denied<br>- Network error in validation = denied<br>- Default case in switch = denied |

#### ERR-002: No Sensitive Data in Error Messages

| Attribute | Value |
|-----------|-------|
| **Title** | Sanitized Error Messages |
| **Description** | The system SHALL NOT include sensitive data in error messages: no stack traces, no internal paths, no database details, no key material hints, no configuration values. |
| **Rationale** | Verbose errors leak information useful for attacks. |
| **Mitigates** | I-002 (Seed Phrase Leakage), I-005 (Account Enumeration), Information disclosure |
| **Priority** | High |
| **Verification** | Trigger various errors; verify no sensitive data in response |
| **Acceptance Criteria** | - No stack traces in responses<br>- No file paths in responses<br>- Generic messages for auth failures<br>- Internal details logged only |

#### ERR-003: Correlation ID in Error Responses

| Attribute | Value |
|-----------|-------|
| **Title** | Error Response Correlation ID Inclusion |
| **Description** | The system SHALL include a correlation ID in all error responses. This enables users to report issues with a reference that maps to detailed internal logs. |
| **Rationale** | Enables debugging without exposing internal details. |
| **Mitigates** | Operational requirements |
| **Priority** | Medium |
| **Verification** | Trigger error; verify correlation ID in response; verify logs match |
| **Acceptance Criteria** | - Correlation ID in error response body<br>- Same ID in internal logs<br>- Logs contain full error details<br>- Response contains only generic message + ID |

#### ERR-004: Consistent Error Response Format

| Attribute | Value |
|-----------|-------|
| **Title** | Standardized Error Response Structure |
| **Description** | The system SHALL return errors in a consistent format: {error: {code: string, message: string, correlationId: string}}. All error responses SHALL use this format regardless of error type. |
| **Rationale** | Consistent format enables reliable error handling by clients. |
| **Mitigates** | Operational requirements, Security through obscurity prevention |
| **Priority** | Medium |
| **Verification** | Trigger various error types; verify consistent format |
| **Acceptance Criteria** | - All errors use standard format<br>- Error codes documented<br>- Messages appropriate for users<br>- No raw exceptions exposed |

#### ERR-005: No Timing Information Leakage

| Attribute | Value |
|-----------|-------|
| **Title** | Constant-Time Error Responses |
| **Description** | The system SHALL ensure error responses for authentication take constant time regardless of failure reason (wrong username vs wrong password). A minimum delay SHALL be enforced. |
| **Rationale** | Timing differences can reveal whether usernames exist. |
| **Mitigates** | I-005 (Account Enumeration), Timing attacks |
| **Priority** | High |
| **Verification** | Time responses for valid vs invalid usernames; verify no significant difference |
| **Acceptance Criteria** | - Response time variance < 50ms<br>- Minimum delay enforced (e.g., 200ms)<br>- Same message for all auth failures<br>- No early return on user not found |

#### ERR-006: Exception Handling Coverage

| Attribute | Value |
|-----------|-------|
| **Title** | Complete Exception Handling |
| **Description** | The system SHALL have try-catch blocks around all async operations. Unhandled rejections SHALL trigger graceful degradation and alerting, not crashes. |
| **Rationale** | Unhandled exceptions can cause service unavailability or undefined behavior. |
| **Mitigates** | D-003 (Memory Exhaustion), Service availability |
| **Priority** | High |
| **Verification** | Inject errors in various code paths; verify no unhandled rejections |
| **Acceptance Criteria** | - process.on('unhandledRejection') handler<br>- All async calls have error handling<br>- Graceful degradation on unexpected errors<br>- Alerts generated for unexpected errors |

---

## 3. Traceability Matrix

### 3.1 Threat to Requirement Mapping

| Threat ID | Threat Name | Requirements |
|-----------|-------------|--------------|
| T-001 | Prompt injection triggering unauthorized transactions | VAL-001, VAL-004, VAL-006, AUTHZ-002, AUTHZ-003, AUTHZ-004, AUTHZ-006, AUTHZ-007 |
| T-002 | Key extraction via memory exposure | KEY-002, KEY-003, KEY-007, ENC-005 |
| T-003 | Policy bypass through input manipulation | VAL-001, VAL-002, VAL-003, VAL-007, AUTHZ-001, AUTHZ-006, ERR-001 |
| T-004 | Insider threat from compromised operator | AUDIT-001, AUDIT-002, AUDIT-004, AUTHZ-005, AUTHZ-006 |
| T-005 | Supply chain attack via malicious dependency | (Out of scope - handled by SBOM and dependency scanning) |
| T-006 | MITM attack on XRPL communication | ENC-004 |
| T-007 | Sequence manipulation attack | (XRPL-level - handled by sequence tracking) |
| T-008 | Fee escalation attack | VAL-003, AUTHZ-002 |
| T-009 | Keystore file theft | ENC-001, ENC-002, ENC-005, ENC-006, KEY-005 |
| T-010 | Brute force password attack | AUTH-001, AUTH-002, AUTH-004, AUTH-005, RATE-006 |
| T-011 | Seed phrase logging exposure | AUTH-006, KEY-004, AUDIT-003 |
| T-012 | Audit log tampering | AUDIT-001, AUDIT-004, AUDIT-007 |
| T-013 | Rate limit exhaustion DoS | RATE-001, RATE-002, RATE-003, RATE-005 |
| T-014 | KDF computational DoS | AUTH-002, RATE-006 |
| T-015 | Agent identity spoofing | AUTH-003 |
| T-016 | Configuration injection | AUTHZ-006 |
| T-017 | Memory exhaustion DoS | VAL-005, ERR-006 |
| T-018 | Transaction parameter tampering | ENC-003, VAL-001, VAL-002 |
| T-019 | Tool chaining privilege escalation | AUTHZ-005 |
| T-020 | Backup file leakage | KEY-005, KEY-006 |

### 3.2 Requirement Coverage Summary

| Category | Requirements | Critical | High | Medium | Low |
|----------|--------------|----------|------|--------|-----|
| AUTH | 6 | 3 | 3 | 0 | 0 |
| AUTHZ | 7 | 4 | 3 | 0 | 0 |
| ENC | 6 | 4 | 2 | 0 | 0 |
| KEY | 7 | 4 | 3 | 0 | 0 |
| VAL | 7 | 5 | 2 | 0 | 0 |
| AUDIT | 7 | 3 | 4 | 0 | 0 |
| RATE | 6 | 2 | 3 | 1 | 0 |
| ERR | 6 | 1 | 3 | 2 | 0 |
| **Total** | **52** | **26** | **23** | **3** | **0** |

---

## 4. Verification Methods Table

| Method | Description | Applicable Requirements |
|--------|-------------|------------------------|
| **Unit Test** | Automated tests verifying individual component behavior | AUTH-001, AUTH-002, AUTH-004, VAL-001, VAL-002, VAL-003, ENC-001, ENC-002 |
| **Integration Test** | Automated tests verifying component interactions | AUTH-002, AUTH-003, AUTHZ-002, AUTHZ-003, AUTHZ-004, RATE-001, RATE-005 |
| **Code Review** | Manual inspection of implementation | KEY-002, KEY-003, AUTH-005, AUTH-006, AUDIT-003, ERR-002 |
| **Static Analysis** | Automated code scanning for security patterns | KEY-003, AUTH-005, AUDIT-003 |
| **Cryptographic Audit** | Expert review of cryptographic implementation | ENC-001, ENC-002, ENC-003, ENC-005, AUTH-001, AUDIT-001 |
| **Penetration Test** | Simulated attacks against deployed system | VAL-004, AUTHZ-002, AUTHZ-003, AUTHZ-005, ERR-001 |
| **Fuzz Testing** | Random/malformed input testing | VAL-001, VAL-004, VAL-005, VAL-006 |
| **Memory Forensics** | Analysis of memory during operation | KEY-002, KEY-004, AUTH-005 |
| **Log Analysis** | Review of audit log output | AUDIT-001, AUDIT-002, AUDIT-003, AUDIT-004 |
| **TLS Scanning** | Automated TLS configuration testing | ENC-004 |
| **Load Testing** | Performance testing under rate limit conditions | RATE-001, RATE-002, RATE-003, RATE-005 |
| **Timing Analysis** | Measurement of response time variance | ERR-005 |

---

## 5. Implementation Priority Matrix

### 5.1 Phase 1 - Foundation (Weeks 1-4)

**Must-have requirements for initial deployment:**

| Requirement | Category | Effort | Dependencies |
|-------------|----------|--------|--------------|
| AUTH-001 | Authentication | 3 days | None |
| AUTH-002 | Authentication | 2 days | AUTH-001 |
| AUTH-005 | Authentication | 1 day | AUTH-001 |
| ENC-001 | Encryption | 3 days | None |
| ENC-002 | Encryption | 1 day | ENC-001 |
| ENC-003 | Encryption | 1 day | ENC-001 |
| KEY-001 | Key Management | 2 days | None |
| KEY-002 | Key Management | 3 days | None |
| KEY-004 | Key Management | 1 day | KEY-002 |
| VAL-001 | Input Validation | 3 days | None |
| VAL-002 | Input Validation | 2 days | VAL-001 |
| VAL-003 | Input Validation | 1 day | VAL-001 |
| VAL-004 | Input Validation | 3 days | VAL-001 |
| AUTHZ-001 | Authorization | 2 days | None |
| AUTHZ-002 | Authorization | 3 days | AUTHZ-001 |
| AUTHZ-005 | Authorization | 2 days | AUTHZ-001 |
| AUTHZ-006 | Authorization | 3 days | None |
| ERR-001 | Error Handling | 2 days | None |
| AUDIT-002 | Audit Logging | 2 days | None |
| AUDIT-003 | Audit Logging | 1 day | AUDIT-002 |

**Phase 1 Total: 40 days effort (parallelizable to ~3-4 weeks)**

### 5.2 Phase 2 - Hardening (Weeks 5-8)

**Enhanced security controls:**

| Requirement | Category | Effort | Dependencies |
|-------------|----------|--------|--------------|
| AUTH-003 | Authentication | 2 days | AUTH-001 |
| AUTH-004 | Authentication | 2 days | None |
| AUTH-006 | Authentication | 1 day | None |
| ENC-004 | Encryption | 2 days | None |
| ENC-005 | Encryption | 2 days | ENC-001, AUTH-001 |
| ENC-006 | Encryption | 1 day | ENC-001 |
| KEY-003 | Key Management | 1 day | KEY-002 |
| KEY-005 | Key Management | 2 days | None |
| KEY-006 | Key Management | 2 days | ENC-001 |
| KEY-007 | Key Management | 1 day | None |
| VAL-005 | Input Validation | 1 day | VAL-001 |
| VAL-006 | Input Validation | 2 days | VAL-001, VAL-004 |
| VAL-007 | Input Validation | 1 day | VAL-001 |
| AUTHZ-003 | Authorization | 2 days | AUTHZ-001 |
| AUTHZ-004 | Authorization | 2 days | AUTHZ-001 |
| AUTHZ-007 | Authorization | 2 days | AUTHZ-001 |
| RATE-001 | Rate Limiting | 3 days | None |
| RATE-002 | Rate Limiting | 2 days | RATE-001 |
| RATE-005 | Rate Limiting | 2 days | RATE-001 |
| RATE-006 | Rate Limiting | 2 days | RATE-001, AUTH-001 |
| AUDIT-001 | Audit Logging | 3 days | AUDIT-002 |
| AUDIT-004 | Audit Logging | 1 day | AUDIT-002 |
| AUDIT-005 | Audit Logging | 1 day | AUDIT-002 |
| AUDIT-006 | Audit Logging | 2 days | AUDIT-002 |
| AUDIT-007 | Audit Logging | 2 days | AUDIT-002 |
| ERR-002 | Error Handling | 1 day | None |
| ERR-005 | Error Handling | 2 days | AUTH-001 |
| ERR-006 | Error Handling | 2 days | None |

**Phase 2 Total: 49 days effort (parallelizable to ~4 weeks)**

### 5.3 Phase 3 - Polish (Weeks 9-12)

**Operational improvements:**

| Requirement | Category | Effort | Dependencies |
|-------------|----------|--------|--------------|
| RATE-003 | Rate Limiting | 2 days | RATE-001 |
| RATE-004 | Rate Limiting | 1 day | RATE-001 |
| ERR-003 | Error Handling | 1 day | AUDIT-006 |
| ERR-004 | Error Handling | 1 day | None |

**Phase 3 Total: 5 days effort**

### 5.4 Implementation Dependency Graph

```
                        ┌─────────────────────────────────────────┐
                        │                 PHASE 1                  │
                        └─────────────────────────────────────────┘
                                           │
     ┌─────────────────────────────────────┼─────────────────────────────────────┐
     │                                     │                                     │
     ▼                                     ▼                                     ▼
┌─────────┐                          ┌─────────┐                          ┌─────────┐
│ AUTH-001│                          │ ENC-001 │                          │ VAL-001 │
│ Argon2id│                          │AES-256-G│                          │  Zod    │
└────┬────┘                          └────┬────┘                          └────┬────┘
     │                                    │                                    │
     ├──────────────┐           ┌─────────┼─────────┐           ┌──────────────┤
     │              │           │         │         │           │              │
     ▼              ▼           ▼         ▼         ▼           ▼              ▼
┌─────────┐   ┌─────────┐ ┌─────────┐┌─────────┐┌─────────┐┌─────────┐   ┌─────────┐
│ AUTH-002│   │ AUTH-005│ │ ENC-002 ││ ENC-003 ││ KEY-002 ││ VAL-002 │   │ VAL-004 │
│ Lockout │   │ No Store│ │   IV    ││ AuthTag ││SecureBuf││ Address │   │PromptInj│
└─────────┘   └─────────┘ └─────────┘└─────────┘└────┬────┘└─────────┘   └────┬────┘
                                                     │                        │
                                                     ▼                        ▼
                                               ┌─────────┐              ┌─────────┐
                                               │ KEY-004 │              │ VAL-006 │
                                               │SeedZero │              │  Memo   │
                                               └─────────┘              └─────────┘

                        ┌─────────────────────────────────────────┐
                        │                 PHASE 2                  │
                        └─────────────────────────────────────────┘
                                           │
     ┌──────────────┬──────────────┬───────┴───────┬──────────────┬──────────────┐
     │              │              │               │              │              │
     ▼              ▼              ▼               ▼              ▼              ▼
┌─────────┐   ┌─────────┐   ┌─────────┐     ┌─────────┐   ┌─────────┐   ┌─────────┐
│AUTHZ-003│   │ RATE-001│   │ AUDIT-01│     │ ENC-004 │   │ KEY-005 │   │ ERR-005 │
│Allowlist│   │  Tiers  │   │HashChain│     │ TLS 1.3 │   │FilePerm │   │ Timing  │
└─────────┘   └────┬────┘   └─────────┘     └─────────┘   └─────────┘   └─────────┘
                   │
          ┌────────┼────────┐
          │        │        │
          ▼        ▼        ▼
    ┌─────────┐┌─────────┐┌─────────┐
    │ RATE-002││ RATE-005││ RATE-006│
    │ Sliding ││Per-Client││  Auth   │
    └─────────┘└─────────┘└─────────┘
```

---

## 6. References

### 6.1 Related Documents

- [Threat Model v1.0.0](./threat-model.md)
- [Security Architecture](./SECURITY-ARCHITECTURE.md)
- [AI Agent Wallet Security Research](../research/ai-agent-wallet-security-2025-2026.md)

### 6.2 Standards and Guidelines

- [NIST SP 800-38D - GCM Mode](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [NIST SP 800-132 - Key Derivation](https://csrc.nist.gov/publications/detail/sp/800-132/final)
- [Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llmrisk/)
- [XRPL Address Encoding](https://xrpl.org/addresses.html)

### 6.3 Industry Best Practices

- [OpenSSF Security Baseline 2025](https://baseline.openssf.org/)
- [CIS Controls](https://www.cisecurity.org/controls)
- [SOC 2 Trust Services Criteria](https://www.aicpa.org/soc2)

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Security Specialist | Initial security requirements specification |

**Next Review Date:** 2026-04-28

**Approval Required From:**
- [ ] Security Lead
- [ ] Technical Lead
- [ ] Product Owner

---

*This document is a controlled specification. Changes require formal review and approval. All requirements are testable and must be verified before production deployment.*
