# 05 - Building Blocks View

**Arc42 Section**: Building Block View
**Version**: 1.0.0
**Date**: 2026-01-28
**Status**: Complete

---

## Table of Contents

1. [Overview](#1-overview)
2. [Level 1: White Box Overall System](#2-level-1-white-box-overall-system)
3. [Level 2: Containers](#3-level-2-containers)
4. [Level 3: Components](#4-level-3-components)
5. [Cross-Cutting Concerns](#5-cross-cutting-concerns)
6. [Design Decisions](#6-design-decisions)

---

## 1. Overview

This document describes the static decomposition of the XRPL Agent Wallet MCP server into building blocks (containers and components). It follows the C4 model approach, progressing from a high-level white box view of the entire system down to component-level details.

**Scope**: The building blocks view covers the runtime components of the MCP server. External systems (AI agents, XRPL network) are shown as black boxes at the boundaries.

**Notation**: This document uses C4 model terminology:
- **Container**: A separately deployable unit (process, service, data store)
- **Component**: A grouping of related functionality within a container
- **Code**: Classes, functions, modules (not covered in this document)

---

## 2. Level 1: White Box Overall System

### System Context Recap

The XRPL Agent Wallet MCP is a secure wallet infrastructure enabling AI agents to autonomously execute XRP Ledger transactions within policy-controlled boundaries.

```
+------------------------------------------------------------------+
|                    XRPL Agent Wallet MCP                          |
|                                                                   |
|  Provides:                                                        |
|  - Policy-controlled transaction signing                          |
|  - Secure key storage and management                             |
|  - Tiered approval workflow (autonomous, delayed, co-sign)       |
|  - Hash-chained audit logging                                    |
|  - XRPL network communication                                    |
|                                                                   |
+------------------------------------------------------------------+
         ^                                          |
         |                                          |
    MCP Tools                              Transaction Submission
    (JSON-RPC)                                   (WebSocket)
         |                                          |
         v                                          v
+------------------+                    +------------------+
|    AI Agent      |                    |  XRPL Network    |
| (untrusted)      |                    | (trusted infra)  |
+------------------+                    +------------------+
```

### Contained Building Blocks

| Building Block | Purpose | Technology |
|----------------|---------|------------|
| **MCP Server** | Protocol handling, tool routing | Node.js/TypeScript |
| **Policy Engine** | Transaction authorization | TypeScript module |
| **Signing Service** | Cryptographic operations | TypeScript module |
| **Keystore** | Secure key persistence | Encrypted JSON files |
| **Audit Logger** | Tamper-evident logging | TypeScript module |
| **XRPL Client** | Network communication | xrpl.js library |

### Important Interfaces

| Interface | Description |
|-----------|-------------|
| **MCP Tool Interface** | JSON-RPC 2.0 over stdio/SSE for agent communication |
| **XRPL WebSocket** | WSS connection to XRPL network nodes |
| **File System** | Local encrypted storage for keys, policies, logs |
| **Notification Webhook** | HTTPS callbacks for approval requests |

---

## 3. Level 2: Containers

The system is decomposed into six containers, each with distinct responsibilities and security boundaries.

### Container Diagram

See [C4 Container Diagram](../c4-diagrams/containers.md) for the visual representation.

### 3.1 MCP Server Container

| Attribute | Description |
|-----------|-------------|
| **Purpose** | Main runtime process, MCP protocol handling, tool routing |
| **Technology** | Node.js 20+ LTS, TypeScript, MCP SDK |
| **Responsibility** | Accept tool invocations, validate input, route to appropriate handlers |
| **Dependencies** | Policy Engine, Signing Service, Audit Logger, XRPL Client |

**Interfaces Provided:**

| Interface | Protocol | Description |
|-----------|----------|-------------|
| MCP Tools | JSON-RPC 2.0/stdio | 10 wallet operation tools |
| Health Check | HTTP | Server health endpoint |
| Metrics | Prometheus | Operational telemetry |

**MCP Tools Exposed:**

| Tool | Description | Sensitivity |
|------|-------------|-------------|
| `create_wallet` | Generate new XRPL wallet | High |
| `import_wallet` | Import existing seed/secret | Critical |
| `list_wallets` | List managed wallet addresses | Low |
| `get_balance` | Query wallet balance | Low |
| `sign_transaction` | Sign transaction (policy-controlled) | Critical |
| `get_transaction_status` | Check transaction result | Low |
| `set_regular_key` | Configure regular key | High |
| `setup_multisign` | Configure multi-signature | High |
| `get_policy` | Retrieve current policy | Medium |
| `check_policy` | Evaluate transaction (dry-run) | Medium |

**Security Considerations:**
- All input validated via Zod schemas before processing
- Rate limiting applied per tool and per wallet
- Prompt injection patterns detected and logged
- Tool sensitivity classification enforced

### 3.2 Policy Engine Container

| Attribute | Description |
|-----------|-------------|
| **Purpose** | Declarative rule evaluation, tier classification, limit tracking |
| **Technology** | TypeScript, JSON policy files |
| **Responsibility** | Evaluate transactions against policies, determine approval tier |
| **Dependencies** | None (isolated, no external calls) |

**Interfaces Provided:**

| Interface | Type | Description |
|-----------|------|-------------|
| `evaluateTransaction()` | Function | Evaluate transaction against policy |
| `getTier()` | Function | Get approval tier for transaction |
| `checkLimits()` | Function | Verify against rate/volume limits |
| `validateDestination()` | Function | Check allowlist/blocklist |

**Policy File Format:**
```json
{
  "version": "1.0",
  "tiers": {
    "autonomous": { "max_amount_xrp": 100, "daily_limit_xrp": 1000 },
    "delayed": { "max_amount_xrp": 1000, "delay_seconds": 300 },
    "cosign": { "min_amount_xrp": 1000, "signer_quorum": 2 }
  },
  "blocklist": { "addresses": [], "memo_patterns": [] },
  "allowlist": { "addresses": [], "trusted_tags": [] }
}
```

**Security Considerations:**
- Immutable evaluation (LLM cannot modify at runtime)
- Fail-secure: errors result in denial
- Complete decision logging for audit
- Policy files integrity-verified on load

### 3.3 Signing Service Container

| Attribute | Description |
|-----------|-------------|
| **Purpose** | Key loading, transaction signing, multi-sign orchestration |
| **Technology** | TypeScript, Node.js crypto, ripple-keypairs |
| **Responsibility** | Securely load keys, generate signatures, manage multi-sign flows |
| **Dependencies** | Keystore |

**Interfaces Provided:**

| Interface | Type | Description |
|-----------|------|-------------|
| `loadWallet()` | Function | Load and decrypt wallet keys |
| `signTransaction()` | Function | Sign transaction blob |
| `initiateMultiSign()` | Function | Start multi-signature workflow |
| `collectSignature()` | Function | Add external signature |

**Cryptographic Operations:**
- Ed25519 and secp256k1 signature algorithms
- XRPL canonical transaction serialization
- Deterministic signature generation

**Security Considerations:**
- Keys decrypted only in memory, never persisted unencrypted
- Memory zeroed immediately after use
- Private keys never returned via API
- Signing isolated from network operations

### 3.4 Keystore Container

| Attribute | Description |
|-----------|-------------|
| **Purpose** | Secure key persistence, encryption/decryption |
| **Technology** | AES-256-GCM encryption, Argon2id KDF, JSON files |
| **Responsibility** | Store encrypted wallets, derive encryption keys from passwords |
| **Dependencies** | File system |

**Storage Format:**
```json
{
  "version": 1,
  "wallet_id": "agent-wallet-001",
  "encrypted_seed": "<base64>",
  "iv": "<base64>",
  "auth_tag": "<base64>",
  "kdf": {
    "algorithm": "argon2id",
    "memory_cost": 65536,
    "time_cost": 3,
    "parallelism": 4
  },
  "created_at": "2026-01-28T00:00:00Z",
  "network": "mainnet"
}
```

**Directory Structure:**
```
~/.xrpl-wallet-mcp/
|-- mainnet/
|   |-- keystore/
|   |   |-- agent-wallet-001.enc
|   |   `-- agent-wallet-002.enc
|   `-- policies/
|-- testnet/
|   `-- keystore/
`-- devnet/
    `-- keystore/
```

**Security Considerations:**
- Network-isolated keystores (mainnet/testnet/devnet separated)
- File permissions: 0600 (owner read/write only)
- Directory permissions: 0700 (owner only)
- Salt per wallet prevents rainbow table attacks
- Argon2id parameters tuned for 200ms+ derivation time

### 3.5 Audit Logger Container

| Attribute | Description |
|-----------|-------------|
| **Purpose** | Tamper-evident logging, compliance evidence |
| **Technology** | TypeScript, HMAC-SHA256, JSON lines |
| **Responsibility** | Log all operations with hash chain integrity |
| **Dependencies** | File system |

**Log Entry Format:**
```json
{
  "seq": 12345,
  "timestamp": "2026-01-28T14:30:00.123Z",
  "event": "transaction_signed",
  "wallet_id": "agent-wallet-001",
  "transaction_type": "Payment",
  "amount_xrp": "50",
  "destination": "rDestination...",
  "tier": 1,
  "policy_decision": "allowed",
  "tx_hash": "ABC123...",
  "prev_hash": "XYZ789...",
  "hash": "DEF456..."
}
```

**Hash Chain Structure:**
```
Entry N:   hash = HMAC(prev_hash || seq || timestamp || event_data)
Entry N+1: hash = HMAC(entry_N.hash || seq || timestamp || event_data)
```

**Security Considerations:**
- HMAC key stored separately from log files
- Append-only (no modification or deletion)
- Daily log rotation with chain continuation
- Chain verification on startup and periodically
- Export formats for compliance (SOC 2, MiCA)

### 3.6 XRPL Client Container

| Attribute | Description |
|-----------|-------------|
| **Purpose** | XRPL network communication, transaction submission |
| **Technology** | xrpl.js 3.x, WebSocket |
| **Responsibility** | Connect to XRPL nodes, submit transactions, query state |
| **Dependencies** | XRPL network (external) |

**Interfaces Provided:**

| Interface | Type | Description |
|-----------|------|-------------|
| `connect()` | Function | Establish WebSocket connection |
| `submit()` | Function | Submit signed transaction |
| `getAccountInfo()` | Function | Query account state |
| `getTransaction()` | Function | Get transaction result |
| `getFee()` | Function | Get current network fee |

**Network Configuration:**
```json
{
  "networks": {
    "mainnet": {
      "primary": "wss://xrplcluster.com/",
      "fallback": ["wss://s1.ripple.com/", "wss://s2.ripple.com/"]
    },
    "testnet": {
      "primary": "wss://s.altnet.rippletest.net/"
    },
    "devnet": {
      "primary": "wss://s.devnet.rippletest.net/"
    }
  }
}
```

**Security Considerations:**
- TLS 1.3 required for all connections
- Certificate validation enabled
- Connection health monitoring
- Automatic reconnection with exponential backoff
- Network mismatch detection (prevent testnet keys on mainnet)

---

## 4. Level 3: Components

This section decomposes key containers into their internal components.

### 4.1 Policy Engine Components

See [C4 Component Diagram - Policy Engine](../c4-diagrams/components.md#policy-engine) for visual representation.

#### 4.1.1 Rule Evaluator

| Attribute | Description |
|-----------|-------------|
| **Purpose** | Evaluate transaction against policy rules |
| **Input** | Transaction object, policy configuration |
| **Output** | Evaluation result (allow/deny with reason) |

**Responsibilities:**
- Parse policy JSON structure
- Match transaction properties against rules
- Apply rule precedence (blocklist > allowlist > default)
- Return deterministic, reproducible decisions

**Interface:**
```typescript
interface RuleEvaluator {
  evaluate(
    transaction: XRPLTransaction,
    policy: Policy
  ): EvaluationResult;
}

interface EvaluationResult {
  allowed: boolean;
  reason: string;
  matched_rule: string;
  tier: ApprovalTier;
}
```

#### 4.1.2 Limit Tracker

| Attribute | Description |
|-----------|-------------|
| **Purpose** | Track and enforce transaction limits (rate, volume, count) |
| **Input** | Wallet ID, transaction amount, time window |
| **Output** | Limit status (within/exceeded) |

**Responsibilities:**
- Maintain sliding window counters per wallet
- Track daily/hourly volume in XRP
- Track transaction count limits
- Persist counters across restarts

**Interface:**
```typescript
interface LimitTracker {
  checkLimits(
    wallet_id: string,
    amount_drops: bigint
  ): LimitCheckResult;

  recordTransaction(
    wallet_id: string,
    amount_drops: bigint
  ): void;

  getLimitStatus(wallet_id: string): LimitStatus;
}

interface LimitStatus {
  daily_volume_xrp: number;
  daily_limit_xrp: number;
  hourly_count: number;
  hourly_limit: number;
  utilization_percent: number;
}
```

#### 4.1.3 Tier Classifier

| Attribute | Description |
|-----------|-------------|
| **Purpose** | Determine approval tier for transaction |
| **Input** | Transaction, evaluation result, limit status |
| **Output** | Approval tier (1-4) |

**Responsibilities:**
- Apply tier classification rules
- Consider amount, destination, transaction type
- Account for limit utilization
- Return tier with justification

**Tier Classification Logic:**
```
Tier 4 (Prohibited): Blocklisted OR policy violation OR limits exceeded
Tier 3 (Co-Sign):    Amount > cosign_threshold OR new destination
Tier 2 (Delayed):    Amount > autonomous_threshold OR elevated risk
Tier 1 (Autonomous): All checks pass, within autonomous bounds
```

**Interface:**
```typescript
interface TierClassifier {
  classify(
    transaction: XRPLTransaction,
    evaluation: EvaluationResult,
    limits: LimitStatus
  ): TierClassification;
}

interface TierClassification {
  tier: 1 | 2 | 3 | 4;
  reason: string;
  delay_seconds?: number;  // Tier 2
  required_approvers?: number;  // Tier 3
}
```

#### 4.1.4 Allowlist Manager

| Attribute | Description |
|-----------|-------------|
| **Purpose** | Manage destination allowlist/blocklist |
| **Input** | Address, memo, transaction type |
| **Output** | List status (allowed/blocked/unknown) |

**Responsibilities:**
- Maintain in-memory allowlist and blocklist
- Check addresses against lists
- Check memo patterns for suspicious content
- Learn from successful transactions (optional)

**Interface:**
```typescript
interface AllowlistManager {
  checkAddress(address: string): ListStatus;
  checkMemo(memo: string): ListStatus;
  addToAllowlist(address: string, tag?: string): void;
  addToBlocklist(address: string, reason: string): void;
  getListStatus(): { allowlist: Address[], blocklist: Address[] };
}

type ListStatus = 'allowed' | 'blocked' | 'unknown';
```

### 4.2 Signing Service Components

See [C4 Component Diagram - Signing Service](../c4-diagrams/components.md#signing-service) for visual representation.

#### 4.2.1 Key Loader

| Attribute | Description |
|-----------|-------------|
| **Purpose** | Load and decrypt wallet keys from keystore |
| **Input** | Wallet ID, password/key |
| **Output** | Decrypted key material (in SecureBuffer) |

**Responsibilities:**
- Read encrypted wallet file
- Derive decryption key via Argon2id
- Decrypt using AES-256-GCM
- Verify authentication tag
- Return key in secure memory buffer

**Interface:**
```typescript
interface KeyLoader {
  loadWallet(
    wallet_id: string,
    password: string
  ): Promise<SecureWallet>;

  unloadWallet(wallet_id: string): void;

  isLoaded(wallet_id: string): boolean;
}

interface SecureWallet {
  wallet_id: string;
  address: string;
  algorithm: 'ed25519' | 'secp256k1';
  publicKey: string;
  // privateKey stored in SecureBuffer, not exposed
}
```

#### 4.2.2 Signature Generator

| Attribute | Description |
|-----------|-------------|
| **Purpose** | Generate cryptographic signatures for transactions |
| **Input** | Transaction blob, signing key |
| **Output** | Signed transaction blob |

**Responsibilities:**
- Canonicalize transaction for signing
- Apply XRPL signing algorithm (Ed25519 or secp256k1)
- Generate deterministic signature
- Assemble signed transaction blob

**Interface:**
```typescript
interface SignatureGenerator {
  sign(
    transaction: XRPLTransaction,
    wallet: SecureWallet
  ): SignedTransaction;

  getTransactionHash(
    transaction: XRPLTransaction
  ): string;
}

interface SignedTransaction {
  tx_blob: string;
  tx_hash: string;
  signed_at: string;
}
```

#### 4.2.3 Multi-Sign Orchestrator

| Attribute | Description |
|-----------|-------------|
| **Purpose** | Coordinate multi-signature collection |
| **Input** | Transaction, required signers, collected signatures |
| **Output** | Multi-signed transaction or pending status |

**Responsibilities:**
- Track pending multi-sign transactions
- Collect signatures from multiple parties
- Verify each signature independently
- Assemble final multi-signed transaction
- Handle timeout and expiration

**Interface:**
```typescript
interface MultiSignOrchestrator {
  initiate(
    transaction: XRPLTransaction,
    signers: SignerEntry[],
    quorum: number
  ): MultiSignRequest;

  addSignature(
    request_id: string,
    signer: string,
    signature: string
  ): MultiSignStatus;

  getStatus(request_id: string): MultiSignStatus;

  finalize(request_id: string): SignedTransaction;
}

interface MultiSignStatus {
  request_id: string;
  collected: number;
  required: number;
  signers: { account: string; signed: boolean }[];
  expires_at: string;
  status: 'pending' | 'ready' | 'expired' | 'completed';
}
```

#### 4.2.4 SecureBuffer Manager

| Attribute | Description |
|-----------|-------------|
| **Purpose** | Manage sensitive data in memory securely |
| **Input** | Sensitive byte data |
| **Output** | Secure buffer with controlled access |

**Responsibilities:**
- Allocate secure memory for sensitive data
- Prevent swapping to disk (where supported)
- Zero memory on release
- Track buffer lifecycle
- Prevent accidental logging/serialization

**Interface:**
```typescript
interface SecureBufferManager {
  allocate(size: number): SecureBuffer;
  fromString(data: string, encoding: BufferEncoding): SecureBuffer;
  release(buffer: SecureBuffer): void;
  releaseAll(): void;
}

interface SecureBuffer {
  readonly length: number;
  read(offset: number, length: number): Uint8Array;
  write(data: Uint8Array, offset: number): void;
  clear(): void;
  // No toString() - prevents accidental exposure
}
```

### 4.3 MCP Server Components

See [C4 Component Diagram - MCP Server](../c4-diagrams/components.md#mcp-server) for visual representation.

#### 4.3.1 Tool Router

| Attribute | Description |
|-----------|-------------|
| **Purpose** | Route MCP tool invocations to handlers |
| **Input** | MCP tool request (name, arguments) |
| **Output** | Handler result or error |

**Responsibilities:**
- Parse incoming MCP requests
- Map tool names to handlers
- Invoke handlers with validated arguments
- Handle errors consistently
- Track request metadata

**Interface:**
```typescript
interface ToolRouter {
  registerTool(
    name: string,
    schema: ZodSchema,
    handler: ToolHandler,
    options: ToolOptions
  ): void;

  route(request: MCPToolRequest): Promise<MCPToolResponse>;

  listTools(): ToolDefinition[];
}

interface ToolOptions {
  sensitivity: 'low' | 'medium' | 'high' | 'critical';
  rate_limit: { requests: number; window_seconds: number };
  requires_unlock: boolean;
}
```

#### 4.3.2 Input Validator

| Attribute | Description |
|-----------|-------------|
| **Purpose** | Validate and sanitize all input |
| **Input** | Raw request data |
| **Output** | Validated data or validation error |

**Responsibilities:**
- Schema validation via Zod
- Type coercion where safe
- String sanitization (trim, length limits)
- XRPL address checksum validation
- Prompt injection pattern detection

**Interface:**
```typescript
interface InputValidator {
  validate<T>(
    schema: ZodSchema<T>,
    data: unknown
  ): ValidationResult<T>;

  sanitizeString(value: string, options: SanitizeOptions): string;

  validateXRPLAddress(address: string): boolean;

  detectInjection(input: string): InjectionResult;
}

interface ValidationResult<T> {
  success: boolean;
  data?: T;
  errors?: ValidationError[];
}

interface InjectionResult {
  detected: boolean;
  patterns: string[];
  risk_score: number;
}
```

#### 4.3.3 Rate Limiter

| Attribute | Description |
|-----------|-------------|
| **Purpose** | Enforce request rate limits |
| **Input** | Client identifier, resource identifier |
| **Output** | Allow/deny with retry-after |

**Responsibilities:**
- Implement token bucket algorithm
- Track per-client request rates
- Track per-tool request rates
- Support burst allowance
- Return rate limit headers

**Interface:**
```typescript
interface RateLimiter {
  checkLimit(
    client_id: string,
    resource: string
  ): RateLimitResult;

  recordRequest(
    client_id: string,
    resource: string
  ): void;

  getStatus(client_id: string): RateLimitStatus;
}

interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  reset_at: number;
  retry_after?: number;
}
```

#### 4.3.4 Response Formatter

| Attribute | Description |
|-----------|-------------|
| **Purpose** | Format responses for MCP protocol |
| **Input** | Handler result or error |
| **Output** | Properly formatted MCP response |

**Responsibilities:**
- Format success responses
- Format error responses with codes
- Sanitize output (no key material)
- Add response metadata
- Support streaming responses

**Interface:**
```typescript
interface ResponseFormatter {
  success(data: unknown): MCPToolResponse;

  error(
    code: ErrorCode,
    message: string,
    details?: unknown
  ): MCPToolResponse;

  stream(generator: AsyncGenerator<unknown>): MCPStreamResponse;
}

interface MCPToolResponse {
  content: Array<{
    type: 'text' | 'image' | 'resource';
    text?: string;
    data?: string;
    mimeType?: string;
  }>;
  isError?: boolean;
}
```

---

## 5. Cross-Cutting Concerns

### 5.1 Error Handling

All components follow fail-secure error handling:

```typescript
// Every operation wrapped in try-catch
async function handleSignRequest(request: SignRequest): Promise<SignResponse> {
  try {
    const validated = inputValidator.validate(SignRequestSchema, request);
    if (!validated.success) {
      await auditLogger.log('validation_failed', { errors: validated.errors });
      return responseFormatter.error('VALIDATION_ERROR', 'Invalid request');
    }

    const policyResult = await policyEngine.evaluate(validated.data.transaction);
    if (!policyResult.allowed) {
      await auditLogger.log('policy_denied', { reason: policyResult.reason });
      return responseFormatter.error('POLICY_DENIED', policyResult.reason);
    }

    // ... signing logic

  } catch (error) {
    await auditLogger.log('unexpected_error', { error: error.message });
    return responseFormatter.error('INTERNAL_ERROR', 'Operation failed');
  }
}
```

### 5.2 Logging Strategy

| Log Level | Usage | Example |
|-----------|-------|---------|
| ERROR | Security events, operation failures | Policy violation, signing failure |
| WARN | Potential issues, rate limiting | Rate limit approached, retry needed |
| INFO | Successful operations | Transaction signed, wallet created |
| DEBUG | Development diagnostics | Request details, timing info |

**Never Logged:**
- Private keys or seeds
- Full transaction details (sensitive portions redacted)
- Passwords or encryption keys

### 5.3 Configuration Management

Configuration hierarchy (later overrides earlier):
1. Default values (in code)
2. Configuration files (`server.json`, `networks.json`)
3. Environment variables
4. Runtime parameters

```typescript
interface Configuration {
  server: {
    transport: 'stdio' | 'sse';
    log_level: LogLevel;
    metrics_enabled: boolean;
  };
  security: {
    rate_limit_requests_per_minute: number;
    max_request_size_bytes: number;
    session_timeout_seconds: number;
  };
  network: NetworkConfiguration;
  keystore: KeystoreConfiguration;
}
```

### 5.4 Testing Strategy

| Component | Test Type | Coverage Target |
|-----------|-----------|-----------------|
| Policy Engine | Unit tests | 100% |
| Signing Service | Unit + Integration | 100% |
| MCP Server | Integration | 90% |
| Keystore | Unit + Security | 100% |
| Audit Logger | Unit | 100% |
| XRPL Client | Integration | 80% |

**Security-Critical Tests:**
- Key derivation correctness
- Encryption/decryption round-trip
- Policy evaluation determinism
- Hash chain integrity
- Rate limiting effectiveness

---

## 6. Design Decisions

### 6.1 Container Boundaries

| Decision | Rationale |
|----------|-----------|
| Policy Engine isolated | No external dependencies ensures deterministic evaluation |
| Signing Service separated | Cryptographic operations isolated from network |
| Keystore as data store | Clear separation of concerns, pluggable backends |
| Audit Logger independent | Can be replaced or extended without affecting core |

### 6.2 Component Responsibilities

**Single Responsibility**: Each component has one clear purpose:
- Rule Evaluator: Only evaluates rules
- Limit Tracker: Only tracks limits
- Key Loader: Only loads keys
- Signature Generator: Only generates signatures

**Dependency Direction**: Dependencies flow inward:
```
MCP Server --> Policy Engine --> (no dependencies)
           --> Signing Service --> Keystore
           --> Audit Logger --> (file system only)
           --> XRPL Client --> (external network only)
```

### 6.3 Security Boundaries

Three primary security boundaries:

1. **Input Boundary**: Between AI Agent and MCP Server
   - All input untrusted
   - Schema validation required
   - Rate limiting enforced

2. **Policy Boundary**: Between MCP Server and Signing Service
   - Policy must approve before signing
   - No bypass mechanism
   - All decisions logged

3. **Cryptographic Boundary**: Around Signing Service
   - Keys never cross this boundary unencrypted
   - Signing isolated from all other operations
   - Memory cleared after use

---

## Related Documents

- [C4 Context Diagram](../c4-diagrams/context.md) - Level 1 system context
- [C4 Container Diagram](../c4-diagrams/containers.md) - Level 2 containers
- [C4 Component Diagram](../c4-diagrams/components.md) - Level 3 components
- [03 - Context](03-context.md) - System context documentation
- [04 - Solution Strategy](04-solution-strategy.md) - Architecture approach
- [Security Architecture](../security/SECURITY-ARCHITECTURE.md) - Security details

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Tech Lead | Initial version |

---

*Arc42 Template - Section 05: Building Block View*
