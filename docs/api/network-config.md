# Network Configuration Specification

**Version:** 1.0.0
**Date:** 2026-01-28
**Status:** Approved
**Related ADR:** [ADR-010: Network Isolation](../architecture/09-decisions/ADR-010-network-isolation.md)

---

## Table of Contents

1. [Overview](#1-overview)
2. [Network Enum](#2-network-enum)
3. [WebSocket Endpoints](#3-websocket-endpoints)
4. [Explorer URLs](#4-explorer-urls)
5. [Faucet URLs](#5-faucet-urls)
6. [Network-Specific Policy Defaults](#6-network-specific-policy-defaults)
7. [Safety Guardrails](#7-safety-guardrails)
8. [Environment Variable Configuration](#8-environment-variable-configuration)
9. [Network Switching Procedures](#9-network-switching-procedures)
10. [Network Isolation Design](#10-network-isolation-design)
11. [Configuration Examples](#11-configuration-examples)

---

## 1. Overview

### Purpose

This document specifies the network configuration for the XRPL Agent Wallet MCP server. The configuration supports three XRPL networks with complete isolation between them to prevent cross-network operational errors.

### Design Principles

1. **Complete Isolation**: Each network has separate keystores, policies, and audit logs
2. **Explicit Selection**: Network must be explicitly specified; no silent defaults to mainnet
3. **Fail-Secure**: Invalid or missing network configuration blocks all operations
4. **Defense in Depth**: Multiple validation layers prevent cross-network mistakes
5. **Graduated Security**: Stricter defaults for mainnet, relaxed for testnet/devnet

### Risk Context

| Network | Real Value | Risk Level | Consequence of Error |
|---------|------------|------------|----------------------|
| **Mainnet** | Yes (real XRP) | Critical | Irreversible fund loss |
| **Testnet** | No (test XRP) | Low | Minor inconvenience, can reset |
| **Devnet** | No (dev XRP) | None | No impact, ephemeral environment |

---

## 2. Network Enum

### TypeScript Definition

```typescript
/**
 * Supported XRPL networks.
 *
 * IMPORTANT: No default value is provided intentionally.
 * All operations must explicitly specify their target network.
 */
type Network = 'mainnet' | 'testnet' | 'devnet';

/**
 * Zod schema for runtime validation
 */
const NetworkSchema = z.enum(['mainnet', 'testnet', 'devnet'], {
  errorMap: () => ({ message: 'Network must be one of: mainnet, testnet, devnet' })
});

/**
 * Network validation helper
 */
function isValidNetwork(value: unknown): value is Network {
  return value === 'mainnet' || value === 'testnet' || value === 'devnet';
}
```

### Network Characteristics

| Network | Chain ID | Purpose | Persistence | XRP Value |
|---------|----------|---------|-------------|-----------|
| `mainnet` | - | Production | Permanent | Real monetary value |
| `testnet` | - | Testing | Periodic resets (~90 days) | No value (free from faucet) |
| `devnet` | - | Development | Frequent resets | No value (free from faucet) |

### Validation Requirements

All MCP tool inputs must include explicit network specification:

```typescript
// Every tool input schema includes network
const GetBalanceInputSchema = z.object({
  wallet_address: XRPLAddressSchema,
  network: NetworkSchema  // Required, no default
});

const SignTransactionInputSchema = z.object({
  wallet_address: XRPLAddressSchema,
  transaction: TransactionSchema,
  network: NetworkSchema  // Required, no default
});
```

---

## 3. WebSocket Endpoints

### Default Endpoints

| Network | Primary WebSocket URL | Backup URLs |
|---------|----------------------|-------------|
| **Mainnet** | `wss://xrplcluster.com` | `wss://s1.ripple.com`, `wss://s2.ripple.com` |
| **Testnet** | `wss://s.altnet.rippletest.net:51233` | `wss://testnet.xrpl-labs.com` |
| **Devnet** | `wss://s.devnet.rippletest.net:51233` | - |

### Complete Endpoint Configuration

```typescript
interface NetworkEndpoints {
  websocket: {
    primary: string;
    backup: string[];
  };
  jsonRpc?: {
    primary: string;
    backup: string[];
  };
}

const NETWORK_ENDPOINTS: Record<Network, NetworkEndpoints> = {
  mainnet: {
    websocket: {
      primary: 'wss://xrplcluster.com',
      backup: [
        'wss://s1.ripple.com',
        'wss://s2.ripple.com'
      ]
    },
    jsonRpc: {
      primary: 'https://xrplcluster.com',
      backup: [
        'https://s1.ripple.com:51234',
        'https://s2.ripple.com:51234'
      ]
    }
  },
  testnet: {
    websocket: {
      primary: 'wss://s.altnet.rippletest.net:51233',
      backup: [
        'wss://testnet.xrpl-labs.com'
      ]
    },
    jsonRpc: {
      primary: 'https://s.altnet.rippletest.net:51234',
      backup: []
    }
  },
  devnet: {
    websocket: {
      primary: 'wss://s.devnet.rippletest.net:51233',
      backup: []
    },
    jsonRpc: {
      primary: 'https://s.devnet.rippletest.net:51234',
      backup: []
    }
  }
};
```

### Connection Configuration

```typescript
interface ConnectionConfig {
  /** Connection timeout in milliseconds */
  connectionTimeout: number;
  /** Request timeout in milliseconds */
  requestTimeout: number;
  /** Maximum reconnection attempts */
  maxReconnectAttempts: number;
  /** Reconnection delay in milliseconds */
  reconnectDelay: number;
  /** Enable TLS certificate validation */
  validateCertificates: boolean;
}

const DEFAULT_CONNECTION_CONFIG: ConnectionConfig = {
  connectionTimeout: 10000,    // 10 seconds
  requestTimeout: 30000,       // 30 seconds
  maxReconnectAttempts: 3,
  reconnectDelay: 1000,        // 1 second
  validateCertificates: true   // Always validate TLS
};
```

### Custom Endpoint Override

For enterprise deployments with private nodes:

```typescript
// Environment variable override
// XRPL_MAINNET_WEBSOCKET_URL=wss://my-private-node.example.com

interface CustomEndpointConfig {
  network: Network;
  websocketUrl: string;
  validateTLS?: boolean;
}

function getEndpointUrl(network: Network): string {
  // Check for environment override first
  const envKey = `XRPL_${network.toUpperCase()}_WEBSOCKET_URL`;
  const customUrl = process.env[envKey];

  if (customUrl) {
    // Validate custom URL
    if (!customUrl.startsWith('wss://')) {
      throw new ConfigurationError(
        `Custom endpoint must use WSS: ${envKey}`,
        'INVALID_ENDPOINT_PROTOCOL'
      );
    }
    return customUrl;
  }

  return NETWORK_ENDPOINTS[network].websocket.primary;
}
```

---

## 4. Explorer URLs

### Block Explorer Configuration

| Network | Explorer URL | Purpose |
|---------|-------------|---------|
| **Mainnet** | `https://xrpscan.com` | Primary mainnet explorer |
| **Mainnet** | `https://livenet.xrpl.org` | Official XRPL explorer |
| **Mainnet** | `https://bithomp.com/explorer` | Alternative explorer |
| **Testnet** | `https://testnet.xrpl.org` | Official testnet explorer |
| **Devnet** | `https://devnet.xrpl.org` | Official devnet explorer |

### Explorer URL Functions

```typescript
interface ExplorerUrls {
  /** Main explorer URL */
  home: string;
  /** Account/wallet lookup */
  account: (address: string) => string;
  /** Transaction lookup */
  transaction: (hash: string) => string;
  /** Ledger lookup */
  ledger: (index: number) => string;
}

const EXPLORER_URLS: Record<Network, ExplorerUrls> = {
  mainnet: {
    home: 'https://xrpscan.com',
    account: (address) => `https://xrpscan.com/account/${address}`,
    transaction: (hash) => `https://xrpscan.com/tx/${hash}`,
    ledger: (index) => `https://xrpscan.com/ledger/${index}`
  },
  testnet: {
    home: 'https://testnet.xrpl.org',
    account: (address) => `https://testnet.xrpl.org/accounts/${address}`,
    transaction: (hash) => `https://testnet.xrpl.org/transactions/${hash}`,
    ledger: (index) => `https://testnet.xrpl.org/ledgers/${index}`
  },
  devnet: {
    home: 'https://devnet.xrpl.org',
    account: (address) => `https://devnet.xrpl.org/accounts/${address}`,
    transaction: (hash) => `https://devnet.xrpl.org/transactions/${hash}`,
    ledger: (index) => `https://devnet.xrpl.org/ledgers/${index}`
  }
};

/**
 * Get explorer URL for a transaction
 */
function getTransactionExplorerUrl(hash: string, network: Network): string {
  return EXPLORER_URLS[network].transaction(hash);
}

/**
 * Get explorer URL for an account
 */
function getAccountExplorerUrl(address: string, network: Network): string {
  return EXPLORER_URLS[network].account(address);
}
```

### Explorer URL in Responses

Transaction responses should include explorer links for user convenience:

```typescript
interface SignTransactionResponse {
  success: true;
  transaction_hash: string;
  signed_blob: string;
  network: Network;
  explorer_url: string;  // Always include explorer URL
}

// Example response
{
  "success": true,
  "transaction_hash": "ABC123DEF456...",
  "signed_blob": "120000...",
  "network": "testnet",
  "explorer_url": "https://testnet.xrpl.org/transactions/ABC123DEF456..."
}
```

---

## 5. Faucet URLs

### Faucet Availability

| Network | Faucet Available | URL | Rate Limit |
|---------|------------------|-----|------------|
| **Mainnet** | No | N/A | N/A |
| **Testnet** | Yes | `https://faucet.altnet.rippletest.net/accounts` | 1 request/minute |
| **Devnet** | Yes | `https://faucet.devnet.rippletest.net/accounts` | 1 request/minute |

### Faucet Configuration

```typescript
interface FaucetConfig {
  /** Whether faucet is available for this network */
  available: boolean;
  /** Faucet API endpoint */
  url?: string;
  /** Amount dispensed per request (XRP) */
  amountXrp?: number;
  /** Rate limit window in seconds */
  rateLimitSeconds?: number;
  /** Rate limit requests per window */
  rateLimitRequests?: number;
}

const FAUCET_CONFIG: Record<Network, FaucetConfig> = {
  mainnet: {
    available: false
    // No faucet for mainnet - real XRP must be acquired through exchanges
  },
  testnet: {
    available: true,
    url: 'https://faucet.altnet.rippletest.net/accounts',
    amountXrp: 1000,
    rateLimitSeconds: 60,
    rateLimitRequests: 1
  },
  devnet: {
    available: true,
    url: 'https://faucet.devnet.rippletest.net/accounts',
    amountXrp: 1000,
    rateLimitSeconds: 60,
    rateLimitRequests: 1
  }
};
```

### Faucet Request Implementation

```typescript
interface FaucetRequest {
  destination: string;  // XRPL address to fund
}

interface FaucetResponse {
  account: {
    xAddress: string;
    classicAddress: string;
    secret?: string;  // Only if new account was generated
  };
  amount: number;
  balance: number;
}

/**
 * Request test XRP from faucet
 *
 * @throws {NetworkError} If network is mainnet (no faucet)
 * @throws {RateLimitError} If faucet rate limit exceeded
 */
async function requestFaucetFunds(
  network: Network,
  address: string
): Promise<FaucetResponse> {
  const config = FAUCET_CONFIG[network];

  if (!config.available) {
    throw new NetworkError(
      `Faucet not available for ${network}. Mainnet XRP must be acquired through exchanges.`,
      'FAUCET_NOT_AVAILABLE'
    );
  }

  const response = await fetch(config.url!, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ destination: address })
  });

  if (response.status === 429) {
    throw new RateLimitError(
      `Faucet rate limit exceeded. Wait ${config.rateLimitSeconds} seconds.`,
      'FAUCET_RATE_LIMITED',
      config.rateLimitSeconds
    );
  }

  if (!response.ok) {
    throw new NetworkError(
      `Faucet request failed: ${response.statusText}`,
      'FAUCET_REQUEST_FAILED'
    );
  }

  return await response.json();
}
```

### Faucet Security Considerations

| Consideration | Implementation |
|---------------|----------------|
| **Mainnet Protection** | Always reject faucet requests for mainnet |
| **Rate Limiting** | Enforce faucet's own rate limits locally |
| **Address Validation** | Validate address format before faucet request |
| **Response Handling** | Never log or expose generated secrets |

---

## 6. Network-Specific Policy Defaults

### Policy Philosophy by Network

| Network | Philosophy | Rationale |
|---------|------------|-----------|
| **Mainnet** | Maximum security, conservative limits | Real funds at risk |
| **Testnet** | Balanced security, relaxed limits | Testing without consequences |
| **Devnet** | Minimal restrictions | Rapid development iteration |

### Default Policy Configuration

#### Mainnet Defaults (Conservative)

```json
{
  "version": "1.0",
  "name": "mainnet-default",
  "network": "mainnet",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 100,
      "daily_limit_xrp": 1000,
      "require_known_destination": true,
      "allowed_transaction_types": ["Payment", "EscrowFinish", "EscrowCancel"],
      "max_fee_drops": 100000
    },
    "delayed": {
      "max_amount_xrp": 1000,
      "daily_limit_xrp": 10000,
      "delay_seconds": 300,
      "veto_enabled": true,
      "notify_on_queue": true
    },
    "cosign": {
      "min_amount_xrp": 1000,
      "new_destination_always": true,
      "signer_quorum": 2,
      "approval_timeout_hours": 24
    },
    "prohibited": {
      "prohibited_transaction_types": ["Clawback", "AccountSet", "SetRegularKey", "SignerListSet"]
    }
  },
  "limits": {
    "max_transactions_per_hour": 50,
    "max_transactions_per_day": 200,
    "max_unique_destinations_per_day": 20,
    "max_total_volume_xrp_per_day": 5000
  }
}
```

#### Testnet Defaults (Permissive)

```json
{
  "version": "1.0",
  "name": "testnet-default",
  "network": "testnet",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 10000,
      "daily_limit_xrp": 100000,
      "require_known_destination": false,
      "allowed_transaction_types": [
        "Payment", "TrustSet", "OfferCreate", "OfferCancel",
        "EscrowCreate", "EscrowFinish", "EscrowCancel",
        "CheckCreate", "CheckCash", "CheckCancel"
      ],
      "max_fee_drops": 1000000
    },
    "delayed": {
      "max_amount_xrp": 100000,
      "daily_limit_xrp": 1000000,
      "delay_seconds": 60,
      "veto_enabled": true,
      "notify_on_queue": false
    },
    "cosign": {
      "min_amount_xrp": 100000,
      "new_destination_always": false,
      "signer_quorum": 1,
      "approval_timeout_hours": 1
    },
    "prohibited": {
      "prohibited_transaction_types": []
    }
  },
  "limits": {
    "max_transactions_per_hour": 1000,
    "max_transactions_per_day": 10000,
    "max_unique_destinations_per_day": 500,
    "max_total_volume_xrp_per_day": 10000000
  }
}
```

#### Devnet Defaults (Maximum Flexibility)

```json
{
  "version": "1.0",
  "name": "devnet-default",
  "network": "devnet",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 1000000,
      "daily_limit_xrp": 10000000,
      "require_known_destination": false,
      "allowed_transaction_types": [
        "Payment", "TrustSet", "OfferCreate", "OfferCancel",
        "EscrowCreate", "EscrowFinish", "EscrowCancel",
        "AccountSet", "NFTokenMint", "NFTokenCreateOffer",
        "NFTokenAcceptOffer", "NFTokenBurn", "AMMCreate"
      ],
      "max_fee_drops": 10000000
    },
    "delayed": {
      "max_amount_xrp": 10000000,
      "daily_limit_xrp": 100000000,
      "delay_seconds": 10,
      "veto_enabled": false,
      "notify_on_queue": false
    },
    "cosign": {
      "min_amount_xrp": 10000000,
      "new_destination_always": false,
      "signer_quorum": 1,
      "approval_timeout_hours": 1
    },
    "prohibited": {
      "prohibited_transaction_types": []
    }
  },
  "limits": {
    "max_transactions_per_hour": 10000,
    "max_transactions_per_day": 100000,
    "max_unique_destinations_per_day": 10000,
    "max_total_volume_xrp_per_day": 100000000
  }
}
```

### Policy Comparison Matrix

| Setting | Mainnet | Testnet | Devnet |
|---------|---------|---------|--------|
| **Autonomous max_amount_xrp** | 100 | 10,000 | 1,000,000 |
| **Autonomous daily_limit_xrp** | 1,000 | 100,000 | 10,000,000 |
| **require_known_destination** | Yes | No | No |
| **Delay seconds** | 300 (5 min) | 60 (1 min) | 10 sec |
| **Veto enabled** | Yes | Yes | No |
| **Signer quorum** | 2 | 1 | 1 |
| **TX per hour** | 50 | 1,000 | 10,000 |
| **TX per day** | 200 | 10,000 | 100,000 |
| **AccountSet allowed** | No (prohibited) | Yes (delayed) | Yes (autonomous) |

---

## 7. Safety Guardrails

### Mainnet Confirmation Requirements

All mainnet operations require additional safety checks:

```typescript
interface MainnetConfirmation {
  /** User has acknowledged mainnet usage */
  acknowledged: boolean;
  /** Timestamp of acknowledgment */
  acknowledgedAt: string;
  /** Session ID for tracking */
  sessionId: string;
}

/**
 * Validate mainnet operation is intentional
 */
async function validateMainnetOperation(
  network: Network,
  context: MCPContext
): Promise<void> {
  if (network !== 'mainnet') {
    return; // No additional checks for testnet/devnet
  }

  // Check 1: Session must have mainnet acknowledgment
  if (!context.session.mainnetAcknowledged) {
    throw new SecurityError(
      'Mainnet operations require explicit acknowledgment. ' +
      'Call wallet_acknowledge_mainnet first.',
      'MAINNET_NOT_ACKNOWLEDGED'
    );
  }

  // Check 2: Acknowledgment must be recent (within 24 hours)
  const acknowledgedAt = new Date(context.session.mainnetAcknowledgedAt);
  const now = new Date();
  const hoursSinceAck = (now.getTime() - acknowledgedAt.getTime()) / (1000 * 60 * 60);

  if (hoursSinceAck > 24) {
    throw new SecurityError(
      'Mainnet acknowledgment expired (>24 hours). Please re-acknowledge.',
      'MAINNET_ACK_EXPIRED'
    );
  }

  // Check 3: Log mainnet operation for audit
  await auditLog.log({
    eventType: 'MAINNET_OPERATION',
    severity: 'INFO',
    network: 'mainnet',
    operation: context.operationName,
    correlationId: context.correlationId
  });
}
```

### Cross-Network Prevention

```typescript
class NetworkIsolationGuard {
  private activeNetwork: Network | null = null;
  private keystoreNetwork: Network | null = null;

  /**
   * Validate that requested network matches loaded keystore
   */
  async validateNetworkMatch(
    requestedNetwork: Network,
    operation: string,
    correlationId: string
  ): Promise<void> {
    // Validation 1: Network must be valid
    if (!isValidNetwork(requestedNetwork)) {
      throw new SecurityError(
        `Invalid network: ${requestedNetwork}`,
        'INVALID_NETWORK'
      );
    }

    // Validation 2: Keystore network must match
    if (this.keystoreNetwork !== null && this.keystoreNetwork !== requestedNetwork) {
      await auditLog.log({
        eventType: 'SECURITY_NETWORK_MISMATCH',
        severity: 'WARN',
        correlationId,
        details: {
          requestedNetwork,
          keystoreNetwork: this.keystoreNetwork,
          operation
        }
      });

      throw new SecurityError(
        `Network mismatch: keystore is for ${this.keystoreNetwork}, ` +
        `but operation requested ${requestedNetwork}. ` +
        `Lock wallet and unlock for ${requestedNetwork}.`,
        'NETWORK_MISMATCH'
      );
    }

    // Validation 3: Cannot switch networks while unlocked
    if (this.activeNetwork !== null && this.activeNetwork !== requestedNetwork) {
      throw new SecurityError(
        `Cannot switch networks while wallet is unlocked. ` +
        `Current network: ${this.activeNetwork}. ` +
        `Lock wallet first, then unlock for ${requestedNetwork}.`,
        'NETWORK_SWITCH_WHILE_UNLOCKED'
      );
    }
  }
}
```

### Warning Messages

| Scenario | Warning Message | Action |
|----------|-----------------|--------|
| First mainnet operation | "You are about to perform a mainnet operation. Real XRP is at risk." | Require acknowledgment |
| Large mainnet transaction | "This transaction exceeds X XRP. Please confirm this is intentional." | Require confirmation |
| New destination on mainnet | "This is the first transaction to this address on mainnet." | Elevate to co-sign tier |
| High fee detected | "Transaction fee (X drops) is unusually high." | Warn user |

### Pre-Operation Checklist (Mainnet)

Before any mainnet signing operation:

```typescript
interface MainnetPreflightCheck {
  checks: Array<{
    name: string;
    passed: boolean;
    message?: string;
  }>;
  allPassed: boolean;
}

async function runMainnetPreflight(
  transaction: Transaction,
  network: Network
): Promise<MainnetPreflightCheck> {
  const checks: MainnetPreflightCheck['checks'] = [];

  // Check 1: Network is explicitly mainnet
  checks.push({
    name: 'network_explicit',
    passed: network === 'mainnet',
    message: 'Network explicitly set to mainnet'
  });

  // Check 2: Destination address is valid
  if (transaction.Destination) {
    const isValid = isValidXRPLAddress(transaction.Destination);
    checks.push({
      name: 'destination_valid',
      passed: isValid,
      message: isValid ? 'Destination address valid' : 'Invalid destination address'
    });
  }

  // Check 3: Amount is within policy limits
  const amount = parseXRPAmount(transaction.Amount);
  const withinLimits = await policyEngine.checkAmountLimits(amount, network);
  checks.push({
    name: 'amount_within_limits',
    passed: withinLimits,
    message: withinLimits ? 'Amount within configured limits' : 'Amount exceeds limits'
  });

  // Check 4: Destination not in blocklist
  if (transaction.Destination) {
    const blocked = await policyEngine.isBlocked(transaction.Destination, network);
    checks.push({
      name: 'destination_not_blocked',
      passed: !blocked,
      message: blocked ? 'Destination is blocklisted' : 'Destination not blocklisted'
    });
  }

  // Check 5: Daily limits not exceeded
  const withinDailyLimits = await policyEngine.checkDailyLimits(amount, network);
  checks.push({
    name: 'daily_limits_ok',
    passed: withinDailyLimits,
    message: withinDailyLimits ? 'Within daily limits' : 'Would exceed daily limits'
  });

  return {
    checks,
    allPassed: checks.every(c => c.passed)
  };
}
```

---

## 8. Environment Variable Configuration

### Required Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `XRPL_NETWORK` | Active network for operations | None | Yes |
| `XRPL_WALLET_HOME` | Base directory for wallet data | `~/.xrpl-wallet-mcp` | No |

### Optional Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `XRPL_MAINNET_WEBSOCKET_URL` | Custom mainnet WebSocket endpoint | `wss://xrplcluster.com` |
| `XRPL_TESTNET_WEBSOCKET_URL` | Custom testnet WebSocket endpoint | `wss://s.altnet.rippletest.net:51233` |
| `XRPL_DEVNET_WEBSOCKET_URL` | Custom devnet WebSocket endpoint | `wss://s.devnet.rippletest.net:51233` |
| `XRPL_CONNECTION_TIMEOUT` | Connection timeout (ms) | `10000` |
| `XRPL_REQUEST_TIMEOUT` | Request timeout (ms) | `30000` |
| `XRPL_MAX_RECONNECT_ATTEMPTS` | Reconnection attempts | `3` |
| `XRPL_LOG_LEVEL` | Logging level | `info` |
| `XRPL_MAINNET_REQUIRE_ACK` | Require mainnet acknowledgment | `true` |

### Environment Configuration Schema

```typescript
const EnvironmentConfigSchema = z.object({
  // Network selection
  XRPL_NETWORK: NetworkSchema,
  XRPL_WALLET_HOME: z.string().default('~/.xrpl-wallet-mcp'),

  // Custom endpoints (optional)
  XRPL_MAINNET_WEBSOCKET_URL: z.string().url().startsWith('wss://').optional(),
  XRPL_TESTNET_WEBSOCKET_URL: z.string().url().startsWith('wss://').optional(),
  XRPL_DEVNET_WEBSOCKET_URL: z.string().url().startsWith('wss://').optional(),

  // Connection settings
  XRPL_CONNECTION_TIMEOUT: z.coerce.number().positive().default(10000),
  XRPL_REQUEST_TIMEOUT: z.coerce.number().positive().default(30000),
  XRPL_MAX_RECONNECT_ATTEMPTS: z.coerce.number().int().positive().default(3),

  // Logging
  XRPL_LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),

  // Safety
  XRPL_MAINNET_REQUIRE_ACK: z.coerce.boolean().default(true)
});

type EnvironmentConfig = z.infer<typeof EnvironmentConfigSchema>;
```

### Configuration Loading

```typescript
/**
 * Load and validate environment configuration
 */
function loadEnvironmentConfig(): EnvironmentConfig {
  const result = EnvironmentConfigSchema.safeParse(process.env);

  if (!result.success) {
    const errors = result.error.errors.map(e => `${e.path.join('.')}: ${e.message}`);
    throw new ConfigurationError(
      `Invalid environment configuration:\n${errors.join('\n')}`,
      'INVALID_ENV_CONFIG'
    );
  }

  return result.data;
}
```

### Example .env File

```bash
# .env.mainnet - Production configuration
XRPL_NETWORK=mainnet
XRPL_WALLET_HOME=/secure/wallets/xrpl
XRPL_LOG_LEVEL=info
XRPL_MAINNET_REQUIRE_ACK=true

# Optional: Use private node
# XRPL_MAINNET_WEBSOCKET_URL=wss://my-private-rippled.example.com

# Strict timeouts for production
XRPL_CONNECTION_TIMEOUT=5000
XRPL_REQUEST_TIMEOUT=15000
XRPL_MAX_RECONNECT_ATTEMPTS=2
```

```bash
# .env.testnet - Testing configuration
XRPL_NETWORK=testnet
XRPL_WALLET_HOME=~/.xrpl-wallet-mcp-test
XRPL_LOG_LEVEL=debug
XRPL_MAINNET_REQUIRE_ACK=false

# Relaxed timeouts for testing
XRPL_CONNECTION_TIMEOUT=30000
XRPL_REQUEST_TIMEOUT=60000
XRPL_MAX_RECONNECT_ATTEMPTS=5
```

```bash
# .env.devnet - Development configuration
XRPL_NETWORK=devnet
XRPL_WALLET_HOME=~/.xrpl-wallet-mcp-dev
XRPL_LOG_LEVEL=debug
XRPL_MAINNET_REQUIRE_ACK=false
```

---

## 9. Network Switching Procedures

### Important Constraints

1. **No hot switching**: Cannot switch networks while wallet is unlocked
2. **Separate keystores**: Each network has completely isolated key storage
3. **Separate policies**: Each network has its own policy configuration
4. **Explicit unlock**: Must unlock for specific network

### Network Switch Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                     Network Switch Process                       │
└─────────────────────────────────────────────────────────────────┘

Current State: Unlocked on Testnet
Target State: Unlocked on Mainnet

Step 1: Lock current wallet
┌─────────────────────┐
│  wallet_lock()      │  -> Clears active session
│                     │  -> Zeros key material in memory
│                     │  -> Sets activeNetwork = null
└─────────────────────┘
         │
         ▼
Step 2: Update environment (if needed)
┌─────────────────────┐
│  XRPL_NETWORK=      │  -> Set to target network
│    mainnet          │  -> Restart server if env-based
└─────────────────────┘
         │
         ▼
Step 3: Unlock for target network
┌─────────────────────┐
│  wallet_unlock(     │  -> Loads mainnet keystore
│    network=mainnet, │  -> Validates network isolation
│    password=...     │  -> Sets activeNetwork = mainnet
│  )                  │  -> Session scoped to mainnet
└─────────────────────┘
         │
         ▼
Step 4: (Mainnet only) Acknowledge mainnet
┌─────────────────────┐
│  acknowledge_       │  -> User confirms mainnet intent
│    mainnet()        │  -> Recorded in session
└─────────────────────┘
         │
         ▼
Step 5: Ready for mainnet operations
┌─────────────────────┐
│  Operations now     │  -> All ops validated against mainnet
│  execute on mainnet │  -> Mainnet keystore used
│                     │  -> Mainnet policy applied
└─────────────────────┘
```

### API for Network Management

```typescript
/**
 * Lock the current wallet (required before network switch)
 */
interface WalletLockInput {
  // No parameters - locks current session
}

interface WalletLockOutput {
  success: boolean;
  message: string;
  previously_active_network: Network | null;
}

/**
 * Unlock wallet for specific network
 */
interface WalletUnlockInput {
  network: Network;
  password: string;
}

interface WalletUnlockOutput {
  success: boolean;
  network: Network;
  session_id: string;
  requires_mainnet_acknowledgment: boolean;
}

/**
 * Acknowledge mainnet usage (required for mainnet operations)
 */
interface AcknowledgeMainnetInput {
  confirmation_text: 'I understand this is mainnet with real XRP';
}

interface AcknowledgeMainnetOutput {
  success: boolean;
  acknowledged_at: string;
  expires_at: string;  // 24 hours from now
}

/**
 * Get current network status
 */
interface GetNetworkStatusOutput {
  current_network: Network | null;
  wallet_unlocked: boolean;
  mainnet_acknowledged: boolean;
  mainnet_ack_expires: string | null;
  available_networks: Network[];
  endpoints: {
    websocket: string;
    explorer: string;
    faucet: string | null;
  };
}
```

### Error Handling for Network Operations

| Error | Cause | Resolution |
|-------|-------|------------|
| `NETWORK_SWITCH_WHILE_UNLOCKED` | Attempted switch without locking | Call `wallet_lock()` first |
| `NETWORK_MISMATCH` | Operation network differs from keystore | Lock and unlock for correct network |
| `MAINNET_NOT_ACKNOWLEDGED` | Mainnet operation without ack | Call `acknowledge_mainnet()` |
| `MAINNET_ACK_EXPIRED` | Acknowledgment older than 24h | Re-acknowledge |
| `KEYSTORE_NOT_FOUND` | No keystore for network | Initialize keystore for network first |

---

## 10. Network Isolation Design

### Summary of ADR-010

The network isolation architecture (detailed in [ADR-010](../architecture/09-decisions/ADR-010-network-isolation.md)) implements complete physical isolation of keystores per network with runtime validation preventing any cross-network operations.

### Storage Structure

```
~/.xrpl-wallet-mcp/
├── mainnet/
│   ├── keystore.enc          # Mainnet keys ONLY
│   ├── keystore.meta         # Mainnet KDF parameters
│   ├── policy.json           # Mainnet-specific policy
│   └── audit.log             # Mainnet audit trail
├── testnet/
│   ├── keystore.enc          # Testnet keys ONLY
│   ├── keystore.meta
│   ├── policy.json           # Relaxed limits for testing
│   └── audit.log
└── devnet/
    ├── keystore.enc          # Devnet keys ONLY
    ├── keystore.meta
    ├── policy.json           # Most permissive
    └── audit.log
```

### Isolation Guarantees

| Guarantee | Implementation |
|-----------|----------------|
| **Key Isolation** | Separate encrypted files per network |
| **Policy Isolation** | Network-specific policy.json files |
| **Audit Isolation** | Separate audit logs per network |
| **Runtime Validation** | NetworkIsolationGuard validates every operation |
| **Connection Isolation** | Separate client connections per network |

### Cross-Network Attack Prevention

| Attack Vector | Prevention Mechanism |
|---------------|---------------------|
| Testnet key on mainnet | Physical separation - key not in mainnet keystore |
| Mainnet TX to testnet | Runtime network validation rejects mismatch |
| Test policy on mainnet | Policies are in network-specific directories |
| Audit log confusion | Separate logs per network with network field |

### Network Configuration Type

```typescript
interface NetworkConfig {
  network: Network;
  websocketUrl: string;
  keystorePath: string;
  policyPath: string;
  auditLogPath: string;
  explorerUrl: string;
  faucetUrl: string | null;
}

function getNetworkConfig(network: Network, walletHome: string): NetworkConfig {
  const basePath = path.join(walletHome, network);
  const endpoints = NETWORK_ENDPOINTS[network];
  const explorer = EXPLORER_URLS[network];
  const faucet = FAUCET_CONFIG[network];

  return {
    network,
    websocketUrl: endpoints.websocket.primary,
    keystorePath: path.join(basePath, 'keystore.enc'),
    policyPath: path.join(basePath, 'policy.json'),
    auditLogPath: path.join(basePath, 'audit.log'),
    explorerUrl: explorer.home,
    faucetUrl: faucet.available ? faucet.url! : null
  };
}
```

---

## 11. Configuration Examples

### Example 1: Development Setup

Quick setup for local development using devnet:

```bash
# Environment setup
export XRPL_NETWORK=devnet
export XRPL_WALLET_HOME=~/.xrpl-wallet-mcp-dev
export XRPL_LOG_LEVEL=debug

# Initialize devnet keystore
xrpl-wallet init --network devnet

# Create a test wallet
xrpl-wallet create --network devnet --name test-wallet

# Fund from faucet
xrpl-wallet faucet --network devnet --wallet test-wallet
```

### Example 2: Testing Setup

Testnet configuration for integration testing:

```typescript
// test-config.ts
export const testConfig = {
  network: 'testnet' as const,
  websocketUrl: 'wss://s.altnet.rippletest.net:51233',
  walletHome: '/tmp/xrpl-wallet-test',
  policy: {
    version: '1.0',
    name: 'test-policy',
    network: 'testnet',
    tiers: {
      autonomous: {
        max_amount_xrp: 50000,
        daily_limit_xrp: 500000,
        require_known_destination: false
      }
    },
    limits: {
      max_transactions_per_hour: 500,
      max_transactions_per_day: 5000
    }
  }
};
```

### Example 3: Production Setup

Mainnet configuration with maximum security:

```typescript
// production-config.ts
export const productionConfig = {
  network: 'mainnet' as const,

  // Use private node for reliability
  websocketUrl: process.env.XRPL_MAINNET_WEBSOCKET_URL || 'wss://xrplcluster.com',

  // Secure storage location
  walletHome: '/secure/xrpl-wallet',

  // Conservative policy
  policy: {
    version: '1.0',
    name: 'production-conservative',
    network: 'mainnet',
    tiers: {
      autonomous: {
        max_amount_xrp: 50,           // Very conservative
        daily_limit_xrp: 500,
        require_known_destination: true,
        allowed_transaction_types: ['Payment']
      },
      delayed: {
        max_amount_xrp: 500,
        delay_seconds: 600,           // 10 minute delay
        veto_enabled: true
      },
      cosign: {
        min_amount_xrp: 500,
        signer_quorum: 2,
        new_destination_always: true
      },
      prohibited: {
        prohibited_transaction_types: [
          'AccountSet', 'SetRegularKey', 'SignerListSet',
          'TrustSet', 'OfferCreate', 'Clawback'
        ]
      }
    },
    limits: {
      max_transactions_per_hour: 10,
      max_transactions_per_day: 50,
      max_unique_destinations_per_day: 5,
      max_total_volume_xrp_per_day: 1000
    },
    blocklist: {
      addresses: [],  // Populate with known scam addresses
      memo_patterns: [
        'ignore.*previous',
        '\\[INST\\]',
        '<<SYS>>',
        'system.*prompt'
      ]
    }
  },

  // Connection settings
  connection: {
    timeout: 5000,
    requestTimeout: 15000,
    maxReconnectAttempts: 2
  },

  // Safety requirements
  requireMainnetAcknowledgment: true,
  acknowledgmentExpiryHours: 8  // Shorter for production
};
```

### Example 4: Multi-Network Agent

Configuration for an agent that operates across multiple networks:

```typescript
// multi-network-config.ts
interface MultiNetworkConfig {
  networks: {
    [K in Network]: {
      enabled: boolean;
      role: 'production' | 'staging' | 'development';
      policyFile: string;
    };
  };
  defaultNetwork: Network;
}

export const multiNetworkConfig: MultiNetworkConfig = {
  networks: {
    mainnet: {
      enabled: true,
      role: 'production',
      policyFile: './policies/mainnet-strict.json'
    },
    testnet: {
      enabled: true,
      role: 'staging',
      policyFile: './policies/testnet-standard.json'
    },
    devnet: {
      enabled: true,
      role: 'development',
      policyFile: './policies/devnet-permissive.json'
    }
  },
  defaultNetwork: 'testnet'  // Default to testnet for safety
};

// Usage: Agent must explicitly unlock for desired network
async function setupMultiNetworkAgent() {
  const config = multiNetworkConfig;

  // Initialize all enabled networks
  for (const [network, settings] of Object.entries(config.networks)) {
    if (settings.enabled) {
      await initializeNetwork(network as Network, settings.policyFile);
    }
  }

  // Start with default network (testnet)
  await unlockWallet(config.defaultNetwork, password);
}
```

### Example 5: Claude MCP Configuration

MCP server configuration for Claude integration:

```json
{
  "mcpServers": {
    "xrpl-wallet": {
      "command": "node",
      "args": ["/path/to/xrpl-wallet-mcp/dist/index.js"],
      "env": {
        "XRPL_NETWORK": "testnet",
        "XRPL_WALLET_HOME": "~/.xrpl-wallet-mcp",
        "XRPL_LOG_LEVEL": "info",
        "XRPL_MAINNET_REQUIRE_ACK": "true"
      }
    }
  }
}
```

---

## Related Documents

- [ADR-010: Network Isolation](../architecture/09-decisions/ADR-010-network-isolation.md) - Full network isolation decision record
- [ADR-003: Policy Engine](../architecture/09-decisions/ADR-003-policy-engine.md) - Per-network policy design
- [Policy Schema](./policy-schema.md) - Complete policy configuration reference
- [Security Architecture](../security/SECURITY-ARCHITECTURE.md) - Network security considerations

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Backend Engineer | Initial network configuration specification |

---

*This document is part of the XRPL Agent Wallet MCP specification.*
