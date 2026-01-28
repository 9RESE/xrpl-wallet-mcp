# ADR-010: Network Isolation

**Status:** Accepted
**Date:** 2026-01-28
**Decision Makers:** Tech Lead, Security Specialist

---

## Context

XRPL operates multiple networks for different purposes:

| Network | Purpose | Real Value | Risk of Mistakes |
|---------|---------|------------|------------------|
| **Mainnet** | Production transactions | Yes (real XRP) | Catastrophic - irreversible loss |
| **Testnet** | Testing and development | No (test XRP) | Low - can be reset |
| **Devnet** | Development and experimentation | No (dev XRP) | None - ephemeral |

The wallet MCP must prevent accidental cross-network operations where:
- A testnet key is used to sign a mainnet transaction
- A mainnet transaction is accidentally submitted to testnet
- Development operations affect production accounts

This is a critical safety guardrail - a single cross-network mistake with mainnet could result in:
- Funds sent to wrong address (testnet address on mainnet = lost forever)
- Transaction signing with wrong key (invalid signature = failed TX)
- Configuration meant for testing applied to production

## Decision

**We will implement complete physical isolation of keystores per network, with runtime validation preventing any cross-network operations.**

### Storage Isolation

```
~/.xrpl-wallet-mcp/
├── mainnet/
│   ├── keystore.enc          # Mainnet keys ONLY
│   ├── keystore.meta         # Mainnet KDF params
│   ├── policy.json           # Mainnet-specific policy
│   └── audit.log             # Mainnet audit trail
├── testnet/
│   ├── keystore.enc          # Testnet keys ONLY
│   ├── keystore.meta
│   ├── policy.json           # May have relaxed limits
│   └── audit.log
└── devnet/
    ├── keystore.enc          # Devnet keys ONLY
    ├── keystore.meta
    ├── policy.json           # Most permissive
    └── audit.log
```

### Network Type Definition

```typescript
type Network = 'mainnet' | 'testnet' | 'devnet';

interface NetworkConfig {
  network: Network;
  websocketUrl: string;
  keystorePath: string;
  policyPath: string;
  auditLogPath: string;
  explorerUrl: string;
}

const NETWORK_CONFIGS: Record<Network, NetworkConfig> = {
  mainnet: {
    network: 'mainnet',
    websocketUrl: 'wss://xrplcluster.com',
    keystorePath: '~/.xrpl-wallet-mcp/mainnet/keystore.enc',
    policyPath: '~/.xrpl-wallet-mcp/mainnet/policy.json',
    auditLogPath: '~/.xrpl-wallet-mcp/mainnet/audit.log',
    explorerUrl: 'https://xrpscan.com'
  },
  testnet: {
    network: 'testnet',
    websocketUrl: 'wss://s.altnet.rippletest.net:51233',
    keystorePath: '~/.xrpl-wallet-mcp/testnet/keystore.enc',
    policyPath: '~/.xrpl-wallet-mcp/testnet/policy.json',
    auditLogPath: '~/.xrpl-wallet-mcp/testnet/audit.log',
    explorerUrl: 'https://testnet.xrpl.org'
  },
  devnet: {
    network: 'devnet',
    websocketUrl: 'wss://s.devnet.rippletest.net:51233',
    keystorePath: '~/.xrpl-wallet-mcp/devnet/keystore.enc',
    policyPath: '~/.xrpl-wallet-mcp/devnet/policy.json',
    auditLogPath: '~/.xrpl-wallet-mcp/devnet/audit.log',
    explorerUrl: 'https://devnet.xrpl.org'
  }
};
```

### Runtime Network Validation

```typescript
class NetworkIsolationGuard {
  private activeNetwork: Network | null = null;
  private keystoreNetwork: Network | null = null;

  async validateNetworkMatch(
    requestedNetwork: Network,
    operation: string,
    correlationId: string
  ): Promise<void> {
    // Check 1: Is the requested network valid?
    if (!['mainnet', 'testnet', 'devnet'].includes(requestedNetwork)) {
      throw new SecurityError(
        `Invalid network: ${requestedNetwork}`,
        'INVALID_NETWORK'
      );
    }

    // Check 2: If keystore is loaded, does it match?
    if (this.keystoreNetwork !== null && this.keystoreNetwork !== requestedNetwork) {
      await auditLog.log({
        eventType: 'SECURITY_NETWORK_MISMATCH',
        correlationId,
        operation: {
          name: operation,
          parameters: {
            requestedNetwork,
            keystoreNetwork: this.keystoreNetwork
          },
          result: 'denied',
          errorCode: 'NETWORK_MISMATCH'
        }
      });

      throw new SecurityError(
        `Network mismatch: keystore is for ${this.keystoreNetwork}, ` +
        `but operation requested ${requestedNetwork}`,
        'NETWORK_MISMATCH'
      );
    }

    // Check 3: Warn if switching networks (requires re-unlock)
    if (this.activeNetwork !== null && this.activeNetwork !== requestedNetwork) {
      throw new SecurityError(
        `Cannot switch networks while wallet is unlocked. ` +
        `Lock wallet and unlock for ${requestedNetwork}.`,
        'NETWORK_SWITCH_WHILE_UNLOCKED'
      );
    }
  }

  setActiveNetwork(network: Network): void {
    this.activeNetwork = network;
    this.keystoreNetwork = network;
  }

  clearActiveNetwork(): void {
    this.activeNetwork = null;
    // Note: keystoreNetwork retained to prevent re-unlock to different network
  }
}
```

### Address Validation per Network

```typescript
async function validateAddressForNetwork(
  address: string,
  network: Network,
  correlationId: string
): Promise<void> {
  const client = getClient(network);

  try {
    // Check if address exists on this network
    const accountInfo = await client.request({
      command: 'account_info',
      account: address
    });

    // Address exists on this network - valid
  } catch (error) {
    if (error.data?.error === 'actNotFound') {
      // Address doesn't exist on this network
      // This could be:
      // 1. New address (valid for create operations)
      // 2. Wrong network (mainnet address used on testnet)

      // Log warning but allow (new addresses are legitimate)
      logger.warn(`Address ${address} not found on ${network}`, { correlationId });
    } else {
      throw error;
    }
  }
}

// Validate wallet belongs to this network's keystore
async function validateWalletOwnership(
  walletAddress: string,
  network: Network,
  keystore: Keystore
): Promise<void> {
  if (!keystore.hasWallet(walletAddress)) {
    throw new SecurityError(
      `Wallet ${walletAddress} not found in ${network} keystore`,
      'WALLET_NOT_IN_KEYSTORE'
    );
  }
}
```

### Cross-Network Operation Prevention

```typescript
async function signTransaction(
  input: SignTransactionInput,
  context: MCPContext
): Promise<SignTransactionOutput> {
  const { transaction, wallet_address, network } = input;
  const correlationId = context.correlationId;

  // Step 1: Validate network isolation
  await networkGuard.validateNetworkMatch(network, 'sign_transaction', correlationId);

  // Step 2: Get network-specific keystore
  const keystore = await getKeystore(network);

  // Step 3: Validate wallet belongs to this keystore
  await validateWalletOwnership(wallet_address, network, keystore);

  // Step 4: Validate transaction account matches wallet
  if (transaction.Account !== wallet_address) {
    throw new ValidationError(
      `Transaction Account (${transaction.Account}) does not match wallet_address (${wallet_address})`,
      'ACCOUNT_MISMATCH'
    );
  }

  // Step 5: Optionally validate destination exists on network
  if (transaction.Destination) {
    await validateAddressForNetwork(transaction.Destination, network, correlationId);
  }

  // Step 6: Connect to correct network for autofill
  const client = getClient(network);
  // ... proceed with signing
}
```

### Per-Network Policy Differences

```typescript
// Mainnet policy - strict limits
const mainnetPolicy = {
  version: '1.0',
  network: 'mainnet',
  tiers: {
    autonomous: {
      max_amount_xrp: 100,        // Conservative limit
      daily_limit_xrp: 1000
    },
    // ... strict cosign thresholds
  }
};

// Testnet policy - relaxed for testing
const testnetPolicy = {
  version: '1.0',
  network: 'testnet',
  tiers: {
    autonomous: {
      max_amount_xrp: 10000,      // Higher for testing
      daily_limit_xrp: 100000
    },
    // ... relaxed thresholds
  }
};

// Devnet policy - most permissive
const devnetPolicy = {
  version: '1.0',
  network: 'devnet',
  tiers: {
    autonomous: {
      max_amount_xrp: 1000000,    // Very high for dev
      daily_limit_xrp: 10000000
    },
    // ... minimal restrictions
  }
};
```

## Consequences

### Positive

- **Physical Isolation**: Keys for different networks can never be mixed
- **Fail-Safe**: Validation failures block operations, never proceed unsafely
- **Clear Boundaries**: Each network has its own policy, audit trail
- **Testing Safety**: Cannot accidentally use mainnet keys in testing
- **Production Safety**: Test operations cannot affect mainnet
- **Audit Clarity**: Logs clearly show which network operations occurred on

### Negative

- **Multiple Unlocks**: Must unlock separately for each network
- **Storage Overhead**: Separate files per network (minimal impact)
- **Context Switching**: Cannot operate on multiple networks simultaneously
- **Setup Complexity**: Must configure each network separately

### Neutral

- Password can be same across networks (user choice)
- Policy can be copy-pasted between networks (then modified)
- Audit logs are network-specific (good for compliance)

## Alternatives Considered

| Option | Pros | Cons | Why Not Chosen |
|--------|------|------|----------------|
| **Single Keystore with Network Flag** | Simpler storage | One bug could expose mainnet keys to testnet | Unacceptable risk |
| **Runtime Network Tagging** | Flexible | Easy to bypass, keys not physically isolated | Insufficient safety |
| **No Network Awareness** | Simpler | Catastrophic cross-network risk | Completely unacceptable |
| **Separate Processes per Network** | Maximum isolation | Operational complexity | Overkill for single-user deployment |

## Implementation Notes

### Keystore Initialization

```typescript
async function initializeNetwork(network: Network, password: string): Promise<void> {
  const config = NETWORK_CONFIGS[network];
  const keystoreDir = path.dirname(config.keystorePath);

  // Create network-specific directory
  await fs.mkdir(keystoreDir, { recursive: true, mode: 0o700 });

  // Initialize empty keystore
  await createKeystore(password, network);

  // Copy default policy
  const defaultPolicy = getDefaultPolicy(network);
  await fs.writeFile(config.policyPath, JSON.stringify(defaultPolicy, null, 2));

  // Initialize audit log
  await initializeAuditLog(config.auditLogPath);

  logger.info(`Initialized ${network} keystore at ${config.keystorePath}`);
}
```

### Network-Aware Client Pool

```typescript
class XRPLClientPool {
  private clients: Map<Network, Client> = new Map();

  async getClient(network: Network): Promise<Client> {
    let client = this.clients.get(network);

    if (!client || !client.isConnected()) {
      const config = NETWORK_CONFIGS[network];
      client = new Client(config.websocketUrl);
      await client.connect();
      this.clients.set(network, client);
    }

    return client;
  }

  async disconnectAll(): Promise<void> {
    for (const [network, client] of this.clients) {
      if (client.isConnected()) {
        await client.disconnect();
      }
    }
    this.clients.clear();
  }
}
```

### CLI Network Selection

```bash
# Unlock specific network
xrpl-wallet unlock --network mainnet

# List wallets for specific network
xrpl-wallet list --network testnet

# Sign transaction (network must match unlocked keystore)
xrpl-wallet sign --network mainnet --wallet rXXX... --tx transaction.json

# Error if network mismatch
# Error: Network mismatch: keystore is for testnet, but operation requested mainnet
```

### MCP Tool Network Parameter

```typescript
// All tools require explicit network parameter
const GetBalanceInputSchema = z.object({
  wallet_address: XRPLAddressSchema,
  network: z.enum(['mainnet', 'testnet', 'devnet'])  // Required, no default
});

// Explicit network prevents accidental mainnet operations
// Must consciously specify 'mainnet' - no silent defaults
```

## Security Considerations

### Defense Against Cross-Network Attacks

| Attack | Defense |
|--------|---------|
| Testnet key used on mainnet | Physical isolation - key not in mainnet keystore |
| Mainnet TX sent to testnet | Network validation rejects mismatch |
| Policy meant for testnet on mainnet | Policies are network-specific files |
| Audit log confusion | Separate logs per network |

### Mainnet Safety Checklist

Before mainnet deployment:

- [ ] Mainnet keystore created separately from testnet
- [ ] Mainnet policy reviewed and approved
- [ ] Mainnet-specific limits configured
- [ ] Mainnet blocklist populated
- [ ] Mainnet monitoring enabled
- [ ] No testnet URLs in mainnet config
- [ ] Mainnet audit log location secured

### Compliance Mapping

| Requirement | Implementation |
|-------------|----------------|
| Network Isolation | Physical file separation |
| Cross-Network Prevention | Runtime validation |
| Audit Separation | Per-network log files |
| Policy Isolation | Per-network policy files |

## References

- [XRPL Networks](https://xrpl.org/parallel-networks.html)
- [Testnet Faucet](https://xrpl.org/xrp-testnet-faucet.html)
- [Devnet Faucet](https://xrpl.org/xrp-devnet-faucet.html)

## Related ADRs

- [ADR-001: Key Storage](ADR-001-key-storage.md) - Keystore structure
- [ADR-003: Policy Engine](ADR-003-policy-engine.md) - Per-network policies
- [ADR-005: Audit Logging](ADR-005-audit-logging.md) - Per-network audit trails

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Tech Lead | Initial ADR |
