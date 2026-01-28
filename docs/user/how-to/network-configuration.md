# How to Configure and Switch Between Networks

This guide walks you through configuring the XRPL Agent Wallet MCP server for different XRPL networks and safely switching between them.

---

## Prerequisites

Before configuring networks, ensure you have:

- XRPL Agent Wallet MCP server installed
- Access to the configuration directory (`~/.xrpl-wallet-mcp/`)
- Understanding of which network suits your use case
- Environment variable access (shell or MCP configuration)

---

## Introduction to XRPL Networks

The XRP Ledger operates multiple networks, each serving different purposes. Understanding these networks is essential for safe wallet operation.

### Available Networks

| Network | Purpose | XRP Value | Persistence |
|---------|---------|-----------|-------------|
| **Mainnet** | Production | Real monetary value | Permanent |
| **Testnet** | Integration testing | No value (free from faucet) | Periodic resets (~90 days) |
| **Devnet** | Development | No value (free from faucet) | Frequent resets |

### Risk Levels

| Network | Risk Level | Consequence of Error |
|---------|------------|----------------------|
| **Mainnet** | Critical | Irreversible fund loss |
| **Testnet** | Low | Minor inconvenience, can reset |
| **Devnet** | None | No impact, ephemeral environment |

### Choosing the Right Network

- **Use Devnet** for initial development and experimentation
- **Use Testnet** for integration testing and pre-production validation
- **Use Mainnet** only for production with real funds

---

## Configuring for Testnet (Development)

Testnet is ideal for testing your AI agent integration before moving to production. It provides a realistic environment with test XRP from the faucet.

### Step 1: Set Environment Variables

Create a `.env.testnet` file or export directly:

```bash
# Required
export XRPL_NETWORK=testnet

# Optional: Custom wallet storage
export XRPL_WALLET_HOME=~/.xrpl-wallet-mcp-test

# Optional: Enable verbose logging
export XRPL_LOG_LEVEL=debug

# Optional: Relaxed timeouts for testing
export XRPL_CONNECTION_TIMEOUT=30000
export XRPL_REQUEST_TIMEOUT=60000
export XRPL_MAX_RECONNECT_ATTEMPTS=5
```

### Step 2: Initialize the Testnet Directory

```bash
mkdir -p ~/.xrpl-wallet-mcp/testnet
chmod 700 ~/.xrpl-wallet-mcp/testnet
```

### Step 3: Create a Testnet Policy

Create `~/.xrpl-wallet-mcp/testnet/policy.json`:

```json
{
  "version": "1.0",
  "name": "testnet-development",
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
      "veto_enabled": true
    },
    "cosign": {
      "min_amount_xrp": 100000,
      "signer_quorum": 1
    },
    "prohibited": {
      "prohibited_transaction_types": []
    }
  },
  "limits": {
    "max_transactions_per_hour": 1000,
    "max_transactions_per_day": 10000
  }
}
```

### Step 4: Fund Your Wallet

Use the testnet faucet to obtain test XRP:

```bash
# Via CLI
xrpl-wallet faucet --network testnet --wallet my-test-wallet

# Or via API
curl -X POST https://faucet.altnet.rippletest.net/accounts \
  -H "Content-Type: application/json" \
  -d '{"destination": "rYourTestnetAddress..."}'
```

The faucet provides 1,000 test XRP per request with a rate limit of 1 request per minute.

### Step 5: Verify Connection

```bash
# Start the server
XRPL_NETWORK=testnet xrpl-wallet start

# Verify the connection
xrpl-wallet status --network testnet
```

Expected output:

```
Network: testnet
Endpoint: wss://s.altnet.rippletest.net:51233
Status: Connected
Ledger: 12345678
Explorer: https://testnet.xrpl.org
Faucet: Available
```

---

## Configuring for Devnet (Experimentation)

Devnet provides the most flexibility for rapid development. It resets frequently, so do not rely on persistent data.

### Step 1: Set Environment Variables

```bash
export XRPL_NETWORK=devnet
export XRPL_WALLET_HOME=~/.xrpl-wallet-mcp-dev
export XRPL_LOG_LEVEL=debug
```

### Step 2: Initialize the Devnet Directory

```bash
mkdir -p ~/.xrpl-wallet-mcp/devnet
chmod 700 ~/.xrpl-wallet-mcp/devnet
```

### Step 3: Create a Devnet Policy

Create `~/.xrpl-wallet-mcp/devnet/policy.json` with maximum flexibility:

```json
{
  "version": "1.0",
  "name": "devnet-unrestricted",
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
      "delay_seconds": 10,
      "veto_enabled": false
    },
    "cosign": {
      "signer_quorum": 1
    },
    "prohibited": {
      "prohibited_transaction_types": []
    }
  },
  "limits": {
    "max_transactions_per_hour": 10000,
    "max_transactions_per_day": 100000
  }
}
```

### Devnet Characteristics

- Resets frequently (sometimes daily)
- New features available before testnet
- Ideal for testing bleeding-edge XRPL features
- No data persistence guarantees

---

## Configuring for Mainnet (Production)

Mainnet handles real XRP with real monetary value. Configuration requires maximum security precautions.

### Step 1: Set Environment Variables

Create a dedicated `.env.mainnet` file:

```bash
# Required
export XRPL_NETWORK=mainnet

# Secure storage location
export XRPL_WALLET_HOME=/secure/xrpl-wallet

# Production logging level
export XRPL_LOG_LEVEL=info

# Require mainnet acknowledgment (recommended)
export XRPL_MAINNET_REQUIRE_ACK=true

# Strict timeouts
export XRPL_CONNECTION_TIMEOUT=5000
export XRPL_REQUEST_TIMEOUT=15000
export XRPL_MAX_RECONNECT_ATTEMPTS=2
```

### Step 2: Secure the Mainnet Directory

```bash
# Create with restricted permissions
mkdir -p /secure/xrpl-wallet/mainnet
chmod 700 /secure/xrpl-wallet/mainnet
chown $(whoami):$(whoami) /secure/xrpl-wallet/mainnet
```

### Step 3: Create a Conservative Mainnet Policy

Create `/secure/xrpl-wallet/mainnet/policy.json`:

```json
{
  "version": "1.0",
  "name": "mainnet-conservative",
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
      "prohibited_transaction_types": [
        "Clawback", "AccountSet", "SetRegularKey", "SignerListSet"
      ]
    }
  },
  "limits": {
    "max_transactions_per_hour": 50,
    "max_transactions_per_day": 200,
    "max_unique_destinations_per_day": 20,
    "max_total_volume_xrp_per_day": 5000
  },
  "blocklist": {
    "memo_patterns": [
      "ignore.*previous",
      "\\[INST\\]",
      "<<SYS>>",
      "system.*prompt"
    ]
  }
}
```

### Step 4: Acknowledge Mainnet Usage

Before performing mainnet operations, explicit acknowledgment is required:

```bash
xrpl-wallet acknowledge-mainnet \
  --confirmation "I understand this is mainnet with real XRP"
```

This acknowledgment:
- Expires after 24 hours (configurable)
- Must be renewed for continued mainnet access
- Is logged in the audit trail

### Important Mainnet Warnings

1. **No faucet available** - Mainnet XRP must be acquired through exchanges
2. **Transactions are irreversible** - Double-check all destinations
3. **Conservative limits recommended** - Start with low thresholds
4. **Enable all safety features** - Delays, veto windows, co-signing

---

## Switching Between Networks

The XRPL Agent Wallet enforces strict network isolation. You cannot switch networks while the wallet is unlocked.

### Network Switch Workflow

```
Current: Unlocked on Testnet
Target: Switch to Mainnet

1. Lock the current wallet
2. Update environment variable
3. Restart the server (or update MCP config)
4. Unlock for the target network
5. (Mainnet only) Acknowledge mainnet usage
```

### Step-by-Step Network Switch

#### Step 1: Lock the Current Wallet

```bash
xrpl-wallet lock
```

This clears the active session and zeroes key material in memory.

#### Step 2: Update the Network Configuration

**Option A: Environment Variable**

```bash
export XRPL_NETWORK=mainnet
```

**Option B: MCP Configuration**

Edit your Claude MCP configuration:

```json
{
  "mcpServers": {
    "xrpl-wallet": {
      "command": "node",
      "args": ["/path/to/xrpl-wallet-mcp/dist/index.js"],
      "env": {
        "XRPL_NETWORK": "mainnet"
      }
    }
  }
}
```

#### Step 3: Restart the Server

```bash
# Stop the current server
xrpl-wallet stop

# Start with new configuration
xrpl-wallet start
```

#### Step 4: Unlock for Target Network

```bash
xrpl-wallet unlock --network mainnet --password "your-secure-password"
```

#### Step 5: Acknowledge Mainnet (if switching to mainnet)

```bash
xrpl-wallet acknowledge-mainnet \
  --confirmation "I understand this is mainnet with real XRP"
```

### Programmatic Network Status

Check current network status via MCP tool:

```typescript
// Call wallet_get_network_status
const status = await wallet_get_network_status();

// Response:
{
  "current_network": "mainnet",
  "wallet_unlocked": true,
  "mainnet_acknowledged": true,
  "mainnet_ack_expires": "2026-01-29T15:30:00Z",
  "available_networks": ["mainnet", "testnet", "devnet"],
  "endpoints": {
    "websocket": "wss://xrplcluster.com",
    "explorer": "https://xrpscan.com",
    "faucet": null
  }
}
```

---

## Network-Specific Policy Recommendations

### Mainnet Policy Recommendations

| Setting | Recommended Value | Rationale |
|---------|-------------------|-----------|
| Autonomous max | 10-100 XRP | Limit exposure to autonomous decisions |
| Require known destination | Yes | Prevent payments to unknown addresses |
| Delay period | 5-15 minutes | Allow time for human review |
| Veto enabled | Yes | Allow cancellation during delay |
| Co-sign quorum | 2+ | Require multiple approvals |
| AccountSet | Prohibited | Prevent account configuration changes |
| SetRegularKey | Prohibited | Prevent key management changes |

### Testnet Policy Recommendations

| Setting | Recommended Value | Rationale |
|---------|-------------------|-----------|
| Autonomous max | 1,000-10,000 XRP | Allow meaningful test transactions |
| Require known destination | No | Enable testing with new addresses |
| Delay period | 1 minute | Quick feedback during testing |
| Transaction types | All standard types | Test full functionality |

### Devnet Policy Recommendations

| Setting | Recommended Value | Rationale |
|---------|-------------------|-----------|
| Autonomous max | 1,000,000 XRP | Unrestricted for development |
| Require known destination | No | Maximum flexibility |
| Delay period | 10 seconds | Minimal delays |
| Transaction types | All types including experimental | Test new features |

---

## Environment Variable Configuration

### Complete Environment Variable Reference

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `XRPL_NETWORK` | Active network (`mainnet`, `testnet`, `devnet`) | None | Yes |
| `XRPL_WALLET_HOME` | Base directory for wallet data | `~/.xrpl-wallet-mcp` | No |
| `XRPL_MAINNET_WEBSOCKET_URL` | Custom mainnet WebSocket endpoint | `wss://xrplcluster.com` | No |
| `XRPL_TESTNET_WEBSOCKET_URL` | Custom testnet WebSocket endpoint | `wss://s.altnet.rippletest.net:51233` | No |
| `XRPL_DEVNET_WEBSOCKET_URL` | Custom devnet WebSocket endpoint | `wss://s.devnet.rippletest.net:51233` | No |
| `XRPL_CONNECTION_TIMEOUT` | Connection timeout in milliseconds | `10000` | No |
| `XRPL_REQUEST_TIMEOUT` | Request timeout in milliseconds | `30000` | No |
| `XRPL_MAX_RECONNECT_ATTEMPTS` | Maximum reconnection attempts | `3` | No |
| `XRPL_LOG_LEVEL` | Logging level (`debug`, `info`, `warn`, `error`) | `info` | No |
| `XRPL_MAINNET_REQUIRE_ACK` | Require mainnet acknowledgment | `true` | No |

### Example Environment Files

**Development (.env.dev)**:

```bash
XRPL_NETWORK=devnet
XRPL_WALLET_HOME=~/.xrpl-wallet-mcp-dev
XRPL_LOG_LEVEL=debug
```

**Testing (.env.test)**:

```bash
XRPL_NETWORK=testnet
XRPL_WALLET_HOME=~/.xrpl-wallet-mcp-test
XRPL_LOG_LEVEL=debug
XRPL_CONNECTION_TIMEOUT=30000
XRPL_REQUEST_TIMEOUT=60000
```

**Production (.env.prod)**:

```bash
XRPL_NETWORK=mainnet
XRPL_WALLET_HOME=/secure/xrpl-wallet
XRPL_LOG_LEVEL=info
XRPL_MAINNET_REQUIRE_ACK=true
XRPL_CONNECTION_TIMEOUT=5000
XRPL_REQUEST_TIMEOUT=15000
XRPL_MAX_RECONNECT_ATTEMPTS=2
```

### Loading Environment Files

```bash
# Load specific environment
source .env.test

# Or use direnv for automatic loading
echo "source_env .env.test" > .envrc
direnv allow
```

---

## Verifying Network Connection

### Command-Line Verification

```bash
# Check network status
xrpl-wallet status --network testnet
```

Expected output:

```
Network Status
==============
Network:     testnet
Endpoint:    wss://s.altnet.rippletest.net:51233
Status:      Connected
Ledger:      45678901
Validated:   45678900
Server:      rippled 2.0.0
Explorer:    https://testnet.xrpl.org
Faucet:      https://faucet.altnet.rippletest.net/accounts
```

### Programmatic Verification

Use the MCP tool to verify connection:

```typescript
// Check server info
const serverInfo = await wallet_server_info({ network: "testnet" });

// Verify expected network
if (serverInfo.network !== "testnet") {
  throw new Error("Connected to wrong network!");
}

// Check ledger is advancing
console.log(`Current ledger: ${serverInfo.ledger_index}`);
```

### Network Endpoint Health Check

```bash
# Test WebSocket connectivity
wscat -c wss://s.altnet.rippletest.net:51233 -x '{"command":"server_info"}'
```

### Verifying Network Isolation

Confirm that keystores are properly isolated:

```bash
ls -la ~/.xrpl-wallet-mcp/
# Expected:
# drwx------ mainnet/
# drwx------ testnet/
# drwx------ devnet/

# Each directory should have separate files
ls ~/.xrpl-wallet-mcp/testnet/
# keystore.enc
# keystore.meta
# policy.json
# audit.log
```

---

## Common Network Issues

### Connection Failures

**Symptom**: Unable to connect to network endpoint

**Solutions**:

1. **Check network status**: XRPL networks occasionally have maintenance
   ```bash
   # Check XRPL status page or community channels
   curl https://xrpl.org/status
   ```

2. **Try backup endpoints**:
   ```bash
   export XRPL_TESTNET_WEBSOCKET_URL=wss://testnet.xrpl-labs.com
   ```

3. **Verify firewall allows WebSocket**:
   ```bash
   # Test port connectivity
   nc -zv s.altnet.rippletest.net 51233
   ```

4. **Check TLS certificate**:
   ```bash
   openssl s_client -connect s.altnet.rippletest.net:51233 -servername s.altnet.rippletest.net
   ```

### Network Mismatch Errors

**Symptom**: `NETWORK_MISMATCH` error when performing operations

**Cause**: Keystore is for a different network than requested

**Solution**:
```bash
# Lock wallet
xrpl-wallet lock

# Unlock for correct network
xrpl-wallet unlock --network testnet --password "your-password"
```

### Mainnet Acknowledgment Expired

**Symptom**: `MAINNET_ACK_EXPIRED` error

**Cause**: Acknowledgment older than 24 hours

**Solution**:
```bash
xrpl-wallet acknowledge-mainnet \
  --confirmation "I understand this is mainnet with real XRP"
```

### Faucet Rate Limited

**Symptom**: 429 error from faucet

**Cause**: Exceeded rate limit (1 request per minute)

**Solution**: Wait 60 seconds before retrying

```bash
# Check rate limit status
sleep 60 && xrpl-wallet faucet --network testnet --wallet my-wallet
```

### Testnet/Devnet Reset

**Symptom**: Wallet address shows zero balance after working previously

**Cause**: Network reset (testnet ~90 days, devnet more frequently)

**Solution**:
1. Accept that test funds are lost (no real value)
2. Re-initialize keystore if needed
3. Request new funds from faucet

```bash
# Re-fund from faucet
xrpl-wallet faucet --network testnet --wallet my-wallet
```

### Wrong Network Endpoints

**Symptom**: Transactions fail or behave unexpectedly

**Verification**:
```typescript
// Check which network you're actually connected to
const info = await wallet_server_info({ network: "testnet" });
console.log(info.info.network_id);  // Should match expected network
```

**Solution**: Reset environment and verify configuration:
```bash
# Clear environment
unset XRPL_MAINNET_WEBSOCKET_URL
unset XRPL_TESTNET_WEBSOCKET_URL
unset XRPL_DEVNET_WEBSOCKET_URL

# Use default endpoints
export XRPL_NETWORK=testnet
xrpl-wallet start
```

---

## MCP Configuration Example

Configure the XRPL wallet server in your Claude MCP settings:

```json
{
  "mcpServers": {
    "xrpl-wallet-testnet": {
      "command": "node",
      "args": ["/path/to/xrpl-wallet-mcp/dist/index.js"],
      "env": {
        "XRPL_NETWORK": "testnet",
        "XRPL_WALLET_HOME": "~/.xrpl-wallet-mcp",
        "XRPL_LOG_LEVEL": "info"
      }
    },
    "xrpl-wallet-mainnet": {
      "command": "node",
      "args": ["/path/to/xrpl-wallet-mcp/dist/index.js"],
      "env": {
        "XRPL_NETWORK": "mainnet",
        "XRPL_WALLET_HOME": "/secure/xrpl-wallet",
        "XRPL_LOG_LEVEL": "info",
        "XRPL_MAINNET_REQUIRE_ACK": "true"
      }
    }
  }
}
```

This configuration provides separate MCP servers for testnet and mainnet, ensuring complete isolation.

---

## Next Steps

- Review the [Policy Configuration Guide](./configure-policies.md) to set up network-specific policies
- Set up [human approval workflows](./set-up-human-approval.md) for mainnet operations
- Configure [monitoring and alerts](./configure-monitoring.md) for transaction activity

---

## Related Documentation

- [Network Configuration API Reference](../../api/network-config.md)
- [ADR-010: Network Isolation](../../architecture/09-decisions/ADR-010-network-isolation.md)
- [Security Architecture](../../security/SECURITY-ARCHITECTURE.md)
- [Policy Configuration Guide](./configure-policies.md)
