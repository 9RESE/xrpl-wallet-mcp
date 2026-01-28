# How to Configure Policies

This guide walks you through configuring security policies for the XRPL Agent Wallet MCP server. Policies control what transactions AI agents can execute autonomously and which require human approval.

---

## Prerequisites

Before configuring policies, ensure you have:

- XRPL Agent Wallet MCP server installed
- Access to the configuration directory (`~/.xrpl-wallet-mcp/`)
- A text editor for JSON files
- Understanding of your agent's intended use case

---

## Policy File Location

Policies are stored in network-specific directories:

```
~/.xrpl-wallet-mcp/
├── mainnet/
│   └── policy.json
├── testnet/
│   └── policy.json
└── devnet/
    └── policy.json
```

Each network has its own isolated policy. The server loads the appropriate policy based on the configured network at startup.

### Creating the Policy File

1. Create the network directory if it does not exist:

   ```bash
   mkdir -p ~/.xrpl-wallet-mcp/mainnet
   ```

2. Create a new policy file:

   ```bash
   touch ~/.xrpl-wallet-mcp/mainnet/policy.json
   ```

3. Set secure file permissions:

   ```bash
   chmod 600 ~/.xrpl-wallet-mcp/mainnet/policy.json
   ```

---

## Setting Transaction Limits

Transaction limits control how much an agent can move in a single transaction and cumulatively over time.

### Single Transaction Limits

Set the maximum amount for autonomous (instant) transactions:

```json
{
  "version": "1.0",
  "name": "my-policy",
  "network": "mainnet",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 100
    }
  }
}
```

The `max_amount_xrp` field caps individual transactions. Transactions exceeding this amount escalate to a higher tier.

### Daily Volume Limits

Limit cumulative daily transaction volume:

```json
{
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 100,
      "daily_limit_xrp": 1000
    },
    "delayed": {
      "max_amount_xrp": 1000,
      "daily_limit_xrp": 10000
    }
  }
}
```

Daily limits apply separately to each tier. Once a tier's daily limit is reached, subsequent transactions are rejected until the daily reset.

### Rate Limits

Control transaction frequency with global limits:

```json
{
  "limits": {
    "max_transactions_per_hour": 100,
    "max_transactions_per_day": 1000,
    "max_unique_destinations_per_day": 50,
    "max_total_volume_xrp_per_day": 10000,
    "daily_reset_utc_hour": 0
  }
}
```

| Field | Purpose |
|-------|---------|
| `max_transactions_per_hour` | Prevents rapid drain attacks |
| `max_transactions_per_day` | Caps overall daily activity |
| `max_unique_destinations_per_day` | Limits fund scattering |
| `max_total_volume_xrp_per_day` | Hard ceiling on daily movement |
| `daily_reset_utc_hour` | When counters reset (0-23 UTC) |

---

## Configuring Destination Allowlists

Allowlists define trusted destinations that receive favorable treatment in policy evaluation.

### Basic Allowlist

Add known-good addresses:

```json
{
  "allowlist": {
    "addresses": [
      "rKnownGoodAddress11111111111111111",
      "rTreasuryWallet222222222222222222222",
      "rVendorPayment3333333333333333333333"
    ]
  }
}
```

Allowlisted addresses can receive autonomous transactions when `require_known_destination` is enabled.

### Exchange Addresses with Tags

Configure exchange addresses that require destination tags:

```json
{
  "allowlist": {
    "addresses": [
      "rInternalWallet11111111111111111111"
    ],
    "exchange_addresses": [
      {
        "address": "rBinance111111111111111111111111111",
        "name": "Binance Hot Wallet",
        "require_tag": true
      },
      {
        "address": "rCoinbase222222222222222222222222222",
        "name": "Coinbase Deposit",
        "require_tag": true
      }
    ],
    "trusted_tags": [
      123456,
      789012
    ]
  }
}
```

When `require_tag` is true, transactions to that exchange address must include a destination tag.

### Using Allowlist in Rules

Reference the allowlist in policy rules:

```json
{
  "rules": [
    {
      "id": "rule-allow-known",
      "name": "allow-known-destinations",
      "priority": 10,
      "condition": {
        "field": "destination",
        "operator": "in",
        "value": { "ref": "allowlist.addresses" }
      },
      "action": {
        "tier": "autonomous",
        "reason": "Known trusted destination"
      }
    }
  ]
}
```

---

## Setting Up Blocklists

Blocklists prevent transactions to known-bad addresses and detect prompt injection attempts in memos.

### Address Blocklist

Block known scam or sanctioned addresses:

```json
{
  "blocklist": {
    "addresses": [
      "rScamAddress111111111111111111111",
      "rSanctionedAddress2222222222222222",
      "rPhishingWallet333333333333333333333"
    ]
  }
}
```

Transactions to blocklisted addresses are immediately prohibited, regardless of other policy rules.

### Memo Pattern Blocklist

Block transactions containing suspicious memo content:

```json
{
  "blocklist": {
    "memo_patterns": [
      "ignore.*previous",
      "\\[INST\\]",
      "<<SYS>>",
      "system.*prompt",
      "admin.*override",
      "bypass.*security"
    ]
  }
}
```

These regex patterns detect common prompt injection attempts. The default patterns catch:

| Pattern | Attack Type |
|---------|-------------|
| `ignore.*previous` | Instruction override attacks |
| `\[INST\]` | Llama-style injection markers |
| `<<SYS>>` | System prompt injection |
| `system.*prompt` | Direct system manipulation |
| `admin.*override` | Fake privilege escalation |

### Token Issuer Blocklist

Block transactions involving tokens from suspicious issuers:

```json
{
  "blocklist": {
    "currency_issuers": [
      "rScamTokenIssuer333333333333333333",
      "rFakeUSD444444444444444444444444444"
    ]
  }
}
```

---

## Configuring Tier Thresholds

The policy engine classifies transactions into four tiers based on risk. Configure thresholds for each tier.

### Tier Hierarchy

```
Tier 4: Prohibited     -> Blocked, never executed
Tier 3: Co-Sign        -> Requires human multi-signature
Tier 2: Delayed        -> Held for review period
Tier 1: Autonomous     -> Immediate execution
```

### Complete Tier Configuration

```json
{
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
      "approval_timeout_hours": 24,
      "notify_signers": true,
      "signer_addresses": [
        "rHumanSigner1111111111111111111111",
        "rHumanSigner2222222222222222222222"
      ]
    },
    "prohibited": {
      "prohibited_transaction_types": ["Clawback", "AccountSet", "SetRegularKey"]
    }
  }
}
```

### Tier Threshold Guidelines

| Setting | Conservative | Moderate | Permissive |
|---------|--------------|----------|------------|
| Autonomous max | 10-50 XRP | 100-500 XRP | 1000+ XRP |
| Autonomous daily | 100-500 XRP | 1000-5000 XRP | 10000+ XRP |
| Delay period | 1 hour | 5 minutes | 1 minute |
| Co-sign quorum | 3 | 2 | 1 |

Choose thresholds based on your risk tolerance and operational needs.

---

## Time-Based Controls

### Delay Configuration

Configure how long transactions are held before execution:

```json
{
  "tiers": {
    "delayed": {
      "delay_seconds": 300,
      "veto_enabled": true,
      "notify_on_queue": true
    }
  }
}
```

The `delay_seconds` field sets the review window (60 to 86,400 seconds). During this window, humans can veto the transaction if `veto_enabled` is true.

### Cooldown After High-Value Transactions

Enforce a pause after large transactions:

```json
{
  "limits": {
    "cooldown_after_high_value": {
      "enabled": true,
      "threshold_xrp": 1000,
      "cooldown_seconds": 300
    }
  }
}
```

When a transaction exceeds `threshold_xrp`, all subsequent transactions are blocked for `cooldown_seconds`. This prevents rapid sequential draining.

### Approval Timeouts

Set expiration for pending co-sign approvals:

```json
{
  "tiers": {
    "cosign": {
      "approval_timeout_hours": 24
    }
  },
  "escalation": {
    "auto_deny_on_timeout": true
  }
}
```

Pending approvals expire after `approval_timeout_hours`. If `auto_deny_on_timeout` is true, expired requests are automatically denied.

---

## Network-Specific Policies

Each network should have a policy tailored to its risk profile.

### Mainnet Policy (Conservative)

For production use with real XRP:

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
      "allowed_transaction_types": ["Payment", "EscrowFinish", "EscrowCancel"]
    },
    "delayed": {
      "max_amount_xrp": 1000,
      "daily_limit_xrp": 10000,
      "delay_seconds": 300,
      "veto_enabled": true
    },
    "cosign": {
      "min_amount_xrp": 1000,
      "new_destination_always": true,
      "signer_quorum": 2
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

### Testnet Policy (Permissive)

For testing with test XRP:

```json
{
  "version": "1.0",
  "name": "testnet-permissive",
  "network": "testnet",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 10000,
      "daily_limit_xrp": 100000,
      "require_known_destination": false,
      "allowed_transaction_types": ["Payment", "TrustSet", "OfferCreate", "OfferCancel", "EscrowCreate", "EscrowFinish", "EscrowCancel"]
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
    "max_transactions_per_day": 10000,
    "max_unique_destinations_per_day": 500,
    "max_total_volume_xrp_per_day": 10000000
  }
}
```

### Devnet Policy (Development)

For local development and rapid iteration:

```json
{
  "version": "1.0",
  "name": "devnet-development",
  "network": "devnet",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 1000000,
      "daily_limit_xrp": 10000000,
      "require_known_destination": false,
      "allowed_transaction_types": ["Payment", "TrustSet", "OfferCreate", "OfferCancel", "EscrowCreate", "EscrowFinish", "EscrowCancel", "AccountSet", "NFTokenMint", "AMMCreate"]
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
    "max_transactions_per_day": 100000,
    "max_unique_destinations_per_day": 10000,
    "max_total_volume_xrp_per_day": 100000000
  }
}
```

---

## Updating Policies at Runtime

Policies are loaded at server startup and cannot be modified by agents at runtime. This is a security feature.

### Applying Policy Changes

1. Edit the policy file:

   ```bash
   nano ~/.xrpl-wallet-mcp/mainnet/policy.json
   ```

2. Validate the policy (see next section):

   ```bash
   xrpl-wallet validate-policy ~/.xrpl-wallet-mcp/mainnet/policy.json
   ```

3. Restart the MCP server to apply changes:

   ```bash
   # If running as a service
   systemctl restart xrpl-wallet-mcp

   # If running manually, stop and restart the process
   ```

### Hot Reload Considerations

The server does not support hot reload of policies. This is intentional to prevent:

- Agents influencing their own policies
- Partial policy states during updates
- Race conditions in policy evaluation

Always restart the server after policy changes.

---

## Policy Validation

Validate policies before deployment to catch configuration errors.

### Schema Validation

Validate against the JSON schema:

```bash
xrpl-wallet validate-policy ./policy.json
```

The validator checks:

- Required fields are present
- Field types are correct
- Values are within allowed ranges
- References (like `allowlist.addresses`) resolve correctly

### Test Transaction Simulation

Test how specific transactions would be evaluated:

```bash
xrpl-wallet test-policy ./policy.json --test-cases ./test-transactions.json
```

Example test cases file:

```json
{
  "test_cases": [
    {
      "name": "small-payment-to-known",
      "transaction": {
        "type": "Payment",
        "destination": "rKnownGoodAddress11111111111111111",
        "amount_xrp": 50
      },
      "expected_tier": "autonomous"
    },
    {
      "name": "large-payment-to-unknown",
      "transaction": {
        "type": "Payment",
        "destination": "rUnknownAddress77777777777777777777",
        "amount_xrp": 5000
      },
      "expected_tier": "cosign"
    },
    {
      "name": "blocklisted-destination",
      "transaction": {
        "type": "Payment",
        "destination": "rScamAddress111111111111111111111",
        "amount_xrp": 10
      },
      "expected_tier": "prohibited"
    }
  ]
}
```

### Common Validation Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `Missing required field: version` | Policy lacks version | Add `"version": "1.0"` |
| `Invalid network value` | Wrong network name | Use "mainnet", "testnet", or "devnet" |
| `Rule priority conflict` | Duplicate priorities | Ensure unique priority values |
| `Invalid regex in memo_patterns` | Malformed regex | Test patterns with a regex validator |
| `Reference not found` | Bad `ref` in condition | Check that referenced list exists |

---

## Examples for Common Use Cases

### Trading Bot Policy

For a DEX trading agent:

```json
{
  "version": "1.0",
  "name": "trading-bot",
  "network": "mainnet",
  "description": "Automated DEX trading with no direct payments",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 500,
      "daily_limit_xrp": 5000,
      "require_known_destination": false,
      "allowed_transaction_types": ["OfferCreate", "OfferCancel", "TrustSet"]
    },
    "delayed": {
      "max_amount_xrp": 2000,
      "daily_limit_xrp": 20000,
      "delay_seconds": 180
    },
    "cosign": {
      "min_amount_xrp": 2000,
      "signer_quorum": 2
    },
    "prohibited": {
      "prohibited_transaction_types": ["Payment", "AccountSet", "SetRegularKey"]
    }
  },
  "rules": [
    {
      "id": "rule-block-payments",
      "name": "block-all-payments",
      "priority": 1,
      "condition": {
        "field": "transaction_type",
        "operator": "==",
        "value": "Payment"
      },
      "action": {
        "tier": "prohibited",
        "reason": "Trading bot cannot make payments"
      }
    }
  ],
  "limits": {
    "max_transactions_per_hour": 200,
    "max_transactions_per_day": 2000
  }
}
```

### Payment Service Policy

For a payment processing agent:

```json
{
  "version": "1.0",
  "name": "payment-service",
  "network": "mainnet",
  "description": "Automated payment processing to pre-approved vendors",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 1000,
      "daily_limit_xrp": 50000,
      "require_known_destination": true,
      "allowed_transaction_types": ["Payment"]
    },
    "delayed": {
      "max_amount_xrp": 10000,
      "daily_limit_xrp": 100000,
      "delay_seconds": 600
    },
    "cosign": {
      "min_amount_xrp": 10000,
      "new_destination_always": true,
      "signer_quorum": 2
    },
    "prohibited": {
      "prohibited_transaction_types": ["OfferCreate", "TrustSet", "AccountSet"]
    }
  },
  "allowlist": {
    "addresses": [
      "rVendor111111111111111111111111111111",
      "rVendor222222222222222222222222222222",
      "rVendor333333333333333333333333333333"
    ]
  },
  "rules": [
    {
      "id": "rule-known-vendor",
      "name": "allow-known-vendors",
      "priority": 10,
      "condition": {
        "and": [
          {
            "field": "transaction_type",
            "operator": "==",
            "value": "Payment"
          },
          {
            "field": "destination",
            "operator": "in",
            "value": { "ref": "allowlist.addresses" }
          }
        ]
      },
      "action": {
        "tier": "autonomous",
        "reason": "Payment to approved vendor"
      }
    },
    {
      "id": "rule-new-vendor",
      "name": "new-vendor-approval",
      "priority": 20,
      "condition": {
        "and": [
          {
            "field": "transaction_type",
            "operator": "==",
            "value": "Payment"
          },
          {
            "field": "is_new_destination",
            "operator": "==",
            "value": true
          }
        ]
      },
      "action": {
        "tier": "cosign",
        "reason": "New vendor requires approval"
      }
    }
  ]
}
```

### NFT Marketplace Policy

For an NFT management agent:

```json
{
  "version": "1.0",
  "name": "nft-marketplace",
  "network": "mainnet",
  "description": "NFT minting and trading operations",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 100,
      "daily_limit_xrp": 1000,
      "require_known_destination": false,
      "allowed_transaction_types": [
        "NFTokenMint",
        "NFTokenCreateOffer",
        "NFTokenAcceptOffer",
        "NFTokenCancelOffer",
        "NFTokenBurn"
      ]
    },
    "delayed": {
      "max_amount_xrp": 500,
      "daily_limit_xrp": 5000,
      "delay_seconds": 300
    },
    "cosign": {
      "min_amount_xrp": 500,
      "signer_quorum": 2
    },
    "prohibited": {
      "prohibited_transaction_types": ["Payment", "AccountSet", "TrustSet"]
    }
  },
  "transaction_types": {
    "NFTokenMint": {
      "enabled": true,
      "default_tier": "autonomous"
    },
    "NFTokenCreateOffer": {
      "enabled": true,
      "default_tier": "autonomous",
      "max_amount_xrp": 100
    }
  },
  "limits": {
    "max_transactions_per_hour": 100,
    "max_transactions_per_day": 500
  }
}
```

### Treasury Management Policy

For highly restricted treasury operations:

```json
{
  "version": "1.0",
  "name": "treasury-management",
  "network": "mainnet",
  "description": "Strict controls for organizational treasury",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 0,
      "daily_limit_xrp": 0,
      "require_known_destination": true,
      "allowed_transaction_types": []
    },
    "delayed": {
      "max_amount_xrp": 100,
      "daily_limit_xrp": 1000,
      "delay_seconds": 3600,
      "veto_enabled": true
    },
    "cosign": {
      "min_amount_xrp": 0,
      "new_destination_always": true,
      "signer_quorum": 3,
      "approval_timeout_hours": 48,
      "signer_addresses": [
        "rTreasurer1111111111111111111111111",
        "rTreasurer2222222222222222222222222",
        "rTreasurer3333333333333333333333333"
      ]
    },
    "prohibited": {
      "prohibited_transaction_types": [
        "OfferCreate",
        "TrustSet",
        "AccountSet",
        "SetRegularKey",
        "SignerListSet",
        "AMMCreate"
      ]
    }
  },
  "rules": [
    {
      "id": "rule-all-cosign",
      "name": "require-all-cosign",
      "priority": 1,
      "condition": {
        "always": true
      },
      "action": {
        "tier": "cosign",
        "reason": "All treasury operations require multi-signature approval"
      }
    }
  ],
  "limits": {
    "max_transactions_per_hour": 5,
    "max_transactions_per_day": 20,
    "max_unique_destinations_per_day": 5,
    "max_total_volume_xrp_per_day": 1000,
    "cooldown_after_high_value": {
      "enabled": true,
      "threshold_xrp": 100,
      "cooldown_seconds": 600
    }
  },
  "escalation": {
    "notification_channels": ["webhook", "email"],
    "auto_deny_on_timeout": true
  }
}
```

---

## Next Steps

- Review the [Policy Schema Reference](../../api/policy-schema.md) for complete field documentation
- Set up [human escalation workflows](./set-up-human-approval.md) for co-sign transactions
- Configure [monitoring and alerts](./configure-monitoring.md) for policy violations

---

## Related Documentation

- [Policy Schema Reference](../../api/policy-schema.md)
- [Security Requirements](../../security/security-requirements.md)
- [ADR-003: Policy Engine Design](../../architecture/09-decisions/ADR-003-policy-engine.md)
