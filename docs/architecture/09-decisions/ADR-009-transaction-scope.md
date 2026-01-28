# ADR-009: Transaction Scope

**Status:** Accepted
**Date:** 2026-01-28
**Decision Makers:** Tech Lead, Security Specialist

---

## Context

The XRPL Agent Wallet MCP server needs to define which XRPL transaction types it supports. The scope decision impacts:

1. **Agent Capabilities**: What operations can AI agents perform?
2. **Policy Complexity**: More types = more policy rules needed
3. **Security Surface**: Each type has unique security considerations
4. **Maintenance Burden**: Each type requires validation and testing
5. **Future Compatibility**: How do we handle new XRPL amendments?

The question is whether to support only escrow-related transactions (matching xrpl-escrow-mcp) or to be a general-purpose signing service.

## Decision

**We will support ALL XRPL transaction types, not just escrow transactions. The wallet MCP is a general-purpose agent wallet, future-proofed for any XRPL operation.**

### Supported Transaction Types

| Category | Transaction Types | Policy Considerations |
|----------|-------------------|----------------------|
| **Payments** | Payment | Amount limits, destination allowlist |
| **Trust Lines** | TrustSet | Issuer validation, limit amounts |
| **Offers** | OfferCreate, OfferCancel | Trading limits, pair restrictions |
| **Escrow** | EscrowCreate, EscrowFinish, EscrowCancel | Condition validation, timing |
| **Payment Channels** | PaymentChannelCreate, PaymentChannelFund, PaymentChannelClaim | Channel limits |
| **Account Settings** | AccountSet, SetRegularKey, SignerListSet | Tier 3 (co-sign) required |
| **NFTs** | NFTokenMint, NFTokenBurn, NFTokenCreateOffer, NFTokenAcceptOffer, NFTokenCancelOffer | NFT-specific policies |
| **AMM** | AMMCreate, AMMDeposit, AMMWithdraw, AMMVote, AMMBid, AMMDelete | DeFi-specific limits |
| **Checks** | CheckCreate, CheckCash, CheckCancel | Check-specific rules |
| **Tickets** | TicketCreate | Sequence management |
| **Clawback** | Clawback | Issuer-only, Tier 4 review |
| **DID** | DIDSet, DIDDelete | Identity operations |
| **Oracle** | OracleSet, OracleDelete | Oracle operations |

### Transaction Type Registry

```typescript
// Comprehensive transaction type definitions
const XRPL_TRANSACTION_TYPES = {
  // Payment transactions
  Payment: {
    category: 'payments',
    defaultTier: 'autonomous',
    policyFields: ['Amount', 'Destination', 'DestinationTag'],
    requiresDestination: true
  },

  // Trust line transactions
  TrustSet: {
    category: 'trustlines',
    defaultTier: 'strict',
    policyFields: ['LimitAmount', 'QualityIn', 'QualityOut'],
    requiresDestination: false
  },

  // DEX transactions
  OfferCreate: {
    category: 'dex',
    defaultTier: 'strict',
    policyFields: ['TakerPays', 'TakerGets', 'Expiration'],
    requiresDestination: false
  },
  OfferCancel: {
    category: 'dex',
    defaultTier: 'autonomous',
    policyFields: ['OfferSequence'],
    requiresDestination: false
  },

  // Escrow transactions
  EscrowCreate: {
    category: 'escrow',
    defaultTier: 'strict',
    policyFields: ['Amount', 'Destination', 'FinishAfter', 'CancelAfter', 'Condition'],
    requiresDestination: true
  },
  EscrowFinish: {
    category: 'escrow',
    defaultTier: 'autonomous',
    policyFields: ['Owner', 'OfferSequence', 'Fulfillment'],
    requiresDestination: false
  },
  EscrowCancel: {
    category: 'escrow',
    defaultTier: 'autonomous',
    policyFields: ['Owner', 'OfferSequence'],
    requiresDestination: false
  },

  // Payment channel transactions
  PaymentChannelCreate: {
    category: 'paychan',
    defaultTier: 'strict',
    policyFields: ['Amount', 'Destination', 'SettleDelay', 'PublicKey'],
    requiresDestination: true
  },
  PaymentChannelFund: {
    category: 'paychan',
    defaultTier: 'strict',
    policyFields: ['Channel', 'Amount'],
    requiresDestination: false
  },
  PaymentChannelClaim: {
    category: 'paychan',
    defaultTier: 'autonomous',
    policyFields: ['Channel', 'Balance', 'Amount', 'Signature', 'PublicKey'],
    requiresDestination: false
  },

  // Account management (high-risk)
  AccountSet: {
    category: 'account',
    defaultTier: 'cosign',  // Always requires human approval
    policyFields: ['SetFlag', 'ClearFlag', 'Domain', 'EmailHash'],
    requiresDestination: false,
    highRisk: true
  },
  SetRegularKey: {
    category: 'account',
    defaultTier: 'cosign',  // Always requires human approval
    policyFields: ['RegularKey'],
    requiresDestination: false,
    highRisk: true
  },
  SignerListSet: {
    category: 'account',
    defaultTier: 'cosign',  // Always requires human approval
    policyFields: ['SignerQuorum', 'SignerEntries'],
    requiresDestination: false,
    highRisk: true
  },

  // NFT transactions
  NFTokenMint: {
    category: 'nft',
    defaultTier: 'strict',
    policyFields: ['NFTokenTaxon', 'URI', 'Flags', 'TransferFee'],
    requiresDestination: false
  },
  NFTokenBurn: {
    category: 'nft',
    defaultTier: 'strict',
    policyFields: ['NFTokenID'],
    requiresDestination: false
  },
  NFTokenCreateOffer: {
    category: 'nft',
    defaultTier: 'strict',
    policyFields: ['NFTokenID', 'Amount', 'Destination', 'Expiration'],
    requiresDestination: false
  },
  NFTokenAcceptOffer: {
    category: 'nft',
    defaultTier: 'strict',
    policyFields: ['NFTokenSellOffer', 'NFTokenBuyOffer', 'NFTokenBrokerFee'],
    requiresDestination: false
  },
  NFTokenCancelOffer: {
    category: 'nft',
    defaultTier: 'autonomous',
    policyFields: ['NFTokenOffers'],
    requiresDestination: false
  },

  // AMM transactions
  AMMCreate: {
    category: 'amm',
    defaultTier: 'cosign',  // Creating pools is high-risk
    policyFields: ['Amount', 'Amount2', 'TradingFee'],
    requiresDestination: false,
    highRisk: true
  },
  AMMDeposit: {
    category: 'amm',
    defaultTier: 'strict',
    policyFields: ['Asset', 'Asset2', 'Amount', 'Amount2', 'LPTokenOut'],
    requiresDestination: false
  },
  AMMWithdraw: {
    category: 'amm',
    defaultTier: 'strict',
    policyFields: ['Asset', 'Asset2', 'Amount', 'Amount2', 'LPTokenIn'],
    requiresDestination: false
  },
  AMMVote: {
    category: 'amm',
    defaultTier: 'strict',
    policyFields: ['Asset', 'Asset2', 'TradingFee'],
    requiresDestination: false
  },
  AMMBid: {
    category: 'amm',
    defaultTier: 'strict',
    policyFields: ['Asset', 'Asset2', 'BidMin', 'BidMax', 'AuthAccounts'],
    requiresDestination: false
  },
  AMMDelete: {
    category: 'amm',
    defaultTier: 'strict',
    policyFields: ['Asset', 'Asset2'],
    requiresDestination: false
  },

  // Check transactions
  CheckCreate: {
    category: 'checks',
    defaultTier: 'strict',
    policyFields: ['Destination', 'SendMax', 'Expiration'],
    requiresDestination: true
  },
  CheckCash: {
    category: 'checks',
    defaultTier: 'autonomous',
    policyFields: ['CheckID', 'Amount', 'DeliverMin'],
    requiresDestination: false
  },
  CheckCancel: {
    category: 'checks',
    defaultTier: 'autonomous',
    policyFields: ['CheckID'],
    requiresDestination: false
  },

  // Tickets
  TicketCreate: {
    category: 'tickets',
    defaultTier: 'strict',
    policyFields: ['TicketCount'],
    requiresDestination: false
  },

  // Clawback (issuer only)
  Clawback: {
    category: 'clawback',
    defaultTier: 'prohibited',  // Must be explicitly allowed
    policyFields: ['Amount'],
    requiresDestination: false,
    highRisk: true
  },

  // DID transactions
  DIDSet: {
    category: 'did',
    defaultTier: 'strict',
    policyFields: ['DIDDocument', 'URI', 'Data'],
    requiresDestination: false
  },
  DIDDelete: {
    category: 'did',
    defaultTier: 'strict',
    policyFields: [],
    requiresDestination: false
  },

  // Oracle transactions
  OracleSet: {
    category: 'oracle',
    defaultTier: 'strict',
    policyFields: ['OracleDocumentID', 'Provider', 'URI', 'AssetClass', 'LastUpdateTime', 'PriceDataSeries'],
    requiresDestination: false
  },
  OracleDelete: {
    category: 'oracle',
    defaultTier: 'strict',
    policyFields: ['OracleDocumentID'],
    requiresDestination: false
  }
} as const;
```

### Policy Integration

The policy engine uses transaction type metadata:

```typescript
function getDefaultTier(txType: string): PolicyTier {
  const metadata = XRPL_TRANSACTION_TYPES[txType];

  if (!metadata) {
    // Unknown transaction type - default to prohibited
    return 'prohibited';
  }

  return metadata.defaultTier;
}

function isHighRiskTransaction(txType: string): boolean {
  const metadata = XRPL_TRANSACTION_TYPES[txType];
  return metadata?.highRisk === true;
}

// Policy rule example: override default tier based on category
const categoryOverrideRule = {
  id: 'rule-category-override',
  name: 'category-based-tier',
  priority: 5,
  condition: {
    field: 'transaction_type',
    operator: 'in_category',
    value: 'account'  // AccountSet, SetRegularKey, SignerListSet
  },
  action: {
    tier: 'cosign',
    reason: 'Account management requires human approval'
  }
};
```

### Transaction Type Validation

```typescript
import { z } from 'zod';

// Dynamic schema based on transaction type
function getTransactionSchema(txType: string): z.ZodSchema {
  const baseSchema = z.object({
    TransactionType: z.literal(txType),
    Account: XRPLAddressSchema,
    Fee: z.string().optional(),
    Sequence: z.number().int().nonnegative().optional(),
    Memos: z.array(MemoSchema).max(10).optional()
  });

  // Add type-specific fields
  switch (txType) {
    case 'Payment':
      return baseSchema.extend({
        Destination: XRPLAddressSchema,
        Amount: XRPAmountSchema,
        DestinationTag: z.number().int().nonnegative().optional()
      });

    case 'TrustSet':
      return baseSchema.extend({
        LimitAmount: IssuedCurrencyAmountSchema
      });

    case 'EscrowCreate':
      return baseSchema.extend({
        Destination: XRPLAddressSchema,
        Amount: XRPAmountSchema,
        FinishAfter: z.number().int().positive().optional(),
        CancelAfter: z.number().int().positive().optional(),
        Condition: z.string().max(256).optional()
      });

    // ... schemas for all transaction types

    default:
      // Allow unknown types with passthrough (validated at XRPL level)
      return baseSchema.passthrough();
  }
}
```

## Consequences

### Positive

- **General Purpose**: Wallet can be used for any XRPL operation
- **Future Proof**: New transaction types work automatically (with default policy)
- **Ecosystem Value**: One wallet MCP serves all agent use cases
- **Agent Flexibility**: Agents can perform complex multi-step operations
- **Reduced Fragmentation**: No need for multiple specialized wallets

### Negative

- **Larger Policy Surface**: More transaction types = more policy rules
- **Validation Complexity**: Each type has unique validation needs
- **Testing Burden**: Must test policy for all transaction types
- **Security Scope**: More ways to move funds if policy is wrong

### Neutral

- Unknown transaction types default to prohibited (safe)
- High-risk types (account management) always require co-sign
- Policy can restrict to specific types if desired

## Alternatives Considered

| Option | Pros | Cons | Why Not Chosen |
|--------|------|------|----------------|
| **Escrow-Only** | Simpler policy, focused scope | Limits agent capabilities severely | Too restrictive for general agent use |
| **Payment-Only** | Very simple | Cannot support DeFi, NFTs, escrow | Misses primary use cases |
| **Whitelist Approach** | Explicit control | Requires updates for new types | Maintenance overhead, blocks innovation |
| **Category-Based Limits** | Balanced control | May be confusing | Adopted as policy layer, not schema layer |

## Implementation Notes

### Unknown Transaction Type Handling

```typescript
function handleUnknownTransactionType(tx: Transaction): PolicyResult {
  // Log for monitoring
  logger.warn(`Unknown transaction type: ${tx.TransactionType}`);

  // Default to prohibited
  return {
    allowed: false,
    tier: 'prohibited',
    reason: `Unknown transaction type: ${tx.TransactionType}. Add to policy to enable.`,
    matched_rule: 'unknown-type-default'
  };
}
```

### New Transaction Type Discovery

```typescript
// When XRPL adds new transaction types via amendments
function checkForNewTransactionTypes(): string[] {
  const knownTypes = new Set(Object.keys(XRPL_TRANSACTION_TYPES));
  const ledgerTypes = await fetchLedgerTransactionTypes();

  const newTypes = ledgerTypes.filter(t => !knownTypes.has(t));

  if (newTypes.length > 0) {
    logger.info(`New XRPL transaction types detected: ${newTypes.join(', ')}`);
    // These will default to 'prohibited' until explicitly configured
  }

  return newTypes;
}
```

### Category-Based Policy Example

```json
{
  "rules": [
    {
      "id": "rule-allow-payments-dex",
      "name": "allow-trading-category",
      "priority": 50,
      "condition": {
        "or": [
          { "field": "transaction_category", "operator": "==", "value": "payments" },
          { "field": "transaction_category", "operator": "==", "value": "dex" }
        ]
      },
      "action": { "tier": "autonomous", "reason": "Trading operations allowed" }
    },
    {
      "id": "rule-restrict-account",
      "name": "account-management-cosign",
      "priority": 10,
      "condition": {
        "field": "transaction_category",
        "operator": "==",
        "value": "account"
      },
      "action": { "tier": "cosign", "reason": "Account changes require approval" }
    }
  ]
}
```

## Security Considerations

### High-Risk Transaction Types

The following types always require Tier 3 (co-sign) or higher:

| Transaction Type | Risk | Rationale |
|------------------|------|-----------|
| SetRegularKey | Critical | Can lock out legitimate owner |
| SignerListSet | Critical | Changes multi-sig configuration |
| AccountSet | High | Can disable master key, freeze account |
| AMMCreate | High | Large capital commitment |
| Clawback | Critical | Issuer-only, irreversible |

### Policy Enforcement Order

1. **Blocklist Check**: Is destination blocklisted?
2. **Type Validation**: Is this transaction type known?
3. **Category Rules**: Apply category-based policy
4. **Amount Rules**: Check value thresholds
5. **Custom Rules**: User-defined policy rules
6. **Default Rule**: Apply default tier for type

### Compliance Mapping

| Concern | Implementation |
|---------|----------------|
| Unknown Type Safety | Default to prohibited |
| High-Risk Detection | `highRisk: true` flag |
| Policy Flexibility | Category-based rules |
| Audit Trail | Transaction type logged |

## References

- [XRPL Transaction Types](https://xrpl.org/transaction-types.html)
- [XRPL Amendments](https://xrpl.org/amendments.html)
- [xrpl.js Transaction Definitions](https://github.com/XRPLF/xrpl.js)

## Related ADRs

- [ADR-003: Policy Engine](ADR-003-policy-engine.md) - Policy evaluates transaction types
- [ADR-006: Input Validation](ADR-006-input-validation.md) - Type-specific schemas
- [ADR-008: Integration Design](ADR-008-integration-design.md) - Unsigned TX handling

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Tech Lead | Initial ADR |
