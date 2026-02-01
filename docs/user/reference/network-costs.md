# XRPL Network Costs Reference

This document provides current reserve requirements and transaction costs for the XRP Ledger.

> **Last Updated**: January 2026 (reserves updated December 2024)

---

## Reserve Requirements

Reserves prevent ledger spam by requiring accounts to hold minimum XRP balances.

### Current Reserves

| Reserve Type | Amount | In Drops |
|-------------|--------|----------|
| **Base Reserve** | 1 XRP | 1,000,000 |
| **Owner Reserve** | 0.2 XRP per object | 200,000 |

### Reserve Formula

```
Total Reserve = Base Reserve + (Owner Count × Owner Reserve)
Total Reserve = 1 XRP + (Owner Count × 0.2 XRP)
```

### Examples

| Scenario | Owner Count | Reserve |
|----------|-------------|---------|
| New account (no objects) | 0 | 1 XRP |
| Account + 1 escrow | 1 | 1.2 XRP |
| Account + 5 escrows | 5 | 2 XRP |
| Account + 1 trust line | 1 | 1.2 XRP |
| Account + signer list (any size) | 1 | 1.2 XRP |
| Account + 10 NFT offers | 10 | 3 XRP |

---

## Objects That Count Toward Owner Reserve

Each of these ledger objects adds **0.2 XRP** to your reserve requirement:

| Object Type | Created By | Notes |
|-------------|------------|-------|
| **Escrow** | EscrowCreate | Released on finish/cancel |
| **Trust Line** | TrustSet | First 2 free for new accounts |
| **Offer** | OfferCreate | DEX order book entry |
| **Signer List** | SignerListSet | One item regardless of signer count |
| **Payment Channel** | PaymentChannelCreate | |
| **Check** | CheckCreate | |
| **Ticket** | TicketCreate | |
| **Deposit Preauth** | DepositPreauth | |
| **NFT Offer** | NFTokenCreateOffer | Buy or sell offer |
| **NFT Page** | NFTokenMint | Holds up to 32 NFTs |
| **Oracle** | OracleSet | 0.2 XRP for 1-5 prices |
| **Oracle (large)** | OracleSet | 0.4 XRP for 6-10 prices |
| **DID** | DIDSet | Decentralized Identifier |
| **Credential** | CredentialCreate | Verifiable credential |
| **MPT Holder** | MPTokenAuthorize | Multi-Purpose Token holding |

### Objects That Do NOT Count

| Object Type | Notes |
|-------------|-------|
| **AMM** | Uses special creation cost instead |
| **Ledger entries owned by network** | Amendments, fees, etc. |

---

## Transaction Costs

### Standard Transaction Fee

| Network | Base Fee |
|---------|----------|
| Mainnet | ~10-12 drops (0.00001 XRP) |
| Testnet | ~10-12 drops |
| Devnet | ~10-12 drops |

### Special Transaction Costs

Some transactions have higher costs to prevent spam:

| Transaction | Cost | Notes |
|-------------|------|-------|
| **AMMCreate** | ~2 XRP | Burned to prevent AMM spam |
| **AccountDelete** | 2 XRP | Discourages account cycling |
| **Multi-signed TX** | +1 signature cost per signer | Higher for more signers |

---

## Reserve Recovery

Reserves are recovered when objects are removed from the ledger:

| Action | Reserve Freed |
|--------|---------------|
| EscrowFinish / EscrowCancel | 0.2 XRP |
| OfferCancel (or filled) | 0.2 XRP |
| TrustSet with zero limit | 0.2 XRP |
| CheckCancel / CheckCash | 0.2 XRP |
| NFTokenCancelOffer / NFTokenAcceptOffer | 0.2 XRP |
| PaymentChannelClaim (close) | 0.2 XRP |
| SignerListSet with empty list | 0.2 XRP |
| OracleDelete | 0.2-0.4 XRP |

---

## Historical Reserve Changes

The XRPL community can vote to change reserves:

| Date | Base Reserve | Owner Reserve |
|------|--------------|---------------|
| **Dec 2024** | 1 XRP | 0.2 XRP |
| 2021 | 10 XRP | 2 XRP |
| Earlier | 20 XRP | 5 XRP |
| Original | 200 XRP | 50 XRP |

---

## Practical Implications

### For Escrow Workflows

Creating an escrow requires:
- Escrow amount (held until release)
- 0.2 XRP owner reserve (returned on finish/cancel)
- ~0.00001 XRP transaction fee

**Example**: To create a 100 XRP escrow:
- Need: 100 XRP + 0.2 XRP reserve + fee
- After EscrowFinish: 0.2 XRP reserve returned

### For Multi-Signature Setup

A signer list counts as 1 object regardless of how many signers:
- 2-of-3 multisig: 0.2 XRP reserve
- 5-of-8 multisig: 0.2 XRP reserve

### For NFT Trading

Each NFT offer costs 0.2 XRP reserve:
- Listing 10 NFTs for sale: 2 XRP in reserves
- Reserves returned when offers are accepted/cancelled

---

## Checking Current Reserves

The wallet_balance tool returns current reserve requirements:

```json
{
  "balance_xrp": "100.5",
  "reserve_drops": "1400000",
  "available_drops": "99100000"
}
```

Reserves are calculated dynamically from the network's current settings.

---

## Sources

- [XRPL Reserves Documentation](https://xrpl.org/docs/concepts/accounts/reserves)
- [Lower Reserves Announcement (Dec 2024)](https://xrpl.org/blog/2024/lower-reserves-are-in-effect)
- [NFT Reserve Requirements](https://xrpl.org/docs/concepts/tokens/nfts/reserve-requirements)

---

**Document History**

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-31 | Initial document with Dec 2024 reserve values |
