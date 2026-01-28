# Supported Transaction Types Reference

Complete reference for all XRPL transaction types supported by the XRPL Agent Wallet MCP server, including policy considerations, default tiers, and usage guidance.

---

## Overview

The XRPL Agent Wallet MCP is a **general-purpose signing service** that supports all XRPL transaction types. Each transaction type has:

- **Default Tier**: The policy tier applied when no specific rules override it
- **Policy Fields**: Transaction fields evaluated by the policy engine
- **Risk Level**: Classification affecting approval requirements

### Policy Tier Summary

| Tier | Name | Behavior | Typical Use |
|------|------|----------|-------------|
| **1** | Autonomous | Signed immediately | Low-risk, within limits |
| **2** | Delayed | Time delay before signing | Medium-risk, requires confirmation |
| **3** | Co-sign | Requires human approval | High-risk, sensitive operations |
| **4** | Prohibited | Never signed | Blocked or unknown types |

### Risk Classification

| Risk Level | Description | Default Tier |
|------------|-------------|--------------|
| **Standard** | Normal operations | Autonomous or Strict |
| **High** | Significant financial impact | Co-sign |
| **Critical** | Account security implications | Co-sign or Prohibited |

---

## Payment Transactions

### Payment

The fundamental transaction for transferring XRP or issued currencies between accounts.

**Transaction Type:** `Payment`
**Category:** Payments
**Default Tier:** Autonomous (Tier 1)

**Description:**

Payment transactions transfer value from one XRPL account to another. They support:
- XRP transfers (drops)
- Issued currency (IOU) transfers
- Cross-currency payments via pathfinding
- Partial payments (with flag)

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `Amount` | Compared against `max_amount_per_tx_drops` and daily limits |
| `Destination` | Checked against allowlist/blocklist |
| `DestinationTag` | May be required for certain destinations |
| `SendMax` | Maximum amount that can be debited (cross-currency) |
| `DeliverMin` | Minimum amount to deliver (partial payments) |

**Policy Fields:** `Amount`, `Destination`, `DestinationTag`, `SendMax`, `DeliverMin`
**Requires Destination:** Yes

**Example Use Cases:**

- Paying for services or goods
- Transferring funds between accounts
- Making payments with specific destination tags (exchange deposits)
- Cross-currency remittances

**Policy Override Examples:**

```json
{
  "rules": [
    {
      "id": "small-payments-auto",
      "condition": {
        "and": [
          { "field": "transaction_type", "operator": "==", "value": "Payment" },
          { "field": "amount_drops", "operator": "<=", "value": "10000000" }
        ]
      },
      "action": { "tier": "autonomous" }
    },
    {
      "id": "large-payments-approval",
      "condition": {
        "and": [
          { "field": "transaction_type", "operator": "==", "value": "Payment" },
          { "field": "amount_drops", "operator": ">", "value": "100000000" }
        ]
      },
      "action": { "tier": "cosign" }
    }
  ]
}
```

---

## Escrow Transactions

Escrow transactions enable time-locked and condition-locked XRP transfers.

### EscrowCreate

Creates a new escrow that locks XRP until conditions are met.

**Transaction Type:** `EscrowCreate`
**Category:** Escrow
**Default Tier:** Strict (Tier 2)

**Description:**

Creates an escrow that holds XRP until:
- A specific time passes (`FinishAfter`)
- A cryptographic condition is fulfilled (`Condition`)
- Both conditions are met

The escrow can also be cancelled after a specified time (`CancelAfter`).

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `Amount` | Locked XRP, subject to amount limits |
| `Destination` | Escrow beneficiary, checked against lists |
| `FinishAfter` | Earliest release time |
| `CancelAfter` | Cancellation deadline |
| `Condition` | Crypto-condition (PREIMAGE-SHA-256) |

**Policy Fields:** `Amount`, `Destination`, `FinishAfter`, `CancelAfter`, `Condition`
**Requires Destination:** Yes

**Example Use Cases:**

- Milestone-based payments
- Time-locked savings
- Conditional agreements
- Dispute resolution mechanisms

---

### EscrowFinish

Completes an escrow, releasing XRP to the destination.

**Transaction Type:** `EscrowFinish`
**Category:** Escrow
**Default Tier:** Autonomous (Tier 1)

**Description:**

Releases escrowed XRP to the destination when:
- Current time is after `FinishAfter` (if set)
- Valid fulfillment is provided (if condition was set)

Anyone can submit EscrowFinish for an escrow without conditions.

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `Owner` | Original escrow creator |
| `OfferSequence` | Escrow sequence number |
| `Fulfillment` | Crypto-condition fulfillment |

**Policy Fields:** `Owner`, `OfferSequence`, `Fulfillment`
**Requires Destination:** No

**Example Use Cases:**

- Claiming milestone payments
- Automated escrow release after time conditions
- Providing fulfillment to unlock conditional escrows

---

### EscrowCancel

Cancels an escrow, returning XRP to the creator.

**Transaction Type:** `EscrowCancel`
**Category:** Escrow
**Default Tier:** Autonomous (Tier 1)

**Description:**

Returns escrowed XRP to the original creator when:
- Current time is after `CancelAfter` (must be set)
- Escrow has not already been finished

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `Owner` | Original escrow creator |
| `OfferSequence` | Escrow sequence number |

**Policy Fields:** `Owner`, `OfferSequence`
**Requires Destination:** No

**Example Use Cases:**

- Reclaiming funds from expired escrows
- Cancelling agreements that were not fulfilled

---

## Trust Line Transactions

### TrustSet

Creates or modifies a trust line for issued currencies.

**Transaction Type:** `TrustSet`
**Category:** Trust Lines
**Default Tier:** Strict (Tier 2)

**Description:**

Trust lines enable holding issued currencies (IOUs) from a specific issuer. TrustSet:
- Creates a new trust line to an issuer
- Modifies the limit on an existing trust line
- Sets quality ratios for incoming/outgoing payments
- Enables/disables rippling through the account

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `LimitAmount` | Maximum currency to hold from issuer |
| `LimitAmount.issuer` | Issuer address (validate trustworthiness) |
| `LimitAmount.currency` | Currency code |
| `QualityIn` | Incoming exchange rate adjustment |
| `QualityOut` | Outgoing exchange rate adjustment |
| `Flags` | tfSetNoRipple, tfSetFreeze, etc. |

**Policy Fields:** `LimitAmount`, `QualityIn`, `QualityOut`
**Requires Destination:** No (issuer is in LimitAmount)

**Risk Level:** Medium - trust lines enable holding potentially worthless tokens

**Example Use Cases:**

- Enabling receipt of stablecoin payments (USD, EUR)
- Setting up trading pairs on the DEX
- Adjusting trust line limits
- Enabling/disabling rippling

**Policy Override Examples:**

```json
{
  "rules": [
    {
      "id": "approved-issuers-only",
      "condition": {
        "and": [
          { "field": "transaction_type", "operator": "==", "value": "TrustSet" },
          { "field": "LimitAmount.issuer", "operator": "in", "value": ["rApprovedIssuer1...", "rApprovedIssuer2..."] }
        ]
      },
      "action": { "tier": "autonomous" }
    },
    {
      "id": "unknown-issuers-blocked",
      "condition": {
        "and": [
          { "field": "transaction_type", "operator": "==", "value": "TrustSet" },
          { "field": "LimitAmount.issuer", "operator": "not_in", "value": ["rApprovedIssuer1...", "rApprovedIssuer2..."] }
        ]
      },
      "action": { "tier": "cosign" }
    }
  ]
}
```

---

## DEX (Offer) Transactions

The XRPL has a built-in decentralized exchange for trading any asset pairs.

### OfferCreate

Creates a trade offer on the XRPL DEX.

**Transaction Type:** `OfferCreate`
**Category:** DEX
**Default Tier:** Strict (Tier 2)

**Description:**

Places an order to exchange one asset for another:
- Immediately crosses matching offers (market order behavior)
- Remaining amount stays as limit order
- Can be set to expire after a specific ledger/time
- Supports various order types via flags

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `TakerPays` | Asset/amount to receive |
| `TakerGets` | Asset/amount to give up |
| `Expiration` | Order expiration time |
| `OfferSequence` | Replace existing offer |
| `Flags` | tfPassive, tfImmediateOrCancel, tfFillOrKill, tfSell |

**Policy Fields:** `TakerPays`, `TakerGets`, `Expiration`
**Requires Destination:** No

**Example Use Cases:**

- Placing limit orders on the DEX
- Market orders (with tfImmediateOrCancel)
- Providing liquidity
- Cross-currency swaps

**Flags Reference:**

| Flag | Description |
|------|-------------|
| `tfPassive` | Don't cross existing offers |
| `tfImmediateOrCancel` | Cancel unfilled portion immediately |
| `tfFillOrKill` | Fill completely or cancel |
| `tfSell` | Sell exact TakerGets amount |

---

### OfferCancel

Cancels an existing DEX offer.

**Transaction Type:** `OfferCancel`
**Category:** DEX
**Default Tier:** Autonomous (Tier 1)

**Description:**

Removes an offer from the order book, freeing any locked reserves.

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `OfferSequence` | Sequence of offer to cancel |

**Policy Fields:** `OfferSequence`
**Requires Destination:** No

**Example Use Cases:**

- Cancelling stale orders
- Updating order prices (cancel + create)
- Emergency order removal

---

## Account Management Transactions

**WARNING: These transactions modify account security settings and always require Tier 3 (co-sign) approval by default.**

### AccountSet

Modifies account settings and flags.

**Transaction Type:** `AccountSet`
**Category:** Account
**Default Tier:** Co-sign (Tier 3)
**Risk Level:** HIGH

**Description:**

Modifies various account properties:
- Account flags (RequireDest, RequireAuth, DisallowXRP, etc.)
- Domain association
- Email hash (deprecated, for Gravatar)
- Message key
- Transfer rate (for issuers)

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `SetFlag` | Flag to enable |
| `ClearFlag` | Flag to disable |
| `Domain` | Associated domain (hex) |
| `TransferRate` | Transfer fee (issuers) |
| `TickSize` | Order book precision |

**Critical Flags:**

| Flag | Risk | Description |
|------|------|-------------|
| `asfDisableMaster` | **CRITICAL** | Disables master key - can lock account |
| `asfRequireAuth` | High | Requires authorization for trust lines |
| `asfAccountTxnID` | Low | Enables transaction ID tracking |
| `asfDefaultRipple` | Medium | Default rippling for issued currencies |
| `asfGlobalFreeze` | High | Freezes all issued currencies |
| `asfNoFreeze` | **IRREVERSIBLE** | Permanently disables freeze capability |

**Policy Fields:** `SetFlag`, `ClearFlag`, `Domain`, `EmailHash`
**Requires Destination:** No

**Example Use Cases:**

- Setting account domain
- Enabling/disabling required destination tags
- Issuer configuration

**Security Note:**

Setting `asfDisableMaster` without a regular key or multi-sig configured will permanently lock the account. This is enforced at Tier 3 with additional validation.

---

### SetRegularKey

Sets or clears the regular key pair for an account.

**Transaction Type:** `SetRegularKey`
**Category:** Account
**Default Tier:** Co-sign (Tier 3)
**Risk Level:** CRITICAL

**Description:**

The regular key is an alternative signing key that can:
- Sign transactions instead of the master key
- Be changed/rotated without changing the account address
- Be removed to revert to master key only

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `RegularKey` | New regular key address (empty to remove) |

**Policy Fields:** `RegularKey`
**Requires Destination:** No

**Security Implications:**

- Setting a regular key controlled by an attacker gives them account access
- This is the transaction type used for the wallet key rotation feature
- Always verify the new key is properly secured before setting

**Example Use Cases:**

- Key rotation (primary use in this MCP)
- Transitioning from hardware to software key
- Revoking compromised regular key

---

### SignerListSet

Configures multi-signature settings for an account.

**Transaction Type:** `SignerListSet`
**Category:** Account
**Default Tier:** Co-sign (Tier 3)
**Risk Level:** CRITICAL

**Description:**

Enables multi-signature (multi-sig) transactions by defining:
- A list of authorized signers with individual weights
- A quorum (threshold) required to authorize transactions
- Up to 32 signers per list

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `SignerQuorum` | Weight required to authorize |
| `SignerEntries` | List of signers with weights |

**Policy Fields:** `SignerQuorum`, `SignerEntries`
**Requires Destination:** No

**Security Implications:**

- Incorrectly configured quorum can lock an account
- All signer addresses must be valid and accessible
- Combined with `asfDisableMaster`, requires multi-sig for all transactions

**Example Use Cases:**

- Setting up corporate treasury multi-sig
- Configuring backup recovery signers
- Implementing m-of-n signing schemes

---

## Check Transactions

Checks are deferred payments that the destination must explicitly cash.

### CheckCreate

Creates a Check that the destination can cash.

**Transaction Type:** `CheckCreate`
**Category:** Checks
**Default Tier:** Strict (Tier 2)

**Description:**

Creates a Check object on the ledger that:
- Reserves funds but doesn't transfer them immediately
- Can be cashed by the destination for up to the specified amount
- Can expire if not cashed within a timeframe
- Supports both XRP and issued currencies

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `Destination` | Check recipient |
| `SendMax` | Maximum amount that can be cashed |
| `Expiration` | Optional expiration time |
| `InvoiceID` | Optional reference identifier |

**Policy Fields:** `Destination`, `SendMax`, `Expiration`
**Requires Destination:** Yes

**Example Use Cases:**

- Deferred payments
- Payment authorization without immediate transfer
- Escrow-like functionality with flexible amounts

---

### CheckCash

Cashes a Check to receive funds.

**Transaction Type:** `CheckCash`
**Category:** Checks
**Default Tier:** Autonomous (Tier 1)

**Description:**

Redeems a Check for the destination to receive funds. Supports:
- Exact amount (receive specific amount up to SendMax)
- Minimum amount (receive at least a minimum, up to SendMax)

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `CheckID` | ID of the Check to cash |
| `Amount` | Exact amount to receive |
| `DeliverMin` | Minimum amount to receive |

**Policy Fields:** `CheckID`, `Amount`, `DeliverMin`
**Requires Destination:** No

**Example Use Cases:**

- Receiving authorized payments
- Partial Check redemption

---

### CheckCancel

Cancels an uncashed Check.

**Transaction Type:** `CheckCancel`
**Category:** Checks
**Default Tier:** Autonomous (Tier 1)

**Description:**

Removes a Check from the ledger. Can be cancelled by:
- The Check creator (sender)
- The Check destination (receiver)
- Anyone, if the Check has expired

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `CheckID` | ID of the Check to cancel |

**Policy Fields:** `CheckID`
**Requires Destination:** No

**Example Use Cases:**

- Revoking payment authorization
- Cleaning up expired Checks

---

## Payment Channel Transactions

Payment channels enable off-ledger micropayments with on-ledger settlement.

### PaymentChannelCreate

Creates a unidirectional payment channel.

**Transaction Type:** `PaymentChannelCreate`
**Category:** Payment Channels
**Default Tier:** Strict (Tier 2)

**Description:**

Creates a payment channel that:
- Locks XRP for off-ledger claim authorization
- Enables instant, fee-less micropayments
- Settles to the ledger when the destination claims
- Has a configurable settlement delay

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `Amount` | XRP to lock in channel |
| `Destination` | Channel recipient |
| `SettleDelay` | Seconds before creator can reclaim |
| `PublicKey` | Key for authorizing claims |
| `CancelAfter` | Optional absolute expiration |
| `DestinationTag` | Optional destination tag |

**Policy Fields:** `Amount`, `Destination`, `SettleDelay`, `PublicKey`
**Requires Destination:** Yes

**Example Use Cases:**

- Streaming payments (pay-per-second)
- Micropayment APIs
- Content monetization
- Gaming payments

---

### PaymentChannelFund

Adds XRP to an existing payment channel.

**Transaction Type:** `PaymentChannelFund`
**Category:** Payment Channels
**Default Tier:** Strict (Tier 2)

**Description:**

Increases the amount of XRP available in a payment channel. Can also extend the expiration.

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `Channel` | Channel ID (256-bit hash) |
| `Amount` | Additional XRP to add |
| `Expiration` | New expiration time |

**Policy Fields:** `Channel`, `Amount`
**Requires Destination:** No

**Example Use Cases:**

- Extending channel capacity
- Renewing channel expiration

---

### PaymentChannelClaim

Claims XRP from a payment channel.

**Transaction Type:** `PaymentChannelClaim`
**Category:** Payment Channels
**Default Tier:** Autonomous (Tier 1)

**Description:**

Settles payment channel claims to the ledger:
- Destination claims authorized amounts
- Creator can close channel after settle delay
- Supports partial claims and channel closure

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `Channel` | Channel ID |
| `Balance` | New total balance to claim |
| `Amount` | Claim amount (for closure) |
| `Signature` | Authorization signature |
| `PublicKey` | Key that signed the claim |
| `Flags` | tfRenew, tfClose |

**Policy Fields:** `Channel`, `Balance`, `Amount`, `Signature`, `PublicKey`
**Requires Destination:** No

**Example Use Cases:**

- Settling accumulated micropayments
- Closing exhausted channels
- Disputing channel state

---

## NFT Transactions

Native NFT support on the XRP Ledger (XLS-20).

### NFTokenMint

Mints a new NFT.

**Transaction Type:** `NFTokenMint`
**Category:** NFT
**Default Tier:** Strict (Tier 2)

**Description:**

Creates a new non-fungible token with configurable properties:
- Taxon for categorization
- Optional URI for metadata
- Transfer fee (royalties)
- Burnable/transferable flags

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `NFTokenTaxon` | Token category/collection |
| `URI` | Metadata URI (hex-encoded) |
| `Flags` | tfBurnable, tfOnlyXRP, tfTransferable, tfTrustLine |
| `TransferFee` | Royalty (0-50000 = 0-50%) |
| `Issuer` | Authorized minting (if applicable) |

**Policy Fields:** `NFTokenTaxon`, `URI`, `Flags`, `TransferFee`
**Requires Destination:** No

**Flag Reference:**

| Flag | Description |
|------|-------------|
| `tfBurnable` | Issuer can burn the token |
| `tfOnlyXRP` | Can only be traded for XRP |
| `tfTransferable` | Can be transferred between accounts |
| `tfTrustLine` | Requires trust line for sales in issued currency |

**Example Use Cases:**

- Creating digital art NFTs
- Issuing game assets
- Tokenizing real-world assets
- Creating membership tokens

---

### NFTokenBurn

Destroys an NFT permanently.

**Transaction Type:** `NFTokenBurn`
**Category:** NFT
**Default Tier:** Strict (Tier 2)

**Description:**

Permanently destroys an NFT. Can be executed by:
- The NFT owner
- The issuer (if tfBurnable was set at mint)

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `NFTokenID` | Token to burn |
| `Owner` | Owner account (if issuer burning) |

**Policy Fields:** `NFTokenID`
**Requires Destination:** No

**Example Use Cases:**

- Destroying unwanted NFTs
- Issuer recalling tokens
- Reducing reserve requirements

---

### NFTokenCreateOffer

Creates an offer to buy or sell an NFT.

**Transaction Type:** `NFTokenCreateOffer`
**Category:** NFT
**Default Tier:** Strict (Tier 2)

**Description:**

Creates a buy or sell offer for an NFT:
- Sell offers list tokens the account owns
- Buy offers express intent to purchase
- Offers can have destinations (private sales)
- Offers can expire

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `NFTokenID` | Token being offered |
| `Amount` | Offer price (XRP or issued currency) |
| `Destination` | Exclusive buyer/seller (optional) |
| `Expiration` | Offer expiration |
| `Flags` | tfSellNFToken (sell vs buy offer) |

**Policy Fields:** `NFTokenID`, `Amount`, `Destination`, `Expiration`
**Requires Destination:** No (Destination is optional)

**Example Use Cases:**

- Listing NFTs for sale
- Making purchase offers
- Private sales to specific buyers

---

### NFTokenAcceptOffer

Accepts an NFT buy or sell offer.

**Transaction Type:** `NFTokenAcceptOffer`
**Category:** NFT
**Default Tier:** Strict (Tier 2)

**Description:**

Accepts an existing offer to complete an NFT trade. Supports:
- Accepting a single sell offer
- Accepting a single buy offer
- Brokered mode (matching buy and sell offers)

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `NFTokenSellOffer` | Sell offer to accept |
| `NFTokenBuyOffer` | Buy offer to accept |
| `NFTokenBrokerFee` | Fee for brokered trades |

**Policy Fields:** `NFTokenSellOffer`, `NFTokenBuyOffer`, `NFTokenBrokerFee`
**Requires Destination:** No

**Example Use Cases:**

- Purchasing listed NFTs
- Accepting purchase offers
- Brokering trades between parties

---

### NFTokenCancelOffer

Cancels existing NFT offers.

**Transaction Type:** `NFTokenCancelOffer`
**Category:** NFT
**Default Tier:** Autonomous (Tier 1)

**Description:**

Cancels one or more NFT offers created by the account.

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `NFTokenOffers` | Array of offer IDs to cancel |

**Policy Fields:** `NFTokenOffers`
**Requires Destination:** No

**Example Use Cases:**

- Cancelling stale offers
- Updating listing prices
- Revoking purchase offers

---

## AMM Transactions

Automated Market Maker functionality on the XRPL (XLS-30).

### AMMCreate

Creates a new AMM liquidity pool.

**Transaction Type:** `AMMCreate`
**Category:** AMM
**Default Tier:** Co-sign (Tier 3)
**Risk Level:** HIGH

**Description:**

Creates a new automated market maker for a trading pair:
- Requires initial deposits of both assets
- Sets the initial trading fee
- Creates LP tokens for the creator
- Requires significant capital commitment

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `Amount` | First asset deposit |
| `Amount2` | Second asset deposit |
| `TradingFee` | Fee in basis points (0-1000) |

**Policy Fields:** `Amount`, `Amount2`, `TradingFee`
**Requires Destination:** No

**Security Note:**

Creating an AMM is a high-value operation that locks significant capital. Default to Tier 3 is intentional.

**Example Use Cases:**

- Creating new trading pairs
- Bootstrapping liquidity for new tokens

---

### AMMDeposit

Deposits assets into an AMM pool.

**Transaction Type:** `AMMDeposit`
**Category:** AMM
**Default Tier:** Strict (Tier 2)

**Description:**

Adds liquidity to an existing AMM pool:
- Single-sided deposits (one asset)
- Two-sided deposits (both assets)
- Receive LP tokens representing share

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `Asset` | First asset identifier |
| `Asset2` | Second asset identifier |
| `Amount` | Deposit amount (first asset) |
| `Amount2` | Deposit amount (second asset) |
| `LPTokenOut` | Minimum LP tokens to receive |
| `EPrice` | Maximum effective price |

**Policy Fields:** `Asset`, `Asset2`, `Amount`, `Amount2`, `LPTokenOut`
**Requires Destination:** No

**Example Use Cases:**

- Adding liquidity to earn fees
- Rebalancing LP positions

---

### AMMWithdraw

Withdraws assets from an AMM pool.

**Transaction Type:** `AMMWithdraw`
**Category:** AMM
**Default Tier:** Strict (Tier 2)

**Description:**

Removes liquidity from an AMM pool:
- Two-sided withdrawals (proportional)
- Single-sided withdrawals (one asset)
- Burns LP tokens

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `Asset` | First asset identifier |
| `Asset2` | Second asset identifier |
| `Amount` | Withdrawal amount (first asset) |
| `Amount2` | Withdrawal amount (second asset) |
| `LPTokenIn` | LP tokens to redeem |
| `EPrice` | Minimum effective price |

**Policy Fields:** `Asset`, `Asset2`, `Amount`, `Amount2`, `LPTokenIn`
**Requires Destination:** No

**Example Use Cases:**

- Exiting LP positions
- Taking profits
- Emergency liquidity removal

---

### AMMVote

Votes on AMM trading fee.

**Transaction Type:** `AMMVote`
**Category:** AMM
**Default Tier:** Strict (Tier 2)

**Description:**

LP token holders can vote to adjust the AMM trading fee. Vote weight is proportional to LP token holdings.

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `Asset` | First asset identifier |
| `Asset2` | Second asset identifier |
| `TradingFee` | Proposed fee (0-1000 basis points) |

**Policy Fields:** `Asset`, `Asset2`, `TradingFee`
**Requires Destination:** No

**Example Use Cases:**

- Governance participation
- Fee optimization

---

### AMMBid

Bids for AMM auction slot.

**Transaction Type:** `AMMBid`
**Category:** AMM
**Default Tier:** Strict (Tier 2)

**Description:**

Bids for the AMM's 24-hour auction slot, which provides:
- Discounted trading fees (0% fee)
- Useful for high-frequency trading
- Bid price is burned

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `Asset` | First asset identifier |
| `Asset2` | Second asset identifier |
| `BidMin` | Minimum bid (optional) |
| `BidMax` | Maximum bid (optional) |
| `AuthAccounts` | Authorized trading accounts |

**Policy Fields:** `Asset`, `Asset2`, `BidMin`, `BidMax`, `AuthAccounts`
**Requires Destination:** No

**Example Use Cases:**

- Winning discounted trading access
- Arbitrage optimization

---

### AMMDelete

Deletes an empty AMM.

**Transaction Type:** `AMMDelete`
**Category:** AMM
**Default Tier:** Strict (Tier 2)

**Description:**

Removes an AMM that has been fully drained of liquidity. Cleans up ledger objects.

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `Asset` | First asset identifier |
| `Asset2` | Second asset identifier |

**Policy Fields:** `Asset`, `Asset2`
**Requires Destination:** No

**Example Use Cases:**

- Ledger cleanup
- Freeing reserves

---

## Utility Transactions

### TicketCreate

Creates Tickets for future transaction sequencing.

**Transaction Type:** `TicketCreate`
**Category:** Tickets
**Default Tier:** Strict (Tier 2)

**Description:**

Tickets allow transactions to be submitted out of sequence order:
- Reserve sequence numbers for later use
- Enable parallel transaction preparation
- Useful for multi-sig coordination

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `TicketCount` | Number of tickets (1-250) |

**Policy Fields:** `TicketCount`
**Requires Destination:** No

**Example Use Cases:**

- Multi-sig transaction preparation
- Batch transaction coordination
- Sequence number management

---

## Identity Transactions (DID)

Decentralized Identity on the XRPL (XLS-40).

### DIDSet

Creates or updates a DID document.

**Transaction Type:** `DIDSet`
**Category:** DID
**Default Tier:** Strict (Tier 2)

**Description:**

Associates decentralized identity information with an XRPL account:
- Full DID document (JSON)
- URI reference to external document
- Arbitrary data field

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `DIDDocument` | Full DID document (hex) |
| `URI` | URI to DID document (hex) |
| `Data` | Arbitrary data (hex) |

**Policy Fields:** `DIDDocument`, `URI`, `Data`
**Requires Destination:** No

**Example Use Cases:**

- Establishing on-chain identity
- Linking to verification credentials
- Self-sovereign identity

---

### DIDDelete

Deletes a DID document.

**Transaction Type:** `DIDDelete`
**Category:** DID
**Default Tier:** Strict (Tier 2)

**Description:**

Removes the DID information from an account.

**Policy Considerations:**

No transaction-specific fields beyond the common fields.

**Policy Fields:** (none)
**Requires Destination:** No

**Example Use Cases:**

- Identity cleanup
- Privacy by deletion

---

## Oracle Transactions

Price oracle functionality on the XRPL (XLS-47).

### OracleSet

Creates or updates a price oracle.

**Transaction Type:** `OracleSet`
**Category:** Oracle
**Default Tier:** Strict (Tier 2)

**Description:**

Publishes price feed data on-chain:
- Multiple price data points per transaction
- Provider identification
- Asset class specification
- Timestamp tracking

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `OracleDocumentID` | Oracle identifier |
| `Provider` | Provider name (hex) |
| `URI` | Oracle documentation URI |
| `AssetClass` | Asset class (hex) |
| `LastUpdateTime` | Update timestamp |
| `PriceDataSeries` | Array of price data |

**Policy Fields:** `OracleDocumentID`, `Provider`, `URI`, `AssetClass`, `LastUpdateTime`, `PriceDataSeries`
**Requires Destination:** No

**Example Use Cases:**

- Publishing price feeds
- Providing DeFi oracle data
- On-chain price attestation

---

### OracleDelete

Deletes a price oracle.

**Transaction Type:** `OracleDelete`
**Category:** Oracle
**Default Tier:** Strict (Tier 2)

**Description:**

Removes an oracle from the ledger.

**Policy Considerations:**

| Field | Policy Relevance |
|-------|------------------|
| `OracleDocumentID` | Oracle to delete |

**Policy Fields:** `OracleDocumentID`
**Requires Destination:** No

**Example Use Cases:**

- Discontinuing oracle service
- Cleaning up old oracles

---

## Blocked Transaction Types

### Clawback

**Transaction Type:** `Clawback`
**Category:** Clawback
**Default Tier:** Prohibited (Tier 4)
**Risk Level:** CRITICAL

**Description:**

Allows issuers to reclaim issued currency from holders. This is a privileged operation only available to accounts with the `lsfAllowTrustLineClawback` flag enabled.

**Why Blocked by Default:**

1. **Issuer-Only Operation**: Only useful for issuer accounts with specific configuration
2. **Irreversible**: Clawed back tokens cannot be restored
3. **Trust Impact**: Affects all holders of the issued currency
4. **Regulatory Implications**: May have legal/compliance considerations

**Enabling Clawback:**

To use Clawback, explicitly allow it in policy:

```json
{
  "rules": [
    {
      "id": "enable-clawback-for-compliance",
      "condition": {
        "field": "transaction_type",
        "operator": "==",
        "value": "Clawback"
      },
      "action": {
        "tier": "cosign",
        "reason": "Clawback enabled for compliance operations - requires human approval"
      }
    }
  ]
}
```

**Example Use Cases (When Enabled):**

- Regulatory compliance (court orders)
- Fraud recovery
- Token migration

---

## Unknown Transaction Types

**Default Tier:** Prohibited (Tier 4)

**Handling:**

When the XRPL introduces new transaction types via amendments, they are automatically blocked until explicitly configured:

```
Unknown transaction type: NewTransactionType. Add to policy to enable.
```

**Why Unknown Types Are Blocked:**

1. **Safety First**: New types may have unknown security implications
2. **Explicit Opt-In**: Prevents unexpected behavior
3. **Audit Trail**: Forces conscious decision to enable
4. **Policy Review**: Encourages updating policies when new features are adopted

**Enabling New Types:**

```json
{
  "rules": [
    {
      "id": "enable-new-type",
      "condition": {
        "field": "transaction_type",
        "operator": "==",
        "value": "NewTransactionType"
      },
      "action": {
        "tier": "strict",
        "reason": "Explicitly enabled after security review"
      }
    }
  ]
}
```

---

## Transaction Type Policy Overrides

### By Category

Override defaults for entire categories:

```json
{
  "rules": [
    {
      "id": "nft-category-autonomous",
      "priority": 50,
      "condition": {
        "field": "transaction_category",
        "operator": "==",
        "value": "nft"
      },
      "action": {
        "tier": "autonomous",
        "reason": "NFT operations allowed for trading agent"
      }
    }
  ]
}
```

### By Specific Type

Override individual transaction types:

```json
{
  "rules": [
    {
      "id": "trustset-approved-issuers",
      "priority": 40,
      "condition": {
        "and": [
          { "field": "transaction_type", "operator": "==", "value": "TrustSet" },
          { "field": "LimitAmount.issuer", "operator": "in", "value": ["rApproved1...", "rApproved2..."] }
        ]
      },
      "action": {
        "tier": "autonomous"
      }
    }
  ]
}
```

### By Amount Threshold

Different tiers based on value:

```json
{
  "rules": [
    {
      "id": "payment-small",
      "priority": 30,
      "condition": {
        "and": [
          { "field": "transaction_type", "operator": "==", "value": "Payment" },
          { "field": "amount_drops", "operator": "<=", "value": "10000000" }
        ]
      },
      "action": { "tier": "autonomous" }
    },
    {
      "id": "payment-medium",
      "priority": 29,
      "condition": {
        "and": [
          { "field": "transaction_type", "operator": "==", "value": "Payment" },
          { "field": "amount_drops", "operator": "<=", "value": "100000000" }
        ]
      },
      "action": { "tier": "delayed" }
    },
    {
      "id": "payment-large",
      "priority": 28,
      "condition": {
        "field": "transaction_type",
        "operator": "==",
        "value": "Payment"
      },
      "action": { "tier": "cosign" }
    }
  ]
}
```

---

## Summary Table

| Transaction Type | Category | Default Tier | Risk | Requires Destination |
|------------------|----------|--------------|------|---------------------|
| Payment | Payments | Autonomous | Standard | Yes |
| TrustSet | Trust Lines | Strict | Medium | No |
| OfferCreate | DEX | Strict | Standard | No |
| OfferCancel | DEX | Autonomous | Standard | No |
| EscrowCreate | Escrow | Strict | Standard | Yes |
| EscrowFinish | Escrow | Autonomous | Standard | No |
| EscrowCancel | Escrow | Autonomous | Standard | No |
| CheckCreate | Checks | Strict | Standard | Yes |
| CheckCash | Checks | Autonomous | Standard | No |
| CheckCancel | Checks | Autonomous | Standard | No |
| PaymentChannelCreate | Payment Channels | Strict | Standard | Yes |
| PaymentChannelFund | Payment Channels | Strict | Standard | No |
| PaymentChannelClaim | Payment Channels | Autonomous | Standard | No |
| AccountSet | Account | Co-sign | High | No |
| SetRegularKey | Account | Co-sign | Critical | No |
| SignerListSet | Account | Co-sign | Critical | No |
| NFTokenMint | NFT | Strict | Standard | No |
| NFTokenBurn | NFT | Strict | Standard | No |
| NFTokenCreateOffer | NFT | Strict | Standard | No |
| NFTokenAcceptOffer | NFT | Strict | Standard | No |
| NFTokenCancelOffer | NFT | Autonomous | Standard | No |
| AMMCreate | AMM | Co-sign | High | No |
| AMMDeposit | AMM | Strict | Standard | No |
| AMMWithdraw | AMM | Strict | Standard | No |
| AMMVote | AMM | Strict | Standard | No |
| AMMBid | AMM | Strict | Standard | No |
| AMMDelete | AMM | Strict | Standard | No |
| TicketCreate | Tickets | Strict | Standard | No |
| DIDSet | DID | Strict | Standard | No |
| DIDDelete | DID | Strict | Standard | No |
| OracleSet | Oracle | Strict | Standard | No |
| OracleDelete | Oracle | Strict | Standard | No |
| Clawback | Clawback | Prohibited | Critical | No |

---

## Related Documentation

- [API Reference](/docs/user/reference/api.md) - Tool specifications
- [Policy Configuration](/docs/user/how-to/configure-policies.md) - Policy setup guide
- [Security Model](/docs/architecture/09-decisions/ADR-002-security-model.md) - Security architecture
- [ADR-009: Transaction Scope](/docs/architecture/09-decisions/ADR-009-transaction-scope.md) - Design rationale

---

## External References

- [XRPL Transaction Types](https://xrpl.org/transaction-types.html) - Official documentation
- [XRPL Amendments](https://xrpl.org/amendments.html) - Protocol changes
- [XLS-20 NFT Standard](https://github.com/XRPLF/XRPL-Standards/tree/master/XLS-20) - NFT specification
- [XLS-30 AMM Standard](https://github.com/XRPLF/XRPL-Standards/tree/master/XLS-30) - AMM specification

---

*XRPL Agent Wallet MCP - Supported Transaction Types Reference v1.0.0*
