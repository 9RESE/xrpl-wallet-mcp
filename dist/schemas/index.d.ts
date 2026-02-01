import { z } from 'zod';

/**
 * XRPL Agent Wallet MCP - Comprehensive Zod Schemas
 *
 * This module defines all TypeScript type definitions using Zod for the
 * XRPL Agent Wallet MCP server. These schemas serve as the single source
 * of truth for all API inputs, outputs, and internal data structures.
 *
 * @module schemas
 * @version 1.0.0
 * @since 2026-01-28
 */

/**
 * XRPL Classic Address validation
 *
 * Format: r[1-9A-HJ-NP-Za-km-z]{24,34}
 * - Starts with 'r'
 * - Followed by 24-34 Base58 characters (excluding 0, O, I, l)
 * - Note: Full checksum validation requires xrpl.js at runtime
 *
 * @example "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
 * @see https://xrpl.org/docs/concepts/accounts/addresses
 */
declare const XRPLAddressSchema: z.ZodString;
/**
 * XRP amount in drops (string representation for precision)
 *
 * XRPL uses drops as the native unit:
 * - 1 XRP = 1,000,000 drops
 * - Minimum: 1 drop
 * - Maximum: 100 quadrillion drops (100 billion XRP)
 *
 * Uses string to avoid JavaScript number precision issues with large values.
 *
 * @example "1000000" (1 XRP)
 * @example "50000000000" (50,000 XRP)
 */
declare const DropsAmountSchema: z.ZodEffects<z.ZodString, string, string>;
/**
 * Optional drops amount that can be "0" for queries
 * Used for balance queries where zero is valid
 */
declare const DropsAmountOptionalZeroSchema: z.ZodEffects<z.ZodString, string, string>;
/**
 * XRPL Transaction Hash validation
 *
 * 64 hexadecimal characters (256-bit hash)
 *
 * @example "E08D6E9754025BA2534A78707605E0601F03ACE063687A0CA1BDDACFCD1698C7"
 */
declare const TransactionHashSchema: z.ZodEffects<z.ZodString, string, string>;
/**
 * XRPL Ledger Index (sequence number)
 * Can be a specific ledger number or special strings
 */
declare const LedgerIndexSchema: z.ZodUnion<[z.ZodNumber, z.ZodEnum<["validated", "closed", "current"]>]>;
/**
 * XRPL Public Key validation
 *
 * Supports two formats:
 * - ED25519: Prefix "ED" + 64 hex characters (66 total)
 * - SECP256K1: Prefix "02" or "03" + 64 hex characters (66 total)
 *
 * @example "ED..." (Ed25519 key)
 * @example "02..." or "03..." (secp256k1 key)
 */
declare const PublicKeySchema: z.ZodEffects<z.ZodString, string, string>;
/**
 * Network identifier for XRPL environments
 *
 * - mainnet: Production network (real XRP)
 * - testnet: Test network (free test XRP via faucet)
 * - devnet: Development network (latest features, may be unstable)
 */
declare const NetworkSchema: z.ZodEnum<["mainnet", "testnet", "devnet"]>;
/**
 * XRPL Transaction Type
 * @see https://xrpl.org/docs/references/protocol/transactions/types
 */
declare const TransactionTypeSchema: z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>;
/**
 * XRPL Account Sequence Number
 * Unsigned 32-bit integer starting from 1
 */
declare const SequenceNumberSchema: z.ZodNumber;
/**
 * Hexadecimal string validation (variable length)
 * Used for transaction blobs and other hex data.
 *
 * IMPORTANT: This schema transforms input to UPPERCASE for consistency.
 * If you need case-preserving behavior, use HexStringRawSchema instead.
 *
 * @example
 * Input:  "deadbeef"
 * Output: "DEADBEEF"
 */
declare const HexStringSchema: z.ZodEffects<z.ZodString, string, string>;
/**
 * Raw hexadecimal string validation (no transform)
 * Used for input schemas where we need to chain additional validators
 */
declare const HexStringRawSchema: z.ZodString;
/**
 * Unsigned transaction blob
 * Variable length hex string representing serialized transaction
 */
declare const UnsignedTransactionBlobSchema: z.ZodString;
/**
 * Signed transaction blob
 * Contains signature(s) appended to transaction data
 */
declare const SignedTransactionBlobSchema: z.ZodString;
/**
 * Wallet identifier (internal reference)
 * Alphanumeric with hyphens and underscores
 */
declare const WalletIdSchema: z.ZodString;
/**
 * Wallet name (human-readable label)
 */
declare const WalletNameSchema: z.ZodString;
/**
 * ISO 8601 timestamp string
 */
declare const TimestampSchema: z.ZodString;
/**
 * Pagination marker for XRPL queries
 * Opaque value returned by previous query
 */
declare const PaginationMarkerSchema: z.ZodString;
/**
 * Approval tier for transactions
 *
 * - Tier 1: Autonomous - Agent can sign immediately
 * - Tier 2: Delayed - Agent signs after delay (human can veto)
 * - Tier 3: Co-Sign - Requires human co-signature
 * - Tier 4: Prohibited - Never allowed, always rejected
 */
declare const ApprovalTierSchema: z.ZodUnion<[z.ZodLiteral<1>, z.ZodLiteral<2>, z.ZodLiteral<3>, z.ZodLiteral<4>]>;
/**
 * Policy limit configuration
 * Defines transaction and volume limits for the agent wallet
 */
declare const PolicyLimitsSchema: z.ZodObject<{
    /**
     * Maximum amount per single transaction in drops
     * @example "10000000" (10 XRP)
     */
    max_amount_per_tx_drops: z.ZodEffects<z.ZodString, string, string>;
    /**
     * Maximum daily transaction volume in drops
     * Resets at midnight UTC
     * @example "100000000" (100 XRP)
     */
    max_daily_volume_drops: z.ZodEffects<z.ZodString, string, string>;
    /**
     * Maximum transactions per hour (rolling window)
     */
    max_tx_per_hour: z.ZodNumber;
    /**
     * Maximum transactions per day (rolling window)
     */
    max_tx_per_day: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    max_amount_per_tx_drops: string;
    max_daily_volume_drops: string;
    max_tx_per_hour: number;
    max_tx_per_day: number;
}, {
    max_amount_per_tx_drops: string;
    max_daily_volume_drops: string;
    max_tx_per_hour: number;
    max_tx_per_day: number;
}>;
/**
 * Destination control mode
 *
 * - allowlist: Only explicitly allowed addresses can receive
 * - blocklist: All addresses except blocked ones can receive
 * - open: Any address can receive (least restrictive)
 */
declare const DestinationModeSchema: z.ZodEnum<["allowlist", "blocklist", "open"]>;
/**
 * Destination controls configuration
 * Manages which addresses the agent can send to
 */
declare const PolicyDestinationsSchema: z.ZodObject<{
    /**
     * Destination filtering mode
     */
    mode: z.ZodEnum<["allowlist", "blocklist", "open"]>;
    /**
     * Allowed destination addresses (used when mode='allowlist')
     */
    allowlist: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    /**
     * Blocked destination addresses (always enforced regardless of mode)
     * Used for known scam/malicious addresses
     */
    blocklist: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    /**
     * Whether to allow transactions to previously unseen addresses
     */
    allow_new_destinations: z.ZodBoolean;
    /**
     * Approval tier required for new destinations
     * Only used when allow_new_destinations is true
     */
    new_destination_tier: z.ZodOptional<z.ZodUnion<[z.ZodLiteral<2>, z.ZodLiteral<3>]>>;
}, "strip", z.ZodTypeAny, {
    mode: "allowlist" | "blocklist" | "open";
    allow_new_destinations: boolean;
    allowlist?: string[] | undefined;
    blocklist?: string[] | undefined;
    new_destination_tier?: 3 | 2 | undefined;
}, {
    mode: "allowlist" | "blocklist" | "open";
    allow_new_destinations: boolean;
    allowlist?: string[] | undefined;
    blocklist?: string[] | undefined;
    new_destination_tier?: 3 | 2 | undefined;
}>;
/**
 * Transaction type controls
 * Specifies which transaction types the agent can execute
 */
declare const PolicyTransactionTypesSchema: z.ZodObject<{
    /**
     * Transaction types the agent can execute autonomously
     * @example ["Payment", "EscrowFinish", "EscrowCancel"]
     */
    allowed: z.ZodArray<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>, "many">;
    /**
     * Transaction types that require human approval (tier 2/3)
     * @example ["EscrowCreate", "TrustSet"]
     */
    require_approval: z.ZodOptional<z.ZodArray<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>, "many">>;
    /**
     * Transaction types that are never allowed (tier 4)
     * Typically account control operations
     * @example ["SetRegularKey", "SignerListSet", "AccountDelete"]
     */
    blocked: z.ZodOptional<z.ZodArray<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>, "many">>;
}, "strip", z.ZodTypeAny, {
    allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
    require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
    blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
}, {
    allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
    require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
    blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
}>;
/**
 * Time-based access controls
 * Restricts when the agent can execute transactions
 */
declare const PolicyTimeControlsSchema: z.ZodObject<{
    /**
     * Active hours in UTC (24-hour format)
     * Transactions outside these hours are escalated to tier 2/3
     */
    active_hours_utc: z.ZodOptional<z.ZodObject<{
        start: z.ZodNumber;
        end: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        start: number;
        end: number;
    }, {
        start: number;
        end: number;
    }>>;
    /**
     * Active days of the week
     * 0 = Sunday, 6 = Saturday
     */
    active_days: z.ZodOptional<z.ZodArray<z.ZodNumber, "many">>;
    /**
     * Timezone for interpreting active hours
     * @example "America/New_York"
     */
    timezone: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    active_hours_utc?: {
        start: number;
        end: number;
    } | undefined;
    active_days?: number[] | undefined;
    timezone?: string | undefined;
}, {
    active_hours_utc?: {
        start: number;
        end: number;
    } | undefined;
    active_days?: number[] | undefined;
    timezone?: string | undefined;
}>;
/**
 * Escalation rules configuration
 * Defines thresholds for tier escalation
 */
declare const PolicyEscalationSchema: z.ZodObject<{
    /**
     * Amount threshold for escalation to tier 2 (drops)
     * Transactions above this require delayed/human approval
     */
    amount_threshold_drops: z.ZodEffects<z.ZodString, string, string>;
    /**
     * Tier assigned to transactions with new destinations
     */
    new_destination: z.ZodUnion<[z.ZodLiteral<2>, z.ZodLiteral<3>]>;
    /**
     * Tier for account settings changes
     * Always tier 3 for safety
     */
    account_settings: z.ZodLiteral<3>;
    /**
     * Delay in seconds before tier 2 transactions auto-approve
     * Human can veto during this window
     */
    delay_seconds: z.ZodOptional<z.ZodNumber>;
}, "strip", z.ZodTypeAny, {
    amount_threshold_drops: string;
    new_destination: 3 | 2;
    account_settings: 3;
    delay_seconds?: number | undefined;
}, {
    amount_threshold_drops: string;
    new_destination: 3 | 2;
    account_settings: 3;
    delay_seconds?: number | undefined;
}>;
/**
 * Notification events for webhooks
 */
declare const NotificationEventSchema: z.ZodEnum<["tier2", "tier3", "rejection", "all"]>;
/**
 * Notification configuration
 * Webhook settings for transaction events
 */
declare const PolicyNotificationsSchema: z.ZodObject<{
    /**
     * Webhook URL for notifications
     * Must be HTTPS for production
     */
    webhook_url: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    /**
     * Events that trigger notifications
     */
    notify_on: z.ZodOptional<z.ZodArray<z.ZodEnum<["tier2", "tier3", "rejection", "all"]>, "many">>;
}, "strip", z.ZodTypeAny, {
    webhook_url?: string | undefined;
    notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
}, {
    webhook_url?: string | undefined;
    notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
}>;
/**
 * Complete Agent Wallet Policy
 *
 * Defines all security and operational constraints for an agent wallet.
 * This policy is immutable at runtime - the LLM cannot modify it.
 */
declare const AgentWalletPolicySchema: z.ZodObject<{
    /**
     * Unique policy identifier
     * @example "conservative-v1"
     */
    policy_id: z.ZodString;
    /**
     * Policy version for tracking changes
     * Semantic versioning recommended
     */
    policy_version: z.ZodString;
    /**
     * Transaction and volume limits
     */
    limits: z.ZodObject<{
        /**
         * Maximum amount per single transaction in drops
         * @example "10000000" (10 XRP)
         */
        max_amount_per_tx_drops: z.ZodEffects<z.ZodString, string, string>;
        /**
         * Maximum daily transaction volume in drops
         * Resets at midnight UTC
         * @example "100000000" (100 XRP)
         */
        max_daily_volume_drops: z.ZodEffects<z.ZodString, string, string>;
        /**
         * Maximum transactions per hour (rolling window)
         */
        max_tx_per_hour: z.ZodNumber;
        /**
         * Maximum transactions per day (rolling window)
         */
        max_tx_per_day: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        max_amount_per_tx_drops: string;
        max_daily_volume_drops: string;
        max_tx_per_hour: number;
        max_tx_per_day: number;
    }, {
        max_amount_per_tx_drops: string;
        max_daily_volume_drops: string;
        max_tx_per_hour: number;
        max_tx_per_day: number;
    }>;
    /**
     * Destination address controls
     */
    destinations: z.ZodObject<{
        /**
         * Destination filtering mode
         */
        mode: z.ZodEnum<["allowlist", "blocklist", "open"]>;
        /**
         * Allowed destination addresses (used when mode='allowlist')
         */
        allowlist: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        /**
         * Blocked destination addresses (always enforced regardless of mode)
         * Used for known scam/malicious addresses
         */
        blocklist: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        /**
         * Whether to allow transactions to previously unseen addresses
         */
        allow_new_destinations: z.ZodBoolean;
        /**
         * Approval tier required for new destinations
         * Only used when allow_new_destinations is true
         */
        new_destination_tier: z.ZodOptional<z.ZodUnion<[z.ZodLiteral<2>, z.ZodLiteral<3>]>>;
    }, "strip", z.ZodTypeAny, {
        mode: "allowlist" | "blocklist" | "open";
        allow_new_destinations: boolean;
        allowlist?: string[] | undefined;
        blocklist?: string[] | undefined;
        new_destination_tier?: 3 | 2 | undefined;
    }, {
        mode: "allowlist" | "blocklist" | "open";
        allow_new_destinations: boolean;
        allowlist?: string[] | undefined;
        blocklist?: string[] | undefined;
        new_destination_tier?: 3 | 2 | undefined;
    }>;
    /**
     * Transaction type restrictions
     */
    transaction_types: z.ZodObject<{
        /**
         * Transaction types the agent can execute autonomously
         * @example ["Payment", "EscrowFinish", "EscrowCancel"]
         */
        allowed: z.ZodArray<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>, "many">;
        /**
         * Transaction types that require human approval (tier 2/3)
         * @example ["EscrowCreate", "TrustSet"]
         */
        require_approval: z.ZodOptional<z.ZodArray<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>, "many">>;
        /**
         * Transaction types that are never allowed (tier 4)
         * Typically account control operations
         * @example ["SetRegularKey", "SignerListSet", "AccountDelete"]
         */
        blocked: z.ZodOptional<z.ZodArray<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>, "many">>;
    }, "strip", z.ZodTypeAny, {
        allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
        require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
        blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
    }, {
        allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
        require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
        blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
    }>;
    /**
     * Time-based access controls (optional)
     */
    time_controls: z.ZodOptional<z.ZodObject<{
        /**
         * Active hours in UTC (24-hour format)
         * Transactions outside these hours are escalated to tier 2/3
         */
        active_hours_utc: z.ZodOptional<z.ZodObject<{
            start: z.ZodNumber;
            end: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            start: number;
            end: number;
        }, {
            start: number;
            end: number;
        }>>;
        /**
         * Active days of the week
         * 0 = Sunday, 6 = Saturday
         */
        active_days: z.ZodOptional<z.ZodArray<z.ZodNumber, "many">>;
        /**
         * Timezone for interpreting active hours
         * @example "America/New_York"
         */
        timezone: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        active_hours_utc?: {
            start: number;
            end: number;
        } | undefined;
        active_days?: number[] | undefined;
        timezone?: string | undefined;
    }, {
        active_hours_utc?: {
            start: number;
            end: number;
        } | undefined;
        active_days?: number[] | undefined;
        timezone?: string | undefined;
    }>>;
    /**
     * Escalation thresholds
     */
    escalation: z.ZodObject<{
        /**
         * Amount threshold for escalation to tier 2 (drops)
         * Transactions above this require delayed/human approval
         */
        amount_threshold_drops: z.ZodEffects<z.ZodString, string, string>;
        /**
         * Tier assigned to transactions with new destinations
         */
        new_destination: z.ZodUnion<[z.ZodLiteral<2>, z.ZodLiteral<3>]>;
        /**
         * Tier for account settings changes
         * Always tier 3 for safety
         */
        account_settings: z.ZodLiteral<3>;
        /**
         * Delay in seconds before tier 2 transactions auto-approve
         * Human can veto during this window
         */
        delay_seconds: z.ZodOptional<z.ZodNumber>;
    }, "strip", z.ZodTypeAny, {
        amount_threshold_drops: string;
        new_destination: 3 | 2;
        account_settings: 3;
        delay_seconds?: number | undefined;
    }, {
        amount_threshold_drops: string;
        new_destination: 3 | 2;
        account_settings: 3;
        delay_seconds?: number | undefined;
    }>;
    /**
     * Notification settings (optional)
     */
    notifications: z.ZodOptional<z.ZodObject<{
        /**
         * Webhook URL for notifications
         * Must be HTTPS for production
         */
        webhook_url: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
        /**
         * Events that trigger notifications
         */
        notify_on: z.ZodOptional<z.ZodArray<z.ZodEnum<["tier2", "tier3", "rejection", "all"]>, "many">>;
    }, "strip", z.ZodTypeAny, {
        webhook_url?: string | undefined;
        notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
    }, {
        webhook_url?: string | undefined;
        notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
    }>>;
}, "strip", z.ZodTypeAny, {
    policy_id: string;
    policy_version: string;
    limits: {
        max_amount_per_tx_drops: string;
        max_daily_volume_drops: string;
        max_tx_per_hour: number;
        max_tx_per_day: number;
    };
    destinations: {
        mode: "allowlist" | "blocklist" | "open";
        allow_new_destinations: boolean;
        allowlist?: string[] | undefined;
        blocklist?: string[] | undefined;
        new_destination_tier?: 3 | 2 | undefined;
    };
    transaction_types: {
        allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
        require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
        blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
    };
    escalation: {
        amount_threshold_drops: string;
        new_destination: 3 | 2;
        account_settings: 3;
        delay_seconds?: number | undefined;
    };
    time_controls?: {
        active_hours_utc?: {
            start: number;
            end: number;
        } | undefined;
        active_days?: number[] | undefined;
        timezone?: string | undefined;
    } | undefined;
    notifications?: {
        webhook_url?: string | undefined;
        notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
    } | undefined;
}, {
    policy_id: string;
    policy_version: string;
    limits: {
        max_amount_per_tx_drops: string;
        max_daily_volume_drops: string;
        max_tx_per_hour: number;
        max_tx_per_day: number;
    };
    destinations: {
        mode: "allowlist" | "blocklist" | "open";
        allow_new_destinations: boolean;
        allowlist?: string[] | undefined;
        blocklist?: string[] | undefined;
        new_destination_tier?: 3 | 2 | undefined;
    };
    transaction_types: {
        allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
        require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
        blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
    };
    escalation: {
        amount_threshold_drops: string;
        new_destination: 3 | 2;
        account_settings: 3;
        delay_seconds?: number | undefined;
    };
    time_controls?: {
        active_hours_utc?: {
            start: number;
            end: number;
        } | undefined;
        active_days?: number[] | undefined;
        timezone?: string | undefined;
    } | undefined;
    notifications?: {
        webhook_url?: string | undefined;
        notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
    } | undefined;
}>;
/**
 * Input schema for wallet_create tool
 *
 * Creates a new XRPL wallet with policy controls.
 * The wallet is generated locally with encrypted key storage.
 */
declare const WalletCreateInputSchema: z.ZodObject<{
    /**
     * Target network for the wallet
     * Keys are isolated per network
     */
    network: z.ZodEnum<["mainnet", "testnet", "devnet"]>;
    /**
     * Policy to apply to this wallet
     * Defines all security constraints
     */
    policy: z.ZodObject<{
        /**
         * Unique policy identifier
         * @example "conservative-v1"
         */
        policy_id: z.ZodString;
        /**
         * Policy version for tracking changes
         * Semantic versioning recommended
         */
        policy_version: z.ZodString;
        /**
         * Transaction and volume limits
         */
        limits: z.ZodObject<{
            /**
             * Maximum amount per single transaction in drops
             * @example "10000000" (10 XRP)
             */
            max_amount_per_tx_drops: z.ZodEffects<z.ZodString, string, string>;
            /**
             * Maximum daily transaction volume in drops
             * Resets at midnight UTC
             * @example "100000000" (100 XRP)
             */
            max_daily_volume_drops: z.ZodEffects<z.ZodString, string, string>;
            /**
             * Maximum transactions per hour (rolling window)
             */
            max_tx_per_hour: z.ZodNumber;
            /**
             * Maximum transactions per day (rolling window)
             */
            max_tx_per_day: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            max_amount_per_tx_drops: string;
            max_daily_volume_drops: string;
            max_tx_per_hour: number;
            max_tx_per_day: number;
        }, {
            max_amount_per_tx_drops: string;
            max_daily_volume_drops: string;
            max_tx_per_hour: number;
            max_tx_per_day: number;
        }>;
        /**
         * Destination address controls
         */
        destinations: z.ZodObject<{
            /**
             * Destination filtering mode
             */
            mode: z.ZodEnum<["allowlist", "blocklist", "open"]>;
            /**
             * Allowed destination addresses (used when mode='allowlist')
             */
            allowlist: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
            /**
             * Blocked destination addresses (always enforced regardless of mode)
             * Used for known scam/malicious addresses
             */
            blocklist: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
            /**
             * Whether to allow transactions to previously unseen addresses
             */
            allow_new_destinations: z.ZodBoolean;
            /**
             * Approval tier required for new destinations
             * Only used when allow_new_destinations is true
             */
            new_destination_tier: z.ZodOptional<z.ZodUnion<[z.ZodLiteral<2>, z.ZodLiteral<3>]>>;
        }, "strip", z.ZodTypeAny, {
            mode: "allowlist" | "blocklist" | "open";
            allow_new_destinations: boolean;
            allowlist?: string[] | undefined;
            blocklist?: string[] | undefined;
            new_destination_tier?: 3 | 2 | undefined;
        }, {
            mode: "allowlist" | "blocklist" | "open";
            allow_new_destinations: boolean;
            allowlist?: string[] | undefined;
            blocklist?: string[] | undefined;
            new_destination_tier?: 3 | 2 | undefined;
        }>;
        /**
         * Transaction type restrictions
         */
        transaction_types: z.ZodObject<{
            /**
             * Transaction types the agent can execute autonomously
             * @example ["Payment", "EscrowFinish", "EscrowCancel"]
             */
            allowed: z.ZodArray<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>, "many">;
            /**
             * Transaction types that require human approval (tier 2/3)
             * @example ["EscrowCreate", "TrustSet"]
             */
            require_approval: z.ZodOptional<z.ZodArray<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>, "many">>;
            /**
             * Transaction types that are never allowed (tier 4)
             * Typically account control operations
             * @example ["SetRegularKey", "SignerListSet", "AccountDelete"]
             */
            blocked: z.ZodOptional<z.ZodArray<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>, "many">>;
        }, "strip", z.ZodTypeAny, {
            allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
            require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
        }, {
            allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
            require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
        }>;
        /**
         * Time-based access controls (optional)
         */
        time_controls: z.ZodOptional<z.ZodObject<{
            /**
             * Active hours in UTC (24-hour format)
             * Transactions outside these hours are escalated to tier 2/3
             */
            active_hours_utc: z.ZodOptional<z.ZodObject<{
                start: z.ZodNumber;
                end: z.ZodNumber;
            }, "strip", z.ZodTypeAny, {
                start: number;
                end: number;
            }, {
                start: number;
                end: number;
            }>>;
            /**
             * Active days of the week
             * 0 = Sunday, 6 = Saturday
             */
            active_days: z.ZodOptional<z.ZodArray<z.ZodNumber, "many">>;
            /**
             * Timezone for interpreting active hours
             * @example "America/New_York"
             */
            timezone: z.ZodOptional<z.ZodString>;
        }, "strip", z.ZodTypeAny, {
            active_hours_utc?: {
                start: number;
                end: number;
            } | undefined;
            active_days?: number[] | undefined;
            timezone?: string | undefined;
        }, {
            active_hours_utc?: {
                start: number;
                end: number;
            } | undefined;
            active_days?: number[] | undefined;
            timezone?: string | undefined;
        }>>;
        /**
         * Escalation thresholds
         */
        escalation: z.ZodObject<{
            /**
             * Amount threshold for escalation to tier 2 (drops)
             * Transactions above this require delayed/human approval
             */
            amount_threshold_drops: z.ZodEffects<z.ZodString, string, string>;
            /**
             * Tier assigned to transactions with new destinations
             */
            new_destination: z.ZodUnion<[z.ZodLiteral<2>, z.ZodLiteral<3>]>;
            /**
             * Tier for account settings changes
             * Always tier 3 for safety
             */
            account_settings: z.ZodLiteral<3>;
            /**
             * Delay in seconds before tier 2 transactions auto-approve
             * Human can veto during this window
             */
            delay_seconds: z.ZodOptional<z.ZodNumber>;
        }, "strip", z.ZodTypeAny, {
            amount_threshold_drops: string;
            new_destination: 3 | 2;
            account_settings: 3;
            delay_seconds?: number | undefined;
        }, {
            amount_threshold_drops: string;
            new_destination: 3 | 2;
            account_settings: 3;
            delay_seconds?: number | undefined;
        }>;
        /**
         * Notification settings (optional)
         */
        notifications: z.ZodOptional<z.ZodObject<{
            /**
             * Webhook URL for notifications
             * Must be HTTPS for production
             */
            webhook_url: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
            /**
             * Events that trigger notifications
             */
            notify_on: z.ZodOptional<z.ZodArray<z.ZodEnum<["tier2", "tier3", "rejection", "all"]>, "many">>;
        }, "strip", z.ZodTypeAny, {
            webhook_url?: string | undefined;
            notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
        }, {
            webhook_url?: string | undefined;
            notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
        }>>;
    }, "strip", z.ZodTypeAny, {
        policy_id: string;
        policy_version: string;
        limits: {
            max_amount_per_tx_drops: string;
            max_daily_volume_drops: string;
            max_tx_per_hour: number;
            max_tx_per_day: number;
        };
        destinations: {
            mode: "allowlist" | "blocklist" | "open";
            allow_new_destinations: boolean;
            allowlist?: string[] | undefined;
            blocklist?: string[] | undefined;
            new_destination_tier?: 3 | 2 | undefined;
        };
        transaction_types: {
            allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
            require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
        };
        escalation: {
            amount_threshold_drops: string;
            new_destination: 3 | 2;
            account_settings: 3;
            delay_seconds?: number | undefined;
        };
        time_controls?: {
            active_hours_utc?: {
                start: number;
                end: number;
            } | undefined;
            active_days?: number[] | undefined;
            timezone?: string | undefined;
        } | undefined;
        notifications?: {
            webhook_url?: string | undefined;
            notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
        } | undefined;
    }, {
        policy_id: string;
        policy_version: string;
        limits: {
            max_amount_per_tx_drops: string;
            max_daily_volume_drops: string;
            max_tx_per_hour: number;
            max_tx_per_day: number;
        };
        destinations: {
            mode: "allowlist" | "blocklist" | "open";
            allow_new_destinations: boolean;
            allowlist?: string[] | undefined;
            blocklist?: string[] | undefined;
            new_destination_tier?: 3 | 2 | undefined;
        };
        transaction_types: {
            allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
            require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
        };
        escalation: {
            amount_threshold_drops: string;
            new_destination: 3 | 2;
            account_settings: 3;
            delay_seconds?: number | undefined;
        };
        time_controls?: {
            active_hours_utc?: {
                start: number;
                end: number;
            } | undefined;
            active_days?: number[] | undefined;
            timezone?: string | undefined;
        } | undefined;
        notifications?: {
            webhook_url?: string | undefined;
            notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
        } | undefined;
    }>;
    /**
     * Human-readable wallet name (optional)
     */
    wallet_name: z.ZodOptional<z.ZodString>;
    /**
     * Address to fund the new wallet from (optional)
     * Requires separate signing outside this MCP
     */
    funding_source: z.ZodOptional<z.ZodString>;
    /**
     * Initial funding amount in drops (optional)
     * Must meet minimum reserve requirements
     */
    initial_funding_drops: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
}, "strip", z.ZodTypeAny, {
    network: "mainnet" | "testnet" | "devnet";
    policy: {
        policy_id: string;
        policy_version: string;
        limits: {
            max_amount_per_tx_drops: string;
            max_daily_volume_drops: string;
            max_tx_per_hour: number;
            max_tx_per_day: number;
        };
        destinations: {
            mode: "allowlist" | "blocklist" | "open";
            allow_new_destinations: boolean;
            allowlist?: string[] | undefined;
            blocklist?: string[] | undefined;
            new_destination_tier?: 3 | 2 | undefined;
        };
        transaction_types: {
            allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
            require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
        };
        escalation: {
            amount_threshold_drops: string;
            new_destination: 3 | 2;
            account_settings: 3;
            delay_seconds?: number | undefined;
        };
        time_controls?: {
            active_hours_utc?: {
                start: number;
                end: number;
            } | undefined;
            active_days?: number[] | undefined;
            timezone?: string | undefined;
        } | undefined;
        notifications?: {
            webhook_url?: string | undefined;
            notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
        } | undefined;
    };
    wallet_name?: string | undefined;
    funding_source?: string | undefined;
    initial_funding_drops?: string | undefined;
}, {
    network: "mainnet" | "testnet" | "devnet";
    policy: {
        policy_id: string;
        policy_version: string;
        limits: {
            max_amount_per_tx_drops: string;
            max_daily_volume_drops: string;
            max_tx_per_hour: number;
            max_tx_per_day: number;
        };
        destinations: {
            mode: "allowlist" | "blocklist" | "open";
            allow_new_destinations: boolean;
            allowlist?: string[] | undefined;
            blocklist?: string[] | undefined;
            new_destination_tier?: 3 | 2 | undefined;
        };
        transaction_types: {
            allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
            require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
        };
        escalation: {
            amount_threshold_drops: string;
            new_destination: 3 | 2;
            account_settings: 3;
            delay_seconds?: number | undefined;
        };
        time_controls?: {
            active_hours_utc?: {
                start: number;
                end: number;
            } | undefined;
            active_days?: number[] | undefined;
            timezone?: string | undefined;
        } | undefined;
        notifications?: {
            webhook_url?: string | undefined;
            notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
        } | undefined;
    };
    wallet_name?: string | undefined;
    funding_source?: string | undefined;
    initial_funding_drops?: string | undefined;
}>;
/**
 * Input schema for wallet_import tool
 *
 * Imports an existing XRPL wallet from a seed.
 * Uses a simple default policy - much easier than wallet_create.
 */
declare const WalletImportInputSchema: z.ZodObject<{
    /**
     * XRPL seed (starts with 's')
     */
    seed: z.ZodString;
    /**
     * Target network for the wallet (defaults to server's configured network)
     */
    network: z.ZodOptional<z.ZodEnum<["mainnet", "testnet", "devnet"]>>;
    /**
     * Human-readable wallet name (optional)
     */
    wallet_name: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    seed: string;
    network?: "mainnet" | "testnet" | "devnet" | undefined;
    wallet_name?: string | undefined;
}, {
    seed: string;
    network?: "mainnet" | "testnet" | "devnet" | undefined;
    wallet_name?: string | undefined;
}>;
/**
 * Input schema for wallet_sign tool
 *
 * Signs a transaction after policy evaluation.
 * This is the primary tool for executing transactions.
 */
declare const WalletSignInputSchema: z.ZodObject<{
    /**
     * Address of the wallet to sign with
     */
    wallet_address: z.ZodString;
    /**
     * Hex-encoded unsigned transaction blob
     */
    unsigned_tx: z.ZodString;
    /**
     * Context/reason for this transaction (for audit trail)
     * Describe why the agent is making this transaction
     * @example "Completing escrow for order #12345"
     */
    context: z.ZodOptional<z.ZodString>;
    /**
     * Whether to automatically fetch and apply the current sequence from ledger.
     * When true (default), queries account_info and updates Sequence, Fee, and
     * LastLedgerSequence in the transaction before signing.
     *
     * This prevents tefPAST_SEQ errors in multi-transaction workflows.
     *
     * Set to false only if you need to sign with a specific pre-set sequence
     * (e.g., for offline signing or ticket-based transactions).
     *
     * @default true
     */
    auto_sequence: z.ZodDefault<z.ZodOptional<z.ZodBoolean>>;
}, "strip", z.ZodTypeAny, {
    wallet_address: string;
    unsigned_tx: string;
    auto_sequence: boolean;
    context?: string | undefined;
}, {
    wallet_address: string;
    unsigned_tx: string;
    context?: string | undefined;
    auto_sequence?: boolean | undefined;
}>;
/**
 * Input schema for wallet_balance tool
 *
 * Queries the balance and status of a managed wallet.
 */
declare const WalletBalanceInputSchema: z.ZodObject<{
    /**
     * Address to query balance for
     */
    wallet_address: z.ZodString;
    /**
     * Wait time in milliseconds before querying (optional)
     * Useful for waiting after a transaction to ensure balance is updated.
     * @default 0
     * @example 5000 (wait 5 seconds)
     */
    wait_after_tx: z.ZodOptional<z.ZodNumber>;
}, "strip", z.ZodTypeAny, {
    wallet_address: string;
    wait_after_tx?: number | undefined;
}, {
    wallet_address: string;
    wait_after_tx?: number | undefined;
}>;
/**
 * Input schema for wallet_policy_check tool
 *
 * Dry-run policy evaluation without signing.
 * Use this to check if a transaction would be approved before building it.
 */
declare const WalletPolicyCheckInputSchema: z.ZodObject<{
    /**
     * Address of the wallet to check against
     */
    wallet_address: z.ZodString;
    /**
     * Hex-encoded unsigned transaction to evaluate
     */
    unsigned_tx: z.ZodString;
}, "strip", z.ZodTypeAny, {
    wallet_address: string;
    unsigned_tx: string;
}, {
    wallet_address: string;
    unsigned_tx: string;
}>;
/**
 * Input schema for wallet_rotate tool
 *
 * Rotates the agent's regular key for security.
 * The old key is disabled and a new one generated.
 */
declare const WalletRotateInputSchema: z.ZodObject<{
    /**
     * Address of the wallet to rotate key for
     */
    wallet_address: z.ZodString;
    /**
     * Reason for rotation (audit trail)
     * @example "Scheduled quarterly rotation"
     * @example "Suspected key compromise"
     */
    reason: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    wallet_address: string;
    reason?: string | undefined;
}, {
    wallet_address: string;
    reason?: string | undefined;
}>;
/**
 * Input schema for wallet_history tool
 *
 * Retrieves transaction history for audit and analysis.
 */
declare const WalletHistoryInputSchema: z.ZodObject<{
    /**
     * Address to get history for
     */
    wallet_address: z.ZodString;
    /**
     * Maximum number of transactions to return
     * @default 20
     */
    limit: z.ZodDefault<z.ZodOptional<z.ZodNumber>>;
    /**
     * Pagination marker from previous response
     */
    marker: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    wallet_address: string;
    limit: number;
    marker?: string | undefined;
}, {
    wallet_address: string;
    limit?: number | undefined;
    marker?: string | undefined;
}>;
/**
 * Input schema for wallet_list tool
 *
 * Lists all wallets managed by this MCP instance.
 */
declare const WalletListInputSchema: z.ZodObject<{
    /**
     * Filter by network (optional)
     */
    network: z.ZodOptional<z.ZodEnum<["mainnet", "testnet", "devnet"]>>;
}, "strip", z.ZodTypeAny, {
    network?: "mainnet" | "testnet" | "devnet" | undefined;
}, {
    network?: "mainnet" | "testnet" | "devnet" | undefined;
}>;
/**
 * Input schema for wallet_fund tool
 *
 * Funds a wallet from the testnet/devnet faucet.
 * Only available on test networks.
 */
declare const WalletFundInputSchema: z.ZodObject<{
    /**
     * Address to fund
     */
    wallet_address: z.ZodString;
    /**
     * Network (must be testnet or devnet)
     */
    network: z.ZodEnum<["testnet", "devnet"]>;
    /**
     * Wait for account to be confirmed on validated ledger (optional)
     * When true, retries account_info until account is queryable.
     * Recommended for automated workflows.
     * @default true
     */
    wait_for_confirmation: z.ZodDefault<z.ZodOptional<z.ZodBoolean>>;
}, "strip", z.ZodTypeAny, {
    network: "testnet" | "devnet";
    wallet_address: string;
    wait_for_confirmation: boolean;
}, {
    network: "testnet" | "devnet";
    wallet_address: string;
    wait_for_confirmation?: boolean | undefined;
}>;
/**
 * Input schema for policy_set tool
 *
 * Updates the policy for an existing wallet.
 * Requires human approval for policy changes.
 */
declare const PolicySetInputSchema: z.ZodObject<{
    /**
     * Wallet address to update policy for
     */
    wallet_address: z.ZodString;
    /**
     * New policy to apply
     */
    policy: z.ZodObject<{
        /**
         * Unique policy identifier
         * @example "conservative-v1"
         */
        policy_id: z.ZodString;
        /**
         * Policy version for tracking changes
         * Semantic versioning recommended
         */
        policy_version: z.ZodString;
        /**
         * Transaction and volume limits
         */
        limits: z.ZodObject<{
            /**
             * Maximum amount per single transaction in drops
             * @example "10000000" (10 XRP)
             */
            max_amount_per_tx_drops: z.ZodEffects<z.ZodString, string, string>;
            /**
             * Maximum daily transaction volume in drops
             * Resets at midnight UTC
             * @example "100000000" (100 XRP)
             */
            max_daily_volume_drops: z.ZodEffects<z.ZodString, string, string>;
            /**
             * Maximum transactions per hour (rolling window)
             */
            max_tx_per_hour: z.ZodNumber;
            /**
             * Maximum transactions per day (rolling window)
             */
            max_tx_per_day: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            max_amount_per_tx_drops: string;
            max_daily_volume_drops: string;
            max_tx_per_hour: number;
            max_tx_per_day: number;
        }, {
            max_amount_per_tx_drops: string;
            max_daily_volume_drops: string;
            max_tx_per_hour: number;
            max_tx_per_day: number;
        }>;
        /**
         * Destination address controls
         */
        destinations: z.ZodObject<{
            /**
             * Destination filtering mode
             */
            mode: z.ZodEnum<["allowlist", "blocklist", "open"]>;
            /**
             * Allowed destination addresses (used when mode='allowlist')
             */
            allowlist: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
            /**
             * Blocked destination addresses (always enforced regardless of mode)
             * Used for known scam/malicious addresses
             */
            blocklist: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
            /**
             * Whether to allow transactions to previously unseen addresses
             */
            allow_new_destinations: z.ZodBoolean;
            /**
             * Approval tier required for new destinations
             * Only used when allow_new_destinations is true
             */
            new_destination_tier: z.ZodOptional<z.ZodUnion<[z.ZodLiteral<2>, z.ZodLiteral<3>]>>;
        }, "strip", z.ZodTypeAny, {
            mode: "allowlist" | "blocklist" | "open";
            allow_new_destinations: boolean;
            allowlist?: string[] | undefined;
            blocklist?: string[] | undefined;
            new_destination_tier?: 3 | 2 | undefined;
        }, {
            mode: "allowlist" | "blocklist" | "open";
            allow_new_destinations: boolean;
            allowlist?: string[] | undefined;
            blocklist?: string[] | undefined;
            new_destination_tier?: 3 | 2 | undefined;
        }>;
        /**
         * Transaction type restrictions
         */
        transaction_types: z.ZodObject<{
            /**
             * Transaction types the agent can execute autonomously
             * @example ["Payment", "EscrowFinish", "EscrowCancel"]
             */
            allowed: z.ZodArray<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>, "many">;
            /**
             * Transaction types that require human approval (tier 2/3)
             * @example ["EscrowCreate", "TrustSet"]
             */
            require_approval: z.ZodOptional<z.ZodArray<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>, "many">>;
            /**
             * Transaction types that are never allowed (tier 4)
             * Typically account control operations
             * @example ["SetRegularKey", "SignerListSet", "AccountDelete"]
             */
            blocked: z.ZodOptional<z.ZodArray<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>, "many">>;
        }, "strip", z.ZodTypeAny, {
            allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
            require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
        }, {
            allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
            require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
        }>;
        /**
         * Time-based access controls (optional)
         */
        time_controls: z.ZodOptional<z.ZodObject<{
            /**
             * Active hours in UTC (24-hour format)
             * Transactions outside these hours are escalated to tier 2/3
             */
            active_hours_utc: z.ZodOptional<z.ZodObject<{
                start: z.ZodNumber;
                end: z.ZodNumber;
            }, "strip", z.ZodTypeAny, {
                start: number;
                end: number;
            }, {
                start: number;
                end: number;
            }>>;
            /**
             * Active days of the week
             * 0 = Sunday, 6 = Saturday
             */
            active_days: z.ZodOptional<z.ZodArray<z.ZodNumber, "many">>;
            /**
             * Timezone for interpreting active hours
             * @example "America/New_York"
             */
            timezone: z.ZodOptional<z.ZodString>;
        }, "strip", z.ZodTypeAny, {
            active_hours_utc?: {
                start: number;
                end: number;
            } | undefined;
            active_days?: number[] | undefined;
            timezone?: string | undefined;
        }, {
            active_hours_utc?: {
                start: number;
                end: number;
            } | undefined;
            active_days?: number[] | undefined;
            timezone?: string | undefined;
        }>>;
        /**
         * Escalation thresholds
         */
        escalation: z.ZodObject<{
            /**
             * Amount threshold for escalation to tier 2 (drops)
             * Transactions above this require delayed/human approval
             */
            amount_threshold_drops: z.ZodEffects<z.ZodString, string, string>;
            /**
             * Tier assigned to transactions with new destinations
             */
            new_destination: z.ZodUnion<[z.ZodLiteral<2>, z.ZodLiteral<3>]>;
            /**
             * Tier for account settings changes
             * Always tier 3 for safety
             */
            account_settings: z.ZodLiteral<3>;
            /**
             * Delay in seconds before tier 2 transactions auto-approve
             * Human can veto during this window
             */
            delay_seconds: z.ZodOptional<z.ZodNumber>;
        }, "strip", z.ZodTypeAny, {
            amount_threshold_drops: string;
            new_destination: 3 | 2;
            account_settings: 3;
            delay_seconds?: number | undefined;
        }, {
            amount_threshold_drops: string;
            new_destination: 3 | 2;
            account_settings: 3;
            delay_seconds?: number | undefined;
        }>;
        /**
         * Notification settings (optional)
         */
        notifications: z.ZodOptional<z.ZodObject<{
            /**
             * Webhook URL for notifications
             * Must be HTTPS for production
             */
            webhook_url: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
            /**
             * Events that trigger notifications
             */
            notify_on: z.ZodOptional<z.ZodArray<z.ZodEnum<["tier2", "tier3", "rejection", "all"]>, "many">>;
        }, "strip", z.ZodTypeAny, {
            webhook_url?: string | undefined;
            notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
        }, {
            webhook_url?: string | undefined;
            notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
        }>>;
    }, "strip", z.ZodTypeAny, {
        policy_id: string;
        policy_version: string;
        limits: {
            max_amount_per_tx_drops: string;
            max_daily_volume_drops: string;
            max_tx_per_hour: number;
            max_tx_per_day: number;
        };
        destinations: {
            mode: "allowlist" | "blocklist" | "open";
            allow_new_destinations: boolean;
            allowlist?: string[] | undefined;
            blocklist?: string[] | undefined;
            new_destination_tier?: 3 | 2 | undefined;
        };
        transaction_types: {
            allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
            require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
        };
        escalation: {
            amount_threshold_drops: string;
            new_destination: 3 | 2;
            account_settings: 3;
            delay_seconds?: number | undefined;
        };
        time_controls?: {
            active_hours_utc?: {
                start: number;
                end: number;
            } | undefined;
            active_days?: number[] | undefined;
            timezone?: string | undefined;
        } | undefined;
        notifications?: {
            webhook_url?: string | undefined;
            notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
        } | undefined;
    }, {
        policy_id: string;
        policy_version: string;
        limits: {
            max_amount_per_tx_drops: string;
            max_daily_volume_drops: string;
            max_tx_per_hour: number;
            max_tx_per_day: number;
        };
        destinations: {
            mode: "allowlist" | "blocklist" | "open";
            allow_new_destinations: boolean;
            allowlist?: string[] | undefined;
            blocklist?: string[] | undefined;
            new_destination_tier?: 3 | 2 | undefined;
        };
        transaction_types: {
            allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
            require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
        };
        escalation: {
            amount_threshold_drops: string;
            new_destination: 3 | 2;
            account_settings: 3;
            delay_seconds?: number | undefined;
        };
        time_controls?: {
            active_hours_utc?: {
                start: number;
                end: number;
            } | undefined;
            active_days?: number[] | undefined;
            timezone?: string | undefined;
        } | undefined;
        notifications?: {
            webhook_url?: string | undefined;
            notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
        } | undefined;
    }>;
    /**
     * Reason for policy change (audit trail)
     */
    reason: z.ZodString;
}, "strip", z.ZodTypeAny, {
    policy: {
        policy_id: string;
        policy_version: string;
        limits: {
            max_amount_per_tx_drops: string;
            max_daily_volume_drops: string;
            max_tx_per_hour: number;
            max_tx_per_day: number;
        };
        destinations: {
            mode: "allowlist" | "blocklist" | "open";
            allow_new_destinations: boolean;
            allowlist?: string[] | undefined;
            blocklist?: string[] | undefined;
            new_destination_tier?: 3 | 2 | undefined;
        };
        transaction_types: {
            allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
            require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
        };
        escalation: {
            amount_threshold_drops: string;
            new_destination: 3 | 2;
            account_settings: 3;
            delay_seconds?: number | undefined;
        };
        time_controls?: {
            active_hours_utc?: {
                start: number;
                end: number;
            } | undefined;
            active_days?: number[] | undefined;
            timezone?: string | undefined;
        } | undefined;
        notifications?: {
            webhook_url?: string | undefined;
            notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
        } | undefined;
    };
    wallet_address: string;
    reason: string;
}, {
    policy: {
        policy_id: string;
        policy_version: string;
        limits: {
            max_amount_per_tx_drops: string;
            max_daily_volume_drops: string;
            max_tx_per_hour: number;
            max_tx_per_day: number;
        };
        destinations: {
            mode: "allowlist" | "blocklist" | "open";
            allow_new_destinations: boolean;
            allowlist?: string[] | undefined;
            blocklist?: string[] | undefined;
            new_destination_tier?: 3 | 2 | undefined;
        };
        transaction_types: {
            allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
            require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
        };
        escalation: {
            amount_threshold_drops: string;
            new_destination: 3 | 2;
            account_settings: 3;
            delay_seconds?: number | undefined;
        };
        time_controls?: {
            active_hours_utc?: {
                start: number;
                end: number;
            } | undefined;
            active_days?: number[] | undefined;
            timezone?: string | undefined;
        } | undefined;
        notifications?: {
            webhook_url?: string | undefined;
            notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
        } | undefined;
    };
    wallet_address: string;
    reason: string;
}>;
/**
 * Input schema for tx_submit tool
 *
 * Submits a signed transaction to the XRPL network.
 */
declare const TxSubmitInputSchema: z.ZodObject<{
    /**
     * Hex-encoded signed transaction blob
     */
    signed_tx: z.ZodString;
    /**
     * Network to submit to
     */
    network: z.ZodEnum<["mainnet", "testnet", "devnet"]>;
    /**
     * Whether to wait for validation (optional)
     * @default true
     */
    wait_for_validation: z.ZodDefault<z.ZodOptional<z.ZodBoolean>>;
}, "strip", z.ZodTypeAny, {
    network: "mainnet" | "testnet" | "devnet";
    signed_tx: string;
    wait_for_validation: boolean;
}, {
    network: "mainnet" | "testnet" | "devnet";
    signed_tx: string;
    wait_for_validation?: boolean | undefined;
}>;
/**
 * Input schema for tx_decode tool
 *
 * Decodes a transaction blob for inspection.
 */
declare const TxDecodeInputSchema: z.ZodObject<{
    /**
     * Transaction blob to decode (signed or unsigned)
     */
    tx_blob: z.ZodString;
}, "strip", z.ZodTypeAny, {
    tx_blob: string;
}, {
    tx_blob: string;
}>;
/**
 * Input schema for network_config tool
 *
 * Configures network connection settings.
 */
declare const NetworkConfigInputSchema: z.ZodObject<{
    /**
     * Network to configure
     */
    network: z.ZodEnum<["mainnet", "testnet", "devnet"]>;
    /**
     * Primary WebSocket URL
     */
    primary_url: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    /**
     * Fallback WebSocket URLs
     */
    fallback_urls: z.ZodOptional<z.ZodArray<z.ZodEffects<z.ZodString, string, string>, "many">>;
    /**
     * Connection timeout in milliseconds
     */
    connection_timeout_ms: z.ZodOptional<z.ZodNumber>;
}, "strip", z.ZodTypeAny, {
    network: "mainnet" | "testnet" | "devnet";
    primary_url?: string | undefined;
    fallback_urls?: string[] | undefined;
    connection_timeout_ms?: number | undefined;
}, {
    network: "mainnet" | "testnet" | "devnet";
    primary_url?: string | undefined;
    fallback_urls?: string[] | undefined;
    connection_timeout_ms?: number | undefined;
}>;
/**
 * Signer entry for multi-signature wallets
 */
declare const SignerEntrySchema: z.ZodObject<{
    /**
     * Signer's XRPL address
     */
    account: z.ZodString;
    /**
     * Signer's weight (contributes to quorum)
     */
    weight: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    account: string;
    weight: number;
}, {
    account: string;
    weight: number;
}>;
/**
 * Output schema for wallet_create tool
 */
declare const WalletCreateOutputSchema: z.ZodObject<{
    /**
     * New wallet's XRPL address
     */
    address: z.ZodString;
    /**
     * Agent's signing key (public only)
     */
    regular_key_public: z.ZodEffects<z.ZodString, string, string>;
    /**
     * Encrypted master key backup for recovery
     * Store this securely - required for disaster recovery
     */
    master_key_backup: z.ZodString;
    /**
     * Policy ID applied to this wallet
     */
    policy_id: z.ZodString;
    /**
     * Internal wallet identifier
     */
    wallet_id: z.ZodString;
    /**
     * Network the wallet was created on
     */
    network: z.ZodEnum<["mainnet", "testnet", "devnet"]>;
    /**
     * Creation timestamp
     */
    created_at: z.ZodString;
}, "strip", z.ZodTypeAny, {
    network: "mainnet" | "testnet" | "devnet";
    policy_id: string;
    address: string;
    regular_key_public: string;
    master_key_backup: string;
    wallet_id: string;
    created_at: string;
}, {
    network: "mainnet" | "testnet" | "devnet";
    policy_id: string;
    address: string;
    regular_key_public: string;
    master_key_backup: string;
    wallet_id: string;
    created_at: string;
}>;
/**
 * Remaining limits after transaction
 */
declare const RemainingLimitsSchema: z.ZodObject<{
    /**
     * Remaining daily volume in drops
     */
    daily_remaining_drops: z.ZodEffects<z.ZodString, string, string>;
    /**
     * Remaining transactions this hour
     */
    hourly_tx_remaining: z.ZodNumber;
    /**
     * Remaining transactions today
     */
    daily_tx_remaining: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    daily_remaining_drops: string;
    hourly_tx_remaining: number;
    daily_tx_remaining: number;
}, {
    daily_remaining_drops: string;
    hourly_tx_remaining: number;
    daily_tx_remaining: number;
}>;
/**
 * Policy violation details
 */
declare const PolicyViolationSchema: z.ZodObject<{
    /**
     * Which rule was violated
     */
    rule: z.ZodString;
    /**
     * The limit that was exceeded
     */
    limit: z.ZodString;
    /**
     * The actual value that violated the limit
     */
    actual: z.ZodString;
}, "strip", z.ZodTypeAny, {
    limit: string;
    rule: string;
    actual: string;
}, {
    limit: string;
    rule: string;
    actual: string;
}>;
/**
 * Output schema for wallet_sign tool - approved transaction
 */
declare const WalletSignApprovedOutputSchema: z.ZodObject<{
    /**
     * Transaction status
     */
    status: z.ZodLiteral<"approved">;
    /**
     * Hex-encoded signed transaction blob
     */
    signed_tx: z.ZodString;
    /**
     * Transaction hash
     */
    tx_hash: z.ZodEffects<z.ZodString, string, string>;
    /**
     * Policy tier that approved this transaction
     */
    policy_tier: z.ZodUnion<[z.ZodLiteral<1>, z.ZodLiteral<2>, z.ZodLiteral<3>, z.ZodLiteral<4>]>;
    /**
     * Remaining limits after this transaction
     */
    limits_after: z.ZodObject<{
        /**
         * Remaining daily volume in drops
         */
        daily_remaining_drops: z.ZodEffects<z.ZodString, string, string>;
        /**
         * Remaining transactions this hour
         */
        hourly_tx_remaining: z.ZodNumber;
        /**
         * Remaining transactions today
         */
        daily_tx_remaining: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        daily_remaining_drops: string;
        hourly_tx_remaining: number;
        daily_tx_remaining: number;
    }, {
        daily_remaining_drops: string;
        hourly_tx_remaining: number;
        daily_tx_remaining: number;
    }>;
    /**
     * Timestamp when signed
     */
    signed_at: z.ZodString;
}, "strip", z.ZodTypeAny, {
    status: "approved";
    signed_tx: string;
    tx_hash: string;
    policy_tier: 3 | 1 | 2 | 4;
    limits_after: {
        daily_remaining_drops: string;
        hourly_tx_remaining: number;
        daily_tx_remaining: number;
    };
    signed_at: string;
}, {
    status: "approved";
    signed_tx: string;
    tx_hash: string;
    policy_tier: 3 | 1 | 2 | 4;
    limits_after: {
        daily_remaining_drops: string;
        hourly_tx_remaining: number;
        daily_tx_remaining: number;
    };
    signed_at: string;
}>;
/**
 * Output schema for wallet_sign tool - pending approval
 */
declare const WalletSignPendingOutputSchema: z.ZodObject<{
    /**
     * Transaction status
     */
    status: z.ZodLiteral<"pending_approval">;
    /**
     * Approval request ID for tracking
     */
    approval_id: z.ZodString;
    /**
     * Reason approval is required
     */
    reason: z.ZodEnum<["exceeds_autonomous_limit", "new_destination", "restricted_tx_type", "outside_active_hours", "requires_cosign"]>;
    /**
     * When this approval request expires
     */
    expires_at: z.ZodString;
    /**
     * URL for human approval (if configured)
     */
    approval_url: z.ZodOptional<z.ZodString>;
    /**
     * Policy tier required
     */
    policy_tier: z.ZodUnion<[z.ZodLiteral<1>, z.ZodLiteral<2>, z.ZodLiteral<3>, z.ZodLiteral<4>]>;
}, "strip", z.ZodTypeAny, {
    status: "pending_approval";
    reason: "new_destination" | "exceeds_autonomous_limit" | "restricted_tx_type" | "outside_active_hours" | "requires_cosign";
    policy_tier: 3 | 1 | 2 | 4;
    approval_id: string;
    expires_at: string;
    approval_url?: string | undefined;
}, {
    status: "pending_approval";
    reason: "new_destination" | "exceeds_autonomous_limit" | "restricted_tx_type" | "outside_active_hours" | "requires_cosign";
    policy_tier: 3 | 1 | 2 | 4;
    approval_id: string;
    expires_at: string;
    approval_url?: string | undefined;
}>;
/**
 * Output schema for wallet_sign tool - rejected
 */
declare const WalletSignRejectedOutputSchema: z.ZodObject<{
    /**
     * Transaction status
     */
    status: z.ZodLiteral<"rejected">;
    /**
     * Human-readable rejection reason
     */
    reason: z.ZodString;
    /**
     * Specific policy violation (if applicable)
     */
    policy_violation: z.ZodOptional<z.ZodObject<{
        /**
         * Which rule was violated
         */
        rule: z.ZodString;
        /**
         * The limit that was exceeded
         */
        limit: z.ZodString;
        /**
         * The actual value that violated the limit
         */
        actual: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        limit: string;
        rule: string;
        actual: string;
    }, {
        limit: string;
        rule: string;
        actual: string;
    }>>;
    /**
     * Policy tier that would be required
     */
    policy_tier: z.ZodLiteral<4>;
}, "strip", z.ZodTypeAny, {
    status: "rejected";
    reason: string;
    policy_tier: 4;
    policy_violation?: {
        limit: string;
        rule: string;
        actual: string;
    } | undefined;
}, {
    status: "rejected";
    reason: string;
    policy_tier: 4;
    policy_violation?: {
        limit: string;
        rule: string;
        actual: string;
    } | undefined;
}>;
/**
 * Combined output schema for wallet_sign tool
 */
declare const WalletSignOutputSchema: z.ZodDiscriminatedUnion<"status", [z.ZodObject<{
    /**
     * Transaction status
     */
    status: z.ZodLiteral<"approved">;
    /**
     * Hex-encoded signed transaction blob
     */
    signed_tx: z.ZodString;
    /**
     * Transaction hash
     */
    tx_hash: z.ZodEffects<z.ZodString, string, string>;
    /**
     * Policy tier that approved this transaction
     */
    policy_tier: z.ZodUnion<[z.ZodLiteral<1>, z.ZodLiteral<2>, z.ZodLiteral<3>, z.ZodLiteral<4>]>;
    /**
     * Remaining limits after this transaction
     */
    limits_after: z.ZodObject<{
        /**
         * Remaining daily volume in drops
         */
        daily_remaining_drops: z.ZodEffects<z.ZodString, string, string>;
        /**
         * Remaining transactions this hour
         */
        hourly_tx_remaining: z.ZodNumber;
        /**
         * Remaining transactions today
         */
        daily_tx_remaining: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        daily_remaining_drops: string;
        hourly_tx_remaining: number;
        daily_tx_remaining: number;
    }, {
        daily_remaining_drops: string;
        hourly_tx_remaining: number;
        daily_tx_remaining: number;
    }>;
    /**
     * Timestamp when signed
     */
    signed_at: z.ZodString;
}, "strip", z.ZodTypeAny, {
    status: "approved";
    signed_tx: string;
    tx_hash: string;
    policy_tier: 3 | 1 | 2 | 4;
    limits_after: {
        daily_remaining_drops: string;
        hourly_tx_remaining: number;
        daily_tx_remaining: number;
    };
    signed_at: string;
}, {
    status: "approved";
    signed_tx: string;
    tx_hash: string;
    policy_tier: 3 | 1 | 2 | 4;
    limits_after: {
        daily_remaining_drops: string;
        hourly_tx_remaining: number;
        daily_tx_remaining: number;
    };
    signed_at: string;
}>, z.ZodObject<{
    /**
     * Transaction status
     */
    status: z.ZodLiteral<"pending_approval">;
    /**
     * Approval request ID for tracking
     */
    approval_id: z.ZodString;
    /**
     * Reason approval is required
     */
    reason: z.ZodEnum<["exceeds_autonomous_limit", "new_destination", "restricted_tx_type", "outside_active_hours", "requires_cosign"]>;
    /**
     * When this approval request expires
     */
    expires_at: z.ZodString;
    /**
     * URL for human approval (if configured)
     */
    approval_url: z.ZodOptional<z.ZodString>;
    /**
     * Policy tier required
     */
    policy_tier: z.ZodUnion<[z.ZodLiteral<1>, z.ZodLiteral<2>, z.ZodLiteral<3>, z.ZodLiteral<4>]>;
}, "strip", z.ZodTypeAny, {
    status: "pending_approval";
    reason: "new_destination" | "exceeds_autonomous_limit" | "restricted_tx_type" | "outside_active_hours" | "requires_cosign";
    policy_tier: 3 | 1 | 2 | 4;
    approval_id: string;
    expires_at: string;
    approval_url?: string | undefined;
}, {
    status: "pending_approval";
    reason: "new_destination" | "exceeds_autonomous_limit" | "restricted_tx_type" | "outside_active_hours" | "requires_cosign";
    policy_tier: 3 | 1 | 2 | 4;
    approval_id: string;
    expires_at: string;
    approval_url?: string | undefined;
}>, z.ZodObject<{
    /**
     * Transaction status
     */
    status: z.ZodLiteral<"rejected">;
    /**
     * Human-readable rejection reason
     */
    reason: z.ZodString;
    /**
     * Specific policy violation (if applicable)
     */
    policy_violation: z.ZodOptional<z.ZodObject<{
        /**
         * Which rule was violated
         */
        rule: z.ZodString;
        /**
         * The limit that was exceeded
         */
        limit: z.ZodString;
        /**
         * The actual value that violated the limit
         */
        actual: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        limit: string;
        rule: string;
        actual: string;
    }, {
        limit: string;
        rule: string;
        actual: string;
    }>>;
    /**
     * Policy tier that would be required
     */
    policy_tier: z.ZodLiteral<4>;
}, "strip", z.ZodTypeAny, {
    status: "rejected";
    reason: string;
    policy_tier: 4;
    policy_violation?: {
        limit: string;
        rule: string;
        actual: string;
    } | undefined;
}, {
    status: "rejected";
    reason: string;
    policy_tier: 4;
    policy_violation?: {
        limit: string;
        rule: string;
        actual: string;
    } | undefined;
}>]>;
/**
 * Output schema for wallet_balance tool
 */
declare const WalletBalanceOutputSchema: z.ZodObject<{
    /**
     * Wallet address
     */
    address: z.ZodString;
    /**
     * Total balance in drops
     */
    balance_drops: z.ZodEffects<z.ZodString, string, string>;
    /**
     * Total balance in XRP (formatted string)
     */
    balance_xrp: z.ZodString;
    /**
     * Reserve requirement in drops
     */
    reserve_drops: z.ZodEffects<z.ZodString, string, string>;
    /**
     * Available balance (total - reserve) in drops
     */
    available_drops: z.ZodEffects<z.ZodString, string, string>;
    /**
     * Current account sequence number
     */
    sequence: z.ZodNumber;
    /**
     * Whether a regular key is configured
     */
    regular_key_set: z.ZodBoolean;
    /**
     * Multi-signature signer list (if configured)
     */
    signer_list: z.ZodNullable<z.ZodArray<z.ZodObject<{
        /**
         * Signer's XRPL address
         */
        account: z.ZodString;
        /**
         * Signer's weight (contributes to quorum)
         */
        weight: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        account: string;
        weight: number;
    }, {
        account: string;
        weight: number;
    }>, "many">>;
    /**
     * Applied policy ID
     */
    policy_id: z.ZodString;
    /**
     * Network
     */
    network: z.ZodEnum<["mainnet", "testnet", "devnet"]>;
    /**
     * Ledger index from which balance was queried
     * Use this for consistency verification across queries.
     */
    ledger_index: z.ZodNumber;
    /**
     * When balance was queried
     */
    queried_at: z.ZodString;
}, "strip", z.ZodTypeAny, {
    network: "mainnet" | "testnet" | "devnet";
    policy_id: string;
    address: string;
    balance_drops: string;
    balance_xrp: string;
    reserve_drops: string;
    available_drops: string;
    sequence: number;
    regular_key_set: boolean;
    signer_list: {
        account: string;
        weight: number;
    }[] | null;
    ledger_index: number;
    queried_at: string;
}, {
    network: "mainnet" | "testnet" | "devnet";
    policy_id: string;
    address: string;
    balance_drops: string;
    balance_xrp: string;
    reserve_drops: string;
    available_drops: string;
    sequence: number;
    regular_key_set: boolean;
    signer_list: {
        account: string;
        weight: number;
    }[] | null;
    ledger_index: number;
    queried_at: string;
}>;
/**
 * Current limit status
 */
declare const LimitStatusSchema: z.ZodObject<{
    /**
     * Daily volume used in drops
     */
    daily_volume_used_drops: z.ZodEffects<z.ZodString, string, string>;
    /**
     * Daily volume limit in drops
     */
    daily_volume_limit_drops: z.ZodEffects<z.ZodString, string, string>;
    /**
     * Transactions this hour
     */
    hourly_tx_used: z.ZodNumber;
    /**
     * Hourly transaction limit
     */
    hourly_tx_limit: z.ZodNumber;
    /**
     * Transactions today
     */
    daily_tx_used: z.ZodNumber;
    /**
     * Daily transaction limit
     */
    daily_tx_limit: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    daily_volume_used_drops: string;
    daily_volume_limit_drops: string;
    hourly_tx_used: number;
    hourly_tx_limit: number;
    daily_tx_used: number;
    daily_tx_limit: number;
}, {
    daily_volume_used_drops: string;
    daily_volume_limit_drops: string;
    hourly_tx_used: number;
    hourly_tx_limit: number;
    daily_tx_used: number;
    daily_tx_limit: number;
}>;
/**
 * Output schema for wallet_policy_check tool
 */
declare const WalletPolicyCheckOutputSchema: z.ZodObject<{
    /**
     * Whether transaction would be approved
     */
    would_approve: z.ZodBoolean;
    /**
     * Tier that would be assigned
     */
    tier: z.ZodUnion<[z.ZodLiteral<1>, z.ZodLiteral<2>, z.ZodLiteral<3>, z.ZodLiteral<4>]>;
    /**
     * Warnings (non-blocking issues)
     */
    warnings: z.ZodArray<z.ZodString, "many">;
    /**
     * Violations (blocking issues)
     */
    violations: z.ZodArray<z.ZodString, "many">;
    /**
     * Current limit status
     */
    limits: z.ZodObject<{
        /**
         * Daily volume used in drops
         */
        daily_volume_used_drops: z.ZodEffects<z.ZodString, string, string>;
        /**
         * Daily volume limit in drops
         */
        daily_volume_limit_drops: z.ZodEffects<z.ZodString, string, string>;
        /**
         * Transactions this hour
         */
        hourly_tx_used: z.ZodNumber;
        /**
         * Hourly transaction limit
         */
        hourly_tx_limit: z.ZodNumber;
        /**
         * Transactions today
         */
        daily_tx_used: z.ZodNumber;
        /**
         * Daily transaction limit
         */
        daily_tx_limit: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        daily_volume_used_drops: string;
        daily_volume_limit_drops: string;
        hourly_tx_used: number;
        hourly_tx_limit: number;
        daily_tx_used: number;
        daily_tx_limit: number;
    }, {
        daily_volume_used_drops: string;
        daily_volume_limit_drops: string;
        hourly_tx_used: number;
        hourly_tx_limit: number;
        daily_tx_used: number;
        daily_tx_limit: number;
    }>;
    /**
     * Transaction details extracted from blob
     */
    transaction_details: z.ZodOptional<z.ZodObject<{
        type: z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>;
        destination: z.ZodOptional<z.ZodString>;
        amount_drops: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    }, "strip", z.ZodTypeAny, {
        type: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge";
        destination?: string | undefined;
        amount_drops?: string | undefined;
    }, {
        type: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge";
        destination?: string | undefined;
        amount_drops?: string | undefined;
    }>>;
}, "strip", z.ZodTypeAny, {
    limits: {
        daily_volume_used_drops: string;
        daily_volume_limit_drops: string;
        hourly_tx_used: number;
        hourly_tx_limit: number;
        daily_tx_used: number;
        daily_tx_limit: number;
    };
    would_approve: boolean;
    tier: 3 | 1 | 2 | 4;
    warnings: string[];
    violations: string[];
    transaction_details?: {
        type: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge";
        destination?: string | undefined;
        amount_drops?: string | undefined;
    } | undefined;
}, {
    limits: {
        daily_volume_used_drops: string;
        daily_volume_limit_drops: string;
        hourly_tx_used: number;
        hourly_tx_limit: number;
        daily_tx_used: number;
        daily_tx_limit: number;
    };
    would_approve: boolean;
    tier: 3 | 1 | 2 | 4;
    warnings: string[];
    violations: string[];
    transaction_details?: {
        type: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge";
        destination?: string | undefined;
        amount_drops?: string | undefined;
    } | undefined;
}>;
/**
 * Output schema for wallet_rotate tool
 */
declare const WalletRotateOutputSchema: z.ZodObject<{
    /**
     * Rotation status
     */
    status: z.ZodLiteral<"rotated">;
    /**
     * New regular key (public)
     */
    new_regular_key_public: z.ZodEffects<z.ZodString, string, string>;
    /**
     * Whether old key was disabled on-chain
     */
    old_key_disabled: z.ZodBoolean;
    /**
     * Transaction hash for SetRegularKey
     */
    rotation_tx_hash: z.ZodEffects<z.ZodString, string, string>;
    /**
     * Rotation timestamp
     */
    rotated_at: z.ZodString;
}, "strip", z.ZodTypeAny, {
    status: "rotated";
    new_regular_key_public: string;
    old_key_disabled: boolean;
    rotation_tx_hash: string;
    rotated_at: string;
}, {
    status: "rotated";
    new_regular_key_public: string;
    old_key_disabled: boolean;
    rotation_tx_hash: string;
    rotated_at: string;
}>;
/**
 * Transaction history entry
 */
declare const TransactionHistoryEntrySchema: z.ZodObject<{
    /**
     * Transaction hash
     */
    hash: z.ZodEffects<z.ZodString, string, string>;
    /**
     * Transaction type
     */
    type: z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>;
    /**
     * Amount in drops (for Payment-like transactions)
     */
    amount_drops: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    /**
     * Destination address (for Payment-like transactions)
     */
    destination: z.ZodOptional<z.ZodString>;
    /**
     * Timestamp when executed
     */
    timestamp: z.ZodString;
    /**
     * Policy tier that approved this
     */
    policy_tier: z.ZodUnion<[z.ZodLiteral<1>, z.ZodLiteral<2>, z.ZodLiteral<3>, z.ZodLiteral<4>]>;
    /**
     * Context provided when signed
     */
    context: z.ZodOptional<z.ZodString>;
    /**
     * Ledger index where validated
     */
    ledger_index: z.ZodNumber;
    /**
     * Whether transaction succeeded
     */
    success: z.ZodBoolean;
}, "strip", z.ZodTypeAny, {
    type: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge";
    policy_tier: 3 | 1 | 2 | 4;
    ledger_index: number;
    hash: string;
    timestamp: string;
    success: boolean;
    context?: string | undefined;
    destination?: string | undefined;
    amount_drops?: string | undefined;
}, {
    type: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge";
    policy_tier: 3 | 1 | 2 | 4;
    ledger_index: number;
    hash: string;
    timestamp: string;
    success: boolean;
    context?: string | undefined;
    destination?: string | undefined;
    amount_drops?: string | undefined;
}>;
/**
 * Output schema for wallet_history tool
 */
declare const WalletHistoryOutputSchema: z.ZodObject<{
    /**
     * Wallet address
     */
    address: z.ZodString;
    /**
     * Transaction history entries
     */
    transactions: z.ZodArray<z.ZodObject<{
        /**
         * Transaction hash
         */
        hash: z.ZodEffects<z.ZodString, string, string>;
        /**
         * Transaction type
         */
        type: z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>;
        /**
         * Amount in drops (for Payment-like transactions)
         */
        amount_drops: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
        /**
         * Destination address (for Payment-like transactions)
         */
        destination: z.ZodOptional<z.ZodString>;
        /**
         * Timestamp when executed
         */
        timestamp: z.ZodString;
        /**
         * Policy tier that approved this
         */
        policy_tier: z.ZodUnion<[z.ZodLiteral<1>, z.ZodLiteral<2>, z.ZodLiteral<3>, z.ZodLiteral<4>]>;
        /**
         * Context provided when signed
         */
        context: z.ZodOptional<z.ZodString>;
        /**
         * Ledger index where validated
         */
        ledger_index: z.ZodNumber;
        /**
         * Whether transaction succeeded
         */
        success: z.ZodBoolean;
    }, "strip", z.ZodTypeAny, {
        type: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge";
        policy_tier: 3 | 1 | 2 | 4;
        ledger_index: number;
        hash: string;
        timestamp: string;
        success: boolean;
        context?: string | undefined;
        destination?: string | undefined;
        amount_drops?: string | undefined;
    }, {
        type: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge";
        policy_tier: 3 | 1 | 2 | 4;
        ledger_index: number;
        hash: string;
        timestamp: string;
        success: boolean;
        context?: string | undefined;
        destination?: string | undefined;
        amount_drops?: string | undefined;
    }>, "many">;
    /**
     * Pagination marker for next page
     */
    marker: z.ZodOptional<z.ZodString>;
    /**
     * Whether there are more results
     */
    has_more: z.ZodBoolean;
}, "strip", z.ZodTypeAny, {
    address: string;
    transactions: {
        type: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge";
        policy_tier: 3 | 1 | 2 | 4;
        ledger_index: number;
        hash: string;
        timestamp: string;
        success: boolean;
        context?: string | undefined;
        destination?: string | undefined;
        amount_drops?: string | undefined;
    }[];
    has_more: boolean;
    marker?: string | undefined;
}, {
    address: string;
    transactions: {
        type: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge";
        policy_tier: 3 | 1 | 2 | 4;
        ledger_index: number;
        hash: string;
        timestamp: string;
        success: boolean;
        context?: string | undefined;
        destination?: string | undefined;
        amount_drops?: string | undefined;
    }[];
    has_more: boolean;
    marker?: string | undefined;
}>;
/**
 * Wallet list entry
 */
declare const WalletListEntrySchema: z.ZodObject<{
    /**
     * Internal wallet ID
     */
    wallet_id: z.ZodString;
    /**
     * XRPL address
     */
    address: z.ZodString;
    /**
     * Human-readable name
     */
    name: z.ZodOptional<z.ZodString>;
    /**
     * Network
     */
    network: z.ZodEnum<["mainnet", "testnet", "devnet"]>;
    /**
     * Applied policy ID
     */
    policy_id: z.ZodString;
    /**
     * Creation timestamp
     */
    created_at: z.ZodString;
}, "strip", z.ZodTypeAny, {
    network: "mainnet" | "testnet" | "devnet";
    policy_id: string;
    address: string;
    wallet_id: string;
    created_at: string;
    name?: string | undefined;
}, {
    network: "mainnet" | "testnet" | "devnet";
    policy_id: string;
    address: string;
    wallet_id: string;
    created_at: string;
    name?: string | undefined;
}>;
/**
 * Output schema for wallet_list tool
 */
declare const WalletListOutputSchema: z.ZodObject<{
    /**
     * List of managed wallets
     */
    wallets: z.ZodArray<z.ZodObject<{
        /**
         * Internal wallet ID
         */
        wallet_id: z.ZodString;
        /**
         * XRPL address
         */
        address: z.ZodString;
        /**
         * Human-readable name
         */
        name: z.ZodOptional<z.ZodString>;
        /**
         * Network
         */
        network: z.ZodEnum<["mainnet", "testnet", "devnet"]>;
        /**
         * Applied policy ID
         */
        policy_id: z.ZodString;
        /**
         * Creation timestamp
         */
        created_at: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        network: "mainnet" | "testnet" | "devnet";
        policy_id: string;
        address: string;
        wallet_id: string;
        created_at: string;
        name?: string | undefined;
    }, {
        network: "mainnet" | "testnet" | "devnet";
        policy_id: string;
        address: string;
        wallet_id: string;
        created_at: string;
        name?: string | undefined;
    }>, "many">;
    /**
     * Total count
     */
    total: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    wallets: {
        network: "mainnet" | "testnet" | "devnet";
        policy_id: string;
        address: string;
        wallet_id: string;
        created_at: string;
        name?: string | undefined;
    }[];
    total: number;
}, {
    wallets: {
        network: "mainnet" | "testnet" | "devnet";
        policy_id: string;
        address: string;
        wallet_id: string;
        created_at: string;
        name?: string | undefined;
    }[];
    total: number;
}>;
/**
 * Output schema for wallet_fund tool
 */
declare const WalletFundOutputSchema: z.ZodObject<{
    /**
     * Funding status
     */
    status: z.ZodEnum<["funded", "pending", "failed"]>;
    /**
     * Amount funded in drops
     */
    amount_drops: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    /**
     * Faucet transaction hash
     */
    tx_hash: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    /**
     * Initial balance after funding in drops
     * Use this for verification in tests instead of hardcoded values.
     */
    initial_balance_drops: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    /**
     * New balance after funding (alias for initial_balance_drops)
     * @deprecated Use initial_balance_drops
     */
    new_balance_drops: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    /**
     * Whether the account is ready for queries on validated ledger
     * True means account_info will succeed.
     */
    account_ready: z.ZodOptional<z.ZodBoolean>;
    /**
     * Ledger index where account was confirmed
     */
    ledger_index: z.ZodOptional<z.ZodNumber>;
    /**
     * Error message if failed
     */
    error: z.ZodOptional<z.ZodString>;
    /**
     * Informational message
     */
    message: z.ZodOptional<z.ZodString>;
    /**
     * Faucet URL used (for debugging)
     */
    faucet_url: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    status: "funded" | "pending" | "failed";
    message?: string | undefined;
    tx_hash?: string | undefined;
    ledger_index?: number | undefined;
    amount_drops?: string | undefined;
    initial_balance_drops?: string | undefined;
    new_balance_drops?: string | undefined;
    account_ready?: boolean | undefined;
    error?: string | undefined;
    faucet_url?: string | undefined;
}, {
    status: "funded" | "pending" | "failed";
    message?: string | undefined;
    tx_hash?: string | undefined;
    ledger_index?: number | undefined;
    amount_drops?: string | undefined;
    initial_balance_drops?: string | undefined;
    new_balance_drops?: string | undefined;
    account_ready?: boolean | undefined;
    error?: string | undefined;
    faucet_url?: string | undefined;
}>;
/**
 * Output schema for policy_set tool
 */
declare const PolicySetOutputSchema: z.ZodObject<{
    /**
     * Update status
     */
    status: z.ZodEnum<["applied", "pending_approval"]>;
    /**
     * Previous policy ID
     */
    previous_policy_id: z.ZodString;
    /**
     * New policy ID
     */
    new_policy_id: z.ZodString;
    /**
     * When applied (if status is 'applied')
     */
    applied_at: z.ZodOptional<z.ZodString>;
    /**
     * Approval ID (if status is 'pending_approval')
     */
    approval_id: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    status: "pending_approval" | "applied";
    previous_policy_id: string;
    new_policy_id: string;
    approval_id?: string | undefined;
    applied_at?: string | undefined;
}, {
    status: "pending_approval" | "applied";
    previous_policy_id: string;
    new_policy_id: string;
    approval_id?: string | undefined;
    applied_at?: string | undefined;
}>;
/**
 * Transaction result from XRPL
 */
declare const TransactionResultSchema: z.ZodObject<{
    /**
     * Result code from XRPL
     */
    result_code: z.ZodString;
    /**
     * Human-readable result message
     */
    result_message: z.ZodString;
    /**
     * Whether transaction succeeded
     */
    success: z.ZodBoolean;
}, "strip", z.ZodTypeAny, {
    success: boolean;
    result_code: string;
    result_message: string;
}, {
    success: boolean;
    result_code: string;
    result_message: string;
}>;
/**
 * Escrow reference for tracking escrow transactions
 */
declare const EscrowReferenceSchema: z.ZodObject<{
    /**
     * Owner address (creator of the escrow)
     */
    owner: z.ZodString;
    /**
     * Sequence number to use for EscrowFinish/EscrowCancel
     * This is the OfferSequence field in finish/cancel transactions.
     */
    sequence: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    sequence: number;
    owner: string;
}, {
    sequence: number;
    owner: string;
}>;
/**
 * Output schema for tx_submit tool
 */
declare const TxSubmitOutputSchema: z.ZodObject<{
    /**
     * Transaction hash
     */
    tx_hash: z.ZodEffects<z.ZodString, string, string>;
    /**
     * Result from XRPL
     */
    result: z.ZodObject<{
        /**
         * Result code from XRPL
         */
        result_code: z.ZodString;
        /**
         * Human-readable result message
         */
        result_message: z.ZodString;
        /**
         * Whether transaction succeeded
         */
        success: z.ZodBoolean;
    }, "strip", z.ZodTypeAny, {
        success: boolean;
        result_code: string;
        result_message: string;
    }, {
        success: boolean;
        result_code: string;
        result_message: string;
    }>;
    /**
     * Ledger index (if validated)
     */
    ledger_index: z.ZodOptional<z.ZodNumber>;
    /**
     * When submitted
     */
    submitted_at: z.ZodString;
    /**
     * When validated (if wait_for_validation was true)
     */
    validated_at: z.ZodOptional<z.ZodString>;
    /**
     * Transaction type that was submitted
     * Useful for routing post-submission logic.
     */
    tx_type: z.ZodOptional<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>>;
    /**
     * Sequence number consumed by this transaction
     * Useful for tracking escrows or other sequence-dependent operations.
     */
    sequence_used: z.ZodOptional<z.ZodNumber>;
    /**
     * Escrow reference (only for EscrowCreate transactions)
     * Contains owner and sequence needed for EscrowFinish/EscrowCancel.
     */
    escrow_reference: z.ZodOptional<z.ZodObject<{
        /**
         * Owner address (creator of the escrow)
         */
        owner: z.ZodString;
        /**
         * Sequence number to use for EscrowFinish/EscrowCancel
         * This is the OfferSequence field in finish/cancel transactions.
         */
        sequence: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        sequence: number;
        owner: string;
    }, {
        sequence: number;
        owner: string;
    }>>;
    /**
     * Next sequence number to use for this account (only on success)
     * Use this for the next transaction instead of querying the ledger.
     * This prevents tefPAST_SEQ race conditions in rapid multi-tx workflows.
     * @since 2.1.0
     */
    next_sequence: z.ZodOptional<z.ZodNumber>;
}, "strip", z.ZodTypeAny, {
    tx_hash: string;
    result: {
        success: boolean;
        result_code: string;
        result_message: string;
    };
    submitted_at: string;
    ledger_index?: number | undefined;
    validated_at?: string | undefined;
    tx_type?: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge" | undefined;
    sequence_used?: number | undefined;
    escrow_reference?: {
        sequence: number;
        owner: string;
    } | undefined;
    next_sequence?: number | undefined;
}, {
    tx_hash: string;
    result: {
        success: boolean;
        result_code: string;
        result_message: string;
    };
    submitted_at: string;
    ledger_index?: number | undefined;
    validated_at?: string | undefined;
    tx_type?: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge" | undefined;
    sequence_used?: number | undefined;
    escrow_reference?: {
        sequence: number;
        owner: string;
    } | undefined;
    next_sequence?: number | undefined;
}>;
/**
 * Decoded transaction fields
 */
declare const DecodedTransactionSchema: z.ZodObject<{
    [x: string]: z.ZodString | z.ZodNumber | z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]> | z.ZodOptional<z.ZodString> | z.ZodUnknown;
    /**
     * Transaction type
     */
    TransactionType: z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>;
    /**
     * Source account
     */
    Account: z.ZodString;
    /**
     * Destination (for Payment-like transactions)
     */
    Destination: z.ZodOptional<z.ZodString>;
    /**
     * Amount in drops (for Payment transactions)
     */
    Amount: z.ZodOptional<z.ZodString>;
    /**
     * Transaction fee in drops
     */
    Fee: z.ZodString;
    /**
     * Sequence number
     */
    Sequence: z.ZodNumber;
}, "passthrough", z.ZodTypeAny, z.objectOutputType<{
    [x: string]: z.ZodString | z.ZodNumber | z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]> | z.ZodOptional<z.ZodString> | z.ZodUnknown;
    /**
     * Transaction type
     */
    TransactionType: z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>;
    /**
     * Source account
     */
    Account: z.ZodString;
    /**
     * Destination (for Payment-like transactions)
     */
    Destination: z.ZodOptional<z.ZodString>;
    /**
     * Amount in drops (for Payment transactions)
     */
    Amount: z.ZodOptional<z.ZodString>;
    /**
     * Transaction fee in drops
     */
    Fee: z.ZodString;
    /**
     * Sequence number
     */
    Sequence: z.ZodNumber;
}, z.ZodTypeAny, "passthrough">, z.objectInputType<{
    [x: string]: z.ZodString | z.ZodNumber | z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]> | z.ZodOptional<z.ZodString> | z.ZodUnknown;
    /**
     * Transaction type
     */
    TransactionType: z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>;
    /**
     * Source account
     */
    Account: z.ZodString;
    /**
     * Destination (for Payment-like transactions)
     */
    Destination: z.ZodOptional<z.ZodString>;
    /**
     * Amount in drops (for Payment transactions)
     */
    Amount: z.ZodOptional<z.ZodString>;
    /**
     * Transaction fee in drops
     */
    Fee: z.ZodString;
    /**
     * Sequence number
     */
    Sequence: z.ZodNumber;
}, z.ZodTypeAny, "passthrough">>;
/**
 * Output schema for tx_decode tool
 */
declare const TxDecodeOutputSchema: z.ZodObject<{
    /**
     * Decoded transaction fields
     */
    transaction: z.ZodObject<{
        [x: string]: z.ZodString | z.ZodNumber | z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]> | z.ZodOptional<z.ZodString> | z.ZodUnknown;
        /**
         * Transaction type
         */
        TransactionType: z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>;
        /**
         * Source account
         */
        Account: z.ZodString;
        /**
         * Destination (for Payment-like transactions)
         */
        Destination: z.ZodOptional<z.ZodString>;
        /**
         * Amount in drops (for Payment transactions)
         */
        Amount: z.ZodOptional<z.ZodString>;
        /**
         * Transaction fee in drops
         */
        Fee: z.ZodString;
        /**
         * Sequence number
         */
        Sequence: z.ZodNumber;
    }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
        [x: string]: z.ZodString | z.ZodNumber | z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]> | z.ZodOptional<z.ZodString> | z.ZodUnknown;
        /**
         * Transaction type
         */
        TransactionType: z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>;
        /**
         * Source account
         */
        Account: z.ZodString;
        /**
         * Destination (for Payment-like transactions)
         */
        Destination: z.ZodOptional<z.ZodString>;
        /**
         * Amount in drops (for Payment transactions)
         */
        Amount: z.ZodOptional<z.ZodString>;
        /**
         * Transaction fee in drops
         */
        Fee: z.ZodString;
        /**
         * Sequence number
         */
        Sequence: z.ZodNumber;
    }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
        [x: string]: z.ZodString | z.ZodNumber | z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]> | z.ZodOptional<z.ZodString> | z.ZodUnknown;
        /**
         * Transaction type
         */
        TransactionType: z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>;
        /**
         * Source account
         */
        Account: z.ZodString;
        /**
         * Destination (for Payment-like transactions)
         */
        Destination: z.ZodOptional<z.ZodString>;
        /**
         * Amount in drops (for Payment transactions)
         */
        Amount: z.ZodOptional<z.ZodString>;
        /**
         * Transaction fee in drops
         */
        Fee: z.ZodString;
        /**
         * Sequence number
         */
        Sequence: z.ZodNumber;
    }, z.ZodTypeAny, "passthrough">>;
    /**
     * Transaction hash (if signed)
     */
    hash: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    /**
     * Whether transaction is signed
     */
    is_signed: z.ZodBoolean;
    /**
     * Signing public key (if signed)
     */
    signing_public_key: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
}, "strip", z.ZodTypeAny, {
    transaction: {
        [x: string]: unknown;
        TransactionType?: unknown;
        Account?: unknown;
        Destination?: unknown;
        Amount?: unknown;
        Fee?: unknown;
        Sequence?: unknown;
    } & {
        [k: string]: unknown;
    };
    is_signed: boolean;
    hash?: string | undefined;
    signing_public_key?: string | undefined;
}, {
    transaction: {
        [x: string]: unknown;
        TransactionType?: unknown;
        Account?: unknown;
        Destination?: unknown;
        Amount?: unknown;
        Fee?: unknown;
        Sequence?: unknown;
    } & {
        [k: string]: unknown;
    };
    is_signed: boolean;
    hash?: string | undefined;
    signing_public_key?: string | undefined;
}>;
/**
 * Output schema for network_config tool
 */
declare const NetworkConfigOutputSchema: z.ZodObject<{
    /**
     * Configuration status
     */
    status: z.ZodLiteral<"configured">;
    /**
     * Network that was configured
     */
    network: z.ZodEnum<["mainnet", "testnet", "devnet"]>;
    /**
     * Applied configuration
     */
    config: z.ZodObject<{
        primary_url: z.ZodString;
        fallback_urls: z.ZodArray<z.ZodString, "many">;
        connection_timeout_ms: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        primary_url: string;
        fallback_urls: string[];
        connection_timeout_ms: number;
    }, {
        primary_url: string;
        fallback_urls: string[];
        connection_timeout_ms: number;
    }>;
}, "strip", z.ZodTypeAny, {
    network: "mainnet" | "testnet" | "devnet";
    status: "configured";
    config: {
        primary_url: string;
        fallback_urls: string[];
        connection_timeout_ms: number;
    };
}, {
    network: "mainnet" | "testnet" | "devnet";
    status: "configured";
    config: {
        primary_url: string;
        fallback_urls: string[];
        connection_timeout_ms: number;
    };
}>;
/**
 * Error codes for MCP tool responses
 */
declare const ErrorCodeSchema: z.ZodEnum<["VALIDATION_ERROR", "INVALID_ADDRESS", "INVALID_TRANSACTION", "INVALID_POLICY", "POLICY_VIOLATION", "RATE_LIMIT_EXCEEDED", "LIMIT_EXCEEDED", "DESTINATION_BLOCKED", "TRANSACTION_TYPE_BLOCKED", "WALLET_NOT_FOUND", "WALLET_LOCKED", "UNAUTHORIZED", "APPROVAL_REQUIRED", "APPROVAL_EXPIRED", "NETWORK_ERROR", "CONNECTION_FAILED", "SUBMISSION_FAILED", "TIMEOUT", "INTERNAL_ERROR", "KEYSTORE_ERROR", "SIGNING_ERROR", "ENCRYPTION_ERROR", "INSUFFICIENT_BALANCE", "INSUFFICIENT_RESERVE", "SEQUENCE_ERROR", "LEDGER_NOT_FOUND"]>;
/**
 * Error response schema for all MCP tools
 */
declare const ErrorResponseSchema: z.ZodObject<{
    /**
     * Error code for programmatic handling
     */
    code: z.ZodEnum<["VALIDATION_ERROR", "INVALID_ADDRESS", "INVALID_TRANSACTION", "INVALID_POLICY", "POLICY_VIOLATION", "RATE_LIMIT_EXCEEDED", "LIMIT_EXCEEDED", "DESTINATION_BLOCKED", "TRANSACTION_TYPE_BLOCKED", "WALLET_NOT_FOUND", "WALLET_LOCKED", "UNAUTHORIZED", "APPROVAL_REQUIRED", "APPROVAL_EXPIRED", "NETWORK_ERROR", "CONNECTION_FAILED", "SUBMISSION_FAILED", "TIMEOUT", "INTERNAL_ERROR", "KEYSTORE_ERROR", "SIGNING_ERROR", "ENCRYPTION_ERROR", "INSUFFICIENT_BALANCE", "INSUFFICIENT_RESERVE", "SEQUENCE_ERROR", "LEDGER_NOT_FOUND"]>;
    /**
     * Human-readable error message
     */
    message: z.ZodString;
    /**
     * Additional error details
     */
    details: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
    /**
     * Request ID for correlation
     */
    request_id: z.ZodOptional<z.ZodString>;
    /**
     * Timestamp
     */
    timestamp: z.ZodString;
}, "strip", z.ZodTypeAny, {
    code: "VALIDATION_ERROR" | "INVALID_ADDRESS" | "INVALID_TRANSACTION" | "INVALID_POLICY" | "POLICY_VIOLATION" | "RATE_LIMIT_EXCEEDED" | "LIMIT_EXCEEDED" | "DESTINATION_BLOCKED" | "TRANSACTION_TYPE_BLOCKED" | "WALLET_NOT_FOUND" | "WALLET_LOCKED" | "UNAUTHORIZED" | "APPROVAL_REQUIRED" | "APPROVAL_EXPIRED" | "NETWORK_ERROR" | "CONNECTION_FAILED" | "SUBMISSION_FAILED" | "TIMEOUT" | "INTERNAL_ERROR" | "KEYSTORE_ERROR" | "SIGNING_ERROR" | "ENCRYPTION_ERROR" | "INSUFFICIENT_BALANCE" | "INSUFFICIENT_RESERVE" | "SEQUENCE_ERROR" | "LEDGER_NOT_FOUND";
    message: string;
    timestamp: string;
    details?: Record<string, unknown> | undefined;
    request_id?: string | undefined;
}, {
    code: "VALIDATION_ERROR" | "INVALID_ADDRESS" | "INVALID_TRANSACTION" | "INVALID_POLICY" | "POLICY_VIOLATION" | "RATE_LIMIT_EXCEEDED" | "LIMIT_EXCEEDED" | "DESTINATION_BLOCKED" | "TRANSACTION_TYPE_BLOCKED" | "WALLET_NOT_FOUND" | "WALLET_LOCKED" | "UNAUTHORIZED" | "APPROVAL_REQUIRED" | "APPROVAL_EXPIRED" | "NETWORK_ERROR" | "CONNECTION_FAILED" | "SUBMISSION_FAILED" | "TIMEOUT" | "INTERNAL_ERROR" | "KEYSTORE_ERROR" | "SIGNING_ERROR" | "ENCRYPTION_ERROR" | "INSUFFICIENT_BALANCE" | "INSUFFICIENT_RESERVE" | "SEQUENCE_ERROR" | "LEDGER_NOT_FOUND";
    message: string;
    timestamp: string;
    details?: Record<string, unknown> | undefined;
    request_id?: string | undefined;
}>;
/**
 * Audit event types
 */
declare const AuditEventTypeSchema: z.ZodEnum<["wallet_created", "wallet_imported", "wallet_deleted", "key_rotated", "transaction_signed", "transaction_submitted", "transaction_validated", "transaction_failed", "policy_evaluated", "policy_violation", "policy_updated", "approval_requested", "approval_granted", "approval_denied", "approval_expired", "rate_limit_triggered", "injection_detected", "authentication_failed", "server_started", "server_stopped", "keystore_unlocked", "keystore_locked"]>;
/**
 * Audit log entry schema
 */
declare const AuditLogEntrySchema: z.ZodObject<{
    /**
     * Sequence number (monotonically increasing)
     */
    seq: z.ZodNumber;
    /**
     * Event timestamp
     */
    timestamp: z.ZodString;
    /**
     * Event type
     */
    event: z.ZodEnum<["wallet_created", "wallet_imported", "wallet_deleted", "key_rotated", "transaction_signed", "transaction_submitted", "transaction_validated", "transaction_failed", "policy_evaluated", "policy_violation", "policy_updated", "approval_requested", "approval_granted", "approval_denied", "approval_expired", "rate_limit_triggered", "injection_detected", "authentication_failed", "server_started", "server_stopped", "keystore_unlocked", "keystore_locked"]>;
    /**
     * Wallet ID (if applicable)
     */
    wallet_id: z.ZodOptional<z.ZodString>;
    /**
     * Wallet address (if applicable)
     */
    wallet_address: z.ZodOptional<z.ZodString>;
    /**
     * Transaction type (if applicable)
     */
    transaction_type: z.ZodOptional<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>>;
    /**
     * Amount in XRP (if applicable)
     */
    amount_xrp: z.ZodOptional<z.ZodString>;
    /**
     * Destination address (if applicable)
     */
    destination: z.ZodOptional<z.ZodString>;
    /**
     * Policy tier (if applicable)
     */
    tier: z.ZodOptional<z.ZodUnion<[z.ZodLiteral<1>, z.ZodLiteral<2>, z.ZodLiteral<3>, z.ZodLiteral<4>]>>;
    /**
     * Policy decision
     */
    policy_decision: z.ZodOptional<z.ZodEnum<["allowed", "denied", "pending"]>>;
    /**
     * Transaction hash (if applicable)
     */
    tx_hash: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    /**
     * Context from agent
     */
    context: z.ZodOptional<z.ZodString>;
    /**
     * Previous entry hash (for chain integrity)
     */
    prev_hash: z.ZodString;
    /**
     * This entry's hash
     */
    hash: z.ZodString;
}, "strip", z.ZodTypeAny, {
    hash: string;
    timestamp: string;
    seq: number;
    event: "policy_violation" | "wallet_created" | "wallet_imported" | "wallet_deleted" | "key_rotated" | "transaction_signed" | "transaction_submitted" | "transaction_validated" | "transaction_failed" | "policy_evaluated" | "policy_updated" | "approval_requested" | "approval_granted" | "approval_denied" | "approval_expired" | "rate_limit_triggered" | "injection_detected" | "authentication_failed" | "server_started" | "server_stopped" | "keystore_unlocked" | "keystore_locked";
    prev_hash: string;
    wallet_address?: string | undefined;
    context?: string | undefined;
    wallet_id?: string | undefined;
    tx_hash?: string | undefined;
    tier?: 3 | 1 | 2 | 4 | undefined;
    destination?: string | undefined;
    transaction_type?: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge" | undefined;
    amount_xrp?: string | undefined;
    policy_decision?: "allowed" | "pending" | "denied" | undefined;
}, {
    hash: string;
    timestamp: string;
    seq: number;
    event: "policy_violation" | "wallet_created" | "wallet_imported" | "wallet_deleted" | "key_rotated" | "transaction_signed" | "transaction_submitted" | "transaction_validated" | "transaction_failed" | "policy_evaluated" | "policy_updated" | "approval_requested" | "approval_granted" | "approval_denied" | "approval_expired" | "rate_limit_triggered" | "injection_detected" | "authentication_failed" | "server_started" | "server_stopped" | "keystore_unlocked" | "keystore_locked";
    prev_hash: string;
    wallet_address?: string | undefined;
    context?: string | undefined;
    wallet_id?: string | undefined;
    tx_hash?: string | undefined;
    tier?: 3 | 1 | 2 | 4 | undefined;
    destination?: string | undefined;
    transaction_type?: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge" | undefined;
    amount_xrp?: string | undefined;
    policy_decision?: "allowed" | "pending" | "denied" | undefined;
}>;
type XRPLAddress = z.infer<typeof XRPLAddressSchema>;
type DropsAmount = z.infer<typeof DropsAmountSchema>;
type TransactionHash = z.infer<typeof TransactionHashSchema>;
type PublicKey = z.infer<typeof PublicKeySchema>;
type Network = z.infer<typeof NetworkSchema>;
type TransactionType = z.infer<typeof TransactionTypeSchema>;
type SequenceNumber = z.infer<typeof SequenceNumberSchema>;
type LedgerIndex = z.infer<typeof LedgerIndexSchema>;
type HexString = z.infer<typeof HexStringSchema>;
type HexStringRaw = z.infer<typeof HexStringRawSchema>;
type UnsignedTransactionBlob = z.infer<typeof UnsignedTransactionBlobSchema>;
type SignedTransactionBlob = z.infer<typeof SignedTransactionBlobSchema>;
type WalletId = z.infer<typeof WalletIdSchema>;
type WalletName = z.infer<typeof WalletNameSchema>;
type Timestamp = z.infer<typeof TimestampSchema>;
type PaginationMarker = z.infer<typeof PaginationMarkerSchema>;
type ApprovalTier = z.infer<typeof ApprovalTierSchema>;
type PolicyLimits = z.infer<typeof PolicyLimitsSchema>;
type DestinationMode = z.infer<typeof DestinationModeSchema>;
type PolicyDestinations = z.infer<typeof PolicyDestinationsSchema>;
type PolicyTransactionTypes = z.infer<typeof PolicyTransactionTypesSchema>;
type PolicyTimeControls = z.infer<typeof PolicyTimeControlsSchema>;
type PolicyEscalation = z.infer<typeof PolicyEscalationSchema>;
type NotificationEvent = z.infer<typeof NotificationEventSchema>;
type PolicyNotifications = z.infer<typeof PolicyNotificationsSchema>;
type AgentWalletPolicy = z.infer<typeof AgentWalletPolicySchema>;
type WalletCreateInput = z.infer<typeof WalletCreateInputSchema>;
type WalletImportInput = z.infer<typeof WalletImportInputSchema>;
type WalletSignInput = z.infer<typeof WalletSignInputSchema>;
type WalletBalanceInput = z.infer<typeof WalletBalanceInputSchema>;
type WalletPolicyCheckInput = z.infer<typeof WalletPolicyCheckInputSchema>;
type WalletRotateInput = z.infer<typeof WalletRotateInputSchema>;
type WalletHistoryInput = z.infer<typeof WalletHistoryInputSchema>;
type WalletListInput = z.infer<typeof WalletListInputSchema>;
type WalletFundInput = z.infer<typeof WalletFundInputSchema>;
type PolicySetInput = z.infer<typeof PolicySetInputSchema>;
type TxSubmitInput = z.infer<typeof TxSubmitInputSchema>;
type TxDecodeInput = z.infer<typeof TxDecodeInputSchema>;
type NetworkConfigInput = z.infer<typeof NetworkConfigInputSchema>;
type SignerEntry = z.infer<typeof SignerEntrySchema>;
type WalletCreateOutput = z.infer<typeof WalletCreateOutputSchema>;
type RemainingLimits = z.infer<typeof RemainingLimitsSchema>;
type PolicyViolation = z.infer<typeof PolicyViolationSchema>;
type WalletSignApprovedOutput = z.infer<typeof WalletSignApprovedOutputSchema>;
type WalletSignPendingOutput = z.infer<typeof WalletSignPendingOutputSchema>;
type WalletSignRejectedOutput = z.infer<typeof WalletSignRejectedOutputSchema>;
type WalletSignOutput = z.infer<typeof WalletSignOutputSchema>;
type WalletBalanceOutput = z.infer<typeof WalletBalanceOutputSchema>;
type LimitStatus = z.infer<typeof LimitStatusSchema>;
type WalletPolicyCheckOutput = z.infer<typeof WalletPolicyCheckOutputSchema>;
type WalletRotateOutput = z.infer<typeof WalletRotateOutputSchema>;
type TransactionHistoryEntry = z.infer<typeof TransactionHistoryEntrySchema>;
type WalletHistoryOutput = z.infer<typeof WalletHistoryOutputSchema>;
type WalletListEntry = z.infer<typeof WalletListEntrySchema>;
type WalletListOutput = z.infer<typeof WalletListOutputSchema>;
type WalletFundOutput = z.infer<typeof WalletFundOutputSchema>;
type PolicySetOutput = z.infer<typeof PolicySetOutputSchema>;
type TransactionResult = z.infer<typeof TransactionResultSchema>;
type EscrowReference = z.infer<typeof EscrowReferenceSchema>;
type TxSubmitOutput = z.infer<typeof TxSubmitOutputSchema>;
type DecodedTransaction = z.infer<typeof DecodedTransactionSchema>;
type TxDecodeOutput = z.infer<typeof TxDecodeOutputSchema>;
type NetworkConfigOutput = z.infer<typeof NetworkConfigOutputSchema>;
type ErrorCode = z.infer<typeof ErrorCodeSchema>;
type ErrorResponse = z.infer<typeof ErrorResponseSchema>;
type AuditEventType = z.infer<typeof AuditEventTypeSchema>;
type AuditLogEntry = z.infer<typeof AuditLogEntrySchema>;
/**
 * Collection of all input schemas for MCP tool registration
 */
declare const InputSchemas: {
    readonly wallet_create: z.ZodObject<{
        /**
         * Target network for the wallet
         * Keys are isolated per network
         */
        network: z.ZodEnum<["mainnet", "testnet", "devnet"]>;
        /**
         * Policy to apply to this wallet
         * Defines all security constraints
         */
        policy: z.ZodObject<{
            /**
             * Unique policy identifier
             * @example "conservative-v1"
             */
            policy_id: z.ZodString;
            /**
             * Policy version for tracking changes
             * Semantic versioning recommended
             */
            policy_version: z.ZodString;
            /**
             * Transaction and volume limits
             */
            limits: z.ZodObject<{
                /**
                 * Maximum amount per single transaction in drops
                 * @example "10000000" (10 XRP)
                 */
                max_amount_per_tx_drops: z.ZodEffects<z.ZodString, string, string>;
                /**
                 * Maximum daily transaction volume in drops
                 * Resets at midnight UTC
                 * @example "100000000" (100 XRP)
                 */
                max_daily_volume_drops: z.ZodEffects<z.ZodString, string, string>;
                /**
                 * Maximum transactions per hour (rolling window)
                 */
                max_tx_per_hour: z.ZodNumber;
                /**
                 * Maximum transactions per day (rolling window)
                 */
                max_tx_per_day: z.ZodNumber;
            }, "strip", z.ZodTypeAny, {
                max_amount_per_tx_drops: string;
                max_daily_volume_drops: string;
                max_tx_per_hour: number;
                max_tx_per_day: number;
            }, {
                max_amount_per_tx_drops: string;
                max_daily_volume_drops: string;
                max_tx_per_hour: number;
                max_tx_per_day: number;
            }>;
            /**
             * Destination address controls
             */
            destinations: z.ZodObject<{
                /**
                 * Destination filtering mode
                 */
                mode: z.ZodEnum<["allowlist", "blocklist", "open"]>;
                /**
                 * Allowed destination addresses (used when mode='allowlist')
                 */
                allowlist: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
                /**
                 * Blocked destination addresses (always enforced regardless of mode)
                 * Used for known scam/malicious addresses
                 */
                blocklist: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
                /**
                 * Whether to allow transactions to previously unseen addresses
                 */
                allow_new_destinations: z.ZodBoolean;
                /**
                 * Approval tier required for new destinations
                 * Only used when allow_new_destinations is true
                 */
                new_destination_tier: z.ZodOptional<z.ZodUnion<[z.ZodLiteral<2>, z.ZodLiteral<3>]>>;
            }, "strip", z.ZodTypeAny, {
                mode: "allowlist" | "blocklist" | "open";
                allow_new_destinations: boolean;
                allowlist?: string[] | undefined;
                blocklist?: string[] | undefined;
                new_destination_tier?: 3 | 2 | undefined;
            }, {
                mode: "allowlist" | "blocklist" | "open";
                allow_new_destinations: boolean;
                allowlist?: string[] | undefined;
                blocklist?: string[] | undefined;
                new_destination_tier?: 3 | 2 | undefined;
            }>;
            /**
             * Transaction type restrictions
             */
            transaction_types: z.ZodObject<{
                /**
                 * Transaction types the agent can execute autonomously
                 * @example ["Payment", "EscrowFinish", "EscrowCancel"]
                 */
                allowed: z.ZodArray<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>, "many">;
                /**
                 * Transaction types that require human approval (tier 2/3)
                 * @example ["EscrowCreate", "TrustSet"]
                 */
                require_approval: z.ZodOptional<z.ZodArray<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>, "many">>;
                /**
                 * Transaction types that are never allowed (tier 4)
                 * Typically account control operations
                 * @example ["SetRegularKey", "SignerListSet", "AccountDelete"]
                 */
                blocked: z.ZodOptional<z.ZodArray<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>, "many">>;
            }, "strip", z.ZodTypeAny, {
                allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
                require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
                blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            }, {
                allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
                require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
                blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            }>;
            /**
             * Time-based access controls (optional)
             */
            time_controls: z.ZodOptional<z.ZodObject<{
                /**
                 * Active hours in UTC (24-hour format)
                 * Transactions outside these hours are escalated to tier 2/3
                 */
                active_hours_utc: z.ZodOptional<z.ZodObject<{
                    start: z.ZodNumber;
                    end: z.ZodNumber;
                }, "strip", z.ZodTypeAny, {
                    start: number;
                    end: number;
                }, {
                    start: number;
                    end: number;
                }>>;
                /**
                 * Active days of the week
                 * 0 = Sunday, 6 = Saturday
                 */
                active_days: z.ZodOptional<z.ZodArray<z.ZodNumber, "many">>;
                /**
                 * Timezone for interpreting active hours
                 * @example "America/New_York"
                 */
                timezone: z.ZodOptional<z.ZodString>;
            }, "strip", z.ZodTypeAny, {
                active_hours_utc?: {
                    start: number;
                    end: number;
                } | undefined;
                active_days?: number[] | undefined;
                timezone?: string | undefined;
            }, {
                active_hours_utc?: {
                    start: number;
                    end: number;
                } | undefined;
                active_days?: number[] | undefined;
                timezone?: string | undefined;
            }>>;
            /**
             * Escalation thresholds
             */
            escalation: z.ZodObject<{
                /**
                 * Amount threshold for escalation to tier 2 (drops)
                 * Transactions above this require delayed/human approval
                 */
                amount_threshold_drops: z.ZodEffects<z.ZodString, string, string>;
                /**
                 * Tier assigned to transactions with new destinations
                 */
                new_destination: z.ZodUnion<[z.ZodLiteral<2>, z.ZodLiteral<3>]>;
                /**
                 * Tier for account settings changes
                 * Always tier 3 for safety
                 */
                account_settings: z.ZodLiteral<3>;
                /**
                 * Delay in seconds before tier 2 transactions auto-approve
                 * Human can veto during this window
                 */
                delay_seconds: z.ZodOptional<z.ZodNumber>;
            }, "strip", z.ZodTypeAny, {
                amount_threshold_drops: string;
                new_destination: 3 | 2;
                account_settings: 3;
                delay_seconds?: number | undefined;
            }, {
                amount_threshold_drops: string;
                new_destination: 3 | 2;
                account_settings: 3;
                delay_seconds?: number | undefined;
            }>;
            /**
             * Notification settings (optional)
             */
            notifications: z.ZodOptional<z.ZodObject<{
                /**
                 * Webhook URL for notifications
                 * Must be HTTPS for production
                 */
                webhook_url: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
                /**
                 * Events that trigger notifications
                 */
                notify_on: z.ZodOptional<z.ZodArray<z.ZodEnum<["tier2", "tier3", "rejection", "all"]>, "many">>;
            }, "strip", z.ZodTypeAny, {
                webhook_url?: string | undefined;
                notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
            }, {
                webhook_url?: string | undefined;
                notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
            }>>;
        }, "strip", z.ZodTypeAny, {
            policy_id: string;
            policy_version: string;
            limits: {
                max_amount_per_tx_drops: string;
                max_daily_volume_drops: string;
                max_tx_per_hour: number;
                max_tx_per_day: number;
            };
            destinations: {
                mode: "allowlist" | "blocklist" | "open";
                allow_new_destinations: boolean;
                allowlist?: string[] | undefined;
                blocklist?: string[] | undefined;
                new_destination_tier?: 3 | 2 | undefined;
            };
            transaction_types: {
                allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
                require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
                blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            };
            escalation: {
                amount_threshold_drops: string;
                new_destination: 3 | 2;
                account_settings: 3;
                delay_seconds?: number | undefined;
            };
            time_controls?: {
                active_hours_utc?: {
                    start: number;
                    end: number;
                } | undefined;
                active_days?: number[] | undefined;
                timezone?: string | undefined;
            } | undefined;
            notifications?: {
                webhook_url?: string | undefined;
                notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
            } | undefined;
        }, {
            policy_id: string;
            policy_version: string;
            limits: {
                max_amount_per_tx_drops: string;
                max_daily_volume_drops: string;
                max_tx_per_hour: number;
                max_tx_per_day: number;
            };
            destinations: {
                mode: "allowlist" | "blocklist" | "open";
                allow_new_destinations: boolean;
                allowlist?: string[] | undefined;
                blocklist?: string[] | undefined;
                new_destination_tier?: 3 | 2 | undefined;
            };
            transaction_types: {
                allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
                require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
                blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            };
            escalation: {
                amount_threshold_drops: string;
                new_destination: 3 | 2;
                account_settings: 3;
                delay_seconds?: number | undefined;
            };
            time_controls?: {
                active_hours_utc?: {
                    start: number;
                    end: number;
                } | undefined;
                active_days?: number[] | undefined;
                timezone?: string | undefined;
            } | undefined;
            notifications?: {
                webhook_url?: string | undefined;
                notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
            } | undefined;
        }>;
        /**
         * Human-readable wallet name (optional)
         */
        wallet_name: z.ZodOptional<z.ZodString>;
        /**
         * Address to fund the new wallet from (optional)
         * Requires separate signing outside this MCP
         */
        funding_source: z.ZodOptional<z.ZodString>;
        /**
         * Initial funding amount in drops (optional)
         * Must meet minimum reserve requirements
         */
        initial_funding_drops: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    }, "strip", z.ZodTypeAny, {
        network: "mainnet" | "testnet" | "devnet";
        policy: {
            policy_id: string;
            policy_version: string;
            limits: {
                max_amount_per_tx_drops: string;
                max_daily_volume_drops: string;
                max_tx_per_hour: number;
                max_tx_per_day: number;
            };
            destinations: {
                mode: "allowlist" | "blocklist" | "open";
                allow_new_destinations: boolean;
                allowlist?: string[] | undefined;
                blocklist?: string[] | undefined;
                new_destination_tier?: 3 | 2 | undefined;
            };
            transaction_types: {
                allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
                require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
                blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            };
            escalation: {
                amount_threshold_drops: string;
                new_destination: 3 | 2;
                account_settings: 3;
                delay_seconds?: number | undefined;
            };
            time_controls?: {
                active_hours_utc?: {
                    start: number;
                    end: number;
                } | undefined;
                active_days?: number[] | undefined;
                timezone?: string | undefined;
            } | undefined;
            notifications?: {
                webhook_url?: string | undefined;
                notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
            } | undefined;
        };
        wallet_name?: string | undefined;
        funding_source?: string | undefined;
        initial_funding_drops?: string | undefined;
    }, {
        network: "mainnet" | "testnet" | "devnet";
        policy: {
            policy_id: string;
            policy_version: string;
            limits: {
                max_amount_per_tx_drops: string;
                max_daily_volume_drops: string;
                max_tx_per_hour: number;
                max_tx_per_day: number;
            };
            destinations: {
                mode: "allowlist" | "blocklist" | "open";
                allow_new_destinations: boolean;
                allowlist?: string[] | undefined;
                blocklist?: string[] | undefined;
                new_destination_tier?: 3 | 2 | undefined;
            };
            transaction_types: {
                allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
                require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
                blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            };
            escalation: {
                amount_threshold_drops: string;
                new_destination: 3 | 2;
                account_settings: 3;
                delay_seconds?: number | undefined;
            };
            time_controls?: {
                active_hours_utc?: {
                    start: number;
                    end: number;
                } | undefined;
                active_days?: number[] | undefined;
                timezone?: string | undefined;
            } | undefined;
            notifications?: {
                webhook_url?: string | undefined;
                notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
            } | undefined;
        };
        wallet_name?: string | undefined;
        funding_source?: string | undefined;
        initial_funding_drops?: string | undefined;
    }>;
    readonly wallet_import: z.ZodObject<{
        /**
         * XRPL seed (starts with 's')
         */
        seed: z.ZodString;
        /**
         * Target network for the wallet (defaults to server's configured network)
         */
        network: z.ZodOptional<z.ZodEnum<["mainnet", "testnet", "devnet"]>>;
        /**
         * Human-readable wallet name (optional)
         */
        wallet_name: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        seed: string;
        network?: "mainnet" | "testnet" | "devnet" | undefined;
        wallet_name?: string | undefined;
    }, {
        seed: string;
        network?: "mainnet" | "testnet" | "devnet" | undefined;
        wallet_name?: string | undefined;
    }>;
    readonly wallet_sign: z.ZodObject<{
        /**
         * Address of the wallet to sign with
         */
        wallet_address: z.ZodString;
        /**
         * Hex-encoded unsigned transaction blob
         */
        unsigned_tx: z.ZodString;
        /**
         * Context/reason for this transaction (for audit trail)
         * Describe why the agent is making this transaction
         * @example "Completing escrow for order #12345"
         */
        context: z.ZodOptional<z.ZodString>;
        /**
         * Whether to automatically fetch and apply the current sequence from ledger.
         * When true (default), queries account_info and updates Sequence, Fee, and
         * LastLedgerSequence in the transaction before signing.
         *
         * This prevents tefPAST_SEQ errors in multi-transaction workflows.
         *
         * Set to false only if you need to sign with a specific pre-set sequence
         * (e.g., for offline signing or ticket-based transactions).
         *
         * @default true
         */
        auto_sequence: z.ZodDefault<z.ZodOptional<z.ZodBoolean>>;
    }, "strip", z.ZodTypeAny, {
        wallet_address: string;
        unsigned_tx: string;
        auto_sequence: boolean;
        context?: string | undefined;
    }, {
        wallet_address: string;
        unsigned_tx: string;
        context?: string | undefined;
        auto_sequence?: boolean | undefined;
    }>;
    readonly wallet_balance: z.ZodObject<{
        /**
         * Address to query balance for
         */
        wallet_address: z.ZodString;
        /**
         * Wait time in milliseconds before querying (optional)
         * Useful for waiting after a transaction to ensure balance is updated.
         * @default 0
         * @example 5000 (wait 5 seconds)
         */
        wait_after_tx: z.ZodOptional<z.ZodNumber>;
    }, "strip", z.ZodTypeAny, {
        wallet_address: string;
        wait_after_tx?: number | undefined;
    }, {
        wallet_address: string;
        wait_after_tx?: number | undefined;
    }>;
    readonly wallet_policy_check: z.ZodObject<{
        /**
         * Address of the wallet to check against
         */
        wallet_address: z.ZodString;
        /**
         * Hex-encoded unsigned transaction to evaluate
         */
        unsigned_tx: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        wallet_address: string;
        unsigned_tx: string;
    }, {
        wallet_address: string;
        unsigned_tx: string;
    }>;
    readonly wallet_rotate: z.ZodObject<{
        /**
         * Address of the wallet to rotate key for
         */
        wallet_address: z.ZodString;
        /**
         * Reason for rotation (audit trail)
         * @example "Scheduled quarterly rotation"
         * @example "Suspected key compromise"
         */
        reason: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        wallet_address: string;
        reason?: string | undefined;
    }, {
        wallet_address: string;
        reason?: string | undefined;
    }>;
    readonly wallet_history: z.ZodObject<{
        /**
         * Address to get history for
         */
        wallet_address: z.ZodString;
        /**
         * Maximum number of transactions to return
         * @default 20
         */
        limit: z.ZodDefault<z.ZodOptional<z.ZodNumber>>;
        /**
         * Pagination marker from previous response
         */
        marker: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        wallet_address: string;
        limit: number;
        marker?: string | undefined;
    }, {
        wallet_address: string;
        limit?: number | undefined;
        marker?: string | undefined;
    }>;
    readonly wallet_list: z.ZodObject<{
        /**
         * Filter by network (optional)
         */
        network: z.ZodOptional<z.ZodEnum<["mainnet", "testnet", "devnet"]>>;
    }, "strip", z.ZodTypeAny, {
        network?: "mainnet" | "testnet" | "devnet" | undefined;
    }, {
        network?: "mainnet" | "testnet" | "devnet" | undefined;
    }>;
    readonly wallet_fund: z.ZodObject<{
        /**
         * Address to fund
         */
        wallet_address: z.ZodString;
        /**
         * Network (must be testnet or devnet)
         */
        network: z.ZodEnum<["testnet", "devnet"]>;
        /**
         * Wait for account to be confirmed on validated ledger (optional)
         * When true, retries account_info until account is queryable.
         * Recommended for automated workflows.
         * @default true
         */
        wait_for_confirmation: z.ZodDefault<z.ZodOptional<z.ZodBoolean>>;
    }, "strip", z.ZodTypeAny, {
        network: "testnet" | "devnet";
        wallet_address: string;
        wait_for_confirmation: boolean;
    }, {
        network: "testnet" | "devnet";
        wallet_address: string;
        wait_for_confirmation?: boolean | undefined;
    }>;
    readonly policy_set: z.ZodObject<{
        /**
         * Wallet address to update policy for
         */
        wallet_address: z.ZodString;
        /**
         * New policy to apply
         */
        policy: z.ZodObject<{
            /**
             * Unique policy identifier
             * @example "conservative-v1"
             */
            policy_id: z.ZodString;
            /**
             * Policy version for tracking changes
             * Semantic versioning recommended
             */
            policy_version: z.ZodString;
            /**
             * Transaction and volume limits
             */
            limits: z.ZodObject<{
                /**
                 * Maximum amount per single transaction in drops
                 * @example "10000000" (10 XRP)
                 */
                max_amount_per_tx_drops: z.ZodEffects<z.ZodString, string, string>;
                /**
                 * Maximum daily transaction volume in drops
                 * Resets at midnight UTC
                 * @example "100000000" (100 XRP)
                 */
                max_daily_volume_drops: z.ZodEffects<z.ZodString, string, string>;
                /**
                 * Maximum transactions per hour (rolling window)
                 */
                max_tx_per_hour: z.ZodNumber;
                /**
                 * Maximum transactions per day (rolling window)
                 */
                max_tx_per_day: z.ZodNumber;
            }, "strip", z.ZodTypeAny, {
                max_amount_per_tx_drops: string;
                max_daily_volume_drops: string;
                max_tx_per_hour: number;
                max_tx_per_day: number;
            }, {
                max_amount_per_tx_drops: string;
                max_daily_volume_drops: string;
                max_tx_per_hour: number;
                max_tx_per_day: number;
            }>;
            /**
             * Destination address controls
             */
            destinations: z.ZodObject<{
                /**
                 * Destination filtering mode
                 */
                mode: z.ZodEnum<["allowlist", "blocklist", "open"]>;
                /**
                 * Allowed destination addresses (used when mode='allowlist')
                 */
                allowlist: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
                /**
                 * Blocked destination addresses (always enforced regardless of mode)
                 * Used for known scam/malicious addresses
                 */
                blocklist: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
                /**
                 * Whether to allow transactions to previously unseen addresses
                 */
                allow_new_destinations: z.ZodBoolean;
                /**
                 * Approval tier required for new destinations
                 * Only used when allow_new_destinations is true
                 */
                new_destination_tier: z.ZodOptional<z.ZodUnion<[z.ZodLiteral<2>, z.ZodLiteral<3>]>>;
            }, "strip", z.ZodTypeAny, {
                mode: "allowlist" | "blocklist" | "open";
                allow_new_destinations: boolean;
                allowlist?: string[] | undefined;
                blocklist?: string[] | undefined;
                new_destination_tier?: 3 | 2 | undefined;
            }, {
                mode: "allowlist" | "blocklist" | "open";
                allow_new_destinations: boolean;
                allowlist?: string[] | undefined;
                blocklist?: string[] | undefined;
                new_destination_tier?: 3 | 2 | undefined;
            }>;
            /**
             * Transaction type restrictions
             */
            transaction_types: z.ZodObject<{
                /**
                 * Transaction types the agent can execute autonomously
                 * @example ["Payment", "EscrowFinish", "EscrowCancel"]
                 */
                allowed: z.ZodArray<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>, "many">;
                /**
                 * Transaction types that require human approval (tier 2/3)
                 * @example ["EscrowCreate", "TrustSet"]
                 */
                require_approval: z.ZodOptional<z.ZodArray<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>, "many">>;
                /**
                 * Transaction types that are never allowed (tier 4)
                 * Typically account control operations
                 * @example ["SetRegularKey", "SignerListSet", "AccountDelete"]
                 */
                blocked: z.ZodOptional<z.ZodArray<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>, "many">>;
            }, "strip", z.ZodTypeAny, {
                allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
                require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
                blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            }, {
                allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
                require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
                blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            }>;
            /**
             * Time-based access controls (optional)
             */
            time_controls: z.ZodOptional<z.ZodObject<{
                /**
                 * Active hours in UTC (24-hour format)
                 * Transactions outside these hours are escalated to tier 2/3
                 */
                active_hours_utc: z.ZodOptional<z.ZodObject<{
                    start: z.ZodNumber;
                    end: z.ZodNumber;
                }, "strip", z.ZodTypeAny, {
                    start: number;
                    end: number;
                }, {
                    start: number;
                    end: number;
                }>>;
                /**
                 * Active days of the week
                 * 0 = Sunday, 6 = Saturday
                 */
                active_days: z.ZodOptional<z.ZodArray<z.ZodNumber, "many">>;
                /**
                 * Timezone for interpreting active hours
                 * @example "America/New_York"
                 */
                timezone: z.ZodOptional<z.ZodString>;
            }, "strip", z.ZodTypeAny, {
                active_hours_utc?: {
                    start: number;
                    end: number;
                } | undefined;
                active_days?: number[] | undefined;
                timezone?: string | undefined;
            }, {
                active_hours_utc?: {
                    start: number;
                    end: number;
                } | undefined;
                active_days?: number[] | undefined;
                timezone?: string | undefined;
            }>>;
            /**
             * Escalation thresholds
             */
            escalation: z.ZodObject<{
                /**
                 * Amount threshold for escalation to tier 2 (drops)
                 * Transactions above this require delayed/human approval
                 */
                amount_threshold_drops: z.ZodEffects<z.ZodString, string, string>;
                /**
                 * Tier assigned to transactions with new destinations
                 */
                new_destination: z.ZodUnion<[z.ZodLiteral<2>, z.ZodLiteral<3>]>;
                /**
                 * Tier for account settings changes
                 * Always tier 3 for safety
                 */
                account_settings: z.ZodLiteral<3>;
                /**
                 * Delay in seconds before tier 2 transactions auto-approve
                 * Human can veto during this window
                 */
                delay_seconds: z.ZodOptional<z.ZodNumber>;
            }, "strip", z.ZodTypeAny, {
                amount_threshold_drops: string;
                new_destination: 3 | 2;
                account_settings: 3;
                delay_seconds?: number | undefined;
            }, {
                amount_threshold_drops: string;
                new_destination: 3 | 2;
                account_settings: 3;
                delay_seconds?: number | undefined;
            }>;
            /**
             * Notification settings (optional)
             */
            notifications: z.ZodOptional<z.ZodObject<{
                /**
                 * Webhook URL for notifications
                 * Must be HTTPS for production
                 */
                webhook_url: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
                /**
                 * Events that trigger notifications
                 */
                notify_on: z.ZodOptional<z.ZodArray<z.ZodEnum<["tier2", "tier3", "rejection", "all"]>, "many">>;
            }, "strip", z.ZodTypeAny, {
                webhook_url?: string | undefined;
                notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
            }, {
                webhook_url?: string | undefined;
                notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
            }>>;
        }, "strip", z.ZodTypeAny, {
            policy_id: string;
            policy_version: string;
            limits: {
                max_amount_per_tx_drops: string;
                max_daily_volume_drops: string;
                max_tx_per_hour: number;
                max_tx_per_day: number;
            };
            destinations: {
                mode: "allowlist" | "blocklist" | "open";
                allow_new_destinations: boolean;
                allowlist?: string[] | undefined;
                blocklist?: string[] | undefined;
                new_destination_tier?: 3 | 2 | undefined;
            };
            transaction_types: {
                allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
                require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
                blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            };
            escalation: {
                amount_threshold_drops: string;
                new_destination: 3 | 2;
                account_settings: 3;
                delay_seconds?: number | undefined;
            };
            time_controls?: {
                active_hours_utc?: {
                    start: number;
                    end: number;
                } | undefined;
                active_days?: number[] | undefined;
                timezone?: string | undefined;
            } | undefined;
            notifications?: {
                webhook_url?: string | undefined;
                notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
            } | undefined;
        }, {
            policy_id: string;
            policy_version: string;
            limits: {
                max_amount_per_tx_drops: string;
                max_daily_volume_drops: string;
                max_tx_per_hour: number;
                max_tx_per_day: number;
            };
            destinations: {
                mode: "allowlist" | "blocklist" | "open";
                allow_new_destinations: boolean;
                allowlist?: string[] | undefined;
                blocklist?: string[] | undefined;
                new_destination_tier?: 3 | 2 | undefined;
            };
            transaction_types: {
                allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
                require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
                blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            };
            escalation: {
                amount_threshold_drops: string;
                new_destination: 3 | 2;
                account_settings: 3;
                delay_seconds?: number | undefined;
            };
            time_controls?: {
                active_hours_utc?: {
                    start: number;
                    end: number;
                } | undefined;
                active_days?: number[] | undefined;
                timezone?: string | undefined;
            } | undefined;
            notifications?: {
                webhook_url?: string | undefined;
                notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
            } | undefined;
        }>;
        /**
         * Reason for policy change (audit trail)
         */
        reason: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        policy: {
            policy_id: string;
            policy_version: string;
            limits: {
                max_amount_per_tx_drops: string;
                max_daily_volume_drops: string;
                max_tx_per_hour: number;
                max_tx_per_day: number;
            };
            destinations: {
                mode: "allowlist" | "blocklist" | "open";
                allow_new_destinations: boolean;
                allowlist?: string[] | undefined;
                blocklist?: string[] | undefined;
                new_destination_tier?: 3 | 2 | undefined;
            };
            transaction_types: {
                allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
                require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
                blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            };
            escalation: {
                amount_threshold_drops: string;
                new_destination: 3 | 2;
                account_settings: 3;
                delay_seconds?: number | undefined;
            };
            time_controls?: {
                active_hours_utc?: {
                    start: number;
                    end: number;
                } | undefined;
                active_days?: number[] | undefined;
                timezone?: string | undefined;
            } | undefined;
            notifications?: {
                webhook_url?: string | undefined;
                notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
            } | undefined;
        };
        wallet_address: string;
        reason: string;
    }, {
        policy: {
            policy_id: string;
            policy_version: string;
            limits: {
                max_amount_per_tx_drops: string;
                max_daily_volume_drops: string;
                max_tx_per_hour: number;
                max_tx_per_day: number;
            };
            destinations: {
                mode: "allowlist" | "blocklist" | "open";
                allow_new_destinations: boolean;
                allowlist?: string[] | undefined;
                blocklist?: string[] | undefined;
                new_destination_tier?: 3 | 2 | undefined;
            };
            transaction_types: {
                allowed: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[];
                require_approval?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
                blocked?: ("AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge")[] | undefined;
            };
            escalation: {
                amount_threshold_drops: string;
                new_destination: 3 | 2;
                account_settings: 3;
                delay_seconds?: number | undefined;
            };
            time_controls?: {
                active_hours_utc?: {
                    start: number;
                    end: number;
                } | undefined;
                active_days?: number[] | undefined;
                timezone?: string | undefined;
            } | undefined;
            notifications?: {
                webhook_url?: string | undefined;
                notify_on?: ("tier2" | "tier3" | "rejection" | "all")[] | undefined;
            } | undefined;
        };
        wallet_address: string;
        reason: string;
    }>;
    readonly tx_submit: z.ZodObject<{
        /**
         * Hex-encoded signed transaction blob
         */
        signed_tx: z.ZodString;
        /**
         * Network to submit to
         */
        network: z.ZodEnum<["mainnet", "testnet", "devnet"]>;
        /**
         * Whether to wait for validation (optional)
         * @default true
         */
        wait_for_validation: z.ZodDefault<z.ZodOptional<z.ZodBoolean>>;
    }, "strip", z.ZodTypeAny, {
        network: "mainnet" | "testnet" | "devnet";
        signed_tx: string;
        wait_for_validation: boolean;
    }, {
        network: "mainnet" | "testnet" | "devnet";
        signed_tx: string;
        wait_for_validation?: boolean | undefined;
    }>;
    readonly tx_decode: z.ZodObject<{
        /**
         * Transaction blob to decode (signed or unsigned)
         */
        tx_blob: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        tx_blob: string;
    }, {
        tx_blob: string;
    }>;
    readonly network_config: z.ZodObject<{
        /**
         * Network to configure
         */
        network: z.ZodEnum<["mainnet", "testnet", "devnet"]>;
        /**
         * Primary WebSocket URL
         */
        primary_url: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
        /**
         * Fallback WebSocket URLs
         */
        fallback_urls: z.ZodOptional<z.ZodArray<z.ZodEffects<z.ZodString, string, string>, "many">>;
        /**
         * Connection timeout in milliseconds
         */
        connection_timeout_ms: z.ZodOptional<z.ZodNumber>;
    }, "strip", z.ZodTypeAny, {
        network: "mainnet" | "testnet" | "devnet";
        primary_url?: string | undefined;
        fallback_urls?: string[] | undefined;
        connection_timeout_ms?: number | undefined;
    }, {
        network: "mainnet" | "testnet" | "devnet";
        primary_url?: string | undefined;
        fallback_urls?: string[] | undefined;
        connection_timeout_ms?: number | undefined;
    }>;
};
/**
 * Collection of all output schemas for validation
 */
declare const OutputSchemas: {
    readonly wallet_create: z.ZodObject<{
        /**
         * New wallet's XRPL address
         */
        address: z.ZodString;
        /**
         * Agent's signing key (public only)
         */
        regular_key_public: z.ZodEffects<z.ZodString, string, string>;
        /**
         * Encrypted master key backup for recovery
         * Store this securely - required for disaster recovery
         */
        master_key_backup: z.ZodString;
        /**
         * Policy ID applied to this wallet
         */
        policy_id: z.ZodString;
        /**
         * Internal wallet identifier
         */
        wallet_id: z.ZodString;
        /**
         * Network the wallet was created on
         */
        network: z.ZodEnum<["mainnet", "testnet", "devnet"]>;
        /**
         * Creation timestamp
         */
        created_at: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        network: "mainnet" | "testnet" | "devnet";
        policy_id: string;
        address: string;
        regular_key_public: string;
        master_key_backup: string;
        wallet_id: string;
        created_at: string;
    }, {
        network: "mainnet" | "testnet" | "devnet";
        policy_id: string;
        address: string;
        regular_key_public: string;
        master_key_backup: string;
        wallet_id: string;
        created_at: string;
    }>;
    readonly wallet_sign: z.ZodDiscriminatedUnion<"status", [z.ZodObject<{
        /**
         * Transaction status
         */
        status: z.ZodLiteral<"approved">;
        /**
         * Hex-encoded signed transaction blob
         */
        signed_tx: z.ZodString;
        /**
         * Transaction hash
         */
        tx_hash: z.ZodEffects<z.ZodString, string, string>;
        /**
         * Policy tier that approved this transaction
         */
        policy_tier: z.ZodUnion<[z.ZodLiteral<1>, z.ZodLiteral<2>, z.ZodLiteral<3>, z.ZodLiteral<4>]>;
        /**
         * Remaining limits after this transaction
         */
        limits_after: z.ZodObject<{
            /**
             * Remaining daily volume in drops
             */
            daily_remaining_drops: z.ZodEffects<z.ZodString, string, string>;
            /**
             * Remaining transactions this hour
             */
            hourly_tx_remaining: z.ZodNumber;
            /**
             * Remaining transactions today
             */
            daily_tx_remaining: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            daily_remaining_drops: string;
            hourly_tx_remaining: number;
            daily_tx_remaining: number;
        }, {
            daily_remaining_drops: string;
            hourly_tx_remaining: number;
            daily_tx_remaining: number;
        }>;
        /**
         * Timestamp when signed
         */
        signed_at: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        status: "approved";
        signed_tx: string;
        tx_hash: string;
        policy_tier: 3 | 1 | 2 | 4;
        limits_after: {
            daily_remaining_drops: string;
            hourly_tx_remaining: number;
            daily_tx_remaining: number;
        };
        signed_at: string;
    }, {
        status: "approved";
        signed_tx: string;
        tx_hash: string;
        policy_tier: 3 | 1 | 2 | 4;
        limits_after: {
            daily_remaining_drops: string;
            hourly_tx_remaining: number;
            daily_tx_remaining: number;
        };
        signed_at: string;
    }>, z.ZodObject<{
        /**
         * Transaction status
         */
        status: z.ZodLiteral<"pending_approval">;
        /**
         * Approval request ID for tracking
         */
        approval_id: z.ZodString;
        /**
         * Reason approval is required
         */
        reason: z.ZodEnum<["exceeds_autonomous_limit", "new_destination", "restricted_tx_type", "outside_active_hours", "requires_cosign"]>;
        /**
         * When this approval request expires
         */
        expires_at: z.ZodString;
        /**
         * URL for human approval (if configured)
         */
        approval_url: z.ZodOptional<z.ZodString>;
        /**
         * Policy tier required
         */
        policy_tier: z.ZodUnion<[z.ZodLiteral<1>, z.ZodLiteral<2>, z.ZodLiteral<3>, z.ZodLiteral<4>]>;
    }, "strip", z.ZodTypeAny, {
        status: "pending_approval";
        reason: "new_destination" | "exceeds_autonomous_limit" | "restricted_tx_type" | "outside_active_hours" | "requires_cosign";
        policy_tier: 3 | 1 | 2 | 4;
        approval_id: string;
        expires_at: string;
        approval_url?: string | undefined;
    }, {
        status: "pending_approval";
        reason: "new_destination" | "exceeds_autonomous_limit" | "restricted_tx_type" | "outside_active_hours" | "requires_cosign";
        policy_tier: 3 | 1 | 2 | 4;
        approval_id: string;
        expires_at: string;
        approval_url?: string | undefined;
    }>, z.ZodObject<{
        /**
         * Transaction status
         */
        status: z.ZodLiteral<"rejected">;
        /**
         * Human-readable rejection reason
         */
        reason: z.ZodString;
        /**
         * Specific policy violation (if applicable)
         */
        policy_violation: z.ZodOptional<z.ZodObject<{
            /**
             * Which rule was violated
             */
            rule: z.ZodString;
            /**
             * The limit that was exceeded
             */
            limit: z.ZodString;
            /**
             * The actual value that violated the limit
             */
            actual: z.ZodString;
        }, "strip", z.ZodTypeAny, {
            limit: string;
            rule: string;
            actual: string;
        }, {
            limit: string;
            rule: string;
            actual: string;
        }>>;
        /**
         * Policy tier that would be required
         */
        policy_tier: z.ZodLiteral<4>;
    }, "strip", z.ZodTypeAny, {
        status: "rejected";
        reason: string;
        policy_tier: 4;
        policy_violation?: {
            limit: string;
            rule: string;
            actual: string;
        } | undefined;
    }, {
        status: "rejected";
        reason: string;
        policy_tier: 4;
        policy_violation?: {
            limit: string;
            rule: string;
            actual: string;
        } | undefined;
    }>]>;
    readonly wallet_balance: z.ZodObject<{
        /**
         * Wallet address
         */
        address: z.ZodString;
        /**
         * Total balance in drops
         */
        balance_drops: z.ZodEffects<z.ZodString, string, string>;
        /**
         * Total balance in XRP (formatted string)
         */
        balance_xrp: z.ZodString;
        /**
         * Reserve requirement in drops
         */
        reserve_drops: z.ZodEffects<z.ZodString, string, string>;
        /**
         * Available balance (total - reserve) in drops
         */
        available_drops: z.ZodEffects<z.ZodString, string, string>;
        /**
         * Current account sequence number
         */
        sequence: z.ZodNumber;
        /**
         * Whether a regular key is configured
         */
        regular_key_set: z.ZodBoolean;
        /**
         * Multi-signature signer list (if configured)
         */
        signer_list: z.ZodNullable<z.ZodArray<z.ZodObject<{
            /**
             * Signer's XRPL address
             */
            account: z.ZodString;
            /**
             * Signer's weight (contributes to quorum)
             */
            weight: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            account: string;
            weight: number;
        }, {
            account: string;
            weight: number;
        }>, "many">>;
        /**
         * Applied policy ID
         */
        policy_id: z.ZodString;
        /**
         * Network
         */
        network: z.ZodEnum<["mainnet", "testnet", "devnet"]>;
        /**
         * Ledger index from which balance was queried
         * Use this for consistency verification across queries.
         */
        ledger_index: z.ZodNumber;
        /**
         * When balance was queried
         */
        queried_at: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        network: "mainnet" | "testnet" | "devnet";
        policy_id: string;
        address: string;
        balance_drops: string;
        balance_xrp: string;
        reserve_drops: string;
        available_drops: string;
        sequence: number;
        regular_key_set: boolean;
        signer_list: {
            account: string;
            weight: number;
        }[] | null;
        ledger_index: number;
        queried_at: string;
    }, {
        network: "mainnet" | "testnet" | "devnet";
        policy_id: string;
        address: string;
        balance_drops: string;
        balance_xrp: string;
        reserve_drops: string;
        available_drops: string;
        sequence: number;
        regular_key_set: boolean;
        signer_list: {
            account: string;
            weight: number;
        }[] | null;
        ledger_index: number;
        queried_at: string;
    }>;
    readonly wallet_policy_check: z.ZodObject<{
        /**
         * Whether transaction would be approved
         */
        would_approve: z.ZodBoolean;
        /**
         * Tier that would be assigned
         */
        tier: z.ZodUnion<[z.ZodLiteral<1>, z.ZodLiteral<2>, z.ZodLiteral<3>, z.ZodLiteral<4>]>;
        /**
         * Warnings (non-blocking issues)
         */
        warnings: z.ZodArray<z.ZodString, "many">;
        /**
         * Violations (blocking issues)
         */
        violations: z.ZodArray<z.ZodString, "many">;
        /**
         * Current limit status
         */
        limits: z.ZodObject<{
            /**
             * Daily volume used in drops
             */
            daily_volume_used_drops: z.ZodEffects<z.ZodString, string, string>;
            /**
             * Daily volume limit in drops
             */
            daily_volume_limit_drops: z.ZodEffects<z.ZodString, string, string>;
            /**
             * Transactions this hour
             */
            hourly_tx_used: z.ZodNumber;
            /**
             * Hourly transaction limit
             */
            hourly_tx_limit: z.ZodNumber;
            /**
             * Transactions today
             */
            daily_tx_used: z.ZodNumber;
            /**
             * Daily transaction limit
             */
            daily_tx_limit: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            daily_volume_used_drops: string;
            daily_volume_limit_drops: string;
            hourly_tx_used: number;
            hourly_tx_limit: number;
            daily_tx_used: number;
            daily_tx_limit: number;
        }, {
            daily_volume_used_drops: string;
            daily_volume_limit_drops: string;
            hourly_tx_used: number;
            hourly_tx_limit: number;
            daily_tx_used: number;
            daily_tx_limit: number;
        }>;
        /**
         * Transaction details extracted from blob
         */
        transaction_details: z.ZodOptional<z.ZodObject<{
            type: z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>;
            destination: z.ZodOptional<z.ZodString>;
            amount_drops: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
        }, "strip", z.ZodTypeAny, {
            type: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge";
            destination?: string | undefined;
            amount_drops?: string | undefined;
        }, {
            type: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge";
            destination?: string | undefined;
            amount_drops?: string | undefined;
        }>>;
    }, "strip", z.ZodTypeAny, {
        limits: {
            daily_volume_used_drops: string;
            daily_volume_limit_drops: string;
            hourly_tx_used: number;
            hourly_tx_limit: number;
            daily_tx_used: number;
            daily_tx_limit: number;
        };
        would_approve: boolean;
        tier: 3 | 1 | 2 | 4;
        warnings: string[];
        violations: string[];
        transaction_details?: {
            type: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge";
            destination?: string | undefined;
            amount_drops?: string | undefined;
        } | undefined;
    }, {
        limits: {
            daily_volume_used_drops: string;
            daily_volume_limit_drops: string;
            hourly_tx_used: number;
            hourly_tx_limit: number;
            daily_tx_used: number;
            daily_tx_limit: number;
        };
        would_approve: boolean;
        tier: 3 | 1 | 2 | 4;
        warnings: string[];
        violations: string[];
        transaction_details?: {
            type: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge";
            destination?: string | undefined;
            amount_drops?: string | undefined;
        } | undefined;
    }>;
    readonly wallet_rotate: z.ZodObject<{
        /**
         * Rotation status
         */
        status: z.ZodLiteral<"rotated">;
        /**
         * New regular key (public)
         */
        new_regular_key_public: z.ZodEffects<z.ZodString, string, string>;
        /**
         * Whether old key was disabled on-chain
         */
        old_key_disabled: z.ZodBoolean;
        /**
         * Transaction hash for SetRegularKey
         */
        rotation_tx_hash: z.ZodEffects<z.ZodString, string, string>;
        /**
         * Rotation timestamp
         */
        rotated_at: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        status: "rotated";
        new_regular_key_public: string;
        old_key_disabled: boolean;
        rotation_tx_hash: string;
        rotated_at: string;
    }, {
        status: "rotated";
        new_regular_key_public: string;
        old_key_disabled: boolean;
        rotation_tx_hash: string;
        rotated_at: string;
    }>;
    readonly wallet_history: z.ZodObject<{
        /**
         * Wallet address
         */
        address: z.ZodString;
        /**
         * Transaction history entries
         */
        transactions: z.ZodArray<z.ZodObject<{
            /**
             * Transaction hash
             */
            hash: z.ZodEffects<z.ZodString, string, string>;
            /**
             * Transaction type
             */
            type: z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>;
            /**
             * Amount in drops (for Payment-like transactions)
             */
            amount_drops: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
            /**
             * Destination address (for Payment-like transactions)
             */
            destination: z.ZodOptional<z.ZodString>;
            /**
             * Timestamp when executed
             */
            timestamp: z.ZodString;
            /**
             * Policy tier that approved this
             */
            policy_tier: z.ZodUnion<[z.ZodLiteral<1>, z.ZodLiteral<2>, z.ZodLiteral<3>, z.ZodLiteral<4>]>;
            /**
             * Context provided when signed
             */
            context: z.ZodOptional<z.ZodString>;
            /**
             * Ledger index where validated
             */
            ledger_index: z.ZodNumber;
            /**
             * Whether transaction succeeded
             */
            success: z.ZodBoolean;
        }, "strip", z.ZodTypeAny, {
            type: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge";
            policy_tier: 3 | 1 | 2 | 4;
            ledger_index: number;
            hash: string;
            timestamp: string;
            success: boolean;
            context?: string | undefined;
            destination?: string | undefined;
            amount_drops?: string | undefined;
        }, {
            type: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge";
            policy_tier: 3 | 1 | 2 | 4;
            ledger_index: number;
            hash: string;
            timestamp: string;
            success: boolean;
            context?: string | undefined;
            destination?: string | undefined;
            amount_drops?: string | undefined;
        }>, "many">;
        /**
         * Pagination marker for next page
         */
        marker: z.ZodOptional<z.ZodString>;
        /**
         * Whether there are more results
         */
        has_more: z.ZodBoolean;
    }, "strip", z.ZodTypeAny, {
        address: string;
        transactions: {
            type: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge";
            policy_tier: 3 | 1 | 2 | 4;
            ledger_index: number;
            hash: string;
            timestamp: string;
            success: boolean;
            context?: string | undefined;
            destination?: string | undefined;
            amount_drops?: string | undefined;
        }[];
        has_more: boolean;
        marker?: string | undefined;
    }, {
        address: string;
        transactions: {
            type: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge";
            policy_tier: 3 | 1 | 2 | 4;
            ledger_index: number;
            hash: string;
            timestamp: string;
            success: boolean;
            context?: string | undefined;
            destination?: string | undefined;
            amount_drops?: string | undefined;
        }[];
        has_more: boolean;
        marker?: string | undefined;
    }>;
    readonly wallet_list: z.ZodObject<{
        /**
         * List of managed wallets
         */
        wallets: z.ZodArray<z.ZodObject<{
            /**
             * Internal wallet ID
             */
            wallet_id: z.ZodString;
            /**
             * XRPL address
             */
            address: z.ZodString;
            /**
             * Human-readable name
             */
            name: z.ZodOptional<z.ZodString>;
            /**
             * Network
             */
            network: z.ZodEnum<["mainnet", "testnet", "devnet"]>;
            /**
             * Applied policy ID
             */
            policy_id: z.ZodString;
            /**
             * Creation timestamp
             */
            created_at: z.ZodString;
        }, "strip", z.ZodTypeAny, {
            network: "mainnet" | "testnet" | "devnet";
            policy_id: string;
            address: string;
            wallet_id: string;
            created_at: string;
            name?: string | undefined;
        }, {
            network: "mainnet" | "testnet" | "devnet";
            policy_id: string;
            address: string;
            wallet_id: string;
            created_at: string;
            name?: string | undefined;
        }>, "many">;
        /**
         * Total count
         */
        total: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        wallets: {
            network: "mainnet" | "testnet" | "devnet";
            policy_id: string;
            address: string;
            wallet_id: string;
            created_at: string;
            name?: string | undefined;
        }[];
        total: number;
    }, {
        wallets: {
            network: "mainnet" | "testnet" | "devnet";
            policy_id: string;
            address: string;
            wallet_id: string;
            created_at: string;
            name?: string | undefined;
        }[];
        total: number;
    }>;
    readonly wallet_fund: z.ZodObject<{
        /**
         * Funding status
         */
        status: z.ZodEnum<["funded", "pending", "failed"]>;
        /**
         * Amount funded in drops
         */
        amount_drops: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
        /**
         * Faucet transaction hash
         */
        tx_hash: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
        /**
         * Initial balance after funding in drops
         * Use this for verification in tests instead of hardcoded values.
         */
        initial_balance_drops: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
        /**
         * New balance after funding (alias for initial_balance_drops)
         * @deprecated Use initial_balance_drops
         */
        new_balance_drops: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
        /**
         * Whether the account is ready for queries on validated ledger
         * True means account_info will succeed.
         */
        account_ready: z.ZodOptional<z.ZodBoolean>;
        /**
         * Ledger index where account was confirmed
         */
        ledger_index: z.ZodOptional<z.ZodNumber>;
        /**
         * Error message if failed
         */
        error: z.ZodOptional<z.ZodString>;
        /**
         * Informational message
         */
        message: z.ZodOptional<z.ZodString>;
        /**
         * Faucet URL used (for debugging)
         */
        faucet_url: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        status: "funded" | "pending" | "failed";
        message?: string | undefined;
        tx_hash?: string | undefined;
        ledger_index?: number | undefined;
        amount_drops?: string | undefined;
        initial_balance_drops?: string | undefined;
        new_balance_drops?: string | undefined;
        account_ready?: boolean | undefined;
        error?: string | undefined;
        faucet_url?: string | undefined;
    }, {
        status: "funded" | "pending" | "failed";
        message?: string | undefined;
        tx_hash?: string | undefined;
        ledger_index?: number | undefined;
        amount_drops?: string | undefined;
        initial_balance_drops?: string | undefined;
        new_balance_drops?: string | undefined;
        account_ready?: boolean | undefined;
        error?: string | undefined;
        faucet_url?: string | undefined;
    }>;
    readonly policy_set: z.ZodObject<{
        /**
         * Update status
         */
        status: z.ZodEnum<["applied", "pending_approval"]>;
        /**
         * Previous policy ID
         */
        previous_policy_id: z.ZodString;
        /**
         * New policy ID
         */
        new_policy_id: z.ZodString;
        /**
         * When applied (if status is 'applied')
         */
        applied_at: z.ZodOptional<z.ZodString>;
        /**
         * Approval ID (if status is 'pending_approval')
         */
        approval_id: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        status: "pending_approval" | "applied";
        previous_policy_id: string;
        new_policy_id: string;
        approval_id?: string | undefined;
        applied_at?: string | undefined;
    }, {
        status: "pending_approval" | "applied";
        previous_policy_id: string;
        new_policy_id: string;
        approval_id?: string | undefined;
        applied_at?: string | undefined;
    }>;
    readonly tx_submit: z.ZodObject<{
        /**
         * Transaction hash
         */
        tx_hash: z.ZodEffects<z.ZodString, string, string>;
        /**
         * Result from XRPL
         */
        result: z.ZodObject<{
            /**
             * Result code from XRPL
             */
            result_code: z.ZodString;
            /**
             * Human-readable result message
             */
            result_message: z.ZodString;
            /**
             * Whether transaction succeeded
             */
            success: z.ZodBoolean;
        }, "strip", z.ZodTypeAny, {
            success: boolean;
            result_code: string;
            result_message: string;
        }, {
            success: boolean;
            result_code: string;
            result_message: string;
        }>;
        /**
         * Ledger index (if validated)
         */
        ledger_index: z.ZodOptional<z.ZodNumber>;
        /**
         * When submitted
         */
        submitted_at: z.ZodString;
        /**
         * When validated (if wait_for_validation was true)
         */
        validated_at: z.ZodOptional<z.ZodString>;
        /**
         * Transaction type that was submitted
         * Useful for routing post-submission logic.
         */
        tx_type: z.ZodOptional<z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>>;
        /**
         * Sequence number consumed by this transaction
         * Useful for tracking escrows or other sequence-dependent operations.
         */
        sequence_used: z.ZodOptional<z.ZodNumber>;
        /**
         * Escrow reference (only for EscrowCreate transactions)
         * Contains owner and sequence needed for EscrowFinish/EscrowCancel.
         */
        escrow_reference: z.ZodOptional<z.ZodObject<{
            /**
             * Owner address (creator of the escrow)
             */
            owner: z.ZodString;
            /**
             * Sequence number to use for EscrowFinish/EscrowCancel
             * This is the OfferSequence field in finish/cancel transactions.
             */
            sequence: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            sequence: number;
            owner: string;
        }, {
            sequence: number;
            owner: string;
        }>>;
        /**
         * Next sequence number to use for this account (only on success)
         * Use this for the next transaction instead of querying the ledger.
         * This prevents tefPAST_SEQ race conditions in rapid multi-tx workflows.
         * @since 2.1.0
         */
        next_sequence: z.ZodOptional<z.ZodNumber>;
    }, "strip", z.ZodTypeAny, {
        tx_hash: string;
        result: {
            success: boolean;
            result_code: string;
            result_message: string;
        };
        submitted_at: string;
        ledger_index?: number | undefined;
        validated_at?: string | undefined;
        tx_type?: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge" | undefined;
        sequence_used?: number | undefined;
        escrow_reference?: {
            sequence: number;
            owner: string;
        } | undefined;
        next_sequence?: number | undefined;
    }, {
        tx_hash: string;
        result: {
            success: boolean;
            result_code: string;
            result_message: string;
        };
        submitted_at: string;
        ledger_index?: number | undefined;
        validated_at?: string | undefined;
        tx_type?: "AccountDelete" | "AccountSet" | "AMMBid" | "AMMCreate" | "AMMDelete" | "AMMDeposit" | "AMMVote" | "AMMWithdraw" | "CheckCancel" | "CheckCash" | "CheckCreate" | "Clawback" | "CredentialAccept" | "CredentialCreate" | "CredentialDelete" | "DelegateSet" | "DepositPreauth" | "DIDDelete" | "DIDSet" | "EnableAmendment" | "EscrowCancel" | "EscrowCreate" | "EscrowFinish" | "MPTokenAuthorize" | "MPTokenIssuanceCreate" | "MPTokenIssuanceDestroy" | "MPTokenIssuanceSet" | "NFTokenAcceptOffer" | "NFTokenBurn" | "NFTokenCancelOffer" | "NFTokenCreateOffer" | "NFTokenMint" | "OfferCancel" | "OfferCreate" | "OracleDelete" | "OracleSet" | "Payment" | "PaymentChannelClaim" | "PaymentChannelCreate" | "PaymentChannelFund" | "PermissionedDomainDelete" | "PermissionedDomainSet" | "SetFee" | "SetRegularKey" | "SignerListSet" | "TicketCreate" | "TrustSet" | "UNLModify" | "XChainAccountCreateCommit" | "XChainAddClaimAttestation" | "XChainClaim" | "XChainCommit" | "XChainCreateBridge" | "XChainCreateClaimID" | "XChainModifyBridge" | undefined;
        sequence_used?: number | undefined;
        escrow_reference?: {
            sequence: number;
            owner: string;
        } | undefined;
        next_sequence?: number | undefined;
    }>;
    readonly tx_decode: z.ZodObject<{
        /**
         * Decoded transaction fields
         */
        transaction: z.ZodObject<{
            [x: string]: z.ZodString | z.ZodNumber | z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]> | z.ZodOptional<z.ZodString> | z.ZodUnknown;
            /**
             * Transaction type
             */
            TransactionType: z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>;
            /**
             * Source account
             */
            Account: z.ZodString;
            /**
             * Destination (for Payment-like transactions)
             */
            Destination: z.ZodOptional<z.ZodString>;
            /**
             * Amount in drops (for Payment transactions)
             */
            Amount: z.ZodOptional<z.ZodString>;
            /**
             * Transaction fee in drops
             */
            Fee: z.ZodString;
            /**
             * Sequence number
             */
            Sequence: z.ZodNumber;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            [x: string]: z.ZodString | z.ZodNumber | z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]> | z.ZodOptional<z.ZodString> | z.ZodUnknown;
            /**
             * Transaction type
             */
            TransactionType: z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>;
            /**
             * Source account
             */
            Account: z.ZodString;
            /**
             * Destination (for Payment-like transactions)
             */
            Destination: z.ZodOptional<z.ZodString>;
            /**
             * Amount in drops (for Payment transactions)
             */
            Amount: z.ZodOptional<z.ZodString>;
            /**
             * Transaction fee in drops
             */
            Fee: z.ZodString;
            /**
             * Sequence number
             */
            Sequence: z.ZodNumber;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            [x: string]: z.ZodString | z.ZodNumber | z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]> | z.ZodOptional<z.ZodString> | z.ZodUnknown;
            /**
             * Transaction type
             */
            TransactionType: z.ZodEnum<["AccountDelete", "AccountSet", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit", "AMMVote", "AMMWithdraw", "CheckCancel", "CheckCash", "CheckCreate", "Clawback", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet", "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate", "EscrowFinish", "MPTokenAuthorize", "MPTokenIssuanceCreate", "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn", "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim", "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet", "SetFee", "SetRegularKey", "SignerListSet", "TicketCreate", "TrustSet", "UNLModify", "XChainAccountCreateCommit", "XChainAddClaimAttestation", "XChainClaim", "XChainCommit", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge", "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge"]>;
            /**
             * Source account
             */
            Account: z.ZodString;
            /**
             * Destination (for Payment-like transactions)
             */
            Destination: z.ZodOptional<z.ZodString>;
            /**
             * Amount in drops (for Payment transactions)
             */
            Amount: z.ZodOptional<z.ZodString>;
            /**
             * Transaction fee in drops
             */
            Fee: z.ZodString;
            /**
             * Sequence number
             */
            Sequence: z.ZodNumber;
        }, z.ZodTypeAny, "passthrough">>;
        /**
         * Transaction hash (if signed)
         */
        hash: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
        /**
         * Whether transaction is signed
         */
        is_signed: z.ZodBoolean;
        /**
         * Signing public key (if signed)
         */
        signing_public_key: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    }, "strip", z.ZodTypeAny, {
        transaction: {
            [x: string]: unknown;
            TransactionType?: unknown;
            Account?: unknown;
            Destination?: unknown;
            Amount?: unknown;
            Fee?: unknown;
            Sequence?: unknown;
        } & {
            [k: string]: unknown;
        };
        is_signed: boolean;
        hash?: string | undefined;
        signing_public_key?: string | undefined;
    }, {
        transaction: {
            [x: string]: unknown;
            TransactionType?: unknown;
            Account?: unknown;
            Destination?: unknown;
            Amount?: unknown;
            Fee?: unknown;
            Sequence?: unknown;
        } & {
            [k: string]: unknown;
        };
        is_signed: boolean;
        hash?: string | undefined;
        signing_public_key?: string | undefined;
    }>;
    readonly network_config: z.ZodObject<{
        /**
         * Configuration status
         */
        status: z.ZodLiteral<"configured">;
        /**
         * Network that was configured
         */
        network: z.ZodEnum<["mainnet", "testnet", "devnet"]>;
        /**
         * Applied configuration
         */
        config: z.ZodObject<{
            primary_url: z.ZodString;
            fallback_urls: z.ZodArray<z.ZodString, "many">;
            connection_timeout_ms: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            primary_url: string;
            fallback_urls: string[];
            connection_timeout_ms: number;
        }, {
            primary_url: string;
            fallback_urls: string[];
            connection_timeout_ms: number;
        }>;
    }, "strip", z.ZodTypeAny, {
        network: "mainnet" | "testnet" | "devnet";
        status: "configured";
        config: {
            primary_url: string;
            fallback_urls: string[];
            connection_timeout_ms: number;
        };
    }, {
        network: "mainnet" | "testnet" | "devnet";
        status: "configured";
        config: {
            primary_url: string;
            fallback_urls: string[];
            connection_timeout_ms: number;
        };
    }>;
    readonly error: z.ZodObject<{
        /**
         * Error code for programmatic handling
         */
        code: z.ZodEnum<["VALIDATION_ERROR", "INVALID_ADDRESS", "INVALID_TRANSACTION", "INVALID_POLICY", "POLICY_VIOLATION", "RATE_LIMIT_EXCEEDED", "LIMIT_EXCEEDED", "DESTINATION_BLOCKED", "TRANSACTION_TYPE_BLOCKED", "WALLET_NOT_FOUND", "WALLET_LOCKED", "UNAUTHORIZED", "APPROVAL_REQUIRED", "APPROVAL_EXPIRED", "NETWORK_ERROR", "CONNECTION_FAILED", "SUBMISSION_FAILED", "TIMEOUT", "INTERNAL_ERROR", "KEYSTORE_ERROR", "SIGNING_ERROR", "ENCRYPTION_ERROR", "INSUFFICIENT_BALANCE", "INSUFFICIENT_RESERVE", "SEQUENCE_ERROR", "LEDGER_NOT_FOUND"]>;
        /**
         * Human-readable error message
         */
        message: z.ZodString;
        /**
         * Additional error details
         */
        details: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
        /**
         * Request ID for correlation
         */
        request_id: z.ZodOptional<z.ZodString>;
        /**
         * Timestamp
         */
        timestamp: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        code: "VALIDATION_ERROR" | "INVALID_ADDRESS" | "INVALID_TRANSACTION" | "INVALID_POLICY" | "POLICY_VIOLATION" | "RATE_LIMIT_EXCEEDED" | "LIMIT_EXCEEDED" | "DESTINATION_BLOCKED" | "TRANSACTION_TYPE_BLOCKED" | "WALLET_NOT_FOUND" | "WALLET_LOCKED" | "UNAUTHORIZED" | "APPROVAL_REQUIRED" | "APPROVAL_EXPIRED" | "NETWORK_ERROR" | "CONNECTION_FAILED" | "SUBMISSION_FAILED" | "TIMEOUT" | "INTERNAL_ERROR" | "KEYSTORE_ERROR" | "SIGNING_ERROR" | "ENCRYPTION_ERROR" | "INSUFFICIENT_BALANCE" | "INSUFFICIENT_RESERVE" | "SEQUENCE_ERROR" | "LEDGER_NOT_FOUND";
        message: string;
        timestamp: string;
        details?: Record<string, unknown> | undefined;
        request_id?: string | undefined;
    }, {
        code: "VALIDATION_ERROR" | "INVALID_ADDRESS" | "INVALID_TRANSACTION" | "INVALID_POLICY" | "POLICY_VIOLATION" | "RATE_LIMIT_EXCEEDED" | "LIMIT_EXCEEDED" | "DESTINATION_BLOCKED" | "TRANSACTION_TYPE_BLOCKED" | "WALLET_NOT_FOUND" | "WALLET_LOCKED" | "UNAUTHORIZED" | "APPROVAL_REQUIRED" | "APPROVAL_EXPIRED" | "NETWORK_ERROR" | "CONNECTION_FAILED" | "SUBMISSION_FAILED" | "TIMEOUT" | "INTERNAL_ERROR" | "KEYSTORE_ERROR" | "SIGNING_ERROR" | "ENCRYPTION_ERROR" | "INSUFFICIENT_BALANCE" | "INSUFFICIENT_RESERVE" | "SEQUENCE_ERROR" | "LEDGER_NOT_FOUND";
        message: string;
        timestamp: string;
        details?: Record<string, unknown> | undefined;
        request_id?: string | undefined;
    }>;
};
/**
 * Tool names type for type-safe tool registration
 */
type ToolName = keyof typeof InputSchemas;

export { type AgentWalletPolicy, AgentWalletPolicySchema, type ApprovalTier, ApprovalTierSchema, type AuditEventType, AuditEventTypeSchema, type AuditLogEntry, AuditLogEntrySchema, type DecodedTransaction, DecodedTransactionSchema, type DestinationMode, DestinationModeSchema, type DropsAmount, DropsAmountOptionalZeroSchema, DropsAmountSchema, type ErrorCode, ErrorCodeSchema, type ErrorResponse, ErrorResponseSchema, type EscrowReference, EscrowReferenceSchema, type HexString, type HexStringRaw, HexStringRawSchema, HexStringSchema, InputSchemas, type LedgerIndex, LedgerIndexSchema, type LimitStatus, LimitStatusSchema, type Network, type NetworkConfigInput, NetworkConfigInputSchema, type NetworkConfigOutput, NetworkConfigOutputSchema, NetworkSchema, type NotificationEvent, NotificationEventSchema, OutputSchemas, type PaginationMarker, PaginationMarkerSchema, type PolicyDestinations, PolicyDestinationsSchema, type PolicyEscalation, PolicyEscalationSchema, type PolicyLimits, PolicyLimitsSchema, type PolicyNotifications, PolicyNotificationsSchema, type PolicySetInput, PolicySetInputSchema, type PolicySetOutput, PolicySetOutputSchema, type PolicyTimeControls, PolicyTimeControlsSchema, type PolicyTransactionTypes, PolicyTransactionTypesSchema, type PolicyViolation, PolicyViolationSchema, type PublicKey, PublicKeySchema, type RemainingLimits, RemainingLimitsSchema, type SequenceNumber, SequenceNumberSchema, type SignedTransactionBlob, SignedTransactionBlobSchema, type SignerEntry, SignerEntrySchema, type Timestamp, TimestampSchema, type ToolName, type TransactionHash, TransactionHashSchema, type TransactionHistoryEntry, TransactionHistoryEntrySchema, type TransactionResult, TransactionResultSchema, type TransactionType, TransactionTypeSchema, type TxDecodeInput, TxDecodeInputSchema, type TxDecodeOutput, TxDecodeOutputSchema, type TxSubmitInput, TxSubmitInputSchema, type TxSubmitOutput, TxSubmitOutputSchema, type UnsignedTransactionBlob, UnsignedTransactionBlobSchema, type WalletBalanceInput, WalletBalanceInputSchema, type WalletBalanceOutput, WalletBalanceOutputSchema, type WalletCreateInput, WalletCreateInputSchema, type WalletCreateOutput, WalletCreateOutputSchema, type WalletFundInput, WalletFundInputSchema, type WalletFundOutput, WalletFundOutputSchema, type WalletHistoryInput, WalletHistoryInputSchema, type WalletHistoryOutput, WalletHistoryOutputSchema, type WalletId, WalletIdSchema, type WalletImportInput, WalletImportInputSchema, type WalletListEntry, WalletListEntrySchema, type WalletListInput, WalletListInputSchema, type WalletListOutput, WalletListOutputSchema, type WalletName, WalletNameSchema, type WalletPolicyCheckInput, WalletPolicyCheckInputSchema, type WalletPolicyCheckOutput, WalletPolicyCheckOutputSchema, type WalletRotateInput, WalletRotateInputSchema, type WalletRotateOutput, WalletRotateOutputSchema, type WalletSignApprovedOutput, WalletSignApprovedOutputSchema, type WalletSignInput, WalletSignInputSchema, type WalletSignOutput, WalletSignOutputSchema, type WalletSignPendingOutput, WalletSignPendingOutputSchema, type WalletSignRejectedOutput, WalletSignRejectedOutputSchema, type XRPLAddress, XRPLAddressSchema };
