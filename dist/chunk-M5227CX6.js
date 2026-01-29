#!/usr/bin/env node
import { z } from 'zod';

var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});
var __commonJS = (cb, mod) => function __require2() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var MAX_DROPS = BigInt("100000000000000000");
BigInt("10000000");
var XRPL_TRANSACTION_TYPES = [
  "AccountDelete",
  "AccountSet",
  "AMMBid",
  "AMMCreate",
  "AMMDelete",
  "AMMDeposit",
  "AMMVote",
  "AMMWithdraw",
  "CheckCancel",
  "CheckCash",
  "CheckCreate",
  "Clawback",
  "DepositPreauth",
  "DIDDelete",
  "DIDSet",
  "EnableAmendment",
  "EscrowCancel",
  "EscrowCreate",
  "EscrowFinish",
  "NFTokenAcceptOffer",
  "NFTokenBurn",
  "NFTokenCancelOffer",
  "NFTokenCreateOffer",
  "NFTokenMint",
  "OfferCancel",
  "OfferCreate",
  "Payment",
  "PaymentChannelClaim",
  "PaymentChannelCreate",
  "PaymentChannelFund",
  "SetFee",
  "SetRegularKey",
  "SignerListSet",
  "TicketCreate",
  "TrustSet",
  "UNLModify",
  "XChainAccountCreateCommit",
  "XChainAddClaimAttestation",
  "XChainClaim",
  "XChainCommit",
  "XChainCreateBridge",
  "XChainCreateClaimID",
  "XChainModifyBridge"
];
var XRPLAddressSchema = z.string().min(25, "XRPL address must be at least 25 characters").max(35, "XRPL address must be at most 35 characters").regex(
  /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/,
  'Invalid XRPL address format: must start with "r" followed by 24-34 Base58 characters'
).describe("XRPL Classic Address (r-address format)");
var DropsAmountSchema = z.string().regex(/^[1-9]\d*$/, "Drops must be a positive integer string without leading zeros").refine(
  (val) => {
    try {
      const drops = BigInt(val);
      return drops >= 1n && drops <= MAX_DROPS;
    } catch {
      return false;
    }
  },
  { message: `Drops must be between 1 and ${MAX_DROPS.toString()}` }
).describe("XRP amount in drops (1 XRP = 1,000,000 drops)");
var DropsAmountOptionalZeroSchema = z.string().regex(/^\d+$/, "Drops must be a non-negative integer string").refine(
  (val) => {
    try {
      const drops = BigInt(val);
      return drops >= 0n && drops <= MAX_DROPS;
    } catch {
      return false;
    }
  },
  { message: `Drops must be between 0 and ${MAX_DROPS.toString()}` }
).describe("XRP amount in drops (can be zero)");
var TransactionHashSchema = z.string().length(64, "Transaction hash must be exactly 64 characters").regex(/^[A-Fa-f0-9]{64}$/, "Transaction hash must be 64 hexadecimal characters").transform((val) => val.toUpperCase()).describe("XRPL transaction hash (64-character hex string)");
var LedgerIndexSchema = z.union([
  z.number().int().positive(),
  z.enum(["validated", "closed", "current"])
]).describe('XRPL ledger index (number or "validated"/"closed"/"current")');
var PublicKeySchema = z.string().length(66, "Public key must be exactly 66 characters").refine(
  (val) => {
    if (val.startsWith("ED")) {
      return /^ED[A-Fa-f0-9]{64}$/.test(val);
    }
    if (val.startsWith("02") || val.startsWith("03")) {
      return /^0[23][A-Fa-f0-9]{64}$/.test(val);
    }
    return false;
  },
  {
    message: "Public key must be ED25519 (ED prefix) or secp256k1 (02/03 prefix) with 64 hex characters"
  }
).describe("XRPL public key (Ed25519 or secp256k1 format)");
var NetworkSchema = z.enum(["mainnet", "testnet", "devnet"]).describe("XRPL network environment");
var TransactionTypeSchema = z.enum(XRPL_TRANSACTION_TYPES).describe("XRPL transaction type");
var SequenceNumberSchema = z.number().int().min(1).max(4294967295).describe("XRPL account sequence number");
var HexStringSchema = z.string().regex(/^[A-Fa-f0-9]*$/, "Must be a valid hexadecimal string").transform((val) => val.toUpperCase()).describe("Hexadecimal string (normalized to uppercase)");
var HexStringRawSchema = z.string().regex(/^[A-Fa-f0-9]*$/, "Must be a valid hexadecimal string").describe("Hexadecimal string (raw)");
var UnsignedTransactionBlobSchema = z.string().min(20, "Transaction blob too short").max(1e6, "Transaction blob exceeds maximum size").regex(/^[A-Fa-f0-9]+$/, "Transaction blob must be hexadecimal").describe("Unsigned XRPL transaction blob (hex-encoded)");
var SignedTransactionBlobSchema = z.string().min(100, "Signed transaction blob too short").max(1e6, "Transaction blob exceeds maximum size").regex(/^[A-Fa-f0-9]+$/, "Transaction blob must be hexadecimal").describe("Signed XRPL transaction blob (hex-encoded)");
var WalletIdSchema = z.string().min(1, "Wallet ID cannot be empty").max(64, "Wallet ID too long").regex(
  /^[a-zA-Z0-9][a-zA-Z0-9_-]*$/,
  "Wallet ID must start with alphanumeric and contain only alphanumeric, hyphens, or underscores"
).describe("Internal wallet identifier");
var WalletNameSchema = z.string().min(1, "Wallet name cannot be empty").max(64, "Wallet name too long").describe("Human-readable wallet name");
var TimestampSchema = z.string().datetime({ message: "Must be a valid ISO 8601 timestamp" }).describe("ISO 8601 timestamp");
var PaginationMarkerSchema = z.string().min(1).max(1e3).describe("Pagination marker from previous response");
var ApprovalTierSchema = z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4)]).describe("Transaction approval tier (1=autonomous, 2=delayed, 3=co-sign, 4=prohibited)");
var PolicyLimitsSchema = z.object({
  /**
   * Maximum amount per single transaction in drops
   * @example "10000000" (10 XRP)
   */
  max_amount_per_tx_drops: DropsAmountSchema.describe(
    "Maximum amount per single transaction in drops"
  ),
  /**
   * Maximum daily transaction volume in drops
   * Resets at midnight UTC
   * @example "100000000" (100 XRP)
   */
  max_daily_volume_drops: DropsAmountSchema.describe(
    "Maximum daily transaction volume in drops"
  ),
  /**
   * Maximum transactions per hour (rolling window)
   */
  max_tx_per_hour: z.number().int().min(1).max(1e3).describe("Maximum transactions per hour"),
  /**
   * Maximum transactions per day (rolling window)
   */
  max_tx_per_day: z.number().int().min(1).max(1e4).describe("Maximum transactions per day")
}).describe("Transaction and volume limits");
var DestinationModeSchema = z.enum(["allowlist", "blocklist", "open"]).describe("Destination control mode");
var PolicyDestinationsSchema = z.object({
  /**
   * Destination filtering mode
   */
  mode: DestinationModeSchema,
  /**
   * Allowed destination addresses (used when mode='allowlist')
   */
  allowlist: z.array(XRPLAddressSchema).max(1e3).optional().describe("Allowed destination addresses"),
  /**
   * Blocked destination addresses (always enforced regardless of mode)
   * Used for known scam/malicious addresses
   */
  blocklist: z.array(XRPLAddressSchema).max(1e4).optional().describe("Blocked destination addresses"),
  /**
   * Whether to allow transactions to previously unseen addresses
   */
  allow_new_destinations: z.boolean().describe("Allow transactions to new/unknown addresses"),
  /**
   * Approval tier required for new destinations
   * Only used when allow_new_destinations is true
   */
  new_destination_tier: z.union([z.literal(2), z.literal(3)]).optional().describe("Approval tier for new destinations")
}).describe("Destination address controls");
var PolicyTransactionTypesSchema = z.object({
  /**
   * Transaction types the agent can execute autonomously
   * @example ["Payment", "EscrowFinish", "EscrowCancel"]
   */
  allowed: z.array(TransactionTypeSchema).min(1).describe("Transaction types allowed for autonomous signing"),
  /**
   * Transaction types that require human approval (tier 2/3)
   * @example ["EscrowCreate", "TrustSet"]
   */
  require_approval: z.array(TransactionTypeSchema).optional().describe("Transaction types requiring human approval"),
  /**
   * Transaction types that are never allowed (tier 4)
   * Typically account control operations
   * @example ["SetRegularKey", "SignerListSet", "AccountDelete"]
   */
  blocked: z.array(TransactionTypeSchema).optional().describe("Transaction types that are never allowed")
}).describe("Transaction type controls");
var PolicyTimeControlsSchema = z.object({
  /**
   * Active hours in UTC (24-hour format)
   * Transactions outside these hours are escalated to tier 2/3
   */
  active_hours_utc: z.object({
    start: z.number().int().min(0).max(23).describe("Start hour (0-23)"),
    end: z.number().int().min(0).max(23).describe("End hour (0-23)")
  }).optional().describe("Active hours in UTC"),
  /**
   * Active days of the week
   * 0 = Sunday, 6 = Saturday
   */
  active_days: z.array(z.number().int().min(0).max(6)).min(1).max(7).optional().describe("Active days (0=Sunday, 6=Saturday)"),
  /**
   * Timezone for interpreting active hours
   * @example "America/New_York"
   */
  timezone: z.string().min(1).max(50).optional().describe("IANA timezone identifier")
}).describe("Time-based access controls");
var PolicyEscalationSchema = z.object({
  /**
   * Amount threshold for escalation to tier 2 (drops)
   * Transactions above this require delayed/human approval
   */
  amount_threshold_drops: DropsAmountSchema.describe(
    "Amount threshold for tier escalation"
  ),
  /**
   * Tier assigned to transactions with new destinations
   */
  new_destination: z.union([z.literal(2), z.literal(3)]).describe("Tier for new destination addresses"),
  /**
   * Tier for account settings changes
   * Always tier 3 for safety
   */
  account_settings: z.literal(3).describe("Tier for account settings changes"),
  /**
   * Delay in seconds before tier 2 transactions auto-approve
   * Human can veto during this window
   */
  delay_seconds: z.number().int().min(60).max(86400).optional().describe("Delay before tier 2 auto-approval (60-86400 seconds)")
}).describe("Escalation thresholds and rules");
var NotificationEventSchema = z.enum(["tier2", "tier3", "rejection", "all"]).describe("Notification event type");
var PolicyNotificationsSchema = z.object({
  /**
   * Webhook URL for notifications
   * Must be HTTPS for production
   */
  webhook_url: z.string().url().refine(
    (url) => url.startsWith("https://") || url.startsWith("http://localhost"),
    "Webhook URL must use HTTPS (except localhost for development)"
  ).optional().describe("Webhook URL for notifications"),
  /**
   * Events that trigger notifications
   */
  notify_on: z.array(NotificationEventSchema).min(1).optional().describe("Events that trigger notifications")
}).describe("Notification configuration");
var AgentWalletPolicySchema = z.object({
  /**
   * Unique policy identifier
   * @example "conservative-v1"
   */
  policy_id: z.string().min(1).max(64).regex(/^[a-z0-9-]+$/, "Policy ID must be lowercase alphanumeric with hyphens").describe("Unique policy identifier"),
  /**
   * Policy version for tracking changes
   * Semantic versioning recommended
   */
  policy_version: z.string().regex(/^\d+\.\d+(\.\d+)?$/, 'Version must be semver format (e.g., "1.0" or "1.0.0")').describe("Policy version (semver)"),
  /**
   * Transaction and volume limits
   */
  limits: PolicyLimitsSchema,
  /**
   * Destination address controls
   */
  destinations: PolicyDestinationsSchema,
  /**
   * Transaction type restrictions
   */
  transaction_types: PolicyTransactionTypesSchema,
  /**
   * Time-based access controls (optional)
   */
  time_controls: PolicyTimeControlsSchema.optional(),
  /**
   * Escalation thresholds
   */
  escalation: PolicyEscalationSchema,
  /**
   * Notification settings (optional)
   */
  notifications: PolicyNotificationsSchema.optional()
}).describe("Complete agent wallet policy configuration");
var WalletCreateInputSchema = z.object({
  /**
   * Target network for the wallet
   * Keys are isolated per network
   */
  network: NetworkSchema,
  /**
   * Policy to apply to this wallet
   * Defines all security constraints
   */
  policy: AgentWalletPolicySchema,
  /**
   * Human-readable wallet name (optional)
   */
  wallet_name: WalletNameSchema.optional(),
  /**
   * Address to fund the new wallet from (optional)
   * Requires separate signing outside this MCP
   */
  funding_source: XRPLAddressSchema.optional(),
  /**
   * Initial funding amount in drops (optional)
   * Must meet minimum reserve requirements
   */
  initial_funding_drops: DropsAmountSchema.optional()
}).describe("Create a new agent wallet");
var WalletSignInputSchema = z.object({
  /**
   * Address of the wallet to sign with
   */
  wallet_address: XRPLAddressSchema,
  /**
   * Hex-encoded unsigned transaction blob
   */
  unsigned_tx: UnsignedTransactionBlobSchema,
  /**
   * Context/reason for this transaction (for audit trail)
   * Describe why the agent is making this transaction
   * @example "Completing escrow for order #12345"
   */
  context: z.string().max(500).optional().describe("Reason for this transaction (audit trail)")
}).describe("Sign a transaction with policy enforcement");
var WalletBalanceInputSchema = z.object({
  /**
   * Address to query balance for
   */
  wallet_address: XRPLAddressSchema
}).describe("Get wallet balance and status");
var WalletPolicyCheckInputSchema = z.object({
  /**
   * Address of the wallet to check against
   */
  wallet_address: XRPLAddressSchema,
  /**
   * Hex-encoded unsigned transaction to evaluate
   */
  unsigned_tx: UnsignedTransactionBlobSchema
}).describe("Check if transaction would be approved (dry-run)");
var WalletRotateInputSchema = z.object({
  /**
   * Address of the wallet to rotate key for
   */
  wallet_address: XRPLAddressSchema,
  /**
   * Reason for rotation (audit trail)
   * @example "Scheduled quarterly rotation"
   * @example "Suspected key compromise"
   */
  reason: z.string().max(200).optional().describe("Reason for key rotation")
}).describe("Rotate the agent wallet signing key");
var WalletHistoryInputSchema = z.object({
  /**
   * Address to get history for
   */
  wallet_address: XRPLAddressSchema,
  /**
   * Maximum number of transactions to return
   * @default 20
   */
  limit: z.number().int().min(1).max(100).optional().default(20).describe("Maximum transactions to return"),
  /**
   * Pagination marker from previous response
   */
  marker: PaginationMarkerSchema.optional()
}).describe("Get transaction history");
var WalletListInputSchema = z.object({
  /**
   * Filter by network (optional)
   */
  network: NetworkSchema.optional()
}).describe("List all managed wallets");
var WalletFundInputSchema = z.object({
  /**
   * Address to fund
   */
  wallet_address: XRPLAddressSchema,
  /**
   * Network (must be testnet or devnet)
   */
  network: z.enum(["testnet", "devnet"]).describe("Network to fund from (testnet or devnet only)")
}).describe("Fund wallet from testnet/devnet faucet");
var PolicySetInputSchema = z.object({
  /**
   * Wallet address to update policy for
   */
  wallet_address: XRPLAddressSchema,
  /**
   * New policy to apply
   */
  policy: AgentWalletPolicySchema,
  /**
   * Reason for policy change (audit trail)
   */
  reason: z.string().max(500).describe("Reason for policy change")
}).describe("Update wallet policy (requires approval)");
var TxSubmitInputSchema = z.object({
  /**
   * Hex-encoded signed transaction blob
   */
  signed_tx: SignedTransactionBlobSchema,
  /**
   * Network to submit to
   */
  network: NetworkSchema,
  /**
   * Whether to wait for validation (optional)
   * @default true
   */
  wait_for_validation: z.boolean().optional().default(true).describe("Wait for transaction validation")
}).describe("Submit signed transaction to XRPL");
var TxDecodeInputSchema = z.object({
  /**
   * Transaction blob to decode (signed or unsigned)
   */
  tx_blob: HexStringRawSchema.min(20).max(1e6)
}).describe("Decode transaction blob for inspection");
var NetworkConfigInputSchema = z.object({
  /**
   * Network to configure
   */
  network: NetworkSchema,
  /**
   * Primary WebSocket URL
   */
  primary_url: z.string().url().refine(
    (url) => url.startsWith("wss://") || url.startsWith("ws://localhost"),
    "WebSocket URL must use wss:// (or ws://localhost for development)"
  ).optional().describe("Primary WebSocket URL"),
  /**
   * Fallback WebSocket URLs
   */
  fallback_urls: z.array(
    z.string().url().refine(
      (url) => url.startsWith("wss://"),
      "Fallback URLs must use wss://"
    )
  ).max(5).optional().describe("Fallback WebSocket URLs"),
  /**
   * Connection timeout in milliseconds
   */
  connection_timeout_ms: z.number().int().min(1e3).max(6e4).optional().describe("Connection timeout (1000-60000 ms)")
}).describe("Configure network connection");
var SignerEntrySchema = z.object({
  /**
   * Signer's XRPL address
   */
  account: XRPLAddressSchema,
  /**
   * Signer's weight (contributes to quorum)
   */
  weight: z.number().int().min(1).max(65535)
}).describe("Multi-signature signer entry");
var WalletCreateOutputSchema = z.object({
  /**
   * New wallet's XRPL address
   */
  address: XRPLAddressSchema,
  /**
   * Agent's signing key (public only)
   */
  regular_key_public: PublicKeySchema,
  /**
   * Encrypted master key backup for recovery
   * Store this securely - required for disaster recovery
   */
  master_key_backup: z.string().describe("Encrypted master key backup"),
  /**
   * Policy ID applied to this wallet
   */
  policy_id: z.string(),
  /**
   * Internal wallet identifier
   */
  wallet_id: WalletIdSchema,
  /**
   * Network the wallet was created on
   */
  network: NetworkSchema,
  /**
   * Creation timestamp
   */
  created_at: TimestampSchema
}).describe("Wallet creation result");
var RemainingLimitsSchema = z.object({
  /**
   * Remaining daily volume in drops
   */
  daily_remaining_drops: DropsAmountOptionalZeroSchema,
  /**
   * Remaining transactions this hour
   */
  hourly_tx_remaining: z.number().int().min(0),
  /**
   * Remaining transactions today
   */
  daily_tx_remaining: z.number().int().min(0)
}).describe("Remaining transaction limits");
var PolicyViolationSchema = z.object({
  /**
   * Which rule was violated
   */
  rule: z.string(),
  /**
   * The limit that was exceeded
   */
  limit: z.string(),
  /**
   * The actual value that violated the limit
   */
  actual: z.string()
}).describe("Policy violation details");
var WalletSignApprovedOutputSchema = z.object({
  /**
   * Transaction status
   */
  status: z.literal("approved"),
  /**
   * Hex-encoded signed transaction blob
   */
  signed_tx: SignedTransactionBlobSchema,
  /**
   * Transaction hash
   */
  tx_hash: TransactionHashSchema,
  /**
   * Policy tier that approved this transaction
   */
  policy_tier: ApprovalTierSchema,
  /**
   * Remaining limits after this transaction
   */
  limits_after: RemainingLimitsSchema,
  /**
   * Timestamp when signed
   */
  signed_at: TimestampSchema
}).describe("Approved and signed transaction");
var WalletSignPendingOutputSchema = z.object({
  /**
   * Transaction status
   */
  status: z.literal("pending_approval"),
  /**
   * Approval request ID for tracking
   */
  approval_id: z.string(),
  /**
   * Reason approval is required
   */
  reason: z.enum([
    "exceeds_autonomous_limit",
    "new_destination",
    "restricted_tx_type",
    "outside_active_hours",
    "requires_cosign"
  ]),
  /**
   * When this approval request expires
   */
  expires_at: TimestampSchema,
  /**
   * URL for human approval (if configured)
   */
  approval_url: z.string().url().optional(),
  /**
   * Policy tier required
   */
  policy_tier: ApprovalTierSchema
}).describe("Transaction pending human approval");
var WalletSignRejectedOutputSchema = z.object({
  /**
   * Transaction status
   */
  status: z.literal("rejected"),
  /**
   * Human-readable rejection reason
   */
  reason: z.string(),
  /**
   * Specific policy violation (if applicable)
   */
  policy_violation: PolicyViolationSchema.optional(),
  /**
   * Policy tier that would be required
   */
  policy_tier: z.literal(4)
}).describe("Rejected transaction");
var WalletSignOutputSchema = z.discriminatedUnion("status", [
  WalletSignApprovedOutputSchema,
  WalletSignPendingOutputSchema,
  WalletSignRejectedOutputSchema
]).describe("Transaction signing result");
var WalletBalanceOutputSchema = z.object({
  /**
   * Wallet address
   */
  address: XRPLAddressSchema,
  /**
   * Total balance in drops
   */
  balance_drops: DropsAmountOptionalZeroSchema,
  /**
   * Total balance in XRP (formatted string)
   */
  balance_xrp: z.string(),
  /**
   * Reserve requirement in drops
   */
  reserve_drops: DropsAmountOptionalZeroSchema,
  /**
   * Available balance (total - reserve) in drops
   */
  available_drops: DropsAmountOptionalZeroSchema,
  /**
   * Current account sequence number
   */
  sequence: SequenceNumberSchema,
  /**
   * Whether a regular key is configured
   */
  regular_key_set: z.boolean(),
  /**
   * Multi-signature signer list (if configured)
   */
  signer_list: z.array(SignerEntrySchema).nullable(),
  /**
   * Applied policy ID
   */
  policy_id: z.string(),
  /**
   * Network
   */
  network: NetworkSchema,
  /**
   * When balance was queried
   */
  queried_at: TimestampSchema
}).describe("Wallet balance and status");
var LimitStatusSchema = z.object({
  /**
   * Daily volume used in drops
   */
  daily_volume_used_drops: DropsAmountOptionalZeroSchema,
  /**
   * Daily volume limit in drops
   */
  daily_volume_limit_drops: DropsAmountOptionalZeroSchema,
  /**
   * Transactions this hour
   */
  hourly_tx_used: z.number().int().min(0),
  /**
   * Hourly transaction limit
   */
  hourly_tx_limit: z.number().int().min(0),
  /**
   * Transactions today
   */
  daily_tx_used: z.number().int().min(0),
  /**
   * Daily transaction limit
   */
  daily_tx_limit: z.number().int().min(0)
}).describe("Current limit utilization");
var WalletPolicyCheckOutputSchema = z.object({
  /**
   * Whether transaction would be approved
   */
  would_approve: z.boolean(),
  /**
   * Tier that would be assigned
   */
  tier: ApprovalTierSchema,
  /**
   * Warnings (non-blocking issues)
   */
  warnings: z.array(z.string()),
  /**
   * Violations (blocking issues)
   */
  violations: z.array(z.string()),
  /**
   * Current limit status
   */
  limits: LimitStatusSchema,
  /**
   * Transaction details extracted from blob
   */
  transaction_details: z.object({
    type: TransactionTypeSchema,
    destination: XRPLAddressSchema.optional(),
    amount_drops: DropsAmountOptionalZeroSchema.optional()
  }).optional()
}).describe("Policy check result");
var WalletRotateOutputSchema = z.object({
  /**
   * Rotation status
   */
  status: z.literal("rotated"),
  /**
   * New regular key (public)
   */
  new_regular_key_public: PublicKeySchema,
  /**
   * Whether old key was disabled on-chain
   */
  old_key_disabled: z.boolean(),
  /**
   * Transaction hash for SetRegularKey
   */
  rotation_tx_hash: TransactionHashSchema,
  /**
   * Rotation timestamp
   */
  rotated_at: TimestampSchema
}).describe("Key rotation result");
var TransactionHistoryEntrySchema = z.object({
  /**
   * Transaction hash
   */
  hash: TransactionHashSchema,
  /**
   * Transaction type
   */
  type: TransactionTypeSchema,
  /**
   * Amount in drops (for Payment-like transactions)
   */
  amount_drops: DropsAmountOptionalZeroSchema.optional(),
  /**
   * Destination address (for Payment-like transactions)
   */
  destination: XRPLAddressSchema.optional(),
  /**
   * Timestamp when executed
   */
  timestamp: TimestampSchema,
  /**
   * Policy tier that approved this
   */
  policy_tier: ApprovalTierSchema,
  /**
   * Context provided when signed
   */
  context: z.string().optional(),
  /**
   * Ledger index where validated
   */
  ledger_index: z.number().int().positive(),
  /**
   * Whether transaction succeeded
   */
  success: z.boolean()
}).describe("Transaction history entry");
var WalletHistoryOutputSchema = z.object({
  /**
   * Wallet address
   */
  address: XRPLAddressSchema,
  /**
   * Transaction history entries
   */
  transactions: z.array(TransactionHistoryEntrySchema),
  /**
   * Pagination marker for next page
   */
  marker: PaginationMarkerSchema.optional(),
  /**
   * Whether there are more results
   */
  has_more: z.boolean()
}).describe("Transaction history");
var WalletListEntrySchema = z.object({
  /**
   * Internal wallet ID
   */
  wallet_id: WalletIdSchema,
  /**
   * XRPL address
   */
  address: XRPLAddressSchema,
  /**
   * Human-readable name
   */
  name: WalletNameSchema.optional(),
  /**
   * Network
   */
  network: NetworkSchema,
  /**
   * Applied policy ID
   */
  policy_id: z.string(),
  /**
   * Creation timestamp
   */
  created_at: TimestampSchema
}).describe("Wallet list entry");
var WalletListOutputSchema = z.object({
  /**
   * List of managed wallets
   */
  wallets: z.array(WalletListEntrySchema),
  /**
   * Total count
   */
  total: z.number().int().min(0)
}).describe("List of managed wallets");
var WalletFundOutputSchema = z.object({
  /**
   * Funding status
   */
  status: z.enum(["funded", "pending", "failed"]),
  /**
   * Amount funded in drops
   */
  amount_drops: DropsAmountOptionalZeroSchema.optional(),
  /**
   * Faucet transaction hash
   */
  tx_hash: TransactionHashSchema.optional(),
  /**
   * New balance after funding
   */
  new_balance_drops: DropsAmountOptionalZeroSchema.optional(),
  /**
   * Error message if failed
   */
  error: z.string().optional()
}).describe("Faucet funding result");
var PolicySetOutputSchema = z.object({
  /**
   * Update status
   */
  status: z.enum(["applied", "pending_approval"]),
  /**
   * Previous policy ID
   */
  previous_policy_id: z.string(),
  /**
   * New policy ID
   */
  new_policy_id: z.string(),
  /**
   * When applied (if status is 'applied')
   */
  applied_at: TimestampSchema.optional(),
  /**
   * Approval ID (if status is 'pending_approval')
   */
  approval_id: z.string().optional()
}).describe("Policy update result");
var TransactionResultSchema = z.object({
  /**
   * Result code from XRPL
   */
  result_code: z.string(),
  /**
   * Human-readable result message
   */
  result_message: z.string(),
  /**
   * Whether transaction succeeded
   */
  success: z.boolean()
}).describe("Transaction result from XRPL");
var TxSubmitOutputSchema = z.object({
  /**
   * Transaction hash
   */
  tx_hash: TransactionHashSchema,
  /**
   * Result from XRPL
   */
  result: TransactionResultSchema,
  /**
   * Ledger index (if validated)
   */
  ledger_index: z.number().int().positive().optional(),
  /**
   * When submitted
   */
  submitted_at: TimestampSchema,
  /**
   * When validated (if wait_for_validation was true)
   */
  validated_at: TimestampSchema.optional()
}).describe("Transaction submission result");
var DecodedTransactionSchema = z.object({
  /**
   * Transaction type
   */
  TransactionType: TransactionTypeSchema,
  /**
   * Source account
   */
  Account: XRPLAddressSchema,
  /**
   * Destination (for Payment-like transactions)
   */
  Destination: XRPLAddressSchema.optional(),
  /**
   * Amount in drops (for Payment transactions)
   */
  Amount: z.string().optional(),
  /**
   * Transaction fee in drops
   */
  Fee: z.string(),
  /**
   * Sequence number
   */
  Sequence: z.number().int(),
  /**
   * Additional fields (varies by transaction type)
   */
  [z.string().toString()]: z.unknown()
}).passthrough().describe("Decoded transaction fields");
var TxDecodeOutputSchema = z.object({
  /**
   * Decoded transaction fields
   */
  transaction: DecodedTransactionSchema,
  /**
   * Transaction hash (if signed)
   */
  hash: TransactionHashSchema.optional(),
  /**
   * Whether transaction is signed
   */
  is_signed: z.boolean(),
  /**
   * Signing public key (if signed)
   */
  signing_public_key: PublicKeySchema.optional()
}).describe("Decoded transaction");
var NetworkConfigOutputSchema = z.object({
  /**
   * Configuration status
   */
  status: z.literal("configured"),
  /**
   * Network that was configured
   */
  network: NetworkSchema,
  /**
   * Applied configuration
   */
  config: z.object({
    primary_url: z.string().url(),
    fallback_urls: z.array(z.string().url()),
    connection_timeout_ms: z.number().int()
  })
}).describe("Network configuration result");
var ErrorCodeSchema = z.enum([
  // Validation errors (4xx equivalent)
  "VALIDATION_ERROR",
  "INVALID_ADDRESS",
  "INVALID_TRANSACTION",
  "INVALID_POLICY",
  // Policy errors
  "POLICY_VIOLATION",
  "RATE_LIMIT_EXCEEDED",
  "LIMIT_EXCEEDED",
  "DESTINATION_BLOCKED",
  "TRANSACTION_TYPE_BLOCKED",
  // Authentication/Authorization errors
  "WALLET_NOT_FOUND",
  "WALLET_LOCKED",
  "UNAUTHORIZED",
  "APPROVAL_REQUIRED",
  "APPROVAL_EXPIRED",
  // Network errors
  "NETWORK_ERROR",
  "CONNECTION_FAILED",
  "SUBMISSION_FAILED",
  "TIMEOUT",
  // Internal errors (5xx equivalent)
  "INTERNAL_ERROR",
  "KEYSTORE_ERROR",
  "SIGNING_ERROR",
  "ENCRYPTION_ERROR",
  // XRPL-specific errors
  "INSUFFICIENT_BALANCE",
  "INSUFFICIENT_RESERVE",
  "SEQUENCE_ERROR",
  "LEDGER_NOT_FOUND"
]).describe("Error code");
var ErrorResponseSchema = z.object({
  /**
   * Error code for programmatic handling
   */
  code: ErrorCodeSchema,
  /**
   * Human-readable error message
   */
  message: z.string(),
  /**
   * Additional error details
   */
  details: z.record(z.unknown()).optional(),
  /**
   * Request ID for correlation
   */
  request_id: z.string().optional(),
  /**
   * Timestamp
   */
  timestamp: TimestampSchema
}).describe("Error response");
var AuditEventTypeSchema = z.enum([
  // Wallet lifecycle
  "wallet_created",
  "wallet_imported",
  "wallet_deleted",
  "key_rotated",
  // Transactions
  "transaction_signed",
  "transaction_submitted",
  "transaction_validated",
  "transaction_failed",
  // Policy
  "policy_evaluated",
  "policy_violation",
  "policy_updated",
  // Approvals
  "approval_requested",
  "approval_granted",
  "approval_denied",
  "approval_expired",
  // Security
  "rate_limit_triggered",
  "injection_detected",
  "authentication_failed",
  // System
  "server_started",
  "server_stopped",
  "keystore_unlocked",
  "keystore_locked"
]).describe("Audit event type");
var AuditLogEntrySchema = z.object({
  /**
   * Sequence number (monotonically increasing)
   */
  seq: z.number().int().min(0),
  /**
   * Event timestamp
   */
  timestamp: TimestampSchema,
  /**
   * Event type
   */
  event: AuditEventTypeSchema,
  /**
   * Wallet ID (if applicable)
   */
  wallet_id: WalletIdSchema.optional(),
  /**
   * Wallet address (if applicable)
   */
  wallet_address: XRPLAddressSchema.optional(),
  /**
   * Transaction type (if applicable)
   */
  transaction_type: TransactionTypeSchema.optional(),
  /**
   * Amount in XRP (if applicable)
   */
  amount_xrp: z.string().optional(),
  /**
   * Destination address (if applicable)
   */
  destination: XRPLAddressSchema.optional(),
  /**
   * Policy tier (if applicable)
   */
  tier: ApprovalTierSchema.optional(),
  /**
   * Policy decision
   */
  policy_decision: z.enum(["allowed", "denied", "pending"]).optional(),
  /**
   * Transaction hash (if applicable)
   */
  tx_hash: TransactionHashSchema.optional(),
  /**
   * Context from agent
   */
  context: z.string().optional(),
  /**
   * Previous entry hash (for chain integrity)
   */
  prev_hash: z.string(),
  /**
   * This entry's hash
   */
  hash: z.string()
}).describe("Audit log entry with hash chain");
var InputSchemas = {
  wallet_create: WalletCreateInputSchema,
  wallet_sign: WalletSignInputSchema,
  wallet_balance: WalletBalanceInputSchema,
  wallet_policy_check: WalletPolicyCheckInputSchema,
  wallet_rotate: WalletRotateInputSchema,
  wallet_history: WalletHistoryInputSchema,
  wallet_list: WalletListInputSchema,
  wallet_fund: WalletFundInputSchema,
  policy_set: PolicySetInputSchema,
  tx_submit: TxSubmitInputSchema,
  tx_decode: TxDecodeInputSchema,
  network_config: NetworkConfigInputSchema
};
var OutputSchemas = {
  wallet_create: WalletCreateOutputSchema,
  wallet_sign: WalletSignOutputSchema,
  wallet_balance: WalletBalanceOutputSchema,
  wallet_policy_check: WalletPolicyCheckOutputSchema,
  wallet_rotate: WalletRotateOutputSchema,
  wallet_history: WalletHistoryOutputSchema,
  wallet_list: WalletListOutputSchema,
  wallet_fund: WalletFundOutputSchema,
  policy_set: PolicySetOutputSchema,
  tx_submit: TxSubmitOutputSchema,
  tx_decode: TxDecodeOutputSchema,
  network_config: NetworkConfigOutputSchema,
  error: ErrorResponseSchema
};

export { AgentWalletPolicySchema, ApprovalTierSchema, AuditEventTypeSchema, AuditLogEntrySchema, DecodedTransactionSchema, DestinationModeSchema, DropsAmountOptionalZeroSchema, DropsAmountSchema, ErrorCodeSchema, ErrorResponseSchema, HexStringRawSchema, HexStringSchema, InputSchemas, LedgerIndexSchema, LimitStatusSchema, NetworkConfigInputSchema, NetworkConfigOutputSchema, NetworkSchema, NotificationEventSchema, OutputSchemas, PaginationMarkerSchema, PolicyDestinationsSchema, PolicyEscalationSchema, PolicyLimitsSchema, PolicyNotificationsSchema, PolicySetInputSchema, PolicySetOutputSchema, PolicyTimeControlsSchema, PolicyTransactionTypesSchema, PolicyViolationSchema, PublicKeySchema, RemainingLimitsSchema, SequenceNumberSchema, SignedTransactionBlobSchema, SignerEntrySchema, TimestampSchema, TransactionHashSchema, TransactionHistoryEntrySchema, TransactionResultSchema, TransactionTypeSchema, TxDecodeInputSchema, TxDecodeOutputSchema, TxSubmitInputSchema, TxSubmitOutputSchema, UnsignedTransactionBlobSchema, WalletBalanceInputSchema, WalletBalanceOutputSchema, WalletCreateInputSchema, WalletCreateOutputSchema, WalletFundInputSchema, WalletFundOutputSchema, WalletHistoryInputSchema, WalletHistoryOutputSchema, WalletIdSchema, WalletListEntrySchema, WalletListInputSchema, WalletListOutputSchema, WalletNameSchema, WalletPolicyCheckInputSchema, WalletPolicyCheckOutputSchema, WalletRotateInputSchema, WalletRotateOutputSchema, WalletSignApprovedOutputSchema, WalletSignInputSchema, WalletSignOutputSchema, WalletSignPendingOutputSchema, WalletSignRejectedOutputSchema, XRPLAddressSchema, __commonJS, __require, __toESM };
//# sourceMappingURL=chunk-M5227CX6.js.map
//# sourceMappingURL=chunk-M5227CX6.js.map