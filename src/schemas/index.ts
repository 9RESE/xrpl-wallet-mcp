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

import { z } from 'zod';

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * Maximum XRP drops value (100 billion XRP = 100 quadrillion drops)
 * XRPL uses drops as the smallest unit: 1 XRP = 1,000,000 drops
 */
const MAX_DROPS = BigInt('100000000000000000'); // 100 quadrillion

/**
 * Minimum reserve requirement in drops (currently 10 XRP)
 */
const MIN_RESERVE_DROPS = BigInt('10000000'); // 10 XRP

/**
 * XRPL Transaction Types as defined in the protocol
 * @see https://xrpl.org/docs/references/protocol/transactions/types
 */
const XRPL_TRANSACTION_TYPES = [
  'AccountDelete',
  'AccountSet',
  'AMMBid',
  'AMMCreate',
  'AMMDelete',
  'AMMDeposit',
  'AMMVote',
  'AMMWithdraw',
  'CheckCancel',
  'CheckCash',
  'CheckCreate',
  'Clawback',
  'DepositPreauth',
  'DIDDelete',
  'DIDSet',
  'EnableAmendment',
  'EscrowCancel',
  'EscrowCreate',
  'EscrowFinish',
  'NFTokenAcceptOffer',
  'NFTokenBurn',
  'NFTokenCancelOffer',
  'NFTokenCreateOffer',
  'NFTokenMint',
  'OfferCancel',
  'OfferCreate',
  'Payment',
  'PaymentChannelClaim',
  'PaymentChannelCreate',
  'PaymentChannelFund',
  'SetFee',
  'SetRegularKey',
  'SignerListSet',
  'TicketCreate',
  'TrustSet',
  'UNLModify',
  'XChainAccountCreateCommit',
  'XChainAddClaimAttestation',
  'XChainClaim',
  'XChainCommit',
  'XChainCreateBridge',
  'XChainCreateClaimID',
  'XChainModifyBridge',
] as const;

// ============================================================================
// XRPL PRIMITIVES
// ============================================================================

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
export const XRPLAddressSchema = z
  .string()
  .min(25, 'XRPL address must be at least 25 characters')
  .max(35, 'XRPL address must be at most 35 characters')
  .regex(
    /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/,
    'Invalid XRPL address format: must start with "r" followed by 24-34 Base58 characters'
  )
  .describe('XRPL Classic Address (r-address format)');

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
export const DropsAmountSchema = z
  .string()
  .regex(/^[1-9]\d*$/, 'Drops must be a positive integer string without leading zeros')
  .refine(
    (val) => {
      try {
        const drops = BigInt(val);
        return drops >= 1n && drops <= MAX_DROPS;
      } catch {
        return false;
      }
    },
    { message: `Drops must be between 1 and ${MAX_DROPS.toString()}` }
  )
  .describe('XRP amount in drops (1 XRP = 1,000,000 drops)');

/**
 * Optional drops amount that can be "0" for queries
 * Used for balance queries where zero is valid
 */
export const DropsAmountOptionalZeroSchema = z
  .string()
  .regex(/^\d+$/, 'Drops must be a non-negative integer string')
  .refine(
    (val) => {
      try {
        const drops = BigInt(val);
        return drops >= 0n && drops <= MAX_DROPS;
      } catch {
        return false;
      }
    },
    { message: `Drops must be between 0 and ${MAX_DROPS.toString()}` }
  )
  .describe('XRP amount in drops (can be zero)');

/**
 * XRPL Transaction Hash validation
 *
 * 64 hexadecimal characters (256-bit hash)
 *
 * @example "E08D6E9754025BA2534A78707605E0601F03ACE063687A0CA1BDDACFCD1698C7"
 */
export const TransactionHashSchema = z
  .string()
  .length(64, 'Transaction hash must be exactly 64 characters')
  .regex(/^[A-Fa-f0-9]{64}$/, 'Transaction hash must be 64 hexadecimal characters')
  .transform((val) => val.toUpperCase())
  .describe('XRPL transaction hash (64-character hex string)');

/**
 * XRPL Ledger Index (sequence number)
 * Can be a specific ledger number or special strings
 */
export const LedgerIndexSchema = z
  .union([
    z.number().int().positive(),
    z.enum(['validated', 'closed', 'current']),
  ])
  .describe('XRPL ledger index (number or "validated"/"closed"/"current")');

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
export const PublicKeySchema = z
  .string()
  .length(66, 'Public key must be exactly 66 characters')
  .refine(
    (val) => {
      // Ed25519: starts with ED
      if (val.startsWith('ED')) {
        return /^ED[A-Fa-f0-9]{64}$/.test(val);
      }
      // secp256k1: starts with 02 or 03 (compressed)
      if (val.startsWith('02') || val.startsWith('03')) {
        return /^0[23][A-Fa-f0-9]{64}$/.test(val);
      }
      return false;
    },
    {
      message:
        'Public key must be ED25519 (ED prefix) or secp256k1 (02/03 prefix) with 64 hex characters',
    }
  )
  .describe('XRPL public key (Ed25519 or secp256k1 format)');

/**
 * Network identifier for XRPL environments
 *
 * - mainnet: Production network (real XRP)
 * - testnet: Test network (free test XRP via faucet)
 * - devnet: Development network (latest features, may be unstable)
 */
export const NetworkSchema = z
  .enum(['mainnet', 'testnet', 'devnet'])
  .describe('XRPL network environment');

/**
 * XRPL Transaction Type
 * @see https://xrpl.org/docs/references/protocol/transactions/types
 */
export const TransactionTypeSchema = z
  .enum(XRPL_TRANSACTION_TYPES)
  .describe('XRPL transaction type');

/**
 * XRPL Account Sequence Number
 * Unsigned 32-bit integer starting from 1
 */
export const SequenceNumberSchema = z
  .number()
  .int()
  .min(1)
  .max(4294967295)
  .describe('XRPL account sequence number');

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
export const HexStringSchema = z
  .string()
  .regex(/^[A-Fa-f0-9]*$/, 'Must be a valid hexadecimal string')
  .transform((val) => val.toUpperCase())
  .describe('Hexadecimal string (normalized to uppercase)');

/**
 * Raw hexadecimal string validation (no transform)
 * Used for input schemas where we need to chain additional validators
 */
export const HexStringRawSchema = z
  .string()
  .regex(/^[A-Fa-f0-9]*$/, 'Must be a valid hexadecimal string')
  .describe('Hexadecimal string (raw)');

/**
 * Unsigned transaction blob
 * Variable length hex string representing serialized transaction
 */
export const UnsignedTransactionBlobSchema = z
  .string()
  .min(20, 'Transaction blob too short')
  .max(1000000, 'Transaction blob exceeds maximum size')
  .regex(/^[A-Fa-f0-9]+$/, 'Transaction blob must be hexadecimal')
  .describe('Unsigned XRPL transaction blob (hex-encoded)');

/**
 * Signed transaction blob
 * Contains signature(s) appended to transaction data
 */
export const SignedTransactionBlobSchema = z
  .string()
  .min(100, 'Signed transaction blob too short')
  .max(1000000, 'Transaction blob exceeds maximum size')
  .regex(/^[A-Fa-f0-9]+$/, 'Transaction blob must be hexadecimal')
  .describe('Signed XRPL transaction blob (hex-encoded)');

/**
 * Wallet identifier (internal reference)
 * Alphanumeric with hyphens and underscores
 */
export const WalletIdSchema = z
  .string()
  .min(1, 'Wallet ID cannot be empty')
  .max(64, 'Wallet ID too long')
  .regex(
    /^[a-zA-Z0-9][a-zA-Z0-9_-]*$/,
    'Wallet ID must start with alphanumeric and contain only alphanumeric, hyphens, or underscores'
  )
  .describe('Internal wallet identifier');

/**
 * Wallet name (human-readable label)
 */
export const WalletNameSchema = z
  .string()
  .min(1, 'Wallet name cannot be empty')
  .max(64, 'Wallet name too long')
  .describe('Human-readable wallet name');

/**
 * ISO 8601 timestamp string
 */
export const TimestampSchema = z
  .string()
  .datetime({ message: 'Must be a valid ISO 8601 timestamp' })
  .describe('ISO 8601 timestamp');

/**
 * Pagination marker for XRPL queries
 * Opaque value returned by previous query
 */
export const PaginationMarkerSchema = z
  .string()
  .min(1)
  .max(1000)
  .describe('Pagination marker from previous response');

// ============================================================================
// POLICY SCHEMAS
// ============================================================================

/**
 * Approval tier for transactions
 *
 * - Tier 1: Autonomous - Agent can sign immediately
 * - Tier 2: Delayed - Agent signs after delay (human can veto)
 * - Tier 3: Co-Sign - Requires human co-signature
 * - Tier 4: Prohibited - Never allowed, always rejected
 */
export const ApprovalTierSchema = z
  .union([z.literal(1), z.literal(2), z.literal(3), z.literal(4)])
  .describe('Transaction approval tier (1=autonomous, 2=delayed, 3=co-sign, 4=prohibited)');

/**
 * Policy limit configuration
 * Defines transaction and volume limits for the agent wallet
 */
export const PolicyLimitsSchema = z
  .object({
    /**
     * Maximum amount per single transaction in drops
     * @example "10000000" (10 XRP)
     */
    max_amount_per_tx_drops: DropsAmountSchema.describe(
      'Maximum amount per single transaction in drops'
    ),

    /**
     * Maximum daily transaction volume in drops
     * Resets at midnight UTC
     * @example "100000000" (100 XRP)
     */
    max_daily_volume_drops: DropsAmountSchema.describe(
      'Maximum daily transaction volume in drops'
    ),

    /**
     * Maximum transactions per hour (rolling window)
     */
    max_tx_per_hour: z
      .number()
      .int()
      .min(1)
      .max(1000)
      .describe('Maximum transactions per hour'),

    /**
     * Maximum transactions per day (rolling window)
     */
    max_tx_per_day: z
      .number()
      .int()
      .min(1)
      .max(10000)
      .describe('Maximum transactions per day'),
  })
  .describe('Transaction and volume limits');

/**
 * Destination control mode
 *
 * - allowlist: Only explicitly allowed addresses can receive
 * - blocklist: All addresses except blocked ones can receive
 * - open: Any address can receive (least restrictive)
 */
export const DestinationModeSchema = z
  .enum(['allowlist', 'blocklist', 'open'])
  .describe('Destination control mode');

/**
 * Destination controls configuration
 * Manages which addresses the agent can send to
 */
export const PolicyDestinationsSchema = z
  .object({
    /**
     * Destination filtering mode
     */
    mode: DestinationModeSchema,

    /**
     * Allowed destination addresses (used when mode='allowlist')
     */
    allowlist: z
      .array(XRPLAddressSchema)
      .max(1000)
      .optional()
      .describe('Allowed destination addresses'),

    /**
     * Blocked destination addresses (always enforced regardless of mode)
     * Used for known scam/malicious addresses
     */
    blocklist: z
      .array(XRPLAddressSchema)
      .max(10000)
      .optional()
      .describe('Blocked destination addresses'),

    /**
     * Whether to allow transactions to previously unseen addresses
     */
    allow_new_destinations: z
      .boolean()
      .describe('Allow transactions to new/unknown addresses'),

    /**
     * Approval tier required for new destinations
     * Only used when allow_new_destinations is true
     */
    new_destination_tier: z
      .union([z.literal(2), z.literal(3)])
      .optional()
      .describe('Approval tier for new destinations'),
  })
  .describe('Destination address controls');

/**
 * Transaction type controls
 * Specifies which transaction types the agent can execute
 */
export const PolicyTransactionTypesSchema = z
  .object({
    /**
     * Transaction types the agent can execute autonomously
     * @example ["Payment", "EscrowFinish", "EscrowCancel"]
     */
    allowed: z
      .array(TransactionTypeSchema)
      .min(1)
      .describe('Transaction types allowed for autonomous signing'),

    /**
     * Transaction types that require human approval (tier 2/3)
     * @example ["EscrowCreate", "TrustSet"]
     */
    require_approval: z
      .array(TransactionTypeSchema)
      .optional()
      .describe('Transaction types requiring human approval'),

    /**
     * Transaction types that are never allowed (tier 4)
     * Typically account control operations
     * @example ["SetRegularKey", "SignerListSet", "AccountDelete"]
     */
    blocked: z
      .array(TransactionTypeSchema)
      .optional()
      .describe('Transaction types that are never allowed'),
  })
  .describe('Transaction type controls');

/**
 * Time-based access controls
 * Restricts when the agent can execute transactions
 */
export const PolicyTimeControlsSchema = z
  .object({
    /**
     * Active hours in UTC (24-hour format)
     * Transactions outside these hours are escalated to tier 2/3
     */
    active_hours_utc: z
      .object({
        start: z.number().int().min(0).max(23).describe('Start hour (0-23)'),
        end: z.number().int().min(0).max(23).describe('End hour (0-23)'),
      })
      .optional()
      .describe('Active hours in UTC'),

    /**
     * Active days of the week
     * 0 = Sunday, 6 = Saturday
     */
    active_days: z
      .array(z.number().int().min(0).max(6))
      .min(1)
      .max(7)
      .optional()
      .describe('Active days (0=Sunday, 6=Saturday)'),

    /**
     * Timezone for interpreting active hours
     * @example "America/New_York"
     */
    timezone: z
      .string()
      .min(1)
      .max(50)
      .optional()
      .describe('IANA timezone identifier'),
  })
  .describe('Time-based access controls');

/**
 * Escalation rules configuration
 * Defines thresholds for tier escalation
 */
export const PolicyEscalationSchema = z
  .object({
    /**
     * Amount threshold for escalation to tier 2 (drops)
     * Transactions above this require delayed/human approval
     */
    amount_threshold_drops: DropsAmountSchema.describe(
      'Amount threshold for tier escalation'
    ),

    /**
     * Tier assigned to transactions with new destinations
     */
    new_destination: z
      .union([z.literal(2), z.literal(3)])
      .describe('Tier for new destination addresses'),

    /**
     * Tier for account settings changes
     * Always tier 3 for safety
     */
    account_settings: z.literal(3).describe('Tier for account settings changes'),

    /**
     * Delay in seconds before tier 2 transactions auto-approve
     * Human can veto during this window
     */
    delay_seconds: z
      .number()
      .int()
      .min(60)
      .max(86400)
      .optional()
      .describe('Delay before tier 2 auto-approval (60-86400 seconds)'),
  })
  .describe('Escalation thresholds and rules');

/**
 * Notification events for webhooks
 */
export const NotificationEventSchema = z
  .enum(['tier2', 'tier3', 'rejection', 'all'])
  .describe('Notification event type');

/**
 * Notification configuration
 * Webhook settings for transaction events
 */
export const PolicyNotificationsSchema = z
  .object({
    /**
     * Webhook URL for notifications
     * Must be HTTPS for production
     */
    webhook_url: z
      .string()
      .url()
      .refine(
        (url) => url.startsWith('https://') || url.startsWith('http://localhost'),
        'Webhook URL must use HTTPS (except localhost for development)'
      )
      .optional()
      .describe('Webhook URL for notifications'),

    /**
     * Events that trigger notifications
     */
    notify_on: z
      .array(NotificationEventSchema)
      .min(1)
      .optional()
      .describe('Events that trigger notifications'),
  })
  .describe('Notification configuration');

/**
 * Complete Agent Wallet Policy
 *
 * Defines all security and operational constraints for an agent wallet.
 * This policy is immutable at runtime - the LLM cannot modify it.
 */
export const AgentWalletPolicySchema = z
  .object({
    /**
     * Unique policy identifier
     * @example "conservative-v1"
     */
    policy_id: z
      .string()
      .min(1)
      .max(64)
      .regex(/^[a-z0-9-]+$/, 'Policy ID must be lowercase alphanumeric with hyphens')
      .describe('Unique policy identifier'),

    /**
     * Policy version for tracking changes
     * Semantic versioning recommended
     */
    policy_version: z
      .string()
      .regex(/^\d+\.\d+(\.\d+)?$/, 'Version must be semver format (e.g., "1.0" or "1.0.0")')
      .describe('Policy version (semver)'),

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
    notifications: PolicyNotificationsSchema.optional(),
  })
  .describe('Complete agent wallet policy configuration');

// ============================================================================
// MCP TOOL INPUT SCHEMAS
// ============================================================================

/**
 * Input schema for wallet_create tool
 *
 * Creates a new XRPL wallet with policy controls.
 * The wallet is generated locally with encrypted key storage.
 */
export const WalletCreateInputSchema = z
  .object({
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
    initial_funding_drops: DropsAmountSchema.optional(),
  })
  .describe('Create a new agent wallet');

/**
 * Input schema for wallet_import tool
 *
 * Imports an existing XRPL wallet from a seed.
 * Uses a simple default policy - much easier than wallet_create.
 */
export const WalletImportInputSchema = z
  .object({
    /**
     * XRPL seed (starts with 's')
     */
    seed: z
      .string()
      .min(20, 'Seed must be at least 20 characters')
      .max(40, 'Seed must be at most 40 characters')
      .regex(/^s[1-9A-HJ-NP-Za-km-z]+$/, 'Invalid XRPL seed format')
      .describe('XRPL seed (starts with "s")'),

    /**
     * Target network for the wallet (defaults to server's configured network)
     */
    network: NetworkSchema.optional(),

    /**
     * Human-readable wallet name (optional)
     */
    wallet_name: WalletNameSchema.optional(),
  })
  .describe('Import an existing wallet from seed');

/**
 * Input schema for wallet_sign tool
 *
 * Signs a transaction after policy evaluation.
 * This is the primary tool for executing transactions.
 */
export const WalletSignInputSchema = z
  .object({
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
    context: z
      .string()
      .max(500)
      .optional()
      .describe('Reason for this transaction (audit trail)'),

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
    auto_sequence: z
      .boolean()
      .optional()
      .default(true)
      .describe('Autofill sequence from ledger before signing (default: true)'),
  })
  .describe('Sign a transaction with policy enforcement');

/**
 * Input schema for wallet_balance tool
 *
 * Queries the balance and status of a managed wallet.
 */
export const WalletBalanceInputSchema = z
  .object({
    /**
     * Address to query balance for
     */
    wallet_address: XRPLAddressSchema,

    /**
     * Wait time in milliseconds before querying (optional)
     * Useful for waiting after a transaction to ensure balance is updated.
     * @default 0
     * @example 5000 (wait 5 seconds)
     */
    wait_after_tx: z
      .number()
      .int()
      .min(0)
      .max(30000)
      .optional()
      .describe('Wait time in ms before querying (0-30000, for post-transaction timing)'),
  })
  .describe('Get wallet balance and status');

/**
 * Input schema for wallet_policy_check tool
 *
 * Dry-run policy evaluation without signing.
 * Use this to check if a transaction would be approved before building it.
 */
export const WalletPolicyCheckInputSchema = z
  .object({
    /**
     * Address of the wallet to check against
     */
    wallet_address: XRPLAddressSchema,

    /**
     * Hex-encoded unsigned transaction to evaluate
     */
    unsigned_tx: UnsignedTransactionBlobSchema,
  })
  .describe('Check if transaction would be approved (dry-run)');

/**
 * Input schema for wallet_rotate tool
 *
 * Rotates the agent's regular key for security.
 * The old key is disabled and a new one generated.
 */
export const WalletRotateInputSchema = z
  .object({
    /**
     * Address of the wallet to rotate key for
     */
    wallet_address: XRPLAddressSchema,

    /**
     * Reason for rotation (audit trail)
     * @example "Scheduled quarterly rotation"
     * @example "Suspected key compromise"
     */
    reason: z
      .string()
      .max(200)
      .optional()
      .describe('Reason for key rotation'),
  })
  .describe('Rotate the agent wallet signing key');

/**
 * Input schema for wallet_history tool
 *
 * Retrieves transaction history for audit and analysis.
 */
export const WalletHistoryInputSchema = z
  .object({
    /**
     * Address to get history for
     */
    wallet_address: XRPLAddressSchema,

    /**
     * Maximum number of transactions to return
     * @default 20
     */
    limit: z
      .number()
      .int()
      .min(1)
      .max(100)
      .optional()
      .default(20)
      .describe('Maximum transactions to return'),

    /**
     * Pagination marker from previous response
     */
    marker: PaginationMarkerSchema.optional(),
  })
  .describe('Get transaction history');

/**
 * Input schema for wallet_list tool
 *
 * Lists all wallets managed by this MCP instance.
 */
export const WalletListInputSchema = z
  .object({
    /**
     * Filter by network (optional)
     */
    network: NetworkSchema.optional(),
  })
  .describe('List all managed wallets');

/**
 * Input schema for wallet_fund tool
 *
 * Funds a wallet from the testnet/devnet faucet.
 * Only available on test networks.
 */
export const WalletFundInputSchema = z
  .object({
    /**
     * Address to fund
     */
    wallet_address: XRPLAddressSchema,

    /**
     * Network (must be testnet or devnet)
     */
    network: z
      .enum(['testnet', 'devnet'])
      .describe('Network to fund from (testnet or devnet only)'),

    /**
     * Wait for account to be confirmed on validated ledger (optional)
     * When true, retries account_info until account is queryable.
     * Recommended for automated workflows.
     * @default true
     */
    wait_for_confirmation: z
      .boolean()
      .optional()
      .default(true)
      .describe('Wait for account to be queryable on validated ledger (default: true)'),
  })
  .describe('Fund wallet from testnet/devnet faucet');

/**
 * Input schema for policy_set tool
 *
 * Updates the policy for an existing wallet.
 * Requires human approval for policy changes.
 */
export const PolicySetInputSchema = z
  .object({
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
    reason: z
      .string()
      .max(500)
      .describe('Reason for policy change'),
  })
  .describe('Update wallet policy (requires approval)');

/**
 * Input schema for tx_submit tool
 *
 * Submits a signed transaction to the XRPL network.
 */
export const TxSubmitInputSchema = z
  .object({
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
    wait_for_validation: z
      .boolean()
      .optional()
      .default(true)
      .describe('Wait for transaction validation'),
  })
  .describe('Submit signed transaction to XRPL');

/**
 * Input schema for tx_decode tool
 *
 * Decodes a transaction blob for inspection.
 */
export const TxDecodeInputSchema = z
  .object({
    /**
     * Transaction blob to decode (signed or unsigned)
     */
    tx_blob: HexStringRawSchema.min(20).max(1000000),
  })
  .describe('Decode transaction blob for inspection');

/**
 * Input schema for network_config tool
 *
 * Configures network connection settings.
 */
export const NetworkConfigInputSchema = z
  .object({
    /**
     * Network to configure
     */
    network: NetworkSchema,

    /**
     * Primary WebSocket URL
     */
    primary_url: z
      .string()
      .url()
      .refine(
        (url) => url.startsWith('wss://') || url.startsWith('ws://localhost'),
        'WebSocket URL must use wss:// (or ws://localhost for development)'
      )
      .optional()
      .describe('Primary WebSocket URL'),

    /**
     * Fallback WebSocket URLs
     */
    fallback_urls: z
      .array(
        z.string().url().refine(
          (url) => url.startsWith('wss://'),
          'Fallback URLs must use wss://'
        )
      )
      .max(5)
      .optional()
      .describe('Fallback WebSocket URLs'),

    /**
     * Connection timeout in milliseconds
     */
    connection_timeout_ms: z
      .number()
      .int()
      .min(1000)
      .max(60000)
      .optional()
      .describe('Connection timeout (1000-60000 ms)'),
  })
  .describe('Configure network connection');

// ============================================================================
// MCP TOOL OUTPUT SCHEMAS
// ============================================================================

/**
 * Signer entry for multi-signature wallets
 */
export const SignerEntrySchema = z
  .object({
    /**
     * Signer's XRPL address
     */
    account: XRPLAddressSchema,

    /**
     * Signer's weight (contributes to quorum)
     */
    weight: z.number().int().min(1).max(65535),
  })
  .describe('Multi-signature signer entry');

/**
 * Output schema for wallet_create tool
 */
export const WalletCreateOutputSchema = z
  .object({
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
    master_key_backup: z.string().describe('Encrypted master key backup'),

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
    created_at: TimestampSchema,
  })
  .describe('Wallet creation result');

/**
 * Remaining limits after transaction
 */
export const RemainingLimitsSchema = z
  .object({
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
    daily_tx_remaining: z.number().int().min(0),
  })
  .describe('Remaining transaction limits');

/**
 * Policy violation details
 */
export const PolicyViolationSchema = z
  .object({
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
    actual: z.string(),
  })
  .describe('Policy violation details');

/**
 * Output schema for wallet_sign tool - approved transaction
 */
export const WalletSignApprovedOutputSchema = z
  .object({
    /**
     * Transaction status
     */
    status: z.literal('approved'),

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
    signed_at: TimestampSchema,
  })
  .describe('Approved and signed transaction');

/**
 * Output schema for wallet_sign tool - pending approval
 */
export const WalletSignPendingOutputSchema = z
  .object({
    /**
     * Transaction status
     */
    status: z.literal('pending_approval'),

    /**
     * Approval request ID for tracking
     */
    approval_id: z.string(),

    /**
     * Reason approval is required
     */
    reason: z.enum([
      'exceeds_autonomous_limit',
      'new_destination',
      'restricted_tx_type',
      'outside_active_hours',
      'requires_cosign',
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
    policy_tier: ApprovalTierSchema,
  })
  .describe('Transaction pending human approval');

/**
 * Output schema for wallet_sign tool - rejected
 */
export const WalletSignRejectedOutputSchema = z
  .object({
    /**
     * Transaction status
     */
    status: z.literal('rejected'),

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
    policy_tier: z.literal(4),
  })
  .describe('Rejected transaction');

/**
 * Combined output schema for wallet_sign tool
 */
export const WalletSignOutputSchema = z
  .discriminatedUnion('status', [
    WalletSignApprovedOutputSchema,
    WalletSignPendingOutputSchema,
    WalletSignRejectedOutputSchema,
  ])
  .describe('Transaction signing result');

/**
 * Output schema for wallet_balance tool
 */
export const WalletBalanceOutputSchema = z
  .object({
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
     * Ledger index from which balance was queried
     * Use this for consistency verification across queries.
     */
    ledger_index: z.number().int().positive(),

    /**
     * When balance was queried
     */
    queried_at: TimestampSchema,
  })
  .describe('Wallet balance and status');

/**
 * Current limit status
 */
export const LimitStatusSchema = z
  .object({
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
    daily_tx_limit: z.number().int().min(0),
  })
  .describe('Current limit utilization');

/**
 * Output schema for wallet_policy_check tool
 */
export const WalletPolicyCheckOutputSchema = z
  .object({
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
      amount_drops: DropsAmountOptionalZeroSchema.optional(),
    }).optional(),
  })
  .describe('Policy check result');

/**
 * Output schema for wallet_rotate tool
 */
export const WalletRotateOutputSchema = z
  .object({
    /**
     * Rotation status
     */
    status: z.literal('rotated'),

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
    rotated_at: TimestampSchema,
  })
  .describe('Key rotation result');

/**
 * Transaction history entry
 */
export const TransactionHistoryEntrySchema = z
  .object({
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
    success: z.boolean(),
  })
  .describe('Transaction history entry');

/**
 * Output schema for wallet_history tool
 */
export const WalletHistoryOutputSchema = z
  .object({
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
    has_more: z.boolean(),
  })
  .describe('Transaction history');

/**
 * Wallet list entry
 */
export const WalletListEntrySchema = z
  .object({
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
    created_at: TimestampSchema,
  })
  .describe('Wallet list entry');

/**
 * Output schema for wallet_list tool
 */
export const WalletListOutputSchema = z
  .object({
    /**
     * List of managed wallets
     */
    wallets: z.array(WalletListEntrySchema),

    /**
     * Total count
     */
    total: z.number().int().min(0),
  })
  .describe('List of managed wallets');

/**
 * Output schema for wallet_fund tool
 */
export const WalletFundOutputSchema = z
  .object({
    /**
     * Funding status
     */
    status: z.enum(['funded', 'pending', 'failed']),

    /**
     * Amount funded in drops
     */
    amount_drops: DropsAmountOptionalZeroSchema.optional(),

    /**
     * Faucet transaction hash
     */
    tx_hash: TransactionHashSchema.optional(),

    /**
     * Initial balance after funding in drops
     * Use this for verification in tests instead of hardcoded values.
     */
    initial_balance_drops: DropsAmountOptionalZeroSchema.optional(),

    /**
     * New balance after funding (alias for initial_balance_drops)
     * @deprecated Use initial_balance_drops
     */
    new_balance_drops: DropsAmountOptionalZeroSchema.optional(),

    /**
     * Whether the account is ready for queries on validated ledger
     * True means account_info will succeed.
     */
    account_ready: z.boolean().optional(),

    /**
     * Ledger index where account was confirmed
     */
    ledger_index: z.number().int().positive().optional(),

    /**
     * Error message if failed
     */
    error: z.string().optional(),

    /**
     * Informational message
     */
    message: z.string().optional(),

    /**
     * Faucet URL used (for debugging)
     */
    faucet_url: z.string().url().optional(),
  })
  .describe('Faucet funding result');

/**
 * Output schema for policy_set tool
 */
export const PolicySetOutputSchema = z
  .object({
    /**
     * Update status
     */
    status: z.enum(['applied', 'pending_approval']),

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
    approval_id: z.string().optional(),
  })
  .describe('Policy update result');

/**
 * Transaction result from XRPL
 */
export const TransactionResultSchema = z
  .object({
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
    success: z.boolean(),
  })
  .describe('Transaction result from XRPL');

/**
 * Escrow reference for tracking escrow transactions
 */
export const EscrowReferenceSchema = z
  .object({
    /**
     * Owner address (creator of the escrow)
     */
    owner: XRPLAddressSchema,

    /**
     * Sequence number to use for EscrowFinish/EscrowCancel
     * This is the OfferSequence field in finish/cancel transactions.
     */
    sequence: SequenceNumberSchema,
  })
  .describe('Escrow reference for finish/cancel operations');

/**
 * Output schema for tx_submit tool
 */
export const TxSubmitOutputSchema = z
  .object({
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
    validated_at: TimestampSchema.optional(),

    /**
     * Transaction type that was submitted
     * Useful for routing post-submission logic.
     */
    tx_type: TransactionTypeSchema.optional(),

    /**
     * Sequence number consumed by this transaction
     * Useful for tracking escrows or other sequence-dependent operations.
     */
    sequence_used: SequenceNumberSchema.optional(),

    /**
     * Escrow reference (only for EscrowCreate transactions)
     * Contains owner and sequence needed for EscrowFinish/EscrowCancel.
     */
    escrow_reference: EscrowReferenceSchema.optional(),

    /**
     * Next sequence number to use for this account (only on success)
     * Use this for the next transaction instead of querying the ledger.
     * This prevents tefPAST_SEQ race conditions in rapid multi-tx workflows.
     * @since 2.1.0
     */
    next_sequence: SequenceNumberSchema.optional(),
  })
  .describe('Transaction submission result');

/**
 * Decoded transaction fields
 */
export const DecodedTransactionSchema = z
  .object({
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
    [z.string().toString()]: z.unknown(),
  })
  .passthrough()
  .describe('Decoded transaction fields');

/**
 * Output schema for tx_decode tool
 */
export const TxDecodeOutputSchema = z
  .object({
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
    signing_public_key: PublicKeySchema.optional(),
  })
  .describe('Decoded transaction');

/**
 * Output schema for network_config tool
 */
export const NetworkConfigOutputSchema = z
  .object({
    /**
     * Configuration status
     */
    status: z.literal('configured'),

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
      connection_timeout_ms: z.number().int(),
    }),
  })
  .describe('Network configuration result');

// ============================================================================
// ERROR SCHEMAS
// ============================================================================

/**
 * Error codes for MCP tool responses
 */
export const ErrorCodeSchema = z
  .enum([
    // Validation errors (4xx equivalent)
    'VALIDATION_ERROR',
    'INVALID_ADDRESS',
    'INVALID_TRANSACTION',
    'INVALID_POLICY',

    // Policy errors
    'POLICY_VIOLATION',
    'RATE_LIMIT_EXCEEDED',
    'LIMIT_EXCEEDED',
    'DESTINATION_BLOCKED',
    'TRANSACTION_TYPE_BLOCKED',

    // Authentication/Authorization errors
    'WALLET_NOT_FOUND',
    'WALLET_LOCKED',
    'UNAUTHORIZED',
    'APPROVAL_REQUIRED',
    'APPROVAL_EXPIRED',

    // Network errors
    'NETWORK_ERROR',
    'CONNECTION_FAILED',
    'SUBMISSION_FAILED',
    'TIMEOUT',

    // Internal errors (5xx equivalent)
    'INTERNAL_ERROR',
    'KEYSTORE_ERROR',
    'SIGNING_ERROR',
    'ENCRYPTION_ERROR',

    // XRPL-specific errors
    'INSUFFICIENT_BALANCE',
    'INSUFFICIENT_RESERVE',
    'SEQUENCE_ERROR',
    'LEDGER_NOT_FOUND',
  ])
  .describe('Error code');

/**
 * Error response schema for all MCP tools
 */
export const ErrorResponseSchema = z
  .object({
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
    timestamp: TimestampSchema,
  })
  .describe('Error response');

// ============================================================================
// AUDIT LOG SCHEMAS
// ============================================================================

/**
 * Audit event types
 */
export const AuditEventTypeSchema = z
  .enum([
    // Wallet lifecycle
    'wallet_created',
    'wallet_imported',
    'wallet_deleted',
    'key_rotated',

    // Transactions
    'transaction_signed',
    'transaction_submitted',
    'transaction_validated',
    'transaction_failed',

    // Policy
    'policy_evaluated',
    'policy_violation',
    'policy_updated',

    // Approvals
    'approval_requested',
    'approval_granted',
    'approval_denied',
    'approval_expired',

    // Security
    'rate_limit_triggered',
    'injection_detected',
    'authentication_failed',

    // System
    'server_started',
    'server_stopped',
    'keystore_unlocked',
    'keystore_locked',
  ])
  .describe('Audit event type');

/**
 * Audit log entry schema
 */
export const AuditLogEntrySchema = z
  .object({
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
    policy_decision: z.enum(['allowed', 'denied', 'pending']).optional(),

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
    hash: z.string(),
  })
  .describe('Audit log entry with hash chain');

// ============================================================================
// TYPE EXPORTS
// ============================================================================

// XRPL Primitives
export type XRPLAddress = z.infer<typeof XRPLAddressSchema>;
export type DropsAmount = z.infer<typeof DropsAmountSchema>;
export type TransactionHash = z.infer<typeof TransactionHashSchema>;
export type PublicKey = z.infer<typeof PublicKeySchema>;
export type Network = z.infer<typeof NetworkSchema>;
export type TransactionType = z.infer<typeof TransactionTypeSchema>;
export type SequenceNumber = z.infer<typeof SequenceNumberSchema>;
export type LedgerIndex = z.infer<typeof LedgerIndexSchema>;
export type HexString = z.infer<typeof HexStringSchema>;
export type HexStringRaw = z.infer<typeof HexStringRawSchema>;
export type UnsignedTransactionBlob = z.infer<typeof UnsignedTransactionBlobSchema>;
export type SignedTransactionBlob = z.infer<typeof SignedTransactionBlobSchema>;
export type WalletId = z.infer<typeof WalletIdSchema>;
export type WalletName = z.infer<typeof WalletNameSchema>;
export type Timestamp = z.infer<typeof TimestampSchema>;
export type PaginationMarker = z.infer<typeof PaginationMarkerSchema>;

// Policy Types
export type ApprovalTier = z.infer<typeof ApprovalTierSchema>;
export type PolicyLimits = z.infer<typeof PolicyLimitsSchema>;
export type DestinationMode = z.infer<typeof DestinationModeSchema>;
export type PolicyDestinations = z.infer<typeof PolicyDestinationsSchema>;
export type PolicyTransactionTypes = z.infer<typeof PolicyTransactionTypesSchema>;
export type PolicyTimeControls = z.infer<typeof PolicyTimeControlsSchema>;
export type PolicyEscalation = z.infer<typeof PolicyEscalationSchema>;
export type NotificationEvent = z.infer<typeof NotificationEventSchema>;
export type PolicyNotifications = z.infer<typeof PolicyNotificationsSchema>;
export type AgentWalletPolicy = z.infer<typeof AgentWalletPolicySchema>;

// MCP Tool Inputs
export type WalletCreateInput = z.infer<typeof WalletCreateInputSchema>;
export type WalletImportInput = z.infer<typeof WalletImportInputSchema>;
export type WalletSignInput = z.infer<typeof WalletSignInputSchema>;
export type WalletBalanceInput = z.infer<typeof WalletBalanceInputSchema>;
export type WalletPolicyCheckInput = z.infer<typeof WalletPolicyCheckInputSchema>;
export type WalletRotateInput = z.infer<typeof WalletRotateInputSchema>;
export type WalletHistoryInput = z.infer<typeof WalletHistoryInputSchema>;
export type WalletListInput = z.infer<typeof WalletListInputSchema>;
export type WalletFundInput = z.infer<typeof WalletFundInputSchema>;
export type PolicySetInput = z.infer<typeof PolicySetInputSchema>;
export type TxSubmitInput = z.infer<typeof TxSubmitInputSchema>;
export type TxDecodeInput = z.infer<typeof TxDecodeInputSchema>;
export type NetworkConfigInput = z.infer<typeof NetworkConfigInputSchema>;

// MCP Tool Outputs
export type SignerEntry = z.infer<typeof SignerEntrySchema>;
export type WalletCreateOutput = z.infer<typeof WalletCreateOutputSchema>;
export type RemainingLimits = z.infer<typeof RemainingLimitsSchema>;
export type PolicyViolation = z.infer<typeof PolicyViolationSchema>;
export type WalletSignApprovedOutput = z.infer<typeof WalletSignApprovedOutputSchema>;
export type WalletSignPendingOutput = z.infer<typeof WalletSignPendingOutputSchema>;
export type WalletSignRejectedOutput = z.infer<typeof WalletSignRejectedOutputSchema>;
export type WalletSignOutput = z.infer<typeof WalletSignOutputSchema>;
export type WalletBalanceOutput = z.infer<typeof WalletBalanceOutputSchema>;
export type LimitStatus = z.infer<typeof LimitStatusSchema>;
export type WalletPolicyCheckOutput = z.infer<typeof WalletPolicyCheckOutputSchema>;
export type WalletRotateOutput = z.infer<typeof WalletRotateOutputSchema>;
export type TransactionHistoryEntry = z.infer<typeof TransactionHistoryEntrySchema>;
export type WalletHistoryOutput = z.infer<typeof WalletHistoryOutputSchema>;
export type WalletListEntry = z.infer<typeof WalletListEntrySchema>;
export type WalletListOutput = z.infer<typeof WalletListOutputSchema>;
export type WalletFundOutput = z.infer<typeof WalletFundOutputSchema>;
export type PolicySetOutput = z.infer<typeof PolicySetOutputSchema>;
export type TransactionResult = z.infer<typeof TransactionResultSchema>;
export type EscrowReference = z.infer<typeof EscrowReferenceSchema>;
export type TxSubmitOutput = z.infer<typeof TxSubmitOutputSchema>;
export type DecodedTransaction = z.infer<typeof DecodedTransactionSchema>;
export type TxDecodeOutput = z.infer<typeof TxDecodeOutputSchema>;
export type NetworkConfigOutput = z.infer<typeof NetworkConfigOutputSchema>;

// Error Types
export type ErrorCode = z.infer<typeof ErrorCodeSchema>;
export type ErrorResponse = z.infer<typeof ErrorResponseSchema>;

// Audit Types
export type AuditEventType = z.infer<typeof AuditEventTypeSchema>;
export type AuditLogEntry = z.infer<typeof AuditLogEntrySchema>;

// ============================================================================
// SCHEMA COLLECTIONS (for MCP tool registration)
// ============================================================================

/**
 * Collection of all input schemas for MCP tool registration
 */
export const InputSchemas = {
  wallet_create: WalletCreateInputSchema,
  wallet_import: WalletImportInputSchema,
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
  network_config: NetworkConfigInputSchema,
} as const;

/**
 * Collection of all output schemas for validation
 */
export const OutputSchemas = {
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
  error: ErrorResponseSchema,
} as const;

/**
 * Tool names type for type-safe tool registration
 */
export type ToolName = keyof typeof InputSchemas;
