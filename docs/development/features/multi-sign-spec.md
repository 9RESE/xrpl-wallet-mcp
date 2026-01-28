# Multi-Signature Orchestration Specification

**Version:** 1.0.0
**Date:** 2026-01-28
**Status:** Complete
**Classification:** CRITICAL

---

## Table of Contents

1. [Overview](#1-overview)
2. [XRPL Multi-Sign Concepts](#2-xrpl-multi-sign-concepts)
3. [Architecture](#3-architecture)
4. [MultiSignOrchestrator Interface](#4-multisignorchestrator-interface)
5. [Signature Collection Workflow](#5-signature-collection-workflow)
6. [Transaction Assembly](#6-transaction-assembly)
7. [SignerList Management](#7-signerlist-management)
8. [Approval Notification System](#8-approval-notification-system)
9. [State Management](#9-state-management)
10. [Error Handling & Recovery](#10-error-handling--recovery)
11. [Security Considerations](#11-security-considerations)
12. [Test Patterns](#12-test-patterns)
13. [Integration Examples](#13-integration-examples)

---

## 1. Overview

### 1.1 Purpose

The Multi-Signature Orchestration system enables Tier 3 transactions (high-value operations) to require multiple signatures before submission to the XRPL network. This implements the co-sign pattern defined in [ADR-004: XRPL Key Strategy](../../architecture/09-decisions/ADR-004-xrpl-key-strategy.md).

### 1.2 Use Cases

| Use Case | Scenario | Quorum |
|----------|----------|--------|
| **Large Transfers** | Amounts exceeding 10x autonomous threshold | Agent + Human |
| **New High-Value Destinations** | First payment above threshold to unknown address | Agent + Human |
| **Account Settings** | SetRegularKey, SignerListSet, AccountDelete | Agent + Human |
| **Emergency Operations** | Key rotation, account recovery | 2+ Humans |
| **Cold Storage Movements** | Treasury to cold storage transfers | Agent + 2 Humans |

### 1.3 Key Features

- ✅ **XRPL Native Multi-Sign**: Uses built-in XRPL multi-signature protocol
- ✅ **Flexible Quorum**: Configurable M-of-N signature requirements
- ✅ **Timeout Protection**: Automatic expiration of pending approvals
- ✅ **Partial Signature Storage**: Preserve signatures across sessions
- ✅ **Human Notifications**: Webhook and email alerts for approvals
- ✅ **Audit Trail**: Complete signature collection history
- ✅ **Resumable Flows**: Can collect signatures over time
- ✅ **Multi-Wallet Support**: Different SignerLists per wallet

---

## 2. XRPL Multi-Sign Concepts

### 2.1 SignerList Structure

An XRPL SignerList defines who can sign transactions for an account:

```typescript
interface SignerList {
  /**
   * Array of authorized signers.
   * Maximum 32 signers per list.
   */
  SignerEntries: Array<{
    SignerEntry: {
      /**
       * XRPL address of the signer.
       */
      Account: string; // r-address

      /**
       * Weight assigned to this signer.
       * Range: 1-65535
       */
      SignerWeight: number;

      /**
       * Optional: URL for wallet locator (WalletLocator).
       * Used for hardware wallet identification.
       */
      WalletLocator?: string;
    };
  }>;

  /**
   * Total weight required for valid signature.
   * Range: 1-4,294,967,295
   * Must be <= sum of all signer weights.
   */
  SignerQuorum: number;
}
```

### 2.2 Quorum Calculation

**Example 1: 2-of-3 Multi-Sig**
```typescript
SignerQuorum: 2
SignerEntries: [
  { Account: 'rAgent...', SignerWeight: 1 },
  { Account: 'rHuman1...', SignerWeight: 1 },
  { Account: 'rHuman2...', SignerWeight: 1 }
]
// Valid combinations:
// - Agent + Human1 (1+1 = 2)
// - Agent + Human2 (1+1 = 2)
// - Human1 + Human2 (1+1 = 2)
```

**Example 2: Weighted Multi-Sig**
```typescript
SignerQuorum: 3
SignerEntries: [
  { Account: 'rAgent...', SignerWeight: 1 },
  { Account: 'rCFO...', SignerWeight: 2 },
  { Account: 'rManager...', SignerWeight: 1 }
]
// Valid combinations:
// - Agent + CFO (1+2 = 3)
// - CFO + Manager (2+1 = 3)
// - Agent + CFO + Manager (1+2+1 = 4) ✓ exceeds quorum
```

### 2.3 Multi-Sign Transaction Format

Multi-signed transactions have special requirements:

```typescript
interface MultiSignedTransaction {
  /**
   * CRITICAL: Must be empty string for multi-signed transactions.
   * Presence of a value indicates single-signature mode.
   */
  SigningPubKey: '',

  /**
   * Fee calculation for multi-sign:
   * Fee = (N+1) × base_fee
   * where N = number of signatures
   */
  Fee: string, // In drops

  /**
   * Array of signatures.
   * Must be sorted by Account address (ascending).
   */
  Signers: Array<{
    Signer: {
      /**
       * Signer's account address.
       */
      Account: string;

      /**
       * Transaction signed by this signer.
       */
      TxnSignature: string; // Hex-encoded signature

      /**
       * Signer's public key.
       */
      SigningPubKey: string; // Hex-encoded
    };
  }>;
}
```

### 2.4 Multi-Sign Signature Process

```
┌─────────────────────────────────────────────┐
│ 1. Prepare Transaction                      │
│    - Set SigningPubKey = ''                 │
│    - Calculate multi-sign fee               │
│    - Omit Signers array                     │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│ 2. Each Signer Signs Independently          │
│    - wallet.sign(tx, { multisign: true })   │
│    - Produces individual signature object   │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│ 3. Collect Signatures                       │
│    - Store each signature as received       │
│    - Track quorum progress                  │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│ 4. Assemble Multi-Signed Transaction        │
│    - Sort signatures by Account address     │
│    - Combine into Signers array             │
│    - Use xrpl.multisign() helper            │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│ 5. Submit to XRPL                           │
│    - Network validates quorum               │
│    - All signatures must be valid           │
└─────────────────────────────────────────────┘
```

---

## 3. Architecture

### 3.1 Component Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                     wallet_sign Tool                             │
│  (Tier 3 classified transaction)                                 │
└────────────────┬─────────────────────────────────────────────────┘
                 │
                 v
┌──────────────────────────────────────────────────────────────────┐
│               MultiSignOrchestrator                              │
│                                                                  │
│  ┌────────────────┐  ┌────────────────┐  ┌─────────────────┐   │
│  │ Request        │  │ Signature      │  │ Quorum          │   │
│  │ Manager        │  │ Collector      │  │ Tracker         │   │
│  └────────────────┘  └────────────────┘  └─────────────────┘   │
│                                                                  │
│  ┌────────────────┐  ┌────────────────┐  ┌─────────────────┐   │
│  │ Transaction    │  │ Timeout        │  │ Notification    │   │
│  │ Assembler      │  │ Manager        │  │ Dispatcher      │   │
│  └────────────────┘  └────────────────┘  └─────────────────┘   │
└─────────┬──────────────────────────────────────────────┬────────┘
          │                                               │
          v                                               v
┌──────────────────────┐                      ┌──────────────────────┐
│ MultiSignStore       │                      │ NotificationService  │
│ (State Persistence)  │                      │ (Webhook/Email)      │
└──────────────────────┘                      └──────────────────────┘
          │
          v
┌──────────────────────┐
│ AuditLogger          │
│ (Compliance Trail)   │
└──────────────────────┘
```

### 3.2 Data Flow

**Tier 3 Classification → Completion:**

```
Agent Request
      ↓
Policy Engine (Tier 3)
      ↓
MultiSignOrchestrator.initiate()
      ↓
Create MultiSignRequest (pending)
      ↓
Store in MultiSignStore
      ↓
Notify Human Approvers
      ↓
Return PendingResponse to Agent
      ↓
┌──── Wait for Signatures ────┐
│                              │
│ Human Approver(s) Review(s) │
│           ↓                  │
│ Human Sign + Submit          │
│           ↓                  │
│ Orchestrator.addSignature()  │
│           ↓                  │
│ Check Quorum                 │
│           ↓                  │
│ Quorum Not Met → Wait More   │ ← Loop
│                              │
└──────────────────────────────┘
      ↓ Quorum Met
Agent Adds Final Signature
      ↓
Orchestrator.complete()
      ↓
Assemble Multi-Signed TX
      ↓
Submit to XRPL
      ↓
Update Status → 'completed'
      ↓
Audit Log + Notify
      ↓
Return tx_hash to Agent
```

---

## 4. MultiSignOrchestrator Interface

### 4.1 Class Definition

```typescript
import { Client, Wallet, Transaction } from 'xrpl';

/**
 * Orchestrates multi-signature transaction workflows for Tier 3 operations.
 *
 * Responsibilities:
 * - Create pending multi-sign requests
 * - Collect signatures from multiple signers
 * - Track quorum progress
 * - Assemble final multi-signed transaction
 * - Handle timeouts and errors
 *
 * @example
 * const orchestrator = new MultiSignOrchestrator(xrplClient, store, notifier);
 * const request = await orchestrator.initiate(walletId, unsignedTx, signers);
 * // ... wait for human signatures ...
 * await orchestrator.addSignature(request.id, humanSignature);
 * const result = await orchestrator.complete(request.id, agentWallet);
 */
export class MultiSignOrchestrator {
  constructor(
    private xrplClient: Client,
    private store: MultiSignStore,
    private notificationService: NotificationService,
    private auditLogger: AuditLogger
  ) {}

  /**
   * Initiate a new multi-signature request.
   *
   * Creates a pending request, notifies approvers, and returns
   * the request ID for status tracking.
   *
   * @param walletId - Internal wallet identifier
   * @param walletAddress - XRPL address of the account
   * @param unsignedTx - Unsigned transaction blob (hex)
   * @param signerConfig - SignerList configuration for this wallet
   * @param context - Human-readable context for audit
   * @returns Multi-signature request with pending status
   *
   * @throws {McpError} WALLET_NOT_FOUND - Wallet doesn't exist
   * @throws {McpError} SIGNERLIST_NOT_CONFIGURED - Wallet has no SignerList
   * @throws {McpError} INVALID_TRANSACTION - Cannot decode transaction
   */
  async initiate(
    walletId: string,
    walletAddress: string,
    unsignedTx: string,
    signerConfig: SignerListConfig,
    context?: string
  ): Promise<MultiSignRequest>;

  /**
   * Add a signature from a human approver.
   *
   * Validates the signature, stores it, and checks if quorum is met.
   * Updates request status and notifies if ready for completion.
   *
   * @param requestId - Multi-sign request UUID
   * @param signature - Signed transaction from approver
   * @param signerAddress - Address of the signer (for validation)
   * @returns Updated request with new signature and quorum status
   *
   * @throws {McpError} REQUEST_NOT_FOUND - Request doesn't exist
   * @throws {McpError} REQUEST_EXPIRED - Request timeout exceeded
   * @throws {McpError} REQUEST_COMPLETED - Already finalized
   * @throws {McpError} INVALID_SIGNER - Address not in SignerList
   * @throws {McpError} DUPLICATE_SIGNATURE - Signer already signed
   * @throws {McpError} SIGNATURE_INVALID - Cryptographic verification failed
   */
  async addSignature(
    requestId: string,
    signature: string,
    signerAddress: string
  ): Promise<MultiSignRequest>;

  /**
   * Complete multi-signature and submit to XRPL.
   *
   * Verifies quorum is met, adds agent signature if needed,
   * assembles the final multi-signed transaction, and submits.
   *
   * @param requestId - Multi-sign request UUID
   * @param agentWallet - Agent's wallet (for final signature if needed)
   * @returns Completed transaction with hash
   *
   * @throws {McpError} REQUEST_NOT_FOUND - Request doesn't exist
   * @throws {McpError} REQUEST_EXPIRED - Request timeout exceeded
   * @throws {McpError} QUORUM_NOT_MET - Insufficient signatures
   * @throws {McpError} SUBMISSION_FAILED - XRPL submission error
   */
  async complete(
    requestId: string,
    agentWallet?: Wallet
  ): Promise<MultiSignCompleteResult>;

  /**
   * Reject a pending multi-sign request.
   *
   * Human approver explicitly rejects the transaction.
   * Discards all collected signatures and logs rejection.
   *
   * @param requestId - Multi-sign request UUID
   * @param rejectingAddress - Address of the rejecting approver
   * @param reason - Human-readable rejection reason
   * @returns Updated request with rejected status
   *
   * @throws {McpError} REQUEST_NOT_FOUND - Request doesn't exist
   * @throws {McpError} REQUEST_COMPLETED - Already finalized
   * @throws {McpError} UNAUTHORIZED_REJECTOR - Not an authorized signer
   */
  async reject(
    requestId: string,
    rejectingAddress: string,
    reason: string
  ): Promise<MultiSignRequest>;

  /**
   * Get current status of a multi-sign request.
   *
   * @param requestId - Multi-sign request UUID
   * @returns Current request state with signatures and quorum
   *
   * @throws {McpError} REQUEST_NOT_FOUND - Request doesn't exist
   */
  async getStatus(requestId: string): Promise<MultiSignRequest>;

  /**
   * List all pending multi-sign requests for a wallet.
   *
   * @param walletId - Internal wallet identifier
   * @param includeExpired - Include expired requests (default: false)
   * @returns Array of pending requests sorted by creation time
   */
  async listPending(
    walletId: string,
    includeExpired?: boolean
  ): Promise<MultiSignRequest[]>;

  /**
   * Cancel an expired request.
   *
   * Automated cleanup of requests that exceeded timeout.
   * Called by scheduled task, not directly by users.
   *
   * @param requestId - Multi-sign request UUID
   * @returns Updated request with expired status
   *
   * @internal
   */
  async expire(requestId: string): Promise<MultiSignRequest>;
}
```

### 4.2 Supporting Types

```typescript
/**
 * SignerList configuration for a wallet.
 */
export interface SignerListConfig {
  /**
   * Array of authorized signers.
   */
  signers: Array<{
    /**
     * XRPL address of the signer.
     */
    address: string;

    /**
     * Weight assigned to this signer.
     */
    weight: number;

    /**
     * Role designation for UI/audit.
     */
    role: 'agent' | 'human_approver' | 'emergency';

    /**
     * Display name for notifications.
     */
    name?: string;

    /**
     * Contact info for notifications.
     */
    email?: string;

    /**
     * Optional: Hardware wallet locator.
     */
    walletLocator?: string;
  }>;

  /**
   * Total weight required for valid signature.
   */
  quorum: number;

  /**
   * Timeout in seconds for pending requests.
   * Default: 86400 (24 hours)
   */
  timeout_seconds?: number;
}

/**
 * Multi-signature request state.
 */
export interface MultiSignRequest {
  /**
   * Unique identifier (UUID v4).
   */
  id: string;

  /**
   * Internal wallet identifier.
   */
  wallet_id: string;

  /**
   * XRPL address of the account.
   */
  wallet_address: string;

  /**
   * Transaction details.
   */
  transaction: {
    /**
     * Transaction type (e.g., 'Payment', 'AccountSet').
     */
    type: string;

    /**
     * Amount in drops (if applicable).
     */
    amount_drops?: string;

    /**
     * Destination address (if applicable).
     */
    destination?: string;

    /**
     * Unsigned transaction blob (hex).
     */
    unsigned_blob: string;

    /**
     * Decoded transaction JSON (for display).
     */
    decoded: Transaction;
  };

  /**
   * Signer tracking.
   */
  signers: Array<{
    /**
     * Signer's XRPL address.
     */
    address: string;

    /**
     * Role designation.
     */
    role: 'agent' | 'human_approver' | 'emergency';

    /**
     * Assigned weight.
     */
    weight: number;

    /**
     * Whether this signer has signed.
     */
    signed: boolean;

    /**
     * Signature blob (if signed).
     */
    signature?: string;

    /**
     * When signature was received.
     */
    signed_at?: string; // ISO 8601
  }>;

  /**
   * Quorum tracking.
   */
  quorum: {
    /**
     * Total weight required.
     */
    required: number;

    /**
     * Current collected weight.
     */
    collected: number;

    /**
     * Whether quorum is met.
     */
    met: boolean;
  };

  /**
   * Request lifecycle status.
   */
  status: 'pending' | 'approved' | 'rejected' | 'expired' | 'completed';

  /**
   * Timestamps.
   */
  created_at: string; // ISO 8601
  expires_at: string; // ISO 8601
  completed_at?: string; // ISO 8601

  /**
   * Result (if completed).
   */
  tx_hash?: string;

  /**
   * Rejection details (if rejected).
   */
  rejection?: {
    rejecting_address: string;
    reason: string;
    rejected_at: string; // ISO 8601
  };

  /**
   * Audit context.
   */
  context?: string;

  /**
   * Notification tracking.
   */
  notifications_sent: Array<{
    recipient: string;
    sent_at: string;
    type: 'created' | 'signature_added' | 'completed' | 'rejected' | 'expired';
  }>;
}

/**
 * Result of completing a multi-sign request.
 */
export interface MultiSignCompleteResult {
  /**
   * Request ID.
   */
  request_id: string;

  /**
   * Fully assembled multi-signed transaction blob (hex).
   */
  signed_tx: string;

  /**
   * Transaction hash from XRPL.
   */
  tx_hash: string;

  /**
   * Final quorum weight collected.
   */
  final_quorum: number;

  /**
   * Addresses that signed.
   */
  signers: string[];

  /**
   * Timestamp when submitted to XRPL.
   */
  submitted_at: string; // ISO 8601
}
```

---

## 5. Signature Collection Workflow

### 5.1 Initiation Phase

```typescript
/**
 * Step 1: wallet_sign tool classifies transaction as Tier 3
 */
async function handleTier3Transaction(
  walletId: string,
  walletAddress: string,
  unsignedTx: string,
  policy: AgentWalletPolicy,
  context?: string
): Promise<WalletSignPendingOutput> {
  // Load SignerList configuration for this wallet
  const signerConfig = await getSignerListConfig(walletId);
  if (!signerConfig) {
    throw new McpError(
      'SIGNERLIST_NOT_CONFIGURED',
      'Wallet does not have multi-signature configured'
    );
  }

  // Create multi-sign request
  const request = await multiSignOrchestrator.initiate(
    walletId,
    walletAddress,
    unsignedTx,
    signerConfig,
    context
  );

  // Return pending response
  return {
    status: 'pending_approval',
    approval_id: request.id,
    reason: 'requires_cosign',
    expires_at: request.expires_at,
    approval_url: buildApprovalUrl(request.id),
    policy_tier: 3,
    auto_approve_in_seconds: null, // No auto-approval for Tier 3
    required_signers: request.signers.map(s => ({
      address: s.address,
      role: s.role,
      signed: s.signed,
    })),
    quorum: {
      collected: request.quorum.collected,
      required: request.quorum.required,
    },
  };
}
```

### 5.2 Human Approval Flow

**Human Approver Interface (separate from MCP)**

```typescript
/**
 * Human approver reviews and signs the transaction.
 * This happens in a separate approval interface (web UI, mobile app).
 *
 * NOT an MCP tool - this is external to the agent.
 */
async function humanApprovalFlow(requestId: string, humanWallet: Wallet) {
  // 1. Fetch request details
  const request = await multiSignOrchestrator.getStatus(requestId);

  // 2. Display transaction details to human
  displayTransactionDetails(request.transaction.decoded);

  // 3. Human reviews and decides
  const decision = await promptHumanDecision();

  if (decision === 'REJECT') {
    // Reject the request
    await multiSignOrchestrator.reject(
      requestId,
      humanWallet.classicAddress,
      'User rejected transaction'
    );
    return;
  }

  // 4. Human signs the transaction
  const signature = humanWallet.sign(
    request.transaction.decoded,
    { multisign: true }
  );

  // 5. Submit signature to orchestrator
  await multiSignOrchestrator.addSignature(
    requestId,
    signature.tx_blob,
    humanWallet.classicAddress
  );

  console.log('Signature submitted. Quorum status:', request.quorum);
}
```

### 5.3 Agent Completion Flow

```typescript
/**
 * Agent checks status and completes when quorum is met.
 */
async function agentCompleteMultiSign(
  requestId: string,
  agentWallet: Wallet
): Promise<MultiSignCompleteResult> {
  // Check current status
  const request = await multiSignOrchestrator.getStatus(requestId);

  // Verify not expired
  if (new Date(request.expires_at) < new Date()) {
    throw new McpError('REQUEST_EXPIRED', 'Multi-sign request has expired');
  }

  // Check if quorum already met (human-only signatures)
  if (request.quorum.met && !needsAgentSignature(request)) {
    // Complete without agent signature
    return await multiSignOrchestrator.complete(requestId);
  }

  // Agent needs to add signature
  const result = await multiSignOrchestrator.complete(requestId, agentWallet);

  return result;
}

/**
 * Helper: Check if agent signature is needed.
 */
function needsAgentSignature(request: MultiSignRequest): boolean {
  const agentSigner = request.signers.find(s => s.role === 'agent');
  return agentSigner ? !agentSigner.signed : false;
}
```

### 5.4 Timeout Handling

```typescript
/**
 * Scheduled task to expire old requests.
 * Runs every 5 minutes.
 */
async function cleanupExpiredRequests() {
  const now = new Date();

  // Find all pending requests
  const pending = await store.listByStatus('pending');

  for (const request of pending) {
    const expiresAt = new Date(request.expires_at);

    if (expiresAt < now) {
      // Expire the request
      await multiSignOrchestrator.expire(request.id);

      // Notify approvers
      await notificationService.notify({
        type: 'multisign_expired',
        requestId: request.id,
        recipients: request.signers.map(s => s.address),
      });

      // Audit log
      await auditLogger.log('multisign_expired', {
        request_id: request.id,
        wallet_address: request.wallet_address,
        collected_signatures: request.signers.filter(s => s.signed).length,
        required_quorum: request.quorum.required,
      });
    }
  }
}
```

---

## 6. Transaction Assembly

### 6.1 Signature Combination

```typescript
import { multisign } from 'xrpl';

/**
 * Assemble final multi-signed transaction.
 *
 * Combines all collected signatures into a single transaction
 * ready for submission to XRPL.
 */
async function assembleMultiSignedTransaction(
  request: MultiSignRequest
): Promise<string> {
  // 1. Verify quorum is met
  if (!request.quorum.met) {
    throw new McpError(
      'QUORUM_NOT_MET',
      `Collected weight ${request.quorum.collected} < required ${request.quorum.required}`
    );
  }

  // 2. Extract signatures from signed signers
  const signatures = request.signers
    .filter(s => s.signed && s.signature)
    .map(s => s.signature!);

  if (signatures.length === 0) {
    throw new McpError('NO_SIGNATURES', 'No signatures collected');
  }

  // 3. Use xrpl.multisign() to combine signatures
  // This automatically:
  // - Sorts signers by Account address (ascending)
  // - Builds Signers array
  // - Sets SigningPubKey = ''
  // - Calculates correct multi-sign fee
  const multiSignedTx = multisign(signatures);

  return multiSignedTx;
}
```

### 6.2 Fee Calculation

```typescript
/**
 * Calculate fee for multi-signed transaction.
 *
 * XRPL multi-sign fee formula:
 * Fee = (N + 1) × base_fee
 * where N = number of signatures
 */
function calculateMultiSignFee(
  baseFeeDrops: bigint,
  signatureCount: number
): string {
  const multiplier = BigInt(signatureCount + 1);
  const totalFee = baseFeeDrops * multiplier;
  return totalFee.toString();
}

/**
 * Example calculations:
 *
 * Base fee: 10 drops
 * 2 signatures: (2+1) × 10 = 30 drops
 * 3 signatures: (3+1) × 10 = 40 drops
 * 5 signatures: (5+1) × 10 = 60 drops
 */
```

### 6.3 Signature Sorting

```typescript
/**
 * Sort signatures by Account address (ascending).
 *
 * XRPL requires Signers array to be sorted lexicographically
 * by the Account field.
 */
function sortSignatures(signatures: Array<{ Account: string }>): typeof signatures {
  return signatures.sort((a, b) => a.Account.localeCompare(b.Account));
}

/**
 * Example sorting:
 *
 * Before:
 * - rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe
 * - rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh
 * - rN7n7otQDd6FczFgLdlqtyMVrn3HMbjVfb
 *
 * After (sorted):
 * - rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh
 * - rN7n7otQDd6FczFgLdlqtyMVrn3HMbjVfb
 * - rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe
 */
```

### 6.4 Submission to XRPL

```typescript
/**
 * Submit multi-signed transaction to XRPL.
 */
async function submitMultiSigned(
  client: Client,
  multiSignedTx: string
): Promise<{ hash: string; result: string }> {
  try {
    // Submit the transaction
    const response = await client.submitAndWait(multiSignedTx, {
      // No wallet needed - already signed
      autofill: false,
      failHard: true,
    });

    // Extract result
    const result = response.result.meta?.TransactionResult || 'UNKNOWN';
    const hash = response.result.hash;

    if (result !== 'tesSUCCESS') {
      throw new McpError(
        'TRANSACTION_FAILED',
        `Transaction failed with result: ${result}`
      );
    }

    return { hash, result };
  } catch (error) {
    // Handle submission errors
    throw new McpError(
      'SUBMISSION_FAILED',
      `Failed to submit multi-signed transaction: ${error.message}`
    );
  }
}
```

---

## 7. SignerList Management

### 7.1 Creating SignerList

```typescript
import { SignerListSet } from 'xrpl';

/**
 * Setup SignerList for an XRPL account.
 *
 * This is a one-time setup operation that requires the master key
 * or current regular key.
 */
async function setupSignerList(
  client: Client,
  masterWallet: Wallet,
  config: SignerListConfig
): Promise<string> {
  // Construct SignerListSet transaction
  const signerListSetTx: SignerListSet = {
    TransactionType: 'SignerListSet',
    Account: masterWallet.classicAddress,
    SignerQuorum: config.quorum,
    SignerEntries: config.signers.map(signer => ({
      SignerEntry: {
        Account: signer.address,
        SignerWeight: signer.weight,
        ...(signer.walletLocator && { WalletLocator: signer.walletLocator }),
      },
    })),
  };

  // Sign with master key (one-time setup)
  const prepared = await client.autofill(signerListSetTx);
  const signed = masterWallet.sign(prepared);

  // Submit
  const result = await client.submitAndWait(signed.tx_blob);

  if (result.result.meta?.TransactionResult !== 'tesSUCCESS') {
    throw new Error(`SignerListSet failed: ${result.result.meta?.TransactionResult}`);
  }

  // Store configuration in database
  await storeSignerListConfig(masterWallet.classicAddress, config);

  return result.result.hash;
}
```

### 7.2 Updating SignerList

```typescript
/**
 * Update SignerList configuration.
 *
 * Requires existing SignerList quorum or master key.
 */
async function updateSignerList(
  client: Client,
  accountAddress: string,
  newConfig: SignerListConfig,
  signers: Wallet[] // Wallets to meet quorum for update
): Promise<string> {
  // Construct update transaction
  const updateTx: SignerListSet = {
    TransactionType: 'SignerListSet',
    Account: accountAddress,
    SignerQuorum: newConfig.quorum,
    SignerEntries: newConfig.signers.map(s => ({
      SignerEntry: {
        Account: s.address,
        SignerWeight: s.weight,
      },
    })),
  };

  // Prepare transaction
  const prepared = await client.autofill(updateTx);

  // Multi-sign the update (requires current SignerList quorum)
  const signatures = signers.map(wallet =>
    wallet.sign(prepared, { multisign: true }).tx_blob
  );

  const multiSigned = multisign(signatures);

  // Submit
  const result = await client.submitAndWait(multiSigned);

  if (result.result.meta?.TransactionResult !== 'tesSUCCESS') {
    throw new Error(`SignerListSet update failed: ${result.result.meta?.TransactionResult}`);
  }

  // Update database
  await storeSignerListConfig(accountAddress, newConfig);

  return result.result.hash;
}
```

### 7.3 Removing SignerList

```typescript
/**
 * Remove SignerList from account.
 *
 * Omitting SignerEntries or setting SignerQuorum to 0
 * removes the SignerList.
 */
async function removeSignerList(
  client: Client,
  masterWallet: Wallet
): Promise<string> {
  const removeTx: SignerListSet = {
    TransactionType: 'SignerListSet',
    Account: masterWallet.classicAddress,
    SignerQuorum: 0, // Setting to 0 removes the list
  };

  // Sign with master key
  const prepared = await client.autofill(removeTx);
  const signed = masterWallet.sign(prepared);

  // Submit
  const result = await client.submitAndWait(signed.tx_blob);

  if (result.result.meta?.TransactionResult !== 'tesSUCCESS') {
    throw new Error(`SignerList removal failed: ${result.result.meta?.TransactionResult}`);
  }

  // Remove from database
  await deleteSignerListConfig(masterWallet.classicAddress);

  return result.result.hash;
}
```

### 7.4 Querying SignerList

```typescript
/**
 * Query current SignerList from XRPL ledger.
 */
async function getSignerListFromLedger(
  client: Client,
  accountAddress: string
): Promise<SignerListConfig | null> {
  try {
    const response = await client.request({
      command: 'account_objects',
      account: accountAddress,
      type: 'signer_list',
    });

    const signerListObj = response.result.account_objects.find(
      obj => obj.LedgerEntryType === 'SignerList'
    );

    if (!signerListObj) {
      return null; // No SignerList configured
    }

    // Convert XRPL format to our config format
    return {
      signers: signerListObj.SignerEntries.map(entry => ({
        address: entry.SignerEntry.Account,
        weight: entry.SignerEntry.SignerWeight,
        role: 'human_approver', // Default role
        walletLocator: entry.SignerEntry.WalletLocator,
      })),
      quorum: signerListObj.SignerQuorum,
    };
  } catch (error) {
    console.error('Failed to query SignerList:', error);
    return null;
  }
}
```

---

## 8. Approval Notification System

### 8.1 Notification Types

```typescript
/**
 * Types of notifications sent during multi-sign workflow.
 */
export enum MultiSignNotificationType {
  /**
   * New multi-sign request created.
   */
  REQUEST_CREATED = 'request_created',

  /**
   * Signature added (quorum progress update).
   */
  SIGNATURE_ADDED = 'signature_added',

  /**
   * Quorum met, ready for completion.
   */
  QUORUM_MET = 'quorum_met',

  /**
   * Multi-sign completed and submitted.
   */
  COMPLETED = 'completed',

  /**
   * Request rejected by approver.
   */
  REJECTED = 'rejected',

  /**
   * Request expired without completion.
   */
  EXPIRED = 'expired',

  /**
   * Reminder for pending signature.
   */
  REMINDER = 'reminder',
}
```

### 8.2 Notification Service Interface

```typescript
/**
 * Service for sending notifications to human approvers.
 */
export interface NotificationService {
  /**
   * Send notification about multi-sign event.
   *
   * @param notification - Notification details
   * @returns Array of successful deliveries
   */
  notify(notification: MultiSignNotification): Promise<NotificationDelivery[]>;

  /**
   * Send reminder for pending signature.
   *
   * @param requestId - Multi-sign request ID
   * @param recipientAddress - Signer's XRPL address
   */
  sendReminder(requestId: string, recipientAddress: string): Promise<void>;
}

/**
 * Notification payload.
 */
export interface MultiSignNotification {
  /**
   * Type of notification.
   */
  type: MultiSignNotificationType;

  /**
   * Multi-sign request ID.
   */
  request_id: string;

  /**
   * Recipients (XRPL addresses).
   */
  recipients: string[];

  /**
   * Notification payload.
   */
  payload: {
    wallet_address: string;
    transaction_type: string;
    amount_xrp?: string;
    destination?: string;
    quorum_status?: {
      collected: number;
      required: number;
    };
    approval_url?: string;
    expires_at: string;
  };
}

/**
 * Delivery result.
 */
export interface NotificationDelivery {
  recipient: string;
  channel: 'email' | 'webhook' | 'sms';
  delivered: boolean;
  delivered_at?: string;
  error?: string;
}
```

### 8.3 Webhook Notification

```typescript
/**
 * Send webhook notification for multi-sign event.
 */
async function sendWebhookNotification(
  webhookUrl: string,
  notification: MultiSignNotification
): Promise<void> {
  const payload = {
    event: notification.type,
    request_id: notification.request_id,
    timestamp: new Date().toISOString(),
    data: notification.payload,
  };

  try {
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'XRPL-Wallet-MCP/1.0',
        'X-XRPL-Event-Type': notification.type,
        'X-XRPL-Request-ID': notification.request_id,
      },
      body: JSON.stringify(payload),
      timeout: 10000, // 10 second timeout
    });

    if (!response.ok) {
      throw new Error(`Webhook failed: ${response.status} ${response.statusText}`);
    }

    console.log(`Webhook notification sent to ${webhookUrl}`);
  } catch (error) {
    console.error(`Webhook notification failed: ${error.message}`);
    // Don't throw - notification failure shouldn't block workflow
  }
}
```

### 8.4 Email Notification

```typescript
/**
 * Send email notification to human approver.
 */
async function sendEmailNotification(
  recipientEmail: string,
  notification: MultiSignNotification
): Promise<void> {
  const subject = getEmailSubject(notification.type);
  const body = renderEmailTemplate(notification);

  try {
    await emailService.send({
      to: recipientEmail,
      subject: subject,
      html: body,
      attachments: [
        {
          filename: 'transaction-details.json',
          content: JSON.stringify(notification.payload, null, 2),
        },
      ],
    });

    console.log(`Email sent to ${recipientEmail}`);
  } catch (error) {
    console.error(`Email notification failed: ${error.message}`);
  }
}

/**
 * Generate email subject line.
 */
function getEmailSubject(type: MultiSignNotificationType): string {
  switch (type) {
    case MultiSignNotificationType.REQUEST_CREATED:
      return '🔐 Multi-Signature Approval Required';
    case MultiSignNotificationType.SIGNATURE_ADDED:
      return '✅ Signature Received - Quorum Progress Update';
    case MultiSignNotificationType.QUORUM_MET:
      return '🎯 Quorum Met - Ready for Completion';
    case MultiSignNotificationType.COMPLETED:
      return '✅ Multi-Signature Transaction Completed';
    case MultiSignNotificationType.REJECTED:
      return '❌ Multi-Signature Request Rejected';
    case MultiSignNotificationType.EXPIRED:
      return '⏰ Multi-Signature Request Expired';
    case MultiSignNotificationType.REMINDER:
      return '⏰ Reminder: Pending Multi-Signature Approval';
    default:
      return 'XRPL Multi-Signature Notification';
  }
}
```

### 8.5 Reminder System

```typescript
/**
 * Scheduled task to send reminders for pending signatures.
 *
 * Runs every 6 hours.
 */
async function sendPendingReminders() {
  const sixHoursAgo = new Date(Date.now() - 6 * 60 * 60 * 1000);

  // Find pending requests created more than 6 hours ago
  const pending = await store.findPendingOlderThan(sixHoursAgo);

  for (const request of pending) {
    // Find signers who haven't signed yet
    const pendingSigners = request.signers.filter(s => !s.signed && s.email);

    for (const signer of pendingSigners) {
      // Check if reminder already sent recently
      const lastReminder = getLastReminderTime(request.id, signer.address);
      if (lastReminder && Date.now() - lastReminder < 6 * 60 * 60 * 1000) {
        continue; // Skip if reminded within last 6 hours
      }

      // Send reminder
      await notificationService.sendReminder(request.id, signer.address);

      // Record reminder sent
      await recordReminderSent(request.id, signer.address);
    }
  }
}
```

---

## 9. State Management

### 9.1 MultiSignStore Interface

```typescript
/**
 * Persistent storage for multi-sign requests.
 */
export interface MultiSignStore {
  /**
   * Create a new multi-sign request.
   */
  create(request: MultiSignRequest): Promise<void>;

  /**
   * Get request by ID.
   */
  get(requestId: string): Promise<MultiSignRequest | null>;

  /**
   * Update existing request.
   */
  update(request: MultiSignRequest): Promise<void>;

  /**
   * List requests by wallet ID.
   */
  listByWallet(walletId: string, includeCompleted?: boolean): Promise<MultiSignRequest[]>;

  /**
   * List requests by status.
   */
  listByStatus(status: MultiSignRequest['status']): Promise<MultiSignRequest[]>;

  /**
   * Find pending requests older than timestamp.
   */
  findPendingOlderThan(timestamp: Date): Promise<MultiSignRequest[]>;

  /**
   * Delete completed/expired requests older than retention period.
   */
  cleanup(retentionDays: number): Promise<number>;
}
```

### 9.2 File-Based Storage Implementation

```typescript
import fs from 'fs/promises';
import path from 'path';

/**
 * File-based implementation of MultiSignStore.
 *
 * Storage structure:
 * {data_dir}/multisign/
 *   ├── pending/
 *   │   ├── {request_id}.json
 *   │   └── ...
 *   ├── completed/
 *   │   ├── {request_id}.json
 *   │   └── ...
 *   └── rejected/
 *       ├── {request_id}.json
 *       └── ...
 */
export class FileMultiSignStore implements MultiSignStore {
  private readonly baseDir: string;

  constructor(dataDir: string) {
    this.baseDir = path.join(dataDir, 'multisign');
  }

  async create(request: MultiSignRequest): Promise<void> {
    const dir = this.getDirectoryForStatus(request.status);
    await fs.mkdir(dir, { recursive: true });

    const filePath = path.join(dir, `${request.id}.json`);
    await fs.writeFile(filePath, JSON.stringify(request, null, 2), 'utf-8');
  }

  async get(requestId: string): Promise<MultiSignRequest | null> {
    // Check all subdirectories
    for (const status of ['pending', 'completed', 'rejected', 'expired']) {
      const filePath = path.join(this.baseDir, status, `${requestId}.json`);
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        return JSON.parse(content);
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
    }
    return null;
  }

  async update(request: MultiSignRequest): Promise<void> {
    // Remove from old location
    await this.delete(request.id);

    // Write to new location
    await this.create(request);
  }

  async listByWallet(walletId: string, includeCompleted = false): Promise<MultiSignRequest[]> {
    const dirs = includeCompleted
      ? ['pending', 'completed', 'rejected', 'expired']
      : ['pending'];

    const requests: MultiSignRequest[] = [];

    for (const dir of dirs) {
      const dirPath = path.join(this.baseDir, dir);
      try {
        const files = await fs.readdir(dirPath);
        for (const file of files) {
          const content = await fs.readFile(path.join(dirPath, file), 'utf-8');
          const request = JSON.parse(content);
          if (request.wallet_id === walletId) {
            requests.push(request);
          }
        }
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
    }

    return requests.sort((a, b) =>
      new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    );
  }

  async listByStatus(status: MultiSignRequest['status']): Promise<MultiSignRequest[]> {
    const dir = this.getDirectoryForStatus(status);
    const requests: MultiSignRequest[] = [];

    try {
      const files = await fs.readdir(dir);
      for (const file of files) {
        const content = await fs.readFile(path.join(dir, file), 'utf-8');
        requests.push(JSON.parse(content));
      }
    } catch (error) {
      if (error.code !== 'ENOENT') return [];
      throw error;
    }

    return requests;
  }

  async findPendingOlderThan(timestamp: Date): Promise<MultiSignRequest[]> {
    const pending = await this.listByStatus('pending');
    return pending.filter(r => new Date(r.created_at) < timestamp);
  }

  async cleanup(retentionDays: number): Promise<number> {
    const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
    let cleaned = 0;

    for (const status of ['completed', 'rejected', 'expired']) {
      const dir = path.join(this.baseDir, status);
      try {
        const files = await fs.readdir(dir);
        for (const file of files) {
          const filePath = path.join(dir, file);
          const content = await fs.readFile(filePath, 'utf-8');
          const request = JSON.parse(content);

          if (new Date(request.created_at) < cutoff) {
            await fs.unlink(filePath);
            cleaned++;
          }
        }
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
    }

    return cleaned;
  }

  private async delete(requestId: string): Promise<void> {
    for (const status of ['pending', 'completed', 'rejected', 'expired']) {
      const filePath = path.join(this.baseDir, status, `${requestId}.json`);
      try {
        await fs.unlink(filePath);
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
    }
  }

  private getDirectoryForStatus(status: MultiSignRequest['status']): string {
    return path.join(this.baseDir, status);
  }
}
```

### 9.3 State Transitions

```
┌─────────┐
│ PENDING │ ← Initial state after initiate()
└────┬────┘
     │
     ├─[Human rejects]──────────► ┌──────────┐
     │                            │ REJECTED │
     │                            └──────────┘
     │
     ├─[Timeout expires]────────► ┌─────────┐
     │                            │ EXPIRED │
     │                            └─────────┘
     │
     ├─[Quorum met]─────────────► ┌──────────┐
     │                            │ APPROVED │
     │                            └────┬─────┘
     │                                 │
     │                                 v
     │                            ┌───────────┐
     └────────────────────────────► COMPLETED │
                                  └───────────┘
```

---

## 10. Error Handling & Recovery

### 10.1 Error Scenarios

| Scenario | Error Code | Recovery Strategy |
|----------|------------|-------------------|
| Request not found | `REQUEST_NOT_FOUND` | Verify request ID, check if expired/deleted |
| Request expired | `REQUEST_EXPIRED` | Create new request with extended timeout |
| Invalid signer | `INVALID_SIGNER` | Verify signer is in SignerList, update config if needed |
| Duplicate signature | `DUPLICATE_SIGNATURE` | Ignore (idempotent), return current status |
| Signature invalid | `SIGNATURE_INVALID` | Re-sign with correct wallet, verify transaction blob |
| Quorum not met | `QUORUM_NOT_MET` | Wait for more signatures, check timeout |
| Network failure | `SUBMISSION_FAILED` | Retry with exponential backoff (3 attempts) |
| Insufficient XRP | `tecUNFUNDED` | Wait for funding, adjust amount, use reserve calculation |

### 10.2 Retry Logic

```typescript
/**
 * Submit multi-signed transaction with retry logic.
 */
async function submitWithRetry(
  client: Client,
  multiSignedTx: string,
  maxAttempts = 3
): Promise<{ hash: string; result: string }> {
  let attempt = 0;
  let lastError: Error | null = null;

  while (attempt < maxAttempts) {
    try {
      const result = await submitMultiSigned(client, multiSignedTx);
      return result;
    } catch (error) {
      lastError = error;
      attempt++;

      // Don't retry on permanent failures
      if (
        error.code === 'TRANSACTION_FAILED' ||
        error.message.includes('temMALFORMED') ||
        error.message.includes('tefPAST_SEQ')
      ) {
        break;
      }

      // Exponential backoff: 1s, 2s, 4s
      if (attempt < maxAttempts) {
        const delay = Math.pow(2, attempt - 1) * 1000;
        await sleep(delay);
      }
    }
  }

  throw new McpError(
    'SUBMISSION_FAILED',
    `Failed after ${attempt} attempts: ${lastError?.message}`
  );
}
```

### 10.3 Partial Signature Recovery

```typescript
/**
 * Recover from partial signature state.
 *
 * If system crashes during signature collection,
 * this restores the request and allows continuation.
 */
async function recoverPartialSignatures(requestId: string): Promise<MultiSignRequest> {
  // Load request from persistent store
  const request = await store.get(requestId);

  if (!request) {
    throw new McpError('REQUEST_NOT_FOUND', `No request found with ID ${requestId}`);
  }

  // Check if expired
  if (new Date(request.expires_at) < new Date()) {
    await multiSignOrchestrator.expire(requestId);
    throw new McpError('REQUEST_EXPIRED', 'Request expired during recovery');
  }

  // Check quorum status
  const collectedWeight = request.signers
    .filter(s => s.signed)
    .reduce((sum, s) => sum + s.weight, 0);

  request.quorum.collected = collectedWeight;
  request.quorum.met = collectedWeight >= request.quorum.required;

  // Update store
  await store.update(request);

  return request;
}
```

### 10.4 Signature Validation

```typescript
import { verify } from 'xrpl';

/**
 * Validate a signature before adding to request.
 */
async function validateSignature(
  signature: string,
  unsignedTx: string,
  expectedSigner: string
): Promise<boolean> {
  try {
    // Decode signature
    const decoded = decode(signature);

    // Verify SigningPubKey is empty (multi-sign requirement)
    if (decoded.SigningPubKey !== '') {
      throw new Error('Multi-sign requires empty SigningPubKey');
    }

    // Verify transaction hash matches
    const unsignedHash = hashTx(unsignedTx);
    const signedHash = decoded.hash;
    if (unsignedHash !== signedHash) {
      throw new Error('Transaction hash mismatch');
    }

    // Verify signer address matches expected
    const signerAddress = decodeAccountID(decoded.Account);
    if (signerAddress !== expectedSigner) {
      throw new Error(`Signer mismatch: expected ${expectedSigner}, got ${signerAddress}`);
    }

    // Cryptographic verification
    const isValid = verify(signature);
    return isValid;
  } catch (error) {
    console.error('Signature validation failed:', error);
    return false;
  }
}
```

---

## 11. Security Considerations

### 11.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| **Signature Replay** | Include LastLedgerSequence, sequence numbers |
| **Unauthorized Signer** | Validate signer in SignerList before accepting |
| **Signature Forgery** | Cryptographic verification of all signatures |
| **Race Condition** | Atomic quorum checks, transaction locking |
| **Timeout Manipulation** | Server-side timeout enforcement, no client control |
| **Request ID Guessing** | UUID v4 (122 bits entropy) |
| **Man-in-the-Middle** | TLS for all network communication |
| **Quorum Bypass** | Double-check quorum before submission |

### 11.2 Access Control

```typescript
/**
 * Verify requester is authorized to access multi-sign request.
 */
async function authorizeAccess(
  requestId: string,
  requesterAddress: string
): Promise<boolean> {
  const request = await store.get(requestId);

  if (!request) {
    return false;
  }

  // Allow access if requester is:
  // 1. The wallet owner (agent)
  // 2. One of the signers
  const isWalletOwner = request.wallet_address === requesterAddress;
  const isSigner = request.signers.some(s => s.address === requesterAddress);

  return isWalletOwner || isSigner;
}
```

### 11.3 Audit Logging

```typescript
/**
 * Audit events for multi-sign operations.
 */
export enum MultiSignAuditEvent {
  REQUEST_CREATED = 'multisign_request_created',
  SIGNATURE_ADDED = 'multisign_signature_added',
  SIGNATURE_REJECTED = 'multisign_signature_rejected',
  QUORUM_MET = 'multisign_quorum_met',
  TRANSACTION_COMPLETED = 'multisign_transaction_completed',
  REQUEST_REJECTED = 'multisign_request_rejected',
  REQUEST_EXPIRED = 'multisign_request_expired',
  SUBMISSION_FAILED = 'multisign_submission_failed',
}

/**
 * Log multi-sign event to audit trail.
 */
async function logMultiSignEvent(
  event: MultiSignAuditEvent,
  details: Record<string, unknown>
): Promise<void> {
  await auditLogger.log({
    event,
    timestamp: new Date().toISOString(),
    correlation_id: details.request_id,
    ...details,
  });
}
```

### 11.4 Rate Limiting

```typescript
/**
 * Rate limit multi-sign requests to prevent abuse.
 */
const multiSignRateLimit = {
  max_pending_per_wallet: 10,     // Max 10 pending requests per wallet
  max_creates_per_hour: 20,       // Max 20 new requests per hour
  max_signature_attempts: 5,      // Max 5 invalid signatures per request
};

/**
 * Check rate limits before creating request.
 */
async function checkRateLimits(walletId: string): Promise<void> {
  const pendingCount = await store.countPendingByWallet(walletId);
  if (pendingCount >= multiSignRateLimit.max_pending_per_wallet) {
    throw new McpError(
      'RATE_LIMIT_EXCEEDED',
      `Maximum ${multiSignRateLimit.max_pending_per_wallet} pending requests reached`
    );
  }

  const recentCount = await store.countCreatedInLastHour(walletId);
  if (recentCount >= multiSignRateLimit.max_creates_per_hour) {
    throw new McpError(
      'RATE_LIMIT_EXCEEDED',
      `Maximum ${multiSignRateLimit.max_creates_per_hour} requests per hour reached`
    );
  }
}
```

---

## 12. Test Patterns

### 12.1 Mock Signers

```typescript
/**
 * Mock signer for testing multi-sign workflows.
 */
export class MockSigner {
  constructor(
    public readonly address: string,
    public readonly weight: number,
    public readonly role: 'agent' | 'human_approver'
  ) {}

  /**
   * Sign a transaction (mock).
   */
  sign(tx: Transaction): string {
    // Return mock signature
    return `MOCK_SIGNATURE_${this.address}_${Date.now()}`;
  }

  /**
   * Create mock wallet for this signer.
   */
  createMockWallet(): Wallet {
    return {
      classicAddress: this.address,
      sign: (tx, options) => ({
        tx_blob: this.sign(tx),
        hash: hashTx(tx),
      }),
    } as Wallet;
  }
}

/**
 * Create mock SignerList for testing.
 */
export function createMockSignerList(): {
  config: SignerListConfig;
  signers: MockSigner[];
} {
  const signers = [
    new MockSigner('rAgent1234567890ABCDEFG', 1, 'agent'),
    new MockSigner('rHuman1234567890ABCDEFG', 1, 'human_approver'),
    new MockSigner('rHuman2234567890ABCDEFG', 1, 'human_approver'),
  ];

  const config: SignerListConfig = {
    signers: signers.map(s => ({
      address: s.address,
      weight: s.weight,
      role: s.role,
    })),
    quorum: 2,
    timeout_seconds: 3600,
  };

  return { config, signers };
}
```

### 12.2 Test Scenarios

```typescript
describe('MultiSignOrchestrator', () => {
  let orchestrator: MultiSignOrchestrator;
  let store: MultiSignStore;
  let mockSigners: MockSigner[];

  beforeEach(() => {
    const { config, signers } = createMockSignerList();
    mockSigners = signers;

    store = new InMemoryMultiSignStore();
    orchestrator = new MultiSignOrchestrator(
      mockXrplClient,
      store,
      mockNotificationService,
      mockAuditLogger
    );
  });

  describe('initiate()', () => {
    it('should create pending multi-sign request', async () => {
      const request = await orchestrator.initiate(
        'wallet_123',
        'rWallet...',
        'DEADBEEF...',
        mockSignerList,
        'Test transaction'
      );

      expect(request.status).toBe('pending');
      expect(request.quorum.collected).toBe(0);
      expect(request.quorum.required).toBe(2);
      expect(request.signers).toHaveLength(3);
    });

    it('should notify all signers on creation', async () => {
      await orchestrator.initiate(
        'wallet_123',
        'rWallet...',
        'DEADBEEF...',
        mockSignerList
      );

      expect(mockNotificationService.notify).toHaveBeenCalledWith({
        type: 'request_created',
        recipients: mockSigners.map(s => s.address),
      });
    });
  });

  describe('addSignature()', () => {
    it('should add valid signature and update quorum', async () => {
      const request = await orchestrator.initiate(...);
      const humanSigner = mockSigners[1];

      const updated = await orchestrator.addSignature(
        request.id,
        humanSigner.sign(request.transaction.decoded),
        humanSigner.address
      );

      expect(updated.quorum.collected).toBe(1);
      expect(updated.quorum.met).toBe(false);

      const signer = updated.signers.find(s => s.address === humanSigner.address);
      expect(signer?.signed).toBe(true);
    });

    it('should reject duplicate signature', async () => {
      const request = await orchestrator.initiate(...);
      const humanSigner = mockSigners[1];
      const signature = humanSigner.sign(request.transaction.decoded);

      await orchestrator.addSignature(request.id, signature, humanSigner.address);

      await expect(
        orchestrator.addSignature(request.id, signature, humanSigner.address)
      ).rejects.toThrow('DUPLICATE_SIGNATURE');
    });

    it('should reject signature from unauthorized signer', async () => {
      const request = await orchestrator.initiate(...);
      const unauthorizedSigner = new MockSigner('rUnauthorized...', 1, 'human_approver');

      await expect(
        orchestrator.addSignature(
          request.id,
          unauthorizedSigner.sign(request.transaction.decoded),
          unauthorizedSigner.address
        )
      ).rejects.toThrow('INVALID_SIGNER');
    });

    it('should detect quorum met', async () => {
      const request = await orchestrator.initiate(...);

      // Add agent signature
      await orchestrator.addSignature(
        request.id,
        mockSigners[0].sign(request.transaction.decoded),
        mockSigners[0].address
      );

      // Add human signature
      const updated = await orchestrator.addSignature(
        request.id,
        mockSigners[1].sign(request.transaction.decoded),
        mockSigners[1].address
      );

      expect(updated.quorum.collected).toBe(2);
      expect(updated.quorum.met).toBe(true);
    });
  });

  describe('complete()', () => {
    it('should submit multi-signed transaction when quorum met', async () => {
      const request = await orchestrator.initiate(...);

      // Collect signatures
      await orchestrator.addSignature(request.id, mockSigners[0].sign(...), ...);
      await orchestrator.addSignature(request.id, mockSigners[1].sign(...), ...);

      // Complete
      const result = await orchestrator.complete(request.id);

      expect(result.tx_hash).toBeDefined();
      expect(result.final_quorum).toBe(2);
      expect(mockXrplClient.submitAndWait).toHaveBeenCalled();
    });

    it('should fail if quorum not met', async () => {
      const request = await orchestrator.initiate(...);

      // Only one signature
      await orchestrator.addSignature(request.id, mockSigners[0].sign(...), ...);

      await expect(orchestrator.complete(request.id)).rejects.toThrow('QUORUM_NOT_MET');
    });

    it('should handle submission retry on network failure', async () => {
      const request = await orchestrator.initiate(...);

      await orchestrator.addSignature(request.id, mockSigners[0].sign(...), ...);
      await orchestrator.addSignature(request.id, mockSigners[1].sign(...), ...);

      mockXrplClient.submitAndWait
        .mockRejectedValueOnce(new Error('Network timeout'))
        .mockResolvedValueOnce({ result: { hash: 'ABC123', meta: { TransactionResult: 'tesSUCCESS' }}});

      const result = await orchestrator.complete(request.id);

      expect(result.tx_hash).toBe('ABC123');
      expect(mockXrplClient.submitAndWait).toHaveBeenCalledTimes(2);
    });
  });

  describe('reject()', () => {
    it('should reject request and discard signatures', async () => {
      const request = await orchestrator.initiate(...);

      await orchestrator.addSignature(request.id, mockSigners[0].sign(...), ...);

      const rejected = await orchestrator.reject(
        request.id,
        mockSigners[1].address,
        'Transaction not approved'
      );

      expect(rejected.status).toBe('rejected');
      expect(rejected.rejection?.reason).toBe('Transaction not approved');
    });
  });

  describe('expire()', () => {
    it('should expire request after timeout', async () => {
      const request = await orchestrator.initiate(...);

      // Simulate timeout passage
      jest.advanceTimersByTime(25 * 60 * 60 * 1000); // 25 hours

      const expired = await orchestrator.expire(request.id);

      expect(expired.status).toBe('expired');
    });
  });
});
```

### 12.3 Integration Test Example

```typescript
/**
 * End-to-end integration test for multi-sign workflow.
 */
describe('Multi-Sign Integration', () => {
  it('should complete full Tier 3 workflow', async () => {
    // 1. Setup
    const { config, signers } = createMockSignerList();
    const agentWallet = signers[0].createMockWallet();
    const humanWallet1 = signers[1].createMockWallet();

    // 2. Agent initiates Tier 3 transaction
    const signRequest = await walletSignTool.call({
      wallet_address: 'rWallet...',
      unsigned_tx: createLargePaymentTx(),
      context: 'Large treasury transfer',
    });

    expect(signRequest.status).toBe('pending_approval');
    expect(signRequest.policy_tier).toBe(3);
    expect(signRequest.quorum.required).toBe(2);

    // 3. Human approver 1 signs
    const humanSignature1 = humanWallet1.sign(
      signRequest.transaction.decoded,
      { multisign: true }
    );

    await orchestrator.addSignature(
      signRequest.approval_id,
      humanSignature1.tx_blob,
      humanWallet1.classicAddress
    );

    // 4. Check status (quorum met)
    const status = await orchestrator.getStatus(signRequest.approval_id);
    expect(status.quorum.met).toBe(true);

    // 5. Agent completes
    const result = await orchestrator.complete(
      signRequest.approval_id,
      agentWallet
    );

    expect(result.tx_hash).toBeDefined();
    expect(result.final_quorum).toBe(2);

    // 6. Verify on-ledger
    const ledgerTx = await xrplClient.request({
      command: 'tx',
      transaction: result.tx_hash,
    });

    expect(ledgerTx.result.meta.TransactionResult).toBe('tesSUCCESS');
    expect(ledgerTx.result.Signers).toHaveLength(2);
  });
});
```

---

## 13. Integration Examples

### 13.1 Setup Multi-Sign for New Wallet

```typescript
/**
 * Complete setup flow for multi-sign enabled wallet.
 */
async function setupMultiSignWallet(
  xrplClient: Client,
  masterWallet: Wallet,
  agentAddress: string,
  humanApprovers: Array<{ address: string; email: string; name: string }>
): Promise<string> {
  // 1. Create SignerList configuration
  const signerConfig: SignerListConfig = {
    signers: [
      {
        address: agentAddress,
        weight: 1,
        role: 'agent',
        name: 'AI Agent',
      },
      ...humanApprovers.map(human => ({
        address: human.address,
        weight: 1,
        role: 'human_approver' as const,
        name: human.name,
        email: human.email,
      })),
    ],
    quorum: 2, // Agent + 1 human
    timeout_seconds: 86400, // 24 hours
  };

  // 2. Setup SignerList on-chain
  const txHash = await setupSignerList(xrplClient, masterWallet, signerConfig);

  console.log(`SignerList configured: ${txHash}`);

  // 3. Store configuration in database
  await storeSignerListConfig(masterWallet.classicAddress, signerConfig);

  // 4. Update wallet policy to use Tier 3 for appropriate transactions
  await updateWalletPolicy(masterWallet.classicAddress, {
    escalation: {
      amount_threshold_drops: '10000000', // 10 XRP
      account_settings: 3, // Always Tier 3
    },
  });

  return txHash;
}
```

### 13.2 Agent Request with Co-Sign

```typescript
/**
 * Agent initiates large payment requiring co-sign.
 */
async function initiateCoSignedPayment(
  fromWallet: string,
  toAddress: string,
  amountXrp: number
): Promise<string> {
  // 1. Build transaction
  const tx = {
    TransactionType: 'Payment',
    Account: fromWallet,
    Destination: toAddress,
    Amount: xrpl.xrpToDrops(amountXrp),
  };

  // 2. Prepare unsigned transaction
  const prepared = await xrplClient.autofill(tx);
  const unsigned = encode(prepared);

  // 3. Request signing via wallet_sign tool
  const result = await walletSignTool.call({
    wallet_address: fromWallet,
    unsigned_tx: unsigned,
    context: `Payment of ${amountXrp} XRP to ${toAddress}`,
  });

  if (result.status === 'pending_approval') {
    console.log(`Multi-sign required. Request ID: ${result.approval_id}`);
    console.log(`Approval URL: ${result.approval_url}`);
    console.log(`Quorum: ${result.quorum.collected}/${result.quorum.required}`);
    console.log(`Expires: ${result.expires_at}`);

    // Poll for completion
    return await pollForCompletion(result.approval_id);
  } else if (result.status === 'approved') {
    // Tier 1 - immediate approval
    return result.tx_hash;
  } else {
    throw new Error(`Signing rejected: ${result.reason}`);
  }
}

/**
 * Poll for multi-sign completion.
 */
async function pollForCompletion(
  approvalId: string,
  maxWaitSeconds = 3600
): Promise<string> {
  const startTime = Date.now();
  const pollInterval = 5000; // 5 seconds

  while (Date.now() - startTime < maxWaitSeconds * 1000) {
    const status = await multiSignOrchestrator.getStatus(approvalId);

    if (status.status === 'completed') {
      return status.tx_hash!;
    }

    if (status.status === 'rejected') {
      throw new Error(`Request rejected: ${status.rejection?.reason}`);
    }

    if (status.status === 'expired') {
      throw new Error('Request expired without completion');
    }

    // Check if ready for agent completion
    if (status.quorum.met && needsAgentSignature(status)) {
      // Agent can complete now
      const agentWallet = await loadAgentWallet();
      const result = await multiSignOrchestrator.complete(approvalId, agentWallet);
      return result.tx_hash;
    }

    await sleep(pollInterval);
  }

  throw new Error('Timeout waiting for multi-sign completion');
}
```

### 13.3 Human Approval Interface

```typescript
/**
 * Human approval dashboard endpoint.
 */
app.get('/approvals/:requestId', async (req, res) => {
  const requestId = req.params.requestId;
  const request = await multiSignOrchestrator.getStatus(requestId);

  if (!request) {
    return res.status(404).send('Request not found');
  }

  res.render('approval', {
    request,
    transaction: formatTransaction(request.transaction.decoded),
    quorum: request.quorum,
    signers: request.signers,
    expiresIn: getTimeRemaining(request.expires_at),
  });
});

/**
 * Human signs and approves.
 */
app.post('/approvals/:requestId/approve', async (req, res) => {
  const requestId = req.params.requestId;
  const { walletSeed, password } = req.body;

  try {
    // Decrypt wallet
    const humanWallet = await decryptWallet(walletSeed, password);

    // Get request
    const request = await multiSignOrchestrator.getStatus(requestId);

    // Sign transaction
    const signature = humanWallet.sign(
      request.transaction.decoded,
      { multisign: true }
    );

    // Submit signature
    await multiSignOrchestrator.addSignature(
      requestId,
      signature.tx_blob,
      humanWallet.classicAddress
    );

    res.json({
      success: true,
      message: 'Signature added successfully',
      quorum: request.quorum,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

/**
 * Human rejects.
 */
app.post('/approvals/:requestId/reject', async (req, res) => {
  const requestId = req.params.requestId;
  const { reason, signerAddress } = req.body;

  await multiSignOrchestrator.reject(requestId, signerAddress, reason);

  res.json({
    success: true,
    message: 'Request rejected',
  });
});
```

---

## Related Documents

- [ADR-004: XRPL Key Strategy](../../architecture/09-decisions/ADR-004-xrpl-key-strategy.md)
- [wallet_sign Tool Specification](../../api/tools/wallet-sign.md)
- [Policy Engine Architecture](../../architecture/05-building-blocks.md#policy-engine)
- [Security Requirements](../../security/security-requirements.md)

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | XRPL Blockchain Engineer | Initial comprehensive specification |

---

*This specification defines the complete multi-signature orchestration system for Tier 3 transactions in the XRPL Agent Wallet MCP server.*
