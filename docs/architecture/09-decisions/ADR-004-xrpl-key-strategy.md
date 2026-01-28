# ADR-004: XRPL Key Strategy

**Status:** Accepted
**Date:** 2026-01-28
**Decision Makers:** Tech Lead, Security Specialist

---

## Context

XRPL accounts support multiple key types and signing configurations. The choice of key strategy directly impacts security, recovery capabilities, and operational flexibility for AI agent operations.

Key considerations:
1. **Master Key Exposure**: If an agent's key is compromised, can the account be recovered?
2. **Key Rotation**: Can keys be rotated without moving funds or changing the account address?
3. **Human Oversight**: How do we implement co-signing for high-value transactions?
4. **Recovery Options**: What happens if the agent's signing key is lost or compromised?
5. **Operational Flexibility**: Can we revoke agent access without affecting the account?

XRPL provides native support for:
- **Master Key**: Generated with the account, controls all account functions
- **Regular Key**: An alternative signing key that can be changed via SetRegularKey
- **Multi-Sign**: Require M-of-N signatures for transaction authorization

## Decision

**We will use Regular Keys for AI agent signing, with the Master Key kept in cold storage, and Multi-Sign for Tier 3 (co-sign) transactions.**

### Key Architecture

```
+------------------------------------------+
|              XRPL Account                |
|                                          |
|  Master Key (Cold Storage)               |
|  +------------------------------------+  |
|  | - Generated at account creation    |  |
|  | - NEVER used by agent              |  |
|  | - Offline/cold storage ONLY        |  |
|  | - Used for recovery operations     |  |
|  | - Can revoke Regular Key           |  |
|  +------------------------------------+  |
|                                          |
|  Regular Key (Agent Signing)             |
|  +------------------------------------+  |
|  | - Assigned via SetRegularKey tx    |  |
|  | - Used for Tier 1/2 transactions   |  |
|  | - Rotatable without fund movement  |  |
|  | - Revocable by Master Key          |  |
|  | - Stored in encrypted keystore     |  |
|  +------------------------------------+  |
|                                          |
|  Multi-Sign Configuration (Tier 3)       |
|  +------------------------------------+  |
|  | - SignerQuorum: 2                  |  |
|  | - Agent Regular Key: Weight 1      |  |
|  | - Human Approval Key: Weight 1     |  |
|  | - Requires both for high-value tx  |  |
|  +------------------------------------+  |
+------------------------------------------+
```

### Implementation Flow

#### Account Setup

```typescript
async function setupAgentAccount(masterSeed: string): Promise<AgentAccountConfig> {
  const masterWallet = Wallet.fromSeed(masterSeed);

  // Generate new regular key for agent
  const agentWallet = Wallet.generate();

  // Assign regular key to account
  const setRegularKeyTx: SetRegularKey = {
    TransactionType: 'SetRegularKey',
    Account: masterWallet.classicAddress,
    RegularKey: agentWallet.classicAddress
  };

  // Sign with master key (one-time setup)
  const signed = masterWallet.sign(setRegularKeyTx);
  await client.submitAndWait(signed.tx_blob);

  // Store only the agent's regular key in the MCP keystore
  // Master key goes to cold storage (hardware wallet, safe deposit, etc.)
  return {
    accountAddress: masterWallet.classicAddress,
    agentKeyAddress: agentWallet.classicAddress,
    agentSeed: agentWallet.seed  // Encrypted and stored
  };
}
```

#### Signing with Regular Key

```typescript
async function signTransaction(tx: Transaction, agentWallet: Wallet): Promise<string> {
  // Agent signs using regular key
  // XRPL validates that regular key is authorized for the Account
  const signed = agentWallet.sign(tx);
  return signed.tx_blob;
}
```

#### Multi-Sign Configuration for Tier 3

```typescript
async function setupMultiSign(
  masterWallet: Wallet,
  agentKeyAddress: string,
  humanKeyAddress: string
): Promise<void> {
  const signerListSetTx: SignerListSet = {
    TransactionType: 'SignerListSet',
    Account: masterWallet.classicAddress,
    SignerQuorum: 2,  // Both signatures required
    SignerEntries: [
      {
        SignerEntry: {
          Account: agentKeyAddress,
          SignerWeight: 1
        }
      },
      {
        SignerEntry: {
          Account: humanKeyAddress,
          SignerWeight: 1
        }
      }
    ]
  };

  // Sign with master key (one-time setup)
  const signed = masterWallet.sign(signerListSetTx);
  await client.submitAndWait(signed.tx_blob);
}
```

#### Tier 3 Co-Sign Flow

```typescript
async function coSignTransaction(
  tx: Transaction,
  agentWallet: Wallet
): Promise<PendingMultiSig> {
  // Agent provides their signature
  const agentSignature = agentWallet.sign(tx, { multisign: true });

  // Store pending transaction for human approval
  const pending: PendingMultiSig = {
    id: generateId(),
    transaction: tx,
    signatures: [agentSignature],
    requiredQuorum: 2,
    currentWeight: 1,
    expiresAt: Date.now() + 24 * 60 * 60 * 1000,  // 24 hours
    status: 'pending_human_approval'
  };

  await storePendingTransaction(pending);
  await notifyApprovers(pending);

  return pending;
}

// Human approval (separate interface, not MCP)
async function humanApprove(
  pendingId: string,
  humanWallet: Wallet
): Promise<string> {
  const pending = await getPendingTransaction(pendingId);

  // Human provides their signature
  const humanSignature = humanWallet.sign(pending.transaction, { multisign: true });

  // Combine signatures
  const combined = multisign([
    pending.signatures[0],
    humanSignature
  ]);

  // Submit fully-signed transaction
  const result = await client.submitAndWait(combined);

  return result.result.hash;
}
```

### Key Rotation

```typescript
async function rotateAgentKey(
  masterWallet: Wallet,  // Only needed for rotation
  accountAddress: string
): Promise<AgentKeyRotationResult> {
  // Generate new regular key
  const newAgentWallet = Wallet.generate();

  // Use master key to assign new regular key
  const setRegularKeyTx: SetRegularKey = {
    TransactionType: 'SetRegularKey',
    Account: accountAddress,
    RegularKey: newAgentWallet.classicAddress
  };

  const signed = masterWallet.sign(setRegularKeyTx);
  await client.submitAndWait(signed.tx_blob);

  // Old regular key is now invalid - no access to account
  return {
    newAgentKeyAddress: newAgentWallet.classicAddress,
    newAgentSeed: newAgentWallet.seed
  };
}
```

### Emergency Revocation

```typescript
async function revokeAgentAccess(masterWallet: Wallet): Promise<void> {
  // Remove regular key - agent can no longer sign
  const setRegularKeyTx: SetRegularKey = {
    TransactionType: 'SetRegularKey',
    Account: masterWallet.classicAddress,
    // Omitting RegularKey field removes it
  };

  const signed = masterWallet.sign(setRegularKeyTx);
  await client.submitAndWait(signed.tx_blob);

  // Account now only accepts master key signatures
}
```

## Consequences

### Positive

- **Recovery Capability**: Compromised agent key can be revoked; master key recovers full control
- **Key Rotation Without Fund Movement**: Regular key can be changed without moving XRP
- **Native XRPL Security**: Uses built-in XRPL features, no custom crypto
- **Clean Separation**: Agent operations isolated from ultimate account control
- **Multi-Sign Ready**: XRPL native multi-sig for human oversight
- **Auditability**: SetRegularKey and SignerListSet transactions visible on ledger
- **No Single Point of Failure**: Master key compromise requires physical access to cold storage
- **Instant Revocation**: Single transaction disables agent access

### Negative

- **Master Key Custody Complexity**: Requires secure offline storage (hardware wallet, vault)
- **Setup Overhead**: Initial configuration requires master key access
- **Rotation Requires Master Key**: Cannot rotate without accessing cold storage
- **Multi-Sign UX**: Co-sign flow requires external approval interface
- **Additional Transaction Costs**: SetRegularKey and SignerListSet consume XRP (minimal)

### Neutral

- Account address remains constant through key rotations
- Regular key can be any valid XRPL key pair
- Multi-sign configuration is optional (Tier 3 only)

## Alternatives Considered

| Option | Pros | Cons | Why Not Chosen |
|--------|------|------|----------------|
| **Master Key Only** | Simple, single key | Compromised key = total loss, no recovery | Unacceptable risk for agent operations |
| **Regular Key Only (No Master Cold Storage)** | Simple setup | Same risk as master-only if master not secured | Doesn't solve recovery problem |
| **Multi-Sign for All Transactions** | Maximum security | Poor agent autonomy, high latency | Defeats purpose of autonomous agent |
| **Key Sharding (Shamir)** | No single point of failure | Complex, off-chain, requires threshold ceremony | Adds complexity without XRPL integration |
| **Account Abstraction** | Flexible policies | Not natively supported by XRPL | Would require custom smart contracts |

## Implementation Notes

### Keystore Structure

```typescript
interface AgentKeystore {
  version: 1;
  network: 'mainnet' | 'testnet' | 'devnet';
  accounts: {
    [accountAddress: string]: {
      regularKey: {
        address: string;
        encryptedSeed: string;  // AES-256-GCM encrypted
      };
      multiSignConfig?: {
        quorum: number;
        signers: Array<{ address: string; weight: number }>;
      };
      // Master key is NEVER stored here
    };
  };
}
```

### Multi-Sign Pending Transaction Storage

```typescript
interface PendingMultiSigStore {
  transactions: {
    [id: string]: {
      transaction: Transaction;
      signatures: string[];
      currentWeight: number;
      requiredQuorum: number;
      createdAt: string;
      expiresAt: string;
      status: 'pending' | 'approved' | 'rejected' | 'expired';
      approvers: string[];
    };
  };
}
```

### Security Controls

| Control | Implementation |
|---------|----------------|
| Master key never online | Stored in hardware wallet/vault, accessed only for setup/recovery |
| Regular key encrypted | AES-256-GCM in keystore (ADR-001) |
| Multi-sign timeout | 24-hour expiration for pending approvals |
| Audit trail | All key operations logged (ADR-005) |

## Security Considerations

### Threat Mitigation

| Threat | Mitigation |
|--------|------------|
| Agent key compromise | Revoke via SetRegularKey using master key |
| Master key compromise | Keep in cold storage, hardware wallet |
| Multi-sig signer compromise | Require multiple signers, timeouts |
| Key rotation attack | Only master key can set regular key |

### Key Hierarchy Trust Model

```
Trust Level 1: Master Key (Highest)
  - Full account control
  - Can revoke all other keys
  - Never online/in MCP keystore

Trust Level 2: Human Approval Key
  - Can co-sign with agent
  - Cannot unilaterally transact (with proper quorum)
  - May be in separate secure system

Trust Level 3: Agent Regular Key (Lowest)
  - Limited by policy engine
  - Subject to revocation
  - Stored in encrypted keystore
```

### Compliance Mapping

| Requirement | Implementation |
|-------------|----------------|
| AUTHZ-002 | Tier 3 uses multi-sign |
| KEY-001 | Regular key generated with CSPRNG |
| KEY-002 | SecureBuffer for key operations |
| AUDIT-002 | Key operations logged |

## References

- [XRPL Regular Keys](https://xrpl.org/cryptographic-keys.html#regular-keys)
- [XRPL Multi-Signing](https://xrpl.org/multi-signing.html)
- [SetRegularKey Transaction](https://xrpl.org/setregularkey.html)
- [SignerListSet Transaction](https://xrpl.org/signerlistset.html)
- Security Requirements: AUTHZ-002, KEY-001, KEY-002

## Related ADRs

- [ADR-001: Key Storage](ADR-001-key-storage.md) - Regular key encryption
- [ADR-003: Policy Engine](ADR-003-policy-engine.md) - Tier 3 triggers multi-sign
- [ADR-010: Network Isolation](ADR-010-network-isolation.md) - Separate keys per network

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Tech Lead | Initial ADR |
