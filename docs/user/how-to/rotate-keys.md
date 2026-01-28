# How to Rotate Keys

This guide walks you through rotating cryptographic keys for XRPL agent wallets. Key rotation replaces the active regular key with a new one, invalidating the old key to limit exposure from potential compromises.

---

## Why Rotate Keys

Key rotation is a critical security practice that protects your wallet against various threats:

| Reason | Description | Urgency |
|--------|-------------|---------|
| **Scheduled Maintenance** | Regular rotation limits the window of exposure if a key is silently compromised | Low |
| **Personnel Changes** | When team members with key access depart, rotate immediately | Medium |
| **Suspected Compromise** | If key material may have been exposed in logs, backups, or breaches | High |
| **Security Upgrade** | Moving to stronger key algorithms (e.g., secp256k1 to ed25519) | Low |
| **Incident Response** | Active security incident requires immediate key invalidation | Critical |
| **Compliance** | Regulatory requirements mandate periodic key lifecycle management | Medium |

**Key rotation is irreversible.** Once a SetRegularKey transaction is validated on-chain, the old key can never sign transactions for that account again.

---

## Prerequisites

Before rotating keys, ensure you have:

- XRPL Agent Wallet MCP server running and accessible
- Wallet exists in the keystore and is unlocked (authenticated session)
- Sufficient XRP balance for transaction fee (minimum 12 drops)
- Human approver available for Tier 3 co-sign approval
- Network connectivity to XRPL nodes
- Backup storage location prepared (recommended)

### Verify Prerequisites

1. Check wallet status:

   ```bash
   # Using MCP client or Claude Desktop
   # Call wallet_list to verify wallet exists
   ```

2. Verify XRP balance:

   ```bash
   # Call wallet_balance to ensure sufficient funds
   # Minimum 12 drops required, recommend 100+ drops
   ```

3. Confirm human approver availability:

   Key rotation always requires Tier 3 (co-sign) approval. Ensure at least one designated human approver can respond within the approval timeout window (default: 24 hours).

---

## Key Rotation Procedure

### Step 1: Initiate the Rotation

Call the `wallet_rotate` tool with the wallet address and reason:

```json
{
  "wallet_address": "rYourWalletAddress1234567890abcdef",
  "reason": "scheduled",
  "create_backup": true
}
```

**Required fields:**

| Field | Description |
|-------|-------------|
| `wallet_address` | XRPL address of the wallet to rotate |
| `reason` | One of: `scheduled`, `personnel_change`, `suspected_compromise`, `security_upgrade`, `incident_response`, `compliance`, `other` |

**Optional fields:**

| Field | Default | Description |
|-------|---------|-------------|
| `create_backup` | `true` | Create encrypted backup of new key (strongly recommended) |
| `reason_description` | - | Detailed description (required for `other` or `incident_response`) |
| `force` | `false` | Bypass 24-hour cooldown period (emergency only) |

### Step 2: Handle Pending Approval

The tool returns a pending response requiring human approval:

```json
{
  "status": "pending_approval",
  "approval_id": "550e8400-e29b-41d4-a716-446655440000",
  "reason": "key_rotation_requires_cosign",
  "policy_tier": 3,
  "required_signers": [
    {
      "address": "rAgentWallet...",
      "role": "agent",
      "signed": false
    },
    {
      "address": "rHumanApprover...",
      "role": "human_approver",
      "signed": false
    }
  ],
  "quorum": {
    "collected": 0,
    "required": 2
  },
  "expires_at": "2026-01-29T14:30:00.000Z",
  "approval_url": "https://dashboard.example.com/approvals/550e8400",
  "new_key_preview": {
    "public_key": "ED1234567890ABCDEF...",
    "address": "rNewKeyAddress12345678901234",
    "algorithm": "ed25519"
  }
}
```

Record the `approval_id` for tracking. Share the `approval_url` with your designated human approver.

### Step 3: Human Approval

The human approver must review the rotation request and either approve or reject it. They should verify:

- The rotation reason is legitimate
- The wallet address is correct
- The timing is appropriate
- No suspicious circumstances exist

Approval can be granted via:
- The approval dashboard URL
- Direct API call with the approval ID
- Command-line approval tool

### Step 4: Confirm Completion

After human approval, the system automatically:

1. Signs the SetRegularKey transaction with the old key
2. Submits the transaction to the XRPL network
3. Waits for validation in a closed ledger
4. Stores the new key in the encrypted keystore
5. Creates an encrypted backup (if enabled)
6. Securely deletes the old key
7. Logs all operations for audit

Poll for completion status or check for the completed response:

```json
{
  "status": "completed",
  "tx_hash": "E08D6E9754025BA2534A78707605E0601F03ACE063687A0CA1BDDACFCD1698C7",
  "ledger_index": 12345678,
  "new_key": {
    "public_key": "ED1234567890ABCDEF...",
    "address": "rNewKeyAddress12345678901234",
    "algorithm": "ed25519"
  },
  "old_key": {
    "public_key": "ED0987654321FEDCBA...",
    "address": "rOldKeyAddress09876543210987",
    "invalidated_at": "2026-01-28T14:35:00.000Z"
  },
  "backup": {
    "created": true,
    "path": "~/.xrpl-wallet-mcp/backups/rYourWallet.../key_abc123.backup.json",
    "checksum": "sha256:abcdef1234567890..."
  },
  "completed_at": "2026-01-28T14:35:30.000Z",
  "audit_seq": 10456
}
```

---

## Verifying Rotation Success

After rotation completes, verify the new key is working correctly.

### 1. Verify On-Chain State

Query the account to confirm the new RegularKey is set:

```typescript
// Request account_info from XRPL
{
  "command": "account_info",
  "account": "rYourWalletAddress1234567890abcdef"
}

// Response should show:
{
  "account_data": {
    "Account": "rYourWalletAddress1234567890abcdef",
    "RegularKey": "rNewKeyAddress12345678901234"  // Verify this matches
  }
}
```

### 2. Test Signing with New Key

Perform a test signing operation to confirm the new key works:

```json
{
  "tool": "wallet_sign",
  "params": {
    "wallet_address": "rYourWalletAddress1234567890abcdef",
    "unsigned_tx": "<test_transaction_blob>",
    "context": "Post-rotation verification test"
  }
}
```

A successful signature confirms the new key is properly stored and accessible.

### 3. Verify Old Key is Invalid

Optionally, confirm the old key can no longer sign (this should fail):

If you have access to the old key material separately (not recommended), attempting to sign with it should produce an invalid signature that the network rejects.

### 4. Check Audit Logs

Review the audit logs to confirm all rotation steps completed:

```
key.rotate.requested      -> Rotation initiated
key.rotate.approved       -> Human approved
key.rotate.tx_validated   -> SetRegularKey confirmed on-chain
key.rotate.new_key_stored -> New key saved to keystore
key.rotate.backup_created -> Backup file created
key.rotate.old_key_deleted -> Old key securely removed
key.rotate.completed      -> Full rotation complete
```

---

## Backup Considerations

### Why Backups Matter

Backups are your last line of defense against:

- Keystore corruption
- Disk failures
- Accidental deletion
- Storage migration errors

**Always keep `create_backup: true`** unless you have an alternative backup strategy.

### Backup File Location

Backups are stored at:

```
~/.xrpl-wallet-mcp/backups/{wallet_address}/{key_id}.backup.json
```

### Securing Your Backups

1. **Set proper permissions:**

   ```bash
   chmod 600 ~/.xrpl-wallet-mcp/backups/*/*
   chmod 700 ~/.xrpl-wallet-mcp/backups/*/
   chmod 700 ~/.xrpl-wallet-mcp/backups/
   ```

2. **Store backups offsite:**

   Copy encrypted backup files to:
   - Hardware security module (HSM)
   - Encrypted USB drive in secure storage
   - Encrypted cloud storage (with separate encryption key)
   - Hardware wallet backup (if supported)

3. **Test backup restoration periodically:**

   See [Recovery from Failed Rotation](#recovery-from-failed-rotation) for restoration procedures.

4. **Never store the backup password with the backup file.**

### Backup Password Management

The backup is encrypted with a separate password (not the keystore password). When a backup is created:

- If a backup password is configured, it uses that password
- If no password is configured, a new password is generated and displayed
- The backup password is never stored by the system

**Store the backup password separately from the backup file** in a secure location such as:
- Password manager
- Sealed envelope in a safe
- Hardware security device

---

## Recovery from Failed Rotation

Different failure scenarios require different recovery approaches.

### Scenario 1: Approval Expired

If the human approver does not respond within the timeout window:

```json
{
  "status": "rejected",
  "rejection_code": "APPROVAL_EXPIRED",
  "reason": "Approval request timed out after 24 hours"
}
```

**Recovery:** Simply submit a new rotation request. No state change occurred.

### Scenario 2: Transaction Failed to Submit

If the SetRegularKey transaction failed to submit to the network:

```json
{
  "status": "rejected",
  "rejection_code": "TRANSACTION_SUBMIT_ERROR",
  "reason": "Failed to submit to XRPL network"
}
```

**Recovery:**
1. Check network connectivity
2. Verify sufficient XRP balance
3. Retry the rotation request

### Scenario 3: Transaction Failed On-Chain

If the SetRegularKey transaction was rejected by validators:

```json
{
  "status": "rejected",
  "rejection_code": "TRANSACTION_FAILED",
  "details": {
    "tx_hash": "ABC123...",
    "xrpl_result": "tecNO_PERMISSION"
  }
}
```

**Recovery:**
1. Check the XRPL error code
2. Resolve the underlying issue (permissions, account state)
3. Retry the rotation request

### Scenario 4: Keystore Storage Failed (CRITICAL)

If the new key failed to store after the transaction validated on-chain:

```json
{
  "status": "rejected",
  "rejection_code": "KEYSTORE_ERROR",
  "message": "CRITICAL: Failed to store new key after on-chain validation",
  "details": {
    "tx_hash": "GHI789JKL012...",
    "ledger_index": 12345678,
    "backup_available": true,
    "backup_path": "~/.xrpl-wallet-mcp/backups/rWallet.../key_abc.backup.json"
  },
  "recovery_steps": [
    "1. Do NOT retry rotation - transaction is already validated",
    "2. Use backup file to restore key",
    "3. Verify restored key can sign",
    "4. Contact support if restoration fails"
  ]
}
```

**This is a critical situation.** The on-chain state has changed but the new key is not accessible.

**Recovery procedure:**

1. **Do NOT retry the rotation.** The SetRegularKey is already validated on-chain.

2. **Locate the backup file** at the path specified in the error.

3. **Restore from backup:**

   ```bash
   # Use the wallet_restore_key tool
   {
     "tool": "wallet_restore_key",
     "params": {
       "backup_path": "~/.xrpl-wallet-mcp/backups/rWallet.../key_abc.backup.json",
       "backup_password": "<your_backup_password>"
     }
   }
   ```

4. **Verify restoration** by testing a signature operation.

### Scenario 5: Both Keys Lost (Emergency)

If both the old key and new key are inaccessible:

**This requires master key recovery.** The master key should be in cold storage and never touched by the MCP server during normal operation.

1. Retrieve the master key from cold storage
2. Use emergency master key rotation (offline process)
3. Generate and set a new regular key
4. Store the new key in the keystore
5. Return the master key to cold storage immediately

**Contact your security team or system administrator for master key recovery.**

---

## Scheduled Rotation Recommendations

### Rotation Frequency

| Environment | Recommendation | Rationale |
|-------------|----------------|-----------|
| **Mainnet (High Value)** | Every 30 days | Minimize exposure window |
| **Mainnet (Standard)** | Every 90 days | Balance security and operations |
| **Testnet** | Every 180 days | Lower risk, reduce overhead |
| **Devnet** | As needed | Development convenience |

### Setting Up Automated Rotation Reminders

Create calendar reminders or automated alerts for rotation dates:

```bash
# Example cron job to send reminder (adjust for your system)
# Reminder 7 days before 90-day rotation window
0 9 * * * /usr/local/bin/check-key-age.sh 83
```

### Rotation Checklist

Before each rotation:

- [ ] Verify wallet balance is sufficient (100+ drops recommended)
- [ ] Confirm human approver availability
- [ ] Ensure backup storage is accessible
- [ ] Review recent audit logs for anomalies
- [ ] Schedule rotation during low-activity period

After each rotation:

- [ ] Verify on-chain RegularKey matches expected new key
- [ ] Test signing with new key
- [ ] Confirm backup was created
- [ ] Store backup password securely
- [ ] Copy backup to offsite storage
- [ ] Update rotation tracking records
- [ ] Review audit logs for completion

---

## Examples

### Example 1: Scheduled Maintenance Rotation

Regular 90-day rotation with standard settings:

```json
{
  "tool": "wallet_rotate",
  "params": {
    "wallet_address": "rN7n3473SaZBCG4dFL83w7a1RXtXtbK2D9",
    "reason": "scheduled",
    "create_backup": true
  }
}
```

### Example 2: Personnel Change Rotation

Immediate rotation when a team member departs:

```json
{
  "tool": "wallet_rotate",
  "params": {
    "wallet_address": "rProductionWallet123456789abcdef",
    "reason": "personnel_change",
    "reason_description": "Employee ID 12345 departed. Rotation per offboarding checklist SEC-OFF-003.",
    "create_backup": true
  }
}
```

### Example 3: Emergency Incident Response

Immediate rotation during an active security incident:

```json
{
  "tool": "wallet_rotate",
  "params": {
    "wallet_address": "rN7n3473SaZBCG4dFL83w7a1RXtXtbK2D9",
    "reason": "incident_response",
    "reason_description": "SECURITY-2026-001: Potential key exposure detected in log aggregator. Immediate rotation per incident response playbook.",
    "create_backup": true,
    "force": true
  }
}
```

The `force: true` flag bypasses the 24-hour cooldown period for emergency situations.

### Example 4: Compliance-Driven Rotation

Rotation to meet regulatory requirements:

```json
{
  "tool": "wallet_rotate",
  "params": {
    "wallet_address": "rComplianceWallet123456789abcdef",
    "reason": "compliance",
    "reason_description": "Quarterly key rotation per SOC2 control requirement KM-003.",
    "create_backup": true
  }
}
```

### Example 5: Handling Rejection

Complete workflow with error handling:

```typescript
async function rotateKeyWithRetry(walletAddress: string): Promise<void> {
  try {
    // Step 1: Initiate rotation
    const result = await mcpClient.callTool("wallet_rotate", {
      wallet_address: walletAddress,
      reason: "scheduled",
      create_backup: true,
    });

    if (result.status === "pending_approval") {
      console.log(`Rotation pending. Approval ID: ${result.approval_id}`);
      console.log(`Approval URL: ${result.approval_url}`);
      console.log(`New key preview: ${result.new_key_preview.address}`);
      console.log(`Expires at: ${result.expires_at}`);

      // Step 2: Poll for completion
      const finalStatus = await pollApprovalStatus(result.approval_id);

      if (finalStatus.status === "completed") {
        console.log("Rotation completed successfully!");
        console.log(`Transaction: ${finalStatus.tx_hash}`);
        console.log(`New key: ${finalStatus.new_key.address}`);
        console.log(`Backup: ${finalStatus.backup.path}`);

        // Step 3: Verify
        await verifyRotation(walletAddress, finalStatus.new_key.address);

      } else if (finalStatus.status === "rejected") {
        console.warn(`Rotation rejected: ${finalStatus.reason}`);
        console.warn(`Code: ${finalStatus.rejection_code}`);

        if (finalStatus.recovery_steps) {
          console.log("Recovery steps:");
          finalStatus.recovery_steps.forEach((step, i) => {
            console.log(`  ${i + 1}. ${step}`);
          });
        }
      }
    }

  } catch (error) {
    if (error.code === "ROTATION_COOLDOWN") {
      console.log(`Cooldown active until ${error.details.cooldown_ends}`);
      console.log("Use force=true for emergency rotation");

    } else if (error.code === "KEYSTORE_ERROR") {
      console.error("CRITICAL: Keystore error after on-chain validation!");
      console.error("DO NOT retry. Use backup restoration instead.");
      console.error(`Backup path: ${error.details.backup_path}`);

    } else {
      console.error(`Rotation failed: ${error.message}`);
    }
  }
}
```

---

## Troubleshooting

### Rotation Cooldown Active

**Error:** `ROTATION_COOLDOWN - Key rotation cooldown period active`

**Cause:** A rotation was performed within the last 24 hours.

**Solution:**
- Wait for the cooldown to expire, or
- Use `force: true` for emergency situations (limited to 5 per 24 hours)

### Insufficient Balance

**Error:** `INSUFFICIENT_BALANCE - Not enough XRP for fee`

**Cause:** The wallet does not have enough XRP to pay the transaction fee.

**Solution:**
- Fund the wallet with at least 12 drops (recommend 100+ drops)
- Check that the wallet reserve is met

### Wallet Not Found

**Error:** `WALLET_NOT_FOUND - Wallet not managed by server`

**Cause:** The specified address is not in the keystore.

**Solution:**
- Verify the wallet address is correct
- Create the wallet using `wallet_create` if needed
- Check that you are connected to the correct network

### Wallet Locked

**Error:** `WALLET_LOCKED - Wallet not unlocked`

**Cause:** No authenticated session exists for the wallet.

**Solution:**
- Authenticate to unlock the wallet before rotation

### Human Approver Unavailable

**Symptom:** Approval expires without response.

**Solution:**
- Verify approver contact information
- Use multiple approvers for redundancy
- Extend approval timeout if needed
- Schedule rotations when approvers are available

---

## Security Best Practices

1. **Never share key material.** The private key and seed should never leave the secure environment.

2. **Use different passwords.** Keystore password and backup password should be different.

3. **Rotate on a schedule.** Do not wait for incidents to rotate keys.

4. **Test backup restoration.** Periodically verify backups can be restored.

5. **Monitor audit logs.** Watch for unexpected rotation attempts.

6. **Limit approver access.** Only designated personnel should approve rotations.

7. **Document each rotation.** Maintain records of when and why rotations occurred.

8. **Secure backup storage.** Encrypt backups and store offsite.

---

## Next Steps

- Set up [human approval workflows](./set-up-human-approval.md) for rotation requests
- Configure [monitoring and alerts](./configure-monitoring.md) for key operations
- Review the [wallet_rotate API reference](../../api/tools/wallet-rotate.md) for complete field documentation

---

## Related Documentation

- [wallet_rotate Tool Reference](../../api/tools/wallet-rotate.md)
- [Configure Policies](./configure-policies.md)
- [ADR-004: XRPL Key Strategy](../../architecture/09-decisions/ADR-004-xrpl-key-strategy.md)
- [Security Requirements](../../security/security-requirements.md)
