# ADR-011: Phase 1 Security Remediation

**Status:** Accepted
**Date:** 2026-01-28
**Decision Makers:** Tech Lead, Security Specialist, Code Review Agent

---

## Context

Following a comprehensive code review of the XRPL Agent Wallet MCP server (commit 73f6ed7), 19 issues were identified across 33 TypeScript source files. The review categorized issues by severity:

- **3 Critical Issues** - Security vulnerabilities blocking release
- **5 High Priority Issues** - Functionality and security bugs requiring immediate attention
- **6 Medium Priority Issues** - Code quality and defense-in-depth gaps
- **5 Low Priority Issues** - Improvements for robustness

The code review document (`docs/development/code-review-2026-01-28.md`) provides detailed analysis of each issue. This ADR documents the architectural decisions made during remediation.

## Decision

**We will implement all 19 remediation items identified in the code review, prioritizing security-critical fixes first.**

### Critical Issue Remediations

#### C1: Required Environment Variables

**Problem**: Empty string fallback for `XRPL_WALLET_PASSWORD` bypassed encryption.

**Solution**: Created centralized environment utilities that throw on missing required variables.

```typescript
// src/utils/env.ts
export function getRequiredEnv(name: string, description: string): string {
  const value = process.env[name];
  if (!value || value.trim() === '') {
    throw new Error(
      `Missing required environment variable: ${name}\n` +
      `Description: ${description}\n` +
      `Please set this variable before starting the server.`
    );
  }
  return value;
}

export function getWalletPassword(): string {
  return getRequiredEnv(
    'XRPL_WALLET_PASSWORD',
    'Master encryption password for wallet keystore. Set this environment variable to a strong password.'
  );
}
```

All tool files updated to use `getWalletPassword()` instead of direct env access.

#### C2: Key Storage/Loading Consistency

**Problem**: Keys stored as hex private key but loaded expecting base58 seed.

**Solution**: Standardized on storing XRPL seed as UTF-8 string throughout:

```typescript
// LocalKeystore.createWallet() - Store seed as UTF-8
const seedBuffer = Buffer.from(xrplWallet.seed!, 'utf-8');

// SigningService.sign() - Load seed as UTF-8
const seedString = secureKey.getBuffer().toString('utf-8');
wallet = Wallet.fromSeed(seedString);
```

#### C3: Multi-Signature Validation

**Problem**: Signatures added to multi-sign requests were not cryptographically verified.

**Solution**: Implemented signature verification using ripple-keypairs:

```typescript
// src/signing/multisig.ts
import { verify } from 'ripple-keypairs';

private validateSignature(
  txBlob: string,
  signature: string,
  publicKey: string
): { valid: boolean; error?: string } {
  const txHash = computeSigningHash(txBlob);
  const isValid = verify(Buffer.from(txHash, 'hex'), signature, publicKey);

  if (!isValid) {
    return { valid: false, error: 'Cryptographic signature verification failed' };
  }
  return { valid: true };
}
```

### High Priority Remediations

#### H1: Audit Logger Hash Chain

**Problem**: Tools passed hardcoded `seq: 0`, `prev_hash: ''`, `hash: ''` bypassing chain.

**Solution**: Removed hash chain fields from all audit logger calls. Logger now generates these automatically per its internal state.

#### H2: Regular Key Persistence

**Problem**: Rotated regular keys were never stored, making rotation useless.

**Solution**: Added keystore methods for regular key storage:

```typescript
interface KeystoreProvider {
  // Existing methods...
  storeRegularKey?(walletId: string, seed: string, password: string): Promise<void>;
  loadRegularKey?(walletId: string, password: string): Promise<SecureBuffer | null>;
}
```

SigningService now prefers regular key over master key when available.

#### H3: Policy Engine Immutability

**Problem**: `PolicyEngine.setPolicy()` was a no-op, silently ignoring policy updates.

**Solution**: Method now throws explicit error explaining immutability:

```typescript
async setPolicy(policy: AgentWalletPolicy): Promise<void> {
  throw new PolicyLoadError(
    'POLICY_IMMUTABLE',
    'PolicyEngine is immutable by design (ADR-003). Policies cannot be changed at runtime. ' +
    'To update policies, modify the policy configuration and restart the server.',
    { requestedPolicy: policy.policy_id }
  );
}
```

#### H4: Flexible Key Length Support

**Problem**: `storeKey()` only accepted 16-byte keys, incompatible with wallet seeds.

**Solution**: Support all standard XRPL key/seed formats:

```typescript
const validLengths = [16, 32, 33]; // 128-bit entropy, Ed25519 key, secp256k1 key
const seedLengths = Array.from({ length: 7 }, (_, i) => 29 + i); // 29-35 bytes for base58 seeds
const allValidLengths = [...validLengths, ...seedLengths];

if (!allValidLengths.includes(keyBuffer.length)) {
  throw new InvalidKeyError(/*...*/);
}
```

#### H5: Rate Limit Persistence

**Problem**: Rate limiting and lockout state lost on server restart.

**Solution**: Implemented file-based persistence:

```typescript
private async persistRateLimitState(): Promise<void> {
  const state = {
    lockouts: Array.from(this.lockouts.entries()),
    authAttempts: Array.from(this.authAttempts.entries()),
    persistedAt: new Date().toISOString()
  };
  await this.atomicWrite(this.rateLimitStatePath, JSON.stringify(state, null, 2));
}

private async restoreRateLimitState(): Promise<void> {
  // Restore state on initialization, with stale entry cleanup
}
```

### Medium Priority Remediations

| Issue | Solution |
|-------|----------|
| **M1: ReDoS Protection** | Added `isReDoSVulnerable()` check before regex compilation |
| **M2: FileLock Cross-Process** | Added file-based locking with stale lock detection |
| **M3: Backup Memory Safety** | Zero payload buffer immediately after encryption |
| **M4: Stack Trace Exposure** | Only expose in `NODE_ENV !== 'production'` |
| **M5: Log Data Sanitization** | Log only safe fields (errorType, errorMessage, correlationId) |
| **M6: Reconnect Stack Overflow** | Changed recursive reconnect to iterative with attempt counter |

### Low Priority Improvements

| Issue | Solution |
|-------|----------|
| **L1: SecureBuffer Verification** | Added optional `verify` parameter to `from()` method |
| **L2: LimitTracker Disposal** | Added `isDisposed` flag and `disposed` getter |
| **L3: Strict Transaction Types** | Added `strictTransactionTypes` option to SigningService |
| **L4: Hex Transform Documentation** | Clarified `toUpperCase()` transform in schema docs |
| **L5: XRPL Timeouts** | Added `withTimeout()` wrapper for all XRPL operations |

## Consequences

### Positive

- **Security Hardened**: All 3 critical vulnerabilities eliminated
- **Fail-Fast Behavior**: Missing required config detected at startup
- **Key Integrity**: Consistent key storage/loading prevents cryptographic failures
- **Audit Integrity**: Hash chains function correctly for tamper detection
- **Production Ready**: Stack traces, logs, and errors sanitized for production
- **Brute Force Resistant**: Rate limiting survives restarts

### Negative

- **Breaking Change**: Server now requires `XRPL_WALLET_PASSWORD` environment variable (previously failed silently)
- **File I/O Overhead**: Rate limit persistence adds file operations
- **Increased Complexity**: Additional validation and safety checks

### Neutral

- Test suite updated (222 tests passing)
- No changes to MCP tool interfaces
- No changes to policy schema format

## Alternatives Considered

| Alternative | Why Not Chosen |
|-------------|----------------|
| **Optional password** | Security unacceptable - empty password defeats encryption |
| **In-memory rate limiting only** | Insufficient for persistent brute force protection |
| **Permissive `setPolicy()`** | Violates ADR-003 immutability requirement |
| **Warning-only for ReDoS** | Potential DoS vector in policy evaluation |

## Implementation Notes

### File Changes

**New Files:**
- `src/utils/env.ts` - Environment variable utilities
- `src/utils/index.ts` - Module exports

**Modified Files (14):**
- `src/tools/wallet-create.ts`, `wallet-sign.ts`, `wallet-rotate.ts`, `wallet-balance.ts`, `wallet-history.ts`, `wallet-policy-check.ts`, `policy-set.ts`
- `src/keystore/local.ts`, `src/keystore/secure-buffer.ts`
- `src/signing/service.ts`, `src/signing/multisig.ts`
- `src/policy/engine.ts`, `src/policy/evaluator.ts`, `src/policy/limits.ts`
- `src/xrpl/client.ts`
- `src/server.ts`
- `src/schemas/index.ts`

### Testing Validation

After remediation:
- All 222 existing tests pass
- New edge case tests recommended for:
  - Missing `XRPL_WALLET_PASSWORD` at startup
  - Key rotation persistence across restarts
  - Rate limit state recovery
  - Invalid multi-sign signature rejection

## Security Considerations

### Addressed Threats

| Threat | Remediation |
|--------|-------------|
| T-010 (Password bypass) | C1: Required env validation |
| T-009 (Keystore corruption) | C2: Consistent key format |
| T-015 (Multi-sign fraud) | C3: Signature verification |
| T-011 (Audit tampering) | H1: Hash chain integrity |
| T-012 (Key rotation bypass) | H2: Regular key persistence |
| T-006 (ReDoS) | M1: Vulnerable pattern detection |
| T-008 (Information disclosure) | M4, M5: Production-safe logging |

### Compliance Impact

| Requirement | Status |
|-------------|--------|
| AUTH-001 | Strengthened (required password) |
| KEY-002 | Improved (SecureBuffer verification) |
| AUDIT-001 | Fixed (hash chain integrity) |
| VAL-004 | Enhanced (ReDoS protection) |

## References

- [Code Review Document](../../development/code-review-2026-01-28.md)
- [ADR-002: Key Derivation Function](ADR-002-key-derivation.md)
- [ADR-003: Policy Engine Design](ADR-003-policy-engine.md)
- [ADR-005: Audit Logging](ADR-005-audit-logging.md)
- [Security Requirements](../../security/security-requirements.md)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

## Related ADRs

- ADR-001: Key Storage (Phase 1) - Key format consistency
- ADR-002: Key Derivation Function - Password handling
- ADR-003: Policy Engine Design - Immutability enforcement
- ADR-005: Audit Logging - Hash chain integrity
- ADR-007: Rate Limiting - Persistence requirements

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Code Review Agent | Initial ADR documenting all 19 remediations |
