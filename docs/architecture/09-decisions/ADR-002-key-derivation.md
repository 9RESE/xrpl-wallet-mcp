# ADR-002: Key Derivation Function

**Status:** Accepted
**Date:** 2026-01-28
**Decision Makers:** Tech Lead, Security Specialist

---

## Context

The XRPL Agent Wallet MCP server uses password-based encryption to protect stored private keys. A Key Derivation Function (KDF) transforms user passwords into cryptographic keys suitable for AES-256-GCM encryption.

The KDF is the primary defense against offline brute-force attacks. If an attacker obtains the encrypted keystore file, the KDF determines how expensive it is to attempt password guessing.

Key requirements:
1. **Brute-force Resistance**: Each password guess must be computationally expensive
2. **GPU Resistance**: Must resist acceleration via commodity GPUs
3. **Side-channel Resistance**: Must resist timing and cache attacks
4. **Memory Hardness**: Attackers cannot trade memory for time
5. **Standards Compliance**: Preferably standardized and well-audited
6. **Performance**: Unlock time must be acceptable for user experience (<2 seconds)

The threat model identifies brute-force password attacks (T-010) as a high-priority threat.

## Decision

**We will use Argon2id with the following parameters:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Variant | argon2id | Hybrid mode: resistant to side-channel AND GPU attacks |
| Memory Cost | 65,536 KB (64 MB) | Makes parallelization expensive |
| Time Cost | 3 iterations | Increases sequential work |
| Parallelism | 4 threads | Utilizes multi-core CPUs |
| Output Length | 32 bytes (256 bits) | Matches AES-256 key size |
| Salt Length | 32 bytes (256 bits) | Sufficient entropy to prevent rainbow tables |

### Implementation

```typescript
import argon2 from 'argon2';

const ARGON2_CONFIG = {
  type: argon2.argon2id,
  memoryCost: 65536,    // 64 MB
  timeCost: 3,          // 3 iterations
  parallelism: 4,       // 4 threads
  hashLength: 32        // 256-bit output
};

async function deriveKey(password: string, salt: Buffer): Promise<Buffer> {
  return argon2.hash(password, {
    ...ARGON2_CONFIG,
    salt,
    raw: true  // Return raw bytes, not encoded string
  });
}
```

### Expected Performance

| Hardware | Derivation Time | Notes |
|----------|-----------------|-------|
| Modern Desktop (8-core, 32GB) | ~500ms | Primary target environment |
| Cloud VM (4-core, 8GB) | ~800ms | Common deployment environment |
| Raspberry Pi 4 | ~2000ms | Edge deployment |
| Low-end VPS (1-core, 2GB) | ~1500ms | Minimum viable deployment |

## Consequences

### Positive

- **PHC Winner**: Argon2 won the Password Hashing Competition (2015), extensively reviewed by cryptographers
- **RFC Standardized**: RFC 9106 provides authoritative specification
- **Hybrid Protection**: argon2id combines argon2i (side-channel resistance) and argon2d (GPU resistance)
- **Memory Hardness**: 64MB requirement makes ASIC/GPU attacks expensive ($8-16M to match single CPU)
- **Modern Algorithm**: Designed with modern attack vectors in mind
- **OWASP Recommended**: Primary recommendation for new systems
- **Flexible Parameters**: Can be tuned for different security/performance tradeoffs
- **Well-Tested Library**: argon2 npm package wraps reference implementation

### Negative

- **Native Dependency**: argon2 npm package requires native compilation (mitigated by prebuilt binaries)
- **Memory Requirement**: 64MB per derivation may stress low-memory systems
- **Not FIPS Certified**: Cannot be used where FIPS compliance is mandatory (see PBKDF2 fallback)
- **Newer Algorithm**: Less deployment history than bcrypt/PBKDF2 (but more security analysis)

### Neutral

- Derivation takes ~500ms-2s depending on hardware (acceptable for wallet unlock)
- Parameters stored alongside ciphertext (required for decryption)
- Future parameter increases possible without breaking existing keystores

## Alternatives Considered

| Algorithm | GPU Resistance | Memory Hard | FIPS Compliant | Why Not Chosen |
|-----------|---------------|-------------|----------------|----------------|
| **PBKDF2-SHA256** | Poor | No | Yes | Highly parallelizable on GPUs; only use for FIPS compliance |
| **bcrypt** | Good | Partial | No | Fixed memory (4KB), less resistant to modern attacks |
| **scrypt** | Good | Yes | No | Complex parameter tuning; Argon2 supersedes it |
| **Argon2i** | Poor | Yes | No | Vulnerable to TMTO attacks; use argon2id instead |
| **Argon2d** | Excellent | Yes | No | Vulnerable to side-channel attacks; use argon2id |

### PBKDF2 Fallback for FIPS Compliance

For deployments requiring FIPS 140-2 compliance, PBKDF2 fallback is available:

```typescript
// FIPS-compliant fallback (significantly weaker than Argon2id)
const PBKDF2_CONFIG = {
  iterations: 600_000,  // OWASP 2023 minimum for SHA-256
  keyLength: 32,
  digest: 'sha256'
};

async function deriveKeyPBKDF2(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, PBKDF2_CONFIG.iterations, PBKDF2_CONFIG.keyLength,
      PBKDF2_CONFIG.digest, (err, key) => {
        if (err) reject(err);
        else resolve(key);
      });
  });
}
```

**Warning**: PBKDF2 provides significantly weaker protection against GPU-accelerated attacks.

## Implementation Notes

### Parameter Validation

```typescript
function validateKdfParams(params: KdfParams): void {
  if (params.kdf !== 'argon2id') {
    throw new Error('Unsupported KDF');
  }
  if (params.memoryCost < 65536) {
    throw new Error('Memory cost below minimum (64MB)');
  }
  if (params.timeCost < 3) {
    throw new Error('Time cost below minimum (3)');
  }
  if (params.parallelism < 1 || params.parallelism > 16) {
    throw new Error('Parallelism out of range (1-16)');
  }
}
```

### Future Parameter Updates

When upgrading parameters (e.g., increasing memory cost):

1. Read keystore with current parameters
2. Decrypt keys
3. Re-encrypt with new parameters
4. Update stored parameters
5. Zero old key material from memory

```typescript
async function upgradeKdfParams(
  password: string,
  network: Network,
  newParams: KdfParams
): Promise<void> {
  // Load with current params
  const keystore = await unlockKeystore(password, network);

  // Re-derive with new params
  const newSalt = crypto.randomBytes(32);
  const newKek = await deriveKey(password, newSalt, newParams);

  // Re-encrypt and save
  await saveKeystore(keystore, newKek, network, newParams);
}
```

### Memory Considerations

Argon2id allocates 64MB per derivation. For concurrent unlock attempts:

```typescript
// Semaphore to limit concurrent derivations
const derivationSemaphore = new Semaphore(2); // Max 2 concurrent

async function deriveKeyWithLimit(password: string, salt: Buffer): Promise<Buffer> {
  return derivationSemaphore.acquire(async () => {
    return deriveKey(password, salt);
  });
}
```

## Security Considerations

### Attack Cost Analysis

With 64MB memory cost and 3 iterations:

| Attack Type | Cost to Achieve 1B Guesses | Notes |
|-------------|---------------------------|-------|
| Single CPU | ~16 years | Sequential processing |
| GPU Farm (1000 GPUs) | ~6 months, $500K+ | Memory bandwidth limited |
| Custom ASIC | ~$8-16M development | Each chip needs 64MB RAM |
| Cloud Computing | ~$1M+ (AWS/GCP) | Memory-bound instances expensive |

### Password Entropy Requirements

Combined with AUTH-004 password complexity requirements:

| Password Strength | Entropy (bits) | Brute Force Time (1000 GPUs) |
|-------------------|----------------|------------------------------|
| 12 chars, mixed | ~72 bits | >1000 years |
| 16 chars, mixed | ~96 bits | >universe lifetime |
| 8 chars, simple | ~40 bits | ~1 year (UNACCEPTABLE) |

### Compliance Mapping

| Requirement | Implementation |
|-------------|----------------|
| AUTH-001 | Argon2id with specified parameters |
| AUTH-001 | Memory cost >= 64MB |
| AUTH-001 | Time cost >= 3 iterations |
| AUTH-001 | Key derivation >= 500ms on reference hardware |
| AUTH-001 | 32-byte cryptographically random salt |

## References

- [RFC 9106 - Argon2 Memory-Hard Function](https://www.rfc-editor.org/rfc/rfc9106)
- [Password Hashing Competition](https://www.password-hashing.net/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Argon2 Reference Implementation](https://github.com/P-H-C/phc-winner-argon2)
- Security Requirements: AUTH-001

## Related ADRs

- [ADR-001: Key Storage](ADR-001-key-storage.md) - Uses derived key for encryption
- [ADR-005: Audit Logging](ADR-005-audit-logging.md) - Logs authentication attempts

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Tech Lead | Initial ADR |
