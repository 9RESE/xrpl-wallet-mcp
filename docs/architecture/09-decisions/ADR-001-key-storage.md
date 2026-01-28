# ADR-001: Key Storage Strategy (Phase 1)

**Status:** Accepted
**Date:** 2026-01-28
**Decision Makers:** Tech Lead, Security Specialist

---

## Context

The XRPL Agent Wallet MCP server must securely store private keys that enable AI agents to sign transactions autonomously. This is the most security-critical component of the system - compromised keys result in irreversible fund loss.

Key storage must balance several competing concerns:

1. **Security**: Keys must be protected against theft, even if the storage medium is compromised
2. **Portability**: Solution should work across different environments (local development, CI/CD, production servers)
3. **Simplicity**: Phase 1 should avoid external dependencies that complicate deployment
4. **Recoverability**: Users must be able to recover from lost passwords or corrupted files
5. **Enterprise Path**: Architecture must support future upgrade to Cloud KMS/HSM without major refactoring

The threat model identifies keystore file theft (T-009) as a critical threat with potential for complete fund loss.

## Decision

**We will implement local file-based key storage using AES-256-GCM encryption with Argon2id key derivation.**

### Storage Architecture

```
~/.xrpl-wallet-mcp/
├── mainnet/
│   ├── keystore.enc       # Encrypted keystore file
│   ├── keystore.meta      # Metadata (version, params, salt)
│   └── audit.log          # Local audit log
├── testnet/
│   └── ...
└── devnet/
    └── ...
```

### Encryption Scheme

1. **Key Derivation**: User password processed through Argon2id to derive 256-bit Key Encryption Key (KEK)
2. **Encryption**: AES-256-GCM encrypts the keystore containing all private keys
3. **Integrity**: GCM authentication tag provides tamper detection
4. **Per-Keystore Salt**: Unique 32-byte random salt for each keystore

### File Format

```json
{
  "version": 1,
  "encryption": {
    "algorithm": "aes-256-gcm",
    "kdf": "argon2id",
    "kdfParams": {
      "memoryCost": 65536,
      "timeCost": 3,
      "parallelism": 4,
      "salt": "<base64>"
    }
  },
  "data": {
    "iv": "<base64>",
    "authTag": "<base64>",
    "ciphertext": "<base64>"
  },
  "metadata": {
    "created": "2026-01-28T00:00:00Z",
    "modified": "2026-01-28T00:00:00Z",
    "keyCount": 3
  }
}
```

### Security Controls

- File permissions: 0600 (owner read/write only)
- Directory permissions: 0700 (owner only)
- Atomic writes via temp file + rename
- Permission verification before read operations

## Consequences

### Positive

- **No External Dependencies**: Works offline, no cloud accounts required, no network latency for key operations
- **Complete Portability**: Single encrypted file can be backed up, moved between systems
- **Simple Recovery**: Password + encrypted file = complete recovery
- **Defense in Depth**: Even if file is stolen, Argon2id makes brute force infeasible
- **Audit Friendly**: Self-contained, deterministic, easily audited encryption
- **Low Operational Complexity**: No key management infrastructure to maintain
- **Fast Development**: Developers can test locally without cloud setup

### Negative

- **Single Point of Failure**: Password loss = permanent key loss (mitigated by master key recovery)
- **Password Strength Dependent**: Security relies on password quality (mitigated by AUTH-004 complexity requirements)
- **No Key Ceremony Support**: Enterprise key generation ceremonies require HSM
- **File System Trust**: Relies on OS file permissions (mitigated by encryption)
- **Memory Exposure Risk**: Decrypted keys exist in process memory during signing (mitigated by KEY-002 SecureBuffer)

### Neutral

- Requires password input at wallet unlock time
- Backup responsibility falls on user/operator
- Different from cloud-native patterns some teams expect

## Alternatives Considered

| Option | Pros | Cons | Why Not Chosen |
|--------|------|------|----------------|
| **Cloud KMS (AWS/GCP/Azure)** | Hardware-backed security, key ceremony support, audit logging built-in | Vendor lock-in, requires cloud account, network dependency, added latency, Phase 1 complexity | Planned for Phase 2; too complex for initial deployment |
| **Hardware Security Module (HSM)** | FIPS 140-2 Level 3, tamper-evident, strongest protection | High cost ($2-5k/year), complex integration, not portable | Planned for Phase 3 for enterprise deployments |
| **Plaintext Files** | Simple, no password required | Zero protection if file accessed, violates security principles | Completely unacceptable for any key storage |
| **OS Keychain (macOS Keychain, Windows DPAPI)** | Native integration, hardware-backed on some systems | Platform-specific, inconsistent security model, complex cross-platform | Complicates deployment; encryption provides equivalent protection |
| **In-Memory Only** | No persistence = no file theft | Keys lost on restart, requires re-import, poor UX | Impractical for production use |

## Implementation Notes

### Keystore Operations

```typescript
// Initialize new keystore
async function createKeystore(password: string, network: Network): Promise<void> {
  const salt = crypto.randomBytes(32);
  const kek = await deriveKey(password, salt);
  const emptyStore = { keys: [], created: new Date().toISOString() };
  await encryptAndSave(emptyStore, kek, network);
}

// Unlock keystore (load into memory)
async function unlockKeystore(password: string, network: Network): Promise<Keystore> {
  const metadata = await loadMetadata(network);
  const kek = await deriveKey(password, metadata.kdfParams.salt);
  const decrypted = await decrypt(network, kek);
  return JSON.parse(decrypted.toString());
}

// Add key to keystore
async function addKey(keystore: Keystore, privateKey: Buffer): Promise<void> {
  keystore.keys.push({ key: privateKey, added: new Date().toISOString() });
  // Re-encrypt and save happens on lock/save operation
}
```

### Memory Safety

Keys are decrypted only when needed and zeroed immediately after use:

```typescript
async function signTransaction(keystore: Keystore, address: string, tx: Transaction) {
  const key = keystore.getKey(address);
  try {
    return await xrpl.sign(tx, key);
  } finally {
    key.fill(0); // Zero key from memory
  }
}
```

## Security Considerations

### Addressed Threats

| Threat | Mitigation |
|--------|------------|
| T-009 (Keystore file theft) | AES-256-GCM encryption makes stolen file useless without password |
| T-010 (Brute force attack) | Argon2id with 64MB memory makes offline attacks infeasible |
| T-001 (File tampering) | GCM auth tag detects any modification to ciphertext |
| KEY-005 (File permission bypass) | Encryption provides protection even if permissions fail |

### Residual Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Password guessing (weak password) | Medium | Critical | Enforce AUTH-004 complexity requirements |
| Memory dump during signing | Low | Critical | SecureBuffer, minimal key lifetime (KEY-002) |
| Backup file exposure | Medium | Critical | User education, backup encryption |

### Compliance Mapping

| Requirement | Implementation |
|-------------|----------------|
| ENC-001 | AES-256-GCM encryption |
| ENC-002 | Unique IV per encryption operation |
| ENC-003 | Auth tag verification before decryption |
| ENC-005 | KEK wrapping scheme |
| ENC-006 | 32-byte random salt per keystore |
| KEY-005 | 0600 file permissions |
| KEY-006 | Atomic write operations |

## Migration Path

### Phase 2: Cloud KMS Integration

The keystore format supports KEK wrapping, enabling seamless migration:

```
Phase 1:  password -> Argon2id -> KEK -> encrypts keystore
Phase 2:  password -> Argon2id -> KEK -> wrapped by Cloud KMS -> encrypts keystore
```

Cloud KMS wraps the derived KEK, adding hardware-backed protection without changing the core encryption scheme.

### Phase 3: HSM Migration

For HSM integration, keys can be migrated:

1. Decrypt keystore with current password
2. Import keys into HSM
3. Store HSM key references in new keystore format
4. Signing operations use HSM API instead of local crypto

## References

- [NIST SP 800-38D - GCM Mode Specification](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106)
- [Node.js Crypto Module](https://nodejs.org/api/crypto.html)
- Security Requirements: ENC-001, ENC-002, ENC-003, ENC-005, ENC-006, KEY-005, KEY-006

## Related ADRs

- [ADR-002: Key Derivation Function](ADR-002-key-derivation.md) - Argon2id parameters
- [ADR-010: Network Isolation](ADR-010-network-isolation.md) - Per-network keystore separation

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Tech Lead | Initial ADR |
