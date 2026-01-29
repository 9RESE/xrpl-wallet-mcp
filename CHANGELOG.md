# Changelog

All notable changes to the XRPL Agent Wallet MCP server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-01-28

### Security

#### Critical Fixes
- **Environment Validation**: `XRPL_WALLET_PASSWORD` is now required at startup; server fails fast if not set
- **Key Storage Consistency**: Fixed key storage/loading mismatch - seeds now stored and loaded as UTF-8 strings consistently
- **Multi-Sign Validation**: Added cryptographic signature verification for multi-sign requests using ripple-keypairs

#### High Priority Fixes
- **Audit Hash Chain**: Removed hardcoded hash chain fields from tool audit calls; logger now generates these correctly
- **Regular Key Persistence**: Rotated regular keys are now properly stored and loaded; SigningService prefers regular key over master key
- **Policy Immutability**: `PolicyEngine.setPolicy()` now throws explicit error explaining immutability per ADR-003
- **Key Length Support**: `storeKey()` now supports all standard XRPL key/seed lengths (16, 29-35, 32, 33 bytes)
- **Rate Limit Persistence**: Lockout and attempt state now persisted to file and restored on startup

#### Medium Priority Fixes
- **ReDoS Protection**: Added `isReDoSVulnerable()` check before compiling regex patterns in policy evaluation
- **FileLock Improvements**: Added file-based locking with stale lock detection for cross-process safety
- **Backup Memory Safety**: Backup payload buffer zeroed immediately after encryption
- **Production Logging**: Stack traces only exposed when `NODE_ENV !== 'production'`
- **Log Sanitization**: Policy engine logs only safe fields (errorType, errorMessage, correlationId)
- **Reconnect Safety**: XRPL client reconnect changed from recursive to iterative to prevent stack overflow

### Added

- `src/utils/env.ts` - Centralized environment variable utilities with required validation
- `src/utils/index.ts` - Utils module exports
- `SigningServiceOptions.strictTransactionTypes` - Option to reject unknown transaction types
- `SecureBuffer.from()` verify parameter - Optional verification that source was zeroed
- `LimitTracker.disposed` getter - Track disposal state for interval cleanup
- `withTimeout()` wrapper for XRPL operations - Configurable timeouts for network operations

### Changed

- All tool files now use `getWalletPassword()` instead of direct environment access
- `LocalKeystore.createWallet()` stores seed as UTF-8 string
- `SigningService.sign()` prefers regular key over master key when available
- `HexStringSchema` documentation clarifies `toUpperCase()` transform

### Documentation

- Added [ADR-011: Security Remediation](./docs/architecture/09-decisions/ADR-011-security-remediation.md)
- Added [Code Review Report](./docs/development/code-review-2026-01-28.md)
- Updated [Security Review Report](./docs/security/security-review-report.md) with implementation addendum
- Updated README with security hardening section

## [0.1.0] - 2026-01-28

### Added

- Initial Phase 1 MVP implementation
- 11 MCP tools: `wallet_create`, `wallet_sign`, `wallet_balance`, `wallet_policy_check`, `wallet_rotate`, `wallet_list`, `wallet_history`, `wallet_fund`, `policy_set`, `tx_submit`, `tx_decode`
- Local keystore with AES-256-GCM encryption
- Argon2id key derivation (64MB, 3 iterations, 4 parallelism)
- Policy engine with 4-tier authorization (autonomous, delayed, cosign, prohibited)
- HMAC-SHA256 hash-chained audit logging
- Multi-signature orchestrator
- XRPL client wrapper with reconnection support
- Rate limiting with token bucket algorithm
- SecureBuffer for memory-safe key handling
- Zod schema validation for all inputs
- Network isolation (mainnet/testnet/devnet)
- 222 passing tests

### Documentation

- Complete Arc42 architecture documentation (01-08)
- 10 Architecture Decision Records (ADR-001 through ADR-010)
- Security documentation: threat model, requirements, compliance mapping, OWASP LLM mitigations
- API documentation for all tools
- User guides following Diataxis framework

---

[0.1.1]: https://github.com/9RESE/xrpl-agent-wallet-mcp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/9RESE/xrpl-agent-wallet-mcp/releases/tag/v0.1.0
