# Understanding the XRPL Wallet MCP Security Model

**Document Type**: Explanation (Diataxis)
**Audience**: Developers, Security-Conscious Users, Auditors
**Version**: 1.0.0
**Date**: 2026-01-28

---

## Introduction: Our Security Philosophy

Building a cryptocurrency wallet that an AI agent can operate presents a fundamental tension: how do you grant an autonomous system enough capability to be useful while ensuring it cannot be manipulated into draining funds or compromising security?

The XRPL Wallet MCP server was designed with a core belief: **trust, but verify at every layer**. Rather than relying on any single security mechanism, we built a system where multiple independent defenses must all be bypassed for an attack to succeed. This approach, known as defense in depth, means that even if one protection fails, others remain standing.

Our philosophy can be summarized in five principles:

1. **Keys never leave secure storage unencrypted** - The most sensitive data (private keys) is protected at rest and handled with extreme care in memory.

2. **Defense in depth** - Every operation passes through multiple independent security checks. No single point of failure can compromise the system.

3. **Fail-secure design** - When something goes wrong, we default to denying access. Errors are never an opportunity for bypass.

4. **Minimal attack surface** - Only necessary functionality is exposed. Every tool, every parameter, every capability is deliberately chosen.

5. **Audit everything** - All security-relevant operations leave a tamper-evident trail. What cannot be hidden cannot be covered up.

This document explains *why* we made these design decisions, not just *what* they are.

---

## Defense in Depth: Eight Layers of Protection

Traditional security often relies on a single strong barrier - a password, a firewall, an access check. But history has shown that any single defense can fail. Defense in depth assumes that every layer *will* eventually be compromised, and designs accordingly.

Our eight-layer architecture ensures that an attacker must defeat multiple independent protections to succeed.

### Layer 1: Transport Security

**What it does**: All communication between the MCP client (the AI agent) and our server is encrypted using TLS 1.3.

**Why it matters**: Even if someone can observe network traffic between the agent and the wallet server, they cannot read the contents. TLS 1.3 specifically was chosen because it removed legacy cryptographic algorithms that had known weaknesses.

**Why not rely on it alone**: Transport security only protects data in transit. Once a message arrives, it needs further protection. An attacker who compromises the AI agent itself could send malicious requests over a perfectly encrypted channel.

### Layer 2: Input Validation

**What it does**: Every piece of data arriving from the outside world is rigorously validated before processing. This includes schema validation (is this a properly formatted request?), business validation (does this XRPL address pass checksum verification?), and injection detection (is someone trying to manipulate the AI through specially crafted data?).

**Why it matters**: The boundary between trusted and untrusted data is where most attacks originate. By treating all external input as potentially hostile, we eliminate entire categories of vulnerabilities. Prompt injection attacks - where malicious data tricks an AI into performing unintended actions - are caught here.

**Why not rely on it alone**: Validation can only check what we anticipate. A novel attack technique might slip through syntactically valid input. Additionally, a validly-formatted request might still be unauthorized.

### Layer 3: Authentication

**What it does**: Before any sensitive operation, the system verifies that the requesting entity has the right to access the wallet. This uses Argon2id for key derivation (making brute-force attacks computationally expensive) and implements progressive lockout (each failed attempt increases the lockout duration).

**Why it matters**: Without authentication, anyone who can reach the server could operate the wallet. Argon2id was specifically chosen because it is memory-hard - it requires significant RAM to compute, which makes GPU-based attacks impractical. The progressive lockout means an attacker who guesses wrong faces exponentially increasing delays.

**Why not rely on it alone**: Authentication proves *who you are*, not *what you're allowed to do*. An authenticated user (or agent) might still attempt unauthorized operations.

### Layer 4: Authorization

**What it does**: Every tool in the MCP server is classified by sensitivity level: READ_ONLY, SENSITIVE, or DESTRUCTIVE. Before executing any tool, the system checks whether the current operation is permitted for the current context.

**Why it matters**: Just because an agent successfully authenticated doesn't mean it should be able to delete wallets or export keys. Authorization ensures that even legitimate users can only perform operations appropriate to their role and context.

**Why not rely on it alone**: Authorization checks are binary (allowed/denied), but real-world transactions have nuance. A legitimate user sending $10 to a known address is different from that same user sending $10,000 to a new address.

### Layer 5: Policy Enforcement

**What it does**: A rules engine evaluates every transaction against configurable policies. This includes amount limits (daily, per-transaction), destination allowlists and blocklists, transaction type restrictions, and risk-based tier classification.

**Why it matters**: This layer adds contextual intelligence to security decisions. The same operation might be approved automatically for small amounts to trusted destinations, require human confirmation for larger amounts, or be blocked entirely for known-bad destinations.

Critically, **the AI agent cannot modify policies at runtime**. Policies are loaded from immutable configuration files, preventing a compromised agent from simply relaxing the rules.

**Why not rely on it alone**: Policies are only as good as their configuration. A permissive policy or one that doesn't anticipate a new attack vector could allow harmful transactions.

### Layer 6: Cryptographic Protection

**What it does**: All sensitive data at rest is encrypted using AES-256-GCM. Private keys never exist in plaintext on disk. In memory, keys are handled through a SecureBuffer pattern that zeros memory immediately after use.

**Why it matters**: If an attacker gains access to the file system, they still cannot read private keys. If they can dump process memory, the window of exposure is minimized.

AES-256-GCM was chosen because it provides both confidentiality (encryption) and integrity (authentication tag). An attacker cannot just decrypt the data; any tampering is detected.

**Why not rely on it alone**: Encryption protects data at rest and during storage, but keys must eventually be decrypted to sign transactions. The memory handling minimizes but cannot eliminate exposure.

### Layer 7: XRPL Native Security

**What it does**: This layer leverages security features built into the XRPL blockchain itself: regular keys (allowing hot/cold wallet separation), multi-signature requirements (requiring multiple parties to approve high-value transactions), and sequence numbers (preventing replay attacks).

**Why it matters**: These protections exist at the protocol level and cannot be bypassed by compromising our server. Even if an attacker completely controlled the MCP server, they still could not forge multi-signature approvals they don't have keys for.

**Why not rely on it alone**: Not all wallets will have multi-signature enabled. These features must be consciously configured.

### Layer 8: Audit and Detection

**What it does**: Every security-relevant operation is logged to a tamper-evident audit trail. Logs are linked by cryptographic hash chains - modifying any past entry would invalidate the chain. Monotonic sequence numbers detect deletion attempts.

**Why it matters**: If all other defenses fail, the audit log ensures that attacks are discoverable. An attacker cannot cover their tracks without leaving evidence.

**Why not rely on it alone**: Detection without prevention only limits damage; it doesn't stop it. That's why audit is the *last* layer, not the first.

### How the Layers Work Together

Consider an attack scenario: a compromised AI agent attempts to drain a wallet.

1. **Transport**: The attacker can send encrypted requests - no help here.
2. **Input Validation**: If the attacker tries prompt injection, it's caught. Malformed requests are rejected.
3. **Authentication**: The agent may have valid credentials, so this layer passes.
4. **Authorization**: The sign_transaction tool is authorized for the agent.
5. **Policy Enforcement**: A $10,000 transfer triggers Tier 3 - multi-signature required. A new destination triggers Tier 2 - 5-minute delay with cancellation window.
6. **Cryptographic Protection**: Keys are properly accessed.
7. **XRPL Native**: Multi-signature requirement on-chain blocks unauthorized large transfers.
8. **Audit**: The attempt is logged. Anomaly detection alerts human operators.

The attack failed at layers 5 and 7, but even if it somehow passed, layer 8 would ensure it was discovered. This is the essence of defense in depth.

---

## The Tiered Security Model: Risk-Based Decisions

Not all transactions carry the same risk. Sending 1 XRP to a frequently-used address is fundamentally different from sending 10,000 XRP to a new destination. The tiered security model provides proportional protection based on transaction risk.

### Why Tiers Exist

A one-size-fits-all security model creates problems at both ends:

- **Too strict**: If every transaction required multi-signature approval, agents couldn't perform routine operations autonomously. This defeats the purpose of an AI-operated wallet.

- **Too lenient**: If any transaction could be signed automatically, a single compromise could drain the entire wallet before anyone noticed.

Tiers solve this by matching security friction to actual risk. Low-risk operations proceed automatically. High-risk operations require human oversight.

### How Tiers Are Determined

Transactions are classified into tiers based on multiple factors evaluated together:

| Factor | Lower Risk | Higher Risk |
|--------|------------|-------------|
| **Amount** | Small (< 100 XRP) | Large (> 1,000 XRP) |
| **Destination** | Known/allowlisted address | New/unknown address |
| **Cumulative Volume** | Within daily limits | Approaching/exceeding limits |
| **Transaction Type** | Payment to known party | Trust line changes, key rotation |
| **Memo Content** | Standard or empty | Suspicious patterns detected |

The system evaluates all factors and applies the most restrictive tier that matches:

```
Transaction Request
        |
        v
   Policy Check -----> Violation? -----> TIER 4: PROHIBITED
        |
        | (passes)
        v
   Amount > 1000 XRP? -----> Yes -----> TIER 3: CO-SIGN
        |
        | (no)
        v
   Amount > 100 XRP OR new dest? -----> Yes -----> TIER 2: DELAYED
        |
        | (no)
        v
   Known destination? -----> No -----> TIER 2: DELAYED
        |
        | (yes)
        v
   TIER 1: AUTONOMOUS
```

### Tier 1: Autonomous

**What happens**: Transaction is signed and submitted immediately with no human intervention.

**Criteria**:
- Amount under 100 XRP
- Destination is on the allowlist or previously used
- Within daily transaction limits (default: 1,000 XRP/day)
- Within hourly rate limits (default: 10 transactions/hour)

**Why this design**: Routine micropayments and regular operations should not require human approval. The limits are set low enough that even if completely abused, the damage is bounded.

**Example use cases**:
- Paying network fees
- Small tips or micropayments
- Regular transfers to known business accounts

### Tier 2: Delayed

**What happens**: Transaction is signed but held for 5 minutes before submission. During this window, a human can cancel the transaction.

**Criteria**:
- Amount between 100-1,000 XRP, OR
- Destination is new (not previously used), OR
- Approaching daily limits

**Why this design**: The delay window provides a safety net without blocking operations. If the AI made a mistake or was manipulated, there's time to intervene. The delay is short enough not to significantly impact legitimate operations.

**Example use cases**:
- Onboarding a new vendor
- Larger routine payments
- Any transaction that looks unusual but isn't necessarily malicious

### Tier 3: Co-Sign (Multi-Signature)

**What happens**: Transaction requires signatures from multiple parties (default: 2 of 3 configured signers) before it can be submitted.

**Criteria**:
- Amount exceeds 1,000 XRP, OR
- Elevated risk indicators, OR
- Explicitly configured transaction types (key rotation, etc.)

**Why this design**: High-value transactions should never be unilateral. Even a fully compromised agent cannot approve large transfers without additional human authorization. The multi-signature happens at the XRPL protocol level, providing cryptographic enforcement.

**Example use cases**:
- Major vendor payments
- Investment movements
- Any operation that would be painful to reverse if wrong

### Tier 4: Prohibited

**What happens**: Transaction is rejected immediately. It is never signed or submitted.

**Criteria**:
- Destination is blocklisted
- Memo contains suspicious patterns (potential prompt injection)
- Policy explicitly prohibits the transaction type
- Cumulative limits would be exceeded

**Why this design**: Some operations should never succeed under any circumstances. Blocklisting known scam addresses provides protection even if an AI is completely compromised and the human is asleep.

**Example use cases**:
- Addresses associated with known scams
- Transactions with memos containing social engineering phrases
- Account deletion (disabled by default)

### Tier Configuration Example

The tier thresholds are configurable per deployment:

```json
{
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 100,
      "daily_limit_xrp": 1000,
      "hourly_transaction_limit": 10,
      "requires_known_destination": true
    },
    "delayed": {
      "min_amount_xrp": 100,
      "max_amount_xrp": 1000,
      "delay_seconds": 300,
      "daily_limit_xrp": 10000,
      "cancellable": true
    },
    "cosign": {
      "min_amount_xrp": 1000,
      "signer_quorum": 2,
      "signer_count": 3,
      "timeout_hours": 24
    }
  }
}
```

A deployment handling small recurring payments might raise the autonomous limit. A high-security treasury might lower it. The defaults are conservative starting points.

---

## XRPL Native Security Features

The XRP Ledger provides security mechanisms at the protocol level. These features are not implemented by our server - they are enforced by the blockchain itself. This means even a completely compromised MCP server cannot bypass them.

### Regular Keys: Hot and Cold Wallet Separation

**The problem**: A hot wallet (one actively used for signing) is inherently more exposed than a cold wallet (one stored offline). If your signing key is on an internet-connected machine, it's more vulnerable.

**The solution**: XRPL allows you to designate a "regular key" that can sign transactions on behalf of an account. The master key remains offline (cold storage), while the regular key handles daily operations.

**Why this matters for agent wallets**: The MCP server only ever holds the regular key. Even a complete server compromise cannot obtain the master key, which means:

- The attacker cannot disable the regular key (only the master key can do that)
- The attacker cannot configure multi-sig requirements (only master key)
- The human administrator can revoke the regular key at any time from cold storage

**How to think about it**: The regular key is like a corporate credit card - it has spending limits and can be cancelled. The master key is like the CEO's signature - it controls everything.

### Multi-Signature: Distributed Authority

**The problem**: Any system where a single key can authorize large transactions has a single point of failure.

**The solution**: XRPL native multi-signature allows configuring accounts to require multiple signatures for transaction approval. A common configuration is "2 of 3" - any two of three designated keys must sign.

**Why this matters for agent wallets**: For Tier 3 transactions, the agent can only provide one signature. At least one additional human (or secure system) must provide another signature before the transaction can be submitted to the network.

**How to think about it**: Multi-signature is like requiring two keys to open a safety deposit box. Neither party alone can access the contents.

### Deposit Authorization: Inbound Protection

**The problem**: By default, anyone can send funds to any XRPL address. This sounds good until you realize it enables "dusting attacks" (sending tiny amounts to associate addresses) and unsolicited token deposits.

**The solution**: Deposit Authorization is an XRPL account flag that requires the account holder to explicitly authorize any incoming payments.

**Why this matters for agent wallets**: Prevents scenarios where an attacker sends a malicious token (that might trigger harmful logic when interacted with) or uses deposits to fingerprint wallet activity.

### Sequence Numbers: Replay Protection

**The problem**: What stops an attacker from recording a valid signed transaction and submitting it again later?

**The solution**: Every XRPL transaction includes a sequence number that must match the account's current sequence. Each successful transaction increments the sequence. Replayed transactions have outdated sequence numbers and are rejected.

**Why this matters for agent wallets**: Even if an attacker captures a valid signed transaction, they cannot replay it. The sequence number has already been used.

---

## Key Protection Mechanisms

Private keys are the most sensitive data in any cryptocurrency system. Whoever controls the keys controls the funds. Our approach to key protection operates on multiple levels.

### At Rest: Encryption

Private keys never exist in plaintext on disk. They are encrypted using:

- **AES-256-GCM**: A symmetric encryption algorithm that provides both confidentiality and integrity protection. The "GCM" mode includes an authentication tag that detects any tampering with the ciphertext.

- **Argon2id key derivation**: User passwords are never used directly as encryption keys. Instead, they are processed through Argon2id, which:
  - Requires significant memory (64MB), making GPU attacks impractical
  - Requires multiple iterations (3), making CPU attacks slow
  - Uses a random salt, ensuring identical passwords produce different keys

**Why this combination**: AES-256 is an industry standard with decades of cryptanalysis. Argon2id won the Password Hashing Competition specifically because it resists modern attack techniques. Together, they ensure that even if an attacker obtains the encrypted keystore file, they cannot extract keys without the password.

### In Memory: SecureBuffer Pattern

Keys must be decrypted to sign transactions, but this creates a window of vulnerability. Our SecureBuffer pattern minimizes this:

1. **Minimize lifetime**: Keys exist in memory only during the signing operation (typically < 100ms)
2. **Immediate zeroing**: After use, the memory is explicitly overwritten with zeros
3. **Prevent serialization**: SecureBuffer objects throw errors if you try to convert them to strings or JSON, preventing accidental logging

**Why this matters**: Memory dumps (from crashes, debugging, or attacks) can expose any data in memory. By zeroing keys immediately after use, we minimize the window where a memory dump would be dangerous.

**Limitations**: JavaScript/Node.js does not provide guarantees about memory handling due to garbage collection. The SecureBuffer pattern is a best-effort mitigation, not a guarantee. For extremely high-security applications, consider native modules or hardware security modules.

### File System: Permission Enforcement

Keystore files are created with restrictive permissions (mode 0600 on Unix - owner read/write only). Before reading a keystore, the system verifies permissions haven't been loosened.

**Why this matters**: Even on a shared system, other users cannot read keystore files. An attacker with local access but different user privileges cannot access the keys.

### Never, Ever, Under Any Circumstances

Some things are absolute rules:

- **Never log keys**: Not in debug logs, error messages, or audit trails. A key in a log is a key that might be sent to a log aggregator, backed up to tape, or included in a bug report.

- **Never transmit keys**: The MCP protocol never sends private keys. Operations that need keys are performed locally, and only results (signed transactions) are returned.

- **Never convert keys to strings**: String operations in JavaScript are particularly prone to creating copies. Keys stay as Buffers.

---

## Audit Logging and Tamper Detection

The audit log serves two critical purposes: accountability (knowing what happened) and detection (identifying attacks). A well-designed audit log is the forensic evidence that makes other security measures enforceable.

### Why Hash Chains?

Traditional logs can be modified. An attacker who gains access could delete evidence of their intrusion or alter timestamps to confuse investigation. Hash chains make this detectable.

Each audit log entry includes:
- A **sequence number** (monotonically increasing)
- A **hash of the previous entry**
- An **HMAC of the entire entry** (using a key stored separately from the logs)

Tampering is detectable because:

- **Modify an entry**: The HMAC won't match, and subsequent entries' previous-hash won't match
- **Delete an entry**: Sequence numbers have a gap
- **Insert an entry**: Would require knowing the HMAC key and forging the chain
- **Truncate entries**: The missing hashes are detectable when verified

### What Gets Logged

Every security-relevant operation creates an audit entry:

| Category | Examples |
|----------|----------|
| **Authentication** | Login attempts (success/failure), lockouts, session starts/ends |
| **Wallet Operations** | Creation, import, listing, deletion |
| **Transactions** | Sign requests, approvals, denials, submissions, confirmations |
| **Policy Events** | Evaluations, violations, limit warnings |
| **Security Events** | Rate limit triggers, injection detection, suspicious activity |
| **System Events** | Startup, shutdown, configuration changes |

### What Never Gets Logged

Even in debug mode, certain things are never logged:

- Private keys (would completely defeat security)
- Seed phrases (same as above)
- Passwords (authentication secrets)
- Full transaction contents (may contain sensitive information)
- Encryption keys (would defeat encryption)

Instead, we log metadata: "Transaction signed for 50 XRP to rDest...ABC, tier 1, policy: approved"

### Log Verification

The system periodically (hourly, by default) verifies the entire audit chain:

1. Starting from the genesis entry, verify each entry's HMAC
2. Verify each entry's previous-hash matches the actual previous entry
3. Verify sequence numbers have no gaps
4. Report any anomalies

This automated verification means tampering is detected quickly, not months later during a manual audit.

---

## Threat Mitigations

Understanding why security measures exist requires understanding what they protect against. Here are the key threats and how our architecture addresses them.

### Prompt Injection

**Threat**: An attacker includes instructions in data (transaction memos, address labels) that manipulate the AI agent into performing unintended actions.

**Mitigation**:
- Input validation layer detects known injection patterns
- Suspicious memo patterns trigger Tier 4 (prohibited)
- Policy engine cannot be modified by the agent at runtime
- Output sanitization prevents instruction-like content in responses

**Residual risk**: Novel injection techniques might not be detected. Defense in depth ensures that even a successfully manipulated agent faces policy and multi-sig barriers.

### Key Theft

**Threat**: An attacker obtains private keys and can sign arbitrary transactions.

**Mitigation**:
- Keys encrypted at rest with AES-256-GCM
- Password-derived encryption keys use Argon2id (memory-hard)
- Keys zeroed from memory immediately after use
- File permissions prevent unauthorized file access
- Regular keys enable cold storage of master keys

**Residual risk**: A sufficiently privileged attacker with long-term access might eventually capture keys during signing operations. Multi-sig provides protocol-level protection even in this scenario.

### Transaction Manipulation

**Threat**: An attacker modifies transaction parameters after policy approval but before signing.

**Mitigation**:
- Transactions are validated at multiple stages
- The same validated transaction object flows through the entire pipeline
- Signed transactions include all parameters; modification invalidates the signature

**Residual risk**: Minimal. The cryptographic signature binds the transaction parameters.

### Replay Attacks

**Threat**: An attacker records a valid signed transaction and submits it again later.

**Mitigation**:
- XRPL sequence numbers prevent replay (each transaction uses a unique sequence)
- Our system tracks expected sequences and rejects stale transactions

**Residual risk**: None for same-account replays. Cross-chain replay is not applicable (XRPL transactions are XRPL-specific).

### Brute Force Authentication

**Threat**: An attacker repeatedly guesses passwords until successful.

**Mitigation**:
- Argon2id makes each attempt computationally expensive (seconds, not milliseconds)
- Progressive lockout doubles timeout after each failure
- Rate limiting restricts attempts per time window

**Residual risk**: Very weak passwords might still be guessable. Password strength requirements at the application layer mitigate this.

### Log Tampering

**Threat**: An attacker who successfully attacks the system modifies logs to hide evidence.

**Mitigation**:
- Hash chain makes any modification detectable
- Sequence numbers reveal deletions
- HMAC key stored separately from logs
- Automated verification detects tampering quickly

**Residual risk**: An attacker with access to both logs and HMAC key could theoretically forge the chain from a point forward. Secure key storage and monitoring mitigate this.

---

## Security vs. Usability Tradeoffs

Security and usability often conflict. Stronger security usually means more friction. Our design philosophy is to make the secure path the easy path, and to add friction proportional to risk.

### Tradeoffs We Made

| Decision | Security Benefit | Usability Cost | Why We Chose This |
|----------|-----------------|----------------|-------------------|
| **Tier 1 limit at 100 XRP** | Bounds damage from compromised agent | Larger routine payments need delays | Most agent operations are small; humans handle large ones |
| **5-minute delay window** | Time to catch mistakes or attacks | Legitimate delayed transactions wait | Long enough to notice, short enough for business |
| **Multi-sig for >1000 XRP** | No unilateral large transfers | Extra approval step for big payments | High-value transactions warrant extra verification |
| **Argon2id with 64MB memory** | Resists GPU cracking | Slower unlocking (seconds) | Unlocking is infrequent; security is paramount |
| **Blocklisting patterns** | Stops known-bad activity | Might false-positive edge cases | Configurable patterns let users tune sensitivity |

### What We Didn't Do

Some security measures we considered but rejected:

| Rejected Measure | Why Rejected |
|------------------|--------------|
| **Hardware Security Module (HSM) requirement** | Would make the tool inaccessible for individual users and smaller deployments |
| **Mandatory 2FA for every operation** | Would prevent autonomous agent operation entirely |
| **Real-time human approval for all transactions** | Defeats purpose of AI-operated wallet |
| **Storing keys only in cloud HSM** | Creates vendor dependency and internet requirement |

### Configurability

Rather than imposing one-size-fits-all security, many parameters are configurable:

- Tier thresholds can be adjusted (raise autonomous limit for trusted deployments)
- Rate limits can be tuned (stricter for exposed servers, relaxed for internal)
- Allowlists and blocklists are user-defined
- Multi-sig quorums can be changed (2-of-3 vs 3-of-5)

This allows each deployment to find its own security/usability balance while the architecture ensures the fundamentals are sound.

---

## Conclusion

The XRPL Wallet MCP security model is built on a simple premise: no single protection should be the only thing standing between an attacker and your funds. By layering eight independent defenses, implementing risk-proportional transaction tiers, leveraging XRPL's native security features, and maintaining tamper-evident audit logs, we create a system where attacks are difficult, limited in damage, and detectable.

Security is never finished. Threats evolve, and defenses must evolve with them. But a well-designed architecture makes it possible to add new protections without rebuilding from scratch. The principles in this document - defense in depth, fail-secure design, minimal attack surface, and comprehensive auditing - provide that foundation.

---

## Related Documentation

- [Security Architecture](../../security/SECURITY-ARCHITECTURE.md) - Technical implementation details
- [Crosscutting Concepts](../../architecture/08-crosscutting.md) - Architectural patterns
- [Threat Model](../../security/threat-model.md) - Detailed threat analysis

---

*Document generated: 2026-01-28*
*Classification: Public*
