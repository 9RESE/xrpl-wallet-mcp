# Understanding Network Isolation

**Document Type:** Explanation (Diataxis)
**Last Updated:** 2026-01-28
**Audience:** Developers, Security-Conscious Users, Operators

---

## Introduction: Why Network Isolation Matters

The XRP Ledger operates three distinct networks: mainnet (real money), testnet (testing), and devnet (development). Each serves a different purpose, and critically, each handles fundamentally different value. A single XRP on mainnet might be worth several dollars. A million XRP on testnet is worth nothing.

This asymmetry creates a dangerous failure mode: what if you accidentally perform a mainnet operation when you intended testnet? Or vice versa? The consequences are not symmetric. Testing on mainnet costs real money. Using mainnet credentials on testnet exposes your real keys to a less secure environment. Both scenarios represent serious operational failures.

The XRPL Wallet MCP server implements strict network isolation specifically to make these accidents impossible. Not unlikely. Not detectable-after-the-fact. Impossible by design.

This document explains *why* network isolation exists, *what* problems it prevents, and *how* the design choices make accidental cross-network operations structurally impossible.

---

## The Problem: Accidental Mainnet Operations

Before understanding our solution, we must understand the threat we are defending against.

### The Three Networks

| Network | Purpose | Real Value | Consequence of Mistakes |
|---------|---------|------------|-------------------------|
| **Mainnet** | Production transactions | Yes (real XRP) | Catastrophic - funds are irreversible |
| **Testnet** | Testing and development | No (free test XRP) | Low - can request more from faucet |
| **Devnet** | Experimentation | No (ephemeral) | None - network resets periodically |

The networks are technically compatible. An address that is valid on mainnet is also syntactically valid on testnet. A transaction format that works on testnet also works on mainnet. This technical compatibility is precisely what makes mistakes so easy.

### How Accidents Happen

Consider these common scenarios, each of which has caused real losses in the cryptocurrency ecosystem:

**Scenario 1: The Copy-Paste Error**

A developer is testing a payment flow. They have a testnet wallet open in one terminal and a mainnet wallet in another. They copy-paste a destination address from the wrong terminal. The transaction succeeds - sending real funds to a testnet address that may not even exist on mainnet, or worse, belongs to someone else entirely.

**Scenario 2: The Environment Variable Mistake**

An API key or configuration file points to mainnet instead of testnet. The developer thinks they are running tests, but every "test" transaction is executing against production. By the time they notice, dozens of real transactions have occurred.

**Scenario 3: The Key Reuse Problem**

A developer generates a key pair for testing. Later, they decide to use the same key for a small mainnet wallet for convenience. Now testnet code that was written assuming the key had no value can accidentally affect a wallet with real funds.

**Scenario 4: The Automation Gone Wrong**

An AI agent is configured to operate a testnet wallet for development. Through misconfiguration, it connects to mainnet instead. Every autonomous operation the agent performs now affects real funds, potentially at machine speed.

### Why Detection Is Not Enough

You might think: "These are just bugs. Good monitoring would catch them." But detection has fundamental limitations:

1. **Timing**: By the time you detect the mistake, transactions may have already confirmed. XRPL transactions finalize in 3-5 seconds.

2. **Irreversibility**: Blockchain transactions cannot be reversed. No customer support can help you.

3. **Volume**: An automated system can execute many transactions before any alert triggers.

4. **Subtlety**: A transaction to a wrong address looks identical to a legitimate transaction. The system cannot know your intent.

The only reliable solution is prevention. Make the accidents impossible to commit, not merely detectable after the fact.

---

## The Solution: Physical Separation

Our approach to network isolation is straightforward: keys for different networks are stored in completely separate locations. Not different entries in the same database. Not different rows in the same table. Physically separate files in separate directories.

### How Storage Is Organized

```
~/.xrpl-wallet-mcp/
├── mainnet/
│   ├── keystore.enc      # Mainnet keys ONLY
│   ├── keystore.meta     # Mainnet KDF parameters
│   ├── policy.json       # Mainnet-specific policy
│   └── audit.log         # Mainnet audit trail
├── testnet/
│   ├── keystore.enc      # Testnet keys ONLY
│   ├── keystore.meta
│   ├── policy.json       # Different policy for testing
│   └── audit.log         # Testnet audit trail
└── devnet/
    ├── keystore.enc      # Devnet keys ONLY
    ├── keystore.meta
    ├── policy.json       # Permissive policy for dev
    └── audit.log         # Devnet audit trail
```

Each network has its own isolated universe. A mainnet keystore knows nothing about testnet keys. A testnet policy cannot reference mainnet wallets. Audit logs clearly record which network each operation occurred on.

### Why Physical Separation Matters

Consider alternatives that do not use physical separation:

**Alternative 1: Network flag on each key**

```
// Hypothetical bad design
keystore.json:
  - key: "sEd...", network: "mainnet"
  - key: "sEd...", network: "testnet"
```

This design has a single keystore containing keys for multiple networks. The problem: a single bug in network flag checking could expose mainnet keys during testnet operations. The flag is the only protection.

**Alternative 2: Runtime network selection**

```
// Hypothetical bad design
wallet.sign(transaction, { network: 'testnet' })
```

This design relies on the caller to specify the correct network. The problem: the caller can make mistakes. The parameter can be wrong. There is nothing structural preventing mainnet operations.

**Our design: Physical isolation**

```
// Good design
const keystorePath = `~/.xrpl-wallet-mcp/${network}/keystore.enc`;
const keystore = await loadKeystore(keystorePath);
```

With physical separation, a testnet operation physically cannot access mainnet keys. The keys are in different files. The code that reads the testnet keystore will never, under any circumstances, read the mainnet keystore, because it is reading from a different path.

This is not about trusting code to check flags correctly. This is about making incorrect access structurally impossible.

---

## How Keystores Are Isolated

The keystore for each network is completely independent. Creating, unlocking, and operating a mainnet keystore has no relationship to the testnet keystore.

### Independent Initialization

When you create a wallet on testnet, the system:

1. Creates the `~/.xrpl-wallet-mcp/testnet/` directory (if needed)
2. Generates or imports the key
3. Encrypts and stores it in `testnet/keystore.enc`
4. Records metadata in `testnet/keystore.meta`

At no point does this process touch any mainnet files. The mainnet directory may not even exist.

### Independent Passwords

Each network's keystore has its own password. You could use:

- A simple password for devnet (it has no value)
- A moderate password for testnet (convenient for testing)
- A strong password for mainnet (protecting real funds)

This reflects the different security requirements. Your devnet password does not need to resist nation-state attacks. Your mainnet password should.

### Independent Unlocking

To operate a wallet, you must unlock the keystore. Unlocking is network-specific:

```
xrpl-wallet unlock --network testnet
```

This unlocks only the testnet keystore. The mainnet keystore remains locked. Even if your testnet session is compromised, the attacker cannot access mainnet keys because they are encrypted with a different password they do not have.

### The Locked State as Protection

When you are finished working on testnet, you lock the keystore. The keys return to their encrypted state. Now, even if the system is compromised, the attacker faces the encryption rather than having access to decrypted keys.

This means that a compromised testnet session cannot escalate to mainnet access. The two are fundamentally separate.

---

## Network Validation During Signing

Physical separation prevents accessing the wrong keys. But what if you load the right keys and then connect to the wrong network? Runtime validation provides the second layer of protection.

### The Network Guard

Every operation that touches the network includes validation:

1. **Is the network valid?** Only 'mainnet', 'testnet', and 'devnet' are accepted. No typos, no creative alternatives.

2. **Does the keystore match?** If you unlocked the testnet keystore, you cannot request mainnet operations.

3. **Is the connection correct?** The WebSocket URL must match the expected network.

### What Happens on Mismatch

If any validation fails, the operation is rejected immediately:

```
Error: Network mismatch: keystore is for testnet,
       but operation requested mainnet
```

The transaction is not signed. The operation does not proceed. The audit log records the attempted cross-network operation as a security event.

### Why Both Layers Are Needed

Physical separation handles the storage layer. Network validation handles the runtime layer. Together, they provide defense in depth:

- Physical separation means the wrong keys are never loaded
- Network validation means even a confused caller is blocked
- Either layer alone would catch most accidents
- Both layers together make accidents virtually impossible

### No Silent Defaults

A critical design decision: there are no default networks. Every operation must explicitly specify which network it targets:

```
// This is rejected - no default
xrpl-wallet balance --wallet rABC...

// This is required - explicit network
xrpl-wallet balance --wallet rABC... --network testnet
```

This eliminates the class of accidents where someone forgets to specify testnet and accidentally operates on a hypothetical "default" mainnet.

---

## Why Keys Cannot Cross Networks

You might wonder: could you take a testnet key and use it on mainnet? After all, keys are just cryptographic material.

### Technical Compatibility

Technically, yes. An XRPL key pair is network-agnostic. The same private key could sign transactions on any network. This is why network isolation must be enforced at the application level.

### Why We Prevent It

Even though keys are technically portable, we prevent cross-network key usage because:

1. **Key exposure**: Keys used on testnet may be handled less carefully. Logs, debugging sessions, and code comments might contain testnet keys. These keys should never have access to real funds.

2. **Audit clarity**: When reviewing an incident, it should be immediately clear which network was affected. Mixed-network keys create ambiguity.

3. **Policy separation**: Testnet policies are deliberately permissive. Mainnet policies are conservative. A key that exists on both networks might be subject to the wrong policy.

4. **Security hygiene**: Treating testnet and mainnet as completely separate encourages good habits. There is no temptation to "just use the same key" for convenience.

### How Prevention Works

When you create a wallet, it is created in a specific network's keystore. The system does not provide any mechanism to copy keys between networks. There is no "export from testnet, import to mainnet" workflow.

If you need a mainnet wallet, you create it on mainnet. If you need a testnet wallet, you create it on testnet. The keys are separate by design.

### The Exception: Key Ceremony

For advanced users performing careful key management, it is technically possible to generate a key externally and import it to multiple networks. This requires deliberate action outside the normal workflow. We do not prevent this because:

- Advanced users may have legitimate reasons
- Preventing it would require trusting a blacklist, which can be circumvented
- The normal workflow strongly discourages it

But the default, supported workflow keeps networks completely separate.

---

## Mainnet Safety Guardrails

Mainnet operations receive extra scrutiny because mistakes are irreversible and costly. Several additional safeguards apply only to mainnet.

### Conservative Default Policy

The default policy for mainnet is deliberately restrictive:

- Autonomous tier limited to 100 XRP per transaction
- Daily limit of 1,000 XRP
- New destinations trigger delayed approval
- Large transactions require multi-signature

Testnet and devnet defaults are much more permissive because there is no real value at risk.

### Explicit Mainnet Confirmation

Some operations require explicit confirmation that you intend to operate on mainnet. This prevents autopilot mistakes where you are mentally in "testing mode" but technically on mainnet.

### Audit Trail Separation

Mainnet audit logs are stored separately and may be subject to different retention policies. In a compliance context, mainnet transaction records may need to be preserved longer than testnet testing artifacts.

### The Mental Model

When you see "mainnet" in a command, warning, or log, it should trigger heightened attention. The system is designed to make mainnet operations feel different from testnet operations, so you cannot sleepwalk into a mistake.

---

## Examples of Prevented Accidents

These scenarios illustrate how network isolation prevents real problems.

### Example 1: The Confused Developer

**Scenario**: A developer is working on both mainnet integration and testnet testing. They have two terminal windows open and accidentally paste a mainnet sign command into the testnet window.

**What happens**: The testnet keystore is loaded. The command specifies mainnet. Network validation fails immediately.

```
Error: Network mismatch: keystore is for testnet,
       but operation requested mainnet
```

**What was prevented**: The transaction was never signed. No mainnet funds were at risk.

### Example 2: The Environment Misconfiguration

**Scenario**: A CI/CD pipeline has an environment variable misconfigured. It should point to testnet but points to mainnet.

**What happens**: The pipeline tries to unlock the mainnet keystore with the testnet password. Authentication fails.

```
Error: Invalid password for mainnet keystore
```

**What was prevented**: The pipeline could not proceed. Even if the operation had been attempted, the wrong password would have blocked it.

### Example 3: The Automated Agent

**Scenario**: An AI agent is configured to manage a testnet wallet. Through a prompt injection attack, an attacker tries to make the agent operate on mainnet.

**What happens**: The agent's session is bound to testnet. Any mainnet operation request fails network validation.

```
Error: Cannot switch networks while wallet is unlocked.
       Lock wallet and unlock for mainnet.
```

**What was prevented**: The attacker could not redirect the agent to mainnet without credentials they do not have.

### Example 4: The Key Theft Attempt

**Scenario**: An attacker gains read access to the testnet keystore file. They attempt to use these keys on mainnet.

**What happens**: The testnet keys do not exist in the mainnet keystore. The attacker has testnet keys, which are worthless.

**What was prevented**: Even with file system access, the attacker gained nothing of value because network isolation means testnet compromise does not affect mainnet.

### Example 5: The Policy Mistake

**Scenario**: A developer configures a permissive policy for testing (high autonomous limits, no delays). They accidentally copy this policy to mainnet.

**What happens**: The policy file is in a different directory. Copying to the mainnet directory requires explicit action. The system warns when mainnet policy is modified.

**What was prevented**: The permissive policy stayed in testnet where it belongs. Even if copied, the higher transaction volumes would trigger additional review.

---

## The Design Philosophy

Network isolation embodies several core principles of the XRPL Wallet MCP security model.

### Structural Safety Over Behavioral Safety

We do not rely on people doing the right thing. We design systems where the wrong thing is not possible. Physical file separation is structural. Runtime validation is structural. Neither depends on human vigilance.

### Defense in Depth

Any single protection might fail. Code might have bugs. Configurations might be wrong. By layering multiple independent protections, we ensure that a single failure does not cause a security breach.

### Fail-Secure Defaults

When something goes wrong, the system denies access. Invalid networks are rejected. Missing keystores cause errors. Ambiguous operations fail. The default is always the safe choice.

### Proportional Security

Mainnet receives the strongest protections because it has real value. Testnet is more permissive because mistakes are costless. Devnet is most permissive because it is ephemeral. This proportionality makes the system usable while keeping critical assets safe.

---

## Summary

Network isolation in the XRPL Wallet MCP is not a feature - it is a fundamental design principle. By physically separating keystores, validating network consistency at runtime, preventing key migration between networks, and applying proportional security policies, we make accidental cross-network operations impossible.

The key insights are:

1. **Physical separation** is stronger than logical flags. Keys in different files cannot be confused.

2. **Runtime validation** catches configuration mistakes before they cause harm.

3. **No defaults** means every operation requires explicit network specification.

4. **Proportional policy** means mainnet is protected without making testnet unusable.

5. **Defense in depth** means multiple layers must all fail for an accident to occur.

When working with the XRPL Wallet MCP, you can be confident that your testnet testing will never accidentally affect your mainnet funds, and your mainnet security will never be compromised by testnet convenience.

---

## Related Documentation

- [ADR-010: Network Isolation](../../architecture/09-decisions/ADR-010-network-isolation.md) - Architectural decision and technical details
- [Network Configuration How-To](../how-to/network-configuration.md) - Step-by-step configuration guide
- [Security Model](security-model.md) - Broader security architecture

---

*This document explains concepts and rationale. For step-by-step instructions on configuring networks, see the Network Configuration How-To Guide.*
