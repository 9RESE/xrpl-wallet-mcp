# Integration Test Patterns Specification

## Document Information

| Field | Value |
|-------|-------|
| **Version** | 1.0.0 |
| **Status** | Draft |
| **Created** | 2026-01-28 |
| **Component** | Testing Framework |

## Table of Contents

1. [Overview](#overview)
2. [Integration Test Scope](#integration-test-scope)
3. [Test Patterns](#test-patterns)
4. [Test Fixtures](#test-fixtures)
5. [Environment Setup](#environment-setup)
6. [Cleanup Procedures](#cleanup-procedures)
7. [Test Isolation Strategies](#test-isolation-strategies)
8. [Async/Await Patterns](#asyncawait-patterns)
9. [Example Integration Test Suite](#example-integration-test-suite)

---

## Overview

This document defines integration test patterns for the XRPL Agent Wallet MCP server. Integration tests verify that multiple components work together correctly, testing real interactions between:

- MCP Server (tool routing)
- Policy Engine (authorization)
- Signing Service (transaction signing)
- Keystore (key management)
- Audit Logger (event recording)
- XRPL Client (network communication)

### Testing Framework

```typescript
// Primary testing framework: vitest
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
```

### Test Categories

| Category | Scope | Network | Duration |
|----------|-------|---------|----------|
| Unit | Single component | Mock | < 100ms |
| Integration | Multi-component | Mock/Testnet | < 5s |
| E2E | Full system | Testnet | < 30s |

---

## Integration Test Scope

### Multi-Component Flow Testing

Integration tests verify interactions between components across the system architecture:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Integration Test Scope                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────┐    ┌──────────────┐    ┌─────────────────┐            │
│  │   MCP    │───▶│   Policy     │───▶│    Signing      │            │
│  │  Server  │    │   Engine     │    │    Service      │            │
│  └──────────┘    └──────────────┘    └─────────────────┘            │
│       │                │                      │                      │
│       │                │                      │                      │
│       ▼                ▼                      ▼                      │
│  ┌──────────┐    ┌──────────────┐    ┌─────────────────┐            │
│  │  Audit   │◀───│   Keystore   │◀───│   XRPL Client   │            │
│  │  Logger  │    │              │    │                 │            │
│  └──────────┘    └──────────────┘    └─────────────────┘            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Component Boundaries

| Integration | Components | Purpose |
|-------------|------------|---------|
| Tool Flow | MCP Server + All | End-to-end tool execution |
| Policy + Signing | PolicyEngine + SigningService | Authorization enforcement |
| Signing + Keystore | SigningService + Keystore | Secure key access |
| Audit Chain | AuditLogger + All | Event logging verification |
| XRPL Network | XRPLClient + Testnet | Real network operations |

### Test Coverage Requirements

```typescript
// Integration test coverage targets
const COVERAGE_TARGETS = {
  componentIntegration: 80,  // Cross-component interactions
  mcpToolFlows: 90,          // MCP tool end-to-end
  policyEnforcement: 95,     // Policy evaluation paths
  auditLogging: 85,          // Audit event coverage
  xrplOperations: 75,        // Network operations (testnet)
};
```

---

## Test Patterns

### 1. MCP Tool Flow Pattern (wallet_create End-to-End)

Tests complete tool execution from MCP request to response.

```typescript
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { MCPServer } from '../src/mcp/server';
import { LocalFileKeystoreProvider } from '../src/keystore/local-file';
import { AuditLogger } from '../src/audit/logger';
import { XRPLClient } from '../src/xrpl/client';

describe('MCP Tool Flow: wallet_create', () => {
  let server: MCPServer;
  let keystore: LocalFileKeystoreProvider;
  let auditLogger: AuditLogger;
  let xrplClient: XRPLClient;
  let testDir: string;

  beforeAll(async () => {
    // Setup test environment
    testDir = await createTestDirectory();

    // Initialize components with real implementations
    keystore = new LocalFileKeystoreProvider({
      storagePath: path.join(testDir, 'keys'),
      encryptionKey: await deriveTestKey('test-password'),
    });

    auditLogger = new AuditLogger({
      storagePath: path.join(testDir, 'audit'),
      hmacKey: generateTestHmacKey(),
    });

    xrplClient = new XRPLClient({
      network: 'testnet',
      timeout: 30000,
    });

    server = new MCPServer({
      keystore,
      auditLogger,
      xrplClient,
    });

    await server.initialize();
  });

  afterAll(async () => {
    await server.shutdown();
    await xrplClient.disconnect();
    await cleanupTestDirectory(testDir);
  });

  it('should create wallet with full component integration', async () => {
    // Execute MCP tool
    const result = await server.executeTool('wallet_create', {
      name: 'test-wallet',
      network: 'testnet',
    });

    // Verify response structure
    expect(result).toMatchObject({
      walletId: expect.any(String),
      address: expect.stringMatching(/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/),
      network: 'testnet',
    });

    // Verify keystore storage
    const storedWallet = await keystore.getWallet(result.walletId);
    expect(storedWallet).toBeDefined();
    expect(storedWallet.address).toBe(result.address);

    // Verify audit log entry
    const auditEntries = await auditLogger.query({
      eventType: 'WALLET_CREATED',
      walletId: result.walletId,
    });
    expect(auditEntries).toHaveLength(1);
    expect(auditEntries[0]).toMatchObject({
      eventType: 'WALLET_CREATED',
      walletId: result.walletId,
      success: true,
    });
  });

  it('should handle wallet creation with testnet funding', async () => {
    const result = await server.executeTool('wallet_create', {
      name: 'funded-wallet',
      network: 'testnet',
      fundFromFaucet: true,
    });

    expect(result.funded).toBe(true);
    expect(result.balance).toBeGreaterThan(0);

    // Verify on-chain balance via XRPL client
    const accountInfo = await xrplClient.getAccountInfo(result.address);
    expect(accountInfo.Balance).toBeDefined();
  }, 60000); // Extended timeout for testnet

  it('should reject creation with duplicate name', async () => {
    // Create first wallet
    await server.executeTool('wallet_create', {
      name: 'unique-wallet',
      network: 'testnet',
    });

    // Attempt duplicate
    await expect(
      server.executeTool('wallet_create', {
        name: 'unique-wallet',
        network: 'testnet',
      })
    ).rejects.toThrow('Wallet with name "unique-wallet" already exists');

    // Verify audit logged the failure
    const auditEntries = await auditLogger.query({
      eventType: 'WALLET_CREATE_FAILED',
    });
    expect(auditEntries.length).toBeGreaterThan(0);
  });
});
```

### 2. XRPL Testnet Integration Pattern

Tests actual network communication with XRPL testnet.

```typescript
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { XRPLClient } from '../src/xrpl/client';
import { Wallet } from 'xrpl';

describe('XRPL Testnet Integration', () => {
  let client: XRPLClient;
  let testWallet: Wallet;

  beforeAll(async () => {
    client = new XRPLClient({
      network: 'testnet',
      timeout: 30000,
      reconnect: {
        maxAttempts: 3,
        delay: 1000,
      },
    });

    await client.connect();

    // Fund a test wallet from faucet
    testWallet = Wallet.generate();
    await client.fundTestnetAccount(testWallet.address);
  }, 120000); // Extended setup timeout

  afterAll(async () => {
    await client.disconnect();
  });

  describe('Connection Management', () => {
    it('should maintain healthy connection', async () => {
      const health = await client.healthCheck();

      expect(health).toMatchObject({
        connected: true,
        network: 'testnet',
        latency: expect.any(Number),
      });
      expect(health.latency).toBeLessThan(5000);
    });

    it('should reconnect after disconnection', async () => {
      // Force disconnect
      await client.disconnect();

      // Attempt operation (should auto-reconnect)
      const serverInfo = await client.getServerInfo();

      expect(serverInfo).toBeDefined();
      expect(client.isConnected()).toBe(true);
    });
  });

  describe('Account Operations', () => {
    it('should fetch account info from testnet', async () => {
      const accountInfo = await client.getAccountInfo(testWallet.address);

      expect(accountInfo).toMatchObject({
        Account: testWallet.address,
        Balance: expect.any(String),
        Sequence: expect.any(Number),
      });
    });

    it('should handle non-existent account gracefully', async () => {
      const nonExistentAddress = 'rNonExistentAddress123456789012';

      await expect(
        client.getAccountInfo(nonExistentAddress)
      ).rejects.toThrow(/Account not found|actNotFound/);
    });
  });

  describe('Transaction Submission', () => {
    it('should submit payment transaction to testnet', async () => {
      // Create destination wallet
      const destWallet = Wallet.generate();
      await client.fundTestnetAccount(destWallet.address);

      // Prepare payment
      const payment = {
        TransactionType: 'Payment',
        Account: testWallet.address,
        Destination: destWallet.address,
        Amount: '1000000', // 1 XRP in drops
      };

      // Submit and wait for validation
      const result = await client.submitAndWait(payment, {
        wallet: testWallet,
      });

      expect(result.result.meta.TransactionResult).toBe('tesSUCCESS');
      expect(result.result.validated).toBe(true);
    }, 60000);

    it('should handle transaction failure correctly', async () => {
      // Attempt payment with insufficient funds
      const emptyWallet = Wallet.generate();

      const payment = {
        TransactionType: 'Payment',
        Account: emptyWallet.address,
        Destination: testWallet.address,
        Amount: '1000000',
      };

      await expect(
        client.submitAndWait(payment, { wallet: emptyWallet })
      ).rejects.toThrow(/tecUNFUNDED|actNotFound/);
    });
  });

  describe('Faucet Integration', () => {
    it('should fund new account from testnet faucet', async () => {
      const newWallet = Wallet.generate();

      const fundResult = await client.fundTestnetAccount(newWallet.address);

      expect(fundResult).toMatchObject({
        address: newWallet.address,
        balance: expect.any(Number),
      });
      expect(fundResult.balance).toBeGreaterThan(0);
    }, 60000);

    it('should handle faucet rate limiting', async () => {
      const wallets = Array.from({ length: 5 }, () => Wallet.generate());

      // Rapid faucet requests may trigger rate limiting
      const results = await Promise.allSettled(
        wallets.map(w => client.fundTestnetAccount(w.address))
      );

      // At least some should succeed
      const successes = results.filter(r => r.status === 'fulfilled');
      expect(successes.length).toBeGreaterThan(0);
    }, 120000);
  });
});
```

### 3. Policy + Signing Integration Pattern

Tests policy evaluation with transaction signing workflows.

```typescript
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { PolicyEngine, PolicyTier } from '../src/policy/engine';
import { SigningService } from '../src/signing/service';
import { LocalFileKeystoreProvider } from '../src/keystore/local-file';
import { AuditLogger } from '../src/audit/logger';

describe('Policy + Signing Integration', () => {
  let policyEngine: PolicyEngine;
  let signingService: SigningService;
  let keystore: LocalFileKeystoreProvider;
  let auditLogger: AuditLogger;
  let testDir: string;
  let testWalletId: string;

  beforeAll(async () => {
    testDir = await createTestDirectory();

    // Initialize real components
    keystore = await createTestKeystoreProvider(testDir);
    auditLogger = await createTestAuditLogger(testDir);

    policyEngine = new PolicyEngine({
      auditLogger,
    });

    signingService = new SigningService({
      keystore,
      policyEngine,
      auditLogger,
    });

    // Create test wallet
    const wallet = await keystore.createWallet('policy-test-wallet');
    testWalletId = wallet.id;
  });

  afterAll(async () => {
    await cleanupTestDirectory(testDir);
  });

  beforeEach(async () => {
    // Reset policy state between tests
    await policyEngine.resetLimits(testWalletId);
  });

  describe('Tier 1: Autonomous Transactions', () => {
    it('should sign small payment without approval', async () => {
      // Configure policy for autonomous small payments
      await policyEngine.setPolicy(testWalletId, {
        autonomousLimit: 10_000_000, // 10 XRP
        dailyLimit: 100_000_000,     // 100 XRP
        allowedDestinations: ['*'],
      });

      const transaction = {
        TransactionType: 'Payment',
        Account: await keystore.getAddress(testWalletId),
        Destination: 'rDestination12345678901234567890',
        Amount: '5000000', // 5 XRP - within autonomous limit
      };

      const result = await signingService.signTransaction(
        testWalletId,
        transaction
      );

      expect(result).toMatchObject({
        signed: true,
        tier: PolicyTier.AUTONOMOUS,
        txBlob: expect.any(String),
        requiresApproval: false,
      });

      // Verify audit log
      const auditEntry = await auditLogger.getLatestEntry(testWalletId);
      expect(auditEntry.eventType).toBe('TRANSACTION_SIGNED');
      expect(auditEntry.details.tier).toBe(PolicyTier.AUTONOMOUS);
    });
  });

  describe('Tier 2: Delayed Transactions', () => {
    it('should queue medium payment for delayed execution', async () => {
      await policyEngine.setPolicy(testWalletId, {
        autonomousLimit: 5_000_000,   // 5 XRP
        delayedLimit: 50_000_000,     // 50 XRP
        delayPeriod: 3600,            // 1 hour
      });

      const transaction = {
        TransactionType: 'Payment',
        Account: await keystore.getAddress(testWalletId),
        Destination: 'rDestination12345678901234567890',
        Amount: '20000000', // 20 XRP - requires delay
      };

      const result = await signingService.signTransaction(
        testWalletId,
        transaction
      );

      expect(result).toMatchObject({
        signed: false,
        tier: PolicyTier.DELAYED,
        pendingId: expect.any(String),
        executeAfter: expect.any(Date),
        requiresApproval: false,
      });

      // Verify pending transaction stored
      const pending = await signingService.getPendingTransaction(result.pendingId);
      expect(pending).toBeDefined();
      expect(pending.status).toBe('PENDING_DELAY');
    });

    it('should execute delayed transaction after period', async () => {
      // Setup with short delay for testing
      await policyEngine.setPolicy(testWalletId, {
        autonomousLimit: 0,
        delayedLimit: 50_000_000,
        delayPeriod: 1, // 1 second for testing
      });

      const transaction = {
        TransactionType: 'Payment',
        Account: await keystore.getAddress(testWalletId),
        Destination: 'rDestination12345678901234567890',
        Amount: '10000000',
      };

      const pendingResult = await signingService.signTransaction(
        testWalletId,
        transaction
      );

      // Wait for delay period
      await sleep(1500);

      // Execute delayed transaction
      const executeResult = await signingService.executeDelayed(
        pendingResult.pendingId
      );

      expect(executeResult).toMatchObject({
        signed: true,
        txBlob: expect.any(String),
        executedAt: expect.any(Date),
      });
    });
  });

  describe('Tier 3: Co-Sign Transactions', () => {
    it('should require co-signer for large transactions', async () => {
      await policyEngine.setPolicy(testWalletId, {
        autonomousLimit: 5_000_000,
        delayedLimit: 50_000_000,
        coSignLimit: 500_000_000,     // 500 XRP
        coSigners: ['rCoSigner123456789012345678901'],
      });

      const transaction = {
        TransactionType: 'Payment',
        Account: await keystore.getAddress(testWalletId),
        Destination: 'rDestination12345678901234567890',
        Amount: '100000000', // 100 XRP - requires co-sign
      };

      const result = await signingService.signTransaction(
        testWalletId,
        transaction
      );

      expect(result).toMatchObject({
        signed: false,
        tier: PolicyTier.CO_SIGN,
        pendingId: expect.any(String),
        requiredSignatures: 2,
        collectedSignatures: 1,
        requiresApproval: true,
      });
    });

    it('should complete co-sign with additional signature', async () => {
      // Setup co-sign policy
      const coSignerWallet = await keystore.createWallet('co-signer-wallet');

      await policyEngine.setPolicy(testWalletId, {
        autonomousLimit: 0,
        coSignLimit: 100_000_000,
        coSigners: [await keystore.getAddress(coSignerWallet.id)],
      });

      const transaction = {
        TransactionType: 'Payment',
        Account: await keystore.getAddress(testWalletId),
        Destination: 'rDestination12345678901234567890',
        Amount: '50000000',
      };

      // First signature
      const pending = await signingService.signTransaction(testWalletId, transaction);

      // Add co-signer signature
      const completed = await signingService.addCoSignature(
        pending.pendingId,
        coSignerWallet.id
      );

      expect(completed).toMatchObject({
        signed: true,
        txBlob: expect.any(String),
        collectedSignatures: 2,
      });
    });
  });

  describe('Tier 4: Prohibited Transactions', () => {
    it('should reject transactions exceeding all limits', async () => {
      await policyEngine.setPolicy(testWalletId, {
        autonomousLimit: 5_000_000,
        delayedLimit: 50_000_000,
        coSignLimit: 100_000_000,
      });

      const transaction = {
        TransactionType: 'Payment',
        Account: await keystore.getAddress(testWalletId),
        Destination: 'rDestination12345678901234567890',
        Amount: '200000000', // 200 XRP - exceeds all limits
      };

      await expect(
        signingService.signTransaction(testWalletId, transaction)
      ).rejects.toThrow('Transaction prohibited by policy');

      // Verify audit log records rejection
      const auditEntry = await auditLogger.getLatestEntry(testWalletId);
      expect(auditEntry.eventType).toBe('TRANSACTION_REJECTED');
      expect(auditEntry.details.tier).toBe(PolicyTier.PROHIBITED);
    });

    it('should reject transactions to blocked destinations', async () => {
      await policyEngine.setPolicy(testWalletId, {
        autonomousLimit: 100_000_000,
        blockedDestinations: ['rBlockedAddress1234567890123456'],
      });

      const transaction = {
        TransactionType: 'Payment',
        Account: await keystore.getAddress(testWalletId),
        Destination: 'rBlockedAddress1234567890123456',
        Amount: '1000000',
      };

      await expect(
        signingService.signTransaction(testWalletId, transaction)
      ).rejects.toThrow('Destination address is blocked');
    });
  });

  describe('Limit Tracking', () => {
    it('should track daily spending limits', async () => {
      await policyEngine.setPolicy(testWalletId, {
        autonomousLimit: 10_000_000,
        dailyLimit: 25_000_000,
      });

      // Transaction 1: 10 XRP
      await signingService.signTransaction(testWalletId, {
        TransactionType: 'Payment',
        Account: await keystore.getAddress(testWalletId),
        Destination: 'rDest1',
        Amount: '10000000',
      });

      // Transaction 2: 10 XRP
      await signingService.signTransaction(testWalletId, {
        TransactionType: 'Payment',
        Account: await keystore.getAddress(testWalletId),
        Destination: 'rDest2',
        Amount: '10000000',
      });

      // Transaction 3: Should exceed daily limit
      await expect(
        signingService.signTransaction(testWalletId, {
          TransactionType: 'Payment',
          Account: await keystore.getAddress(testWalletId),
          Destination: 'rDest3',
          Amount: '10000000',
        })
      ).rejects.toThrow('Daily limit exceeded');

      // Verify limit state
      const limitState = await policyEngine.getLimitState(testWalletId);
      expect(limitState.dailyUsed).toBe(20_000_000);
      expect(limitState.dailyRemaining).toBe(5_000_000);
    });
  });
});
```

### 4. Audit Logging Across Components Pattern

Tests audit log integrity across multi-component operations.

```typescript
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { AuditLogger, ChainVerificationResult } from '../src/audit/logger';
import { MCPServer } from '../src/mcp/server';
import { createFullTestStack } from './fixtures/test-stack';

describe('Audit Logging Across Components', () => {
  let testStack: TestStack;
  let auditLogger: AuditLogger;

  beforeAll(async () => {
    testStack = await createFullTestStack();
    auditLogger = testStack.auditLogger;
  });

  afterAll(async () => {
    await testStack.cleanup();
  });

  describe('Hash Chain Integrity', () => {
    it('should maintain hash chain across wallet operations', async () => {
      // Perform multiple operations
      const wallet = await testStack.server.executeTool('wallet_create', {
        name: 'audit-test-wallet',
        network: 'testnet',
      });

      await testStack.server.executeTool('wallet_get_balance', {
        walletId: wallet.walletId,
      });

      await testStack.server.executeTool('wallet_list', {});

      // Verify chain integrity
      const verification = await auditLogger.verifyChain();

      expect(verification).toMatchObject({
        valid: true,
        entriesVerified: expect.any(Number),
        brokenLinks: [],
      });
      expect(verification.entriesVerified).toBeGreaterThanOrEqual(3);
    });

    it('should detect tampering in audit log', async () => {
      // Create some audit entries
      await testStack.server.executeTool('wallet_create', {
        name: 'tamper-test-wallet',
        network: 'testnet',
      });

      // Tamper with the audit log (simulate attack)
      await auditLogger._testTamperEntry(1, {
        eventType: 'MODIFIED_EVENT',
      });

      // Verify chain detects tampering
      const verification = await auditLogger.verifyChain();

      expect(verification.valid).toBe(false);
      expect(verification.brokenLinks.length).toBeGreaterThan(0);
    });
  });

  describe('Event Correlation', () => {
    it('should correlate events across components', async () => {
      const correlationId = generateCorrelationId();

      // Execute operation with correlation ID
      const wallet = await testStack.server.executeTool('wallet_create', {
        name: 'correlated-wallet',
        network: 'testnet',
        _correlationId: correlationId,
      });

      // Query all events for this correlation
      const events = await auditLogger.query({
        correlationId,
      });

      // Should have events from multiple components
      const eventTypes = events.map(e => e.eventType);

      expect(eventTypes).toContain('MCP_TOOL_INVOKED');
      expect(eventTypes).toContain('KEYSTORE_KEY_GENERATED');
      expect(eventTypes).toContain('WALLET_CREATED');
    });

    it('should trace full transaction lifecycle', async () => {
      // Create wallet and sign transaction
      const wallet = await testStack.server.executeTool('wallet_create', {
        name: 'lifecycle-wallet',
        network: 'testnet',
        fundFromFaucet: true,
      });

      const signResult = await testStack.server.executeTool('wallet_sign', {
        walletId: wallet.walletId,
        transaction: {
          TransactionType: 'Payment',
          Destination: 'rDestination12345678901234567890',
          Amount: '1000000',
        },
      });

      // Query full transaction lifecycle
      const events = await auditLogger.query({
        walletId: wallet.walletId,
      });

      const eventSequence = events.map(e => e.eventType);

      // Verify expected event sequence
      expect(eventSequence).toEqual(expect.arrayContaining([
        'WALLET_CREATED',
        'FAUCET_FUNDED',
        'POLICY_EVALUATED',
        'TRANSACTION_SIGNED',
      ]));
    });
  });

  describe('Audit Querying', () => {
    it('should filter events by time range', async () => {
      const startTime = new Date();

      // Create some events
      await testStack.server.executeTool('wallet_create', {
        name: 'time-range-wallet-1',
        network: 'testnet',
      });

      await sleep(100);
      const midTime = new Date();

      await testStack.server.executeTool('wallet_create', {
        name: 'time-range-wallet-2',
        network: 'testnet',
      });

      const endTime = new Date();

      // Query first half
      const firstHalf = await auditLogger.query({
        startTime,
        endTime: midTime,
      });

      // Query second half
      const secondHalf = await auditLogger.query({
        startTime: midTime,
        endTime,
      });

      // Each should have some events
      expect(firstHalf.length).toBeGreaterThan(0);
      expect(secondHalf.length).toBeGreaterThan(0);
    });

    it('should support pagination for large result sets', async () => {
      // Create many events
      for (let i = 0; i < 50; i++) {
        await auditLogger.log({
          eventType: 'TEST_EVENT',
          details: { index: i },
        });
      }

      // Query with pagination
      const page1 = await auditLogger.query({
        eventType: 'TEST_EVENT',
        limit: 20,
        offset: 0,
      });

      const page2 = await auditLogger.query({
        eventType: 'TEST_EVENT',
        limit: 20,
        offset: 20,
      });

      expect(page1).toHaveLength(20);
      expect(page2).toHaveLength(20);
      expect(page1[0].details.index).not.toBe(page2[0].details.index);
    });
  });
});
```

---

## Test Fixtures

### Pre-Created Wallets Fixture

```typescript
// tests/fixtures/wallets.ts
import { Wallet } from 'xrpl';
import { LocalFileKeystoreProvider } from '../../src/keystore/local-file';

export interface TestWalletFixture {
  id: string;
  address: string;
  wallet: Wallet;
  funded: boolean;
  network: 'testnet' | 'devnet';
}

export async function createTestWallets(
  keystore: LocalFileKeystoreProvider,
  count: number = 3
): Promise<TestWalletFixture[]> {
  const wallets: TestWalletFixture[] = [];

  for (let i = 0; i < count; i++) {
    const result = await keystore.createWallet(`test-wallet-${i}`);
    wallets.push({
      id: result.id,
      address: result.address,
      wallet: result.wallet,
      funded: false,
      network: 'testnet',
    });
  }

  return wallets;
}

export async function fundTestWallets(
  xrplClient: XRPLClient,
  wallets: TestWalletFixture[]
): Promise<void> {
  for (const wallet of wallets) {
    try {
      await xrplClient.fundTestnetAccount(wallet.address);
      wallet.funded = true;
    } catch (error) {
      console.warn(`Failed to fund wallet ${wallet.address}:`, error);
    }
  }
}

// Pre-defined test wallet seeds for deterministic testing
export const DETERMINISTIC_SEEDS = {
  primary: 'sEdTJdPn5TA2Gx1zRyTKKkjAA6Y4wYV',
  secondary: 'sEdVJrrmNwCo4X6T5Fy5xvCx1Z5wFmn',
  cosigner: 'sEdSJHS4oiAdz7w6XnyaYhW4BXzDhqm',
};

export function createDeterministicWallet(
  name: keyof typeof DETERMINISTIC_SEEDS
): Wallet {
  return Wallet.fromSeed(DETERMINISTIC_SEEDS[name]);
}
```

### Policy Configuration Fixtures

```typescript
// tests/fixtures/policies.ts
import { PolicyConfig, PolicyTier } from '../../src/policy/engine';

export const TEST_POLICIES = {
  // Permissive policy for basic testing
  permissive: {
    autonomousLimit: 1_000_000_000, // 1000 XRP
    dailyLimit: 10_000_000_000,     // 10000 XRP
    hourlyLimit: 1_000_000_000,     // 1000 XRP
    allowedDestinations: ['*'],
    blockedDestinations: [],
    allowedTransactionTypes: ['*'],
  } as PolicyConfig,

  // Restrictive policy for security testing
  restrictive: {
    autonomousLimit: 1_000_000,     // 1 XRP
    delayedLimit: 10_000_000,       // 10 XRP
    coSignLimit: 100_000_000,       // 100 XRP
    dailyLimit: 50_000_000,         // 50 XRP
    delayPeriod: 3600,              // 1 hour
    coSigners: [],
    allowedDestinations: [],
    allowedTransactionTypes: ['Payment'],
  } as PolicyConfig,

  // Multi-sig required policy
  multiSig: {
    autonomousLimit: 0,
    coSignLimit: 1_000_000_000,
    requiredSignatures: 2,
    coSigners: [
      'rCoSigner1234567890123456789012',
      'rCoSigner2345678901234567890123',
    ],
  } as PolicyConfig,

  // Time-based policy
  timeBased: {
    autonomousLimit: 10_000_000,
    delayedLimit: 100_000_000,
    delayPeriod: 60,              // 1 minute for testing
    dailyLimit: 200_000_000,
    windowStart: '09:00',
    windowEnd: '17:00',
    timezone: 'UTC',
  } as PolicyConfig,
};

export function createTestPolicy(
  overrides: Partial<PolicyConfig> = {}
): PolicyConfig {
  return {
    ...TEST_POLICIES.permissive,
    ...overrides,
  };
}

export function createTierTestCases(): Array<{
  name: string;
  amount: string;
  expectedTier: PolicyTier;
  policy: PolicyConfig;
}> {
  return [
    {
      name: 'Autonomous - small payment',
      amount: '500000',  // 0.5 XRP
      expectedTier: PolicyTier.AUTONOMOUS,
      policy: createTestPolicy({ autonomousLimit: 1_000_000 }),
    },
    {
      name: 'Delayed - medium payment',
      amount: '5000000',  // 5 XRP
      expectedTier: PolicyTier.DELAYED,
      policy: createTestPolicy({
        autonomousLimit: 1_000_000,
        delayedLimit: 10_000_000,
      }),
    },
    {
      name: 'Co-Sign - large payment',
      amount: '50000000',  // 50 XRP
      expectedTier: PolicyTier.CO_SIGN,
      policy: createTestPolicy({
        autonomousLimit: 1_000_000,
        delayedLimit: 10_000_000,
        coSignLimit: 100_000_000,
      }),
    },
    {
      name: 'Prohibited - exceeds all limits',
      amount: '500000000',  // 500 XRP
      expectedTier: PolicyTier.PROHIBITED,
      policy: createTestPolicy({
        autonomousLimit: 1_000_000,
        delayedLimit: 10_000_000,
        coSignLimit: 100_000_000,
      }),
    },
  ];
}
```

### Mock XRPL Responses Fixture

```typescript
// tests/fixtures/xrpl-mocks.ts
import { vi } from 'vitest';

export const MOCK_ACCOUNT_INFO = {
  success: {
    result: {
      account_data: {
        Account: 'rTestAccount1234567890123456789',
        Balance: '100000000',
        Sequence: 1,
        Flags: 0,
        OwnerCount: 0,
        PreviousTxnID: 'ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890',
        PreviousTxnLgrSeq: 12345678,
        LedgerEntryType: 'AccountRoot',
        index: '1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF',
      },
      ledger_current_index: 12345679,
      validated: false,
    },
    status: 'success',
    type: 'response',
  },
  notFound: {
    result: {
      account: 'rNonExistent123456789012345678',
      error: 'actNotFound',
      error_code: 19,
      error_message: 'Account not found.',
      ledger_current_index: 12345679,
      request: {
        account: 'rNonExistent123456789012345678',
        command: 'account_info',
      },
      validated: false,
    },
    status: 'error',
    type: 'response',
  },
};

export const MOCK_SUBMIT_RESPONSE = {
  success: {
    result: {
      engine_result: 'tesSUCCESS',
      engine_result_code: 0,
      engine_result_message: 'The transaction was applied.',
      tx_blob: 'ABCDEF...',
      tx_json: {
        Account: 'rTestAccount1234567890123456789',
        Amount: '1000000',
        Destination: 'rDestination12345678901234567890',
        Fee: '12',
        Flags: 0,
        Sequence: 1,
        SigningPubKey: 'ABCDEF...',
        TransactionType: 'Payment',
        TxnSignature: 'ABCDEF...',
        hash: 'TXHASH1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890',
      },
    },
    status: 'success',
    type: 'response',
  },
  failure: {
    result: {
      engine_result: 'tecUNFUNDED_PAYMENT',
      engine_result_code: 104,
      engine_result_message: 'Insufficient XRP balance to send.',
    },
    status: 'success',
    type: 'response',
  },
};

export const MOCK_SERVER_INFO = {
  result: {
    info: {
      build_version: '2.0.0',
      complete_ledgers: '32570-12345679',
      hostid: 'testnet',
      io_latency_ms: 1,
      jq_trans_overflow: '0',
      last_close: {
        converge_time_s: 2,
        proposers: 4,
      },
      load_factor: 1,
      network_id: 1,
      peer_disconnects: '0',
      peer_disconnects_resources: '0',
      peers: 10,
      pubkey_node: 'n9...',
      server_state: 'full',
      state_accounting: {
        connected: { duration_us: '1000000', transitions: '1' },
        disconnected: { duration_us: '0', transitions: '0' },
        full: { duration_us: '100000000', transitions: '1' },
        syncing: { duration_us: '1000000', transitions: '1' },
        tracking: { duration_us: '0', transitions: '0' },
      },
      time: '2026-Jan-28 12:00:00.000000 UTC',
      uptime: 86400,
      validated_ledger: {
        age: 1,
        base_fee_xrp: 0.00001,
        hash: 'LEDGERHASH...',
        reserve_base_xrp: 10,
        reserve_inc_xrp: 2,
        seq: 12345679,
      },
      validation_quorum: 3,
    },
  },
  status: 'success',
  type: 'response',
};

export function createMockXRPLClient() {
  return {
    connect: vi.fn().mockResolvedValue(undefined),
    disconnect: vi.fn().mockResolvedValue(undefined),
    isConnected: vi.fn().mockReturnValue(true),
    request: vi.fn().mockImplementation(async (command: any) => {
      switch (command.command) {
        case 'account_info':
          return MOCK_ACCOUNT_INFO.success;
        case 'submit':
          return MOCK_SUBMIT_RESPONSE.success;
        case 'server_info':
          return MOCK_SERVER_INFO;
        default:
          throw new Error(`Unknown command: ${command.command}`);
      }
    }),
    submitAndWait: vi.fn().mockResolvedValue({
      result: {
        ...MOCK_SUBMIT_RESPONSE.success.result,
        meta: { TransactionResult: 'tesSUCCESS' },
        validated: true,
      },
    }),
    fundTestnetAccount: vi.fn().mockResolvedValue({
      address: 'rTestAccount1234567890123456789',
      balance: 1000,
    }),
  };
}
```

### Test Stack Fixture

```typescript
// tests/fixtures/test-stack.ts
import { tmpdir } from 'os';
import { mkdtemp, rm } from 'fs/promises';
import { join } from 'path';
import { MCPServer } from '../../src/mcp/server';
import { LocalFileKeystoreProvider } from '../../src/keystore/local-file';
import { AuditLogger } from '../../src/audit/logger';
import { PolicyEngine } from '../../src/policy/engine';
import { SigningService } from '../../src/signing/service';
import { XRPLClient } from '../../src/xrpl/client';

export interface TestStack {
  testDir: string;
  server: MCPServer;
  keystore: LocalFileKeystoreProvider;
  auditLogger: AuditLogger;
  policyEngine: PolicyEngine;
  signingService: SigningService;
  xrplClient: XRPLClient;
  cleanup: () => Promise<void>;
}

export interface TestStackOptions {
  useRealXRPL?: boolean;
  network?: 'testnet' | 'devnet';
  initializeServer?: boolean;
}

export async function createFullTestStack(
  options: TestStackOptions = {}
): Promise<TestStack> {
  const {
    useRealXRPL = false,
    network = 'testnet',
    initializeServer = true,
  } = options;

  // Create temporary directory
  const testDir = await mkdtemp(join(tmpdir(), 'xrpl-test-'));

  // Derive encryption key for testing
  const encryptionKey = await deriveTestKey('test-password-12345');
  const hmacKey = Buffer.from('test-hmac-key-32-bytes-long!!!!!');

  // Initialize keystore
  const keystore = new LocalFileKeystoreProvider({
    storagePath: join(testDir, 'keys'),
    encryptionKey,
  });

  // Initialize audit logger
  const auditLogger = new AuditLogger({
    storagePath: join(testDir, 'audit'),
    hmacKey,
  });

  // Initialize XRPL client (mock or real)
  const xrplClient = useRealXRPL
    ? new XRPLClient({
        network,
        timeout: 30000,
        reconnect: { maxAttempts: 3, delay: 1000 },
      })
    : createMockXRPLClient() as unknown as XRPLClient;

  if (useRealXRPL) {
    await xrplClient.connect();
  }

  // Initialize policy engine
  const policyEngine = new PolicyEngine({
    auditLogger,
  });

  // Initialize signing service
  const signingService = new SigningService({
    keystore,
    policyEngine,
    auditLogger,
  });

  // Initialize MCP server
  const server = new MCPServer({
    keystore,
    auditLogger,
    policyEngine,
    signingService,
    xrplClient,
  });

  if (initializeServer) {
    await server.initialize();
  }

  // Cleanup function
  const cleanup = async () => {
    await server.shutdown();
    if (useRealXRPL) {
      await xrplClient.disconnect();
    }
    await rm(testDir, { recursive: true, force: true });
  };

  return {
    testDir,
    server,
    keystore,
    auditLogger,
    policyEngine,
    signingService,
    xrplClient,
    cleanup,
  };
}

// Helper to derive test encryption key
async function deriveTestKey(password: string): Promise<Buffer> {
  const { Argon2 } = await import('argon2');
  return Argon2.hash(password, {
    type: Argon2.Argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
    hashLength: 32,
    salt: Buffer.from('test-salt-16-by!'),
  });
}
```

---

## Environment Setup

### Testnet Configuration

```typescript
// tests/config/testnet.ts
export const TESTNET_CONFIG = {
  // Primary testnet endpoints
  websocket: 'wss://s.altnet.rippletest.net:51233',
  jsonRpc: 'https://s.altnet.rippletest.net:51234',

  // Faucet configuration
  faucet: {
    url: 'https://faucet.altnet.rippletest.net/accounts',
    rateLimit: {
      requestsPerMinute: 10,
      cooldownMs: 60000,
    },
  },

  // Network parameters
  network: {
    networkId: 1,
    reserveBase: 10_000_000,  // 10 XRP
    reserveIncrement: 2_000_000,  // 2 XRP
    baseFee: 10,  // drops
  },

  // Test timeouts
  timeouts: {
    connection: 30000,
    transaction: 60000,
    faucet: 60000,
  },
};

export const DEVNET_CONFIG = {
  websocket: 'wss://s.devnet.rippletest.net:51233',
  jsonRpc: 'https://s.devnet.rippletest.net:51234',
  faucet: {
    url: 'https://faucet.devnet.rippletest.net/accounts',
    rateLimit: {
      requestsPerMinute: 20,
      cooldownMs: 30000,
    },
  },
  network: {
    networkId: 2,
    reserveBase: 10_000_000,
    reserveIncrement: 2_000_000,
    baseFee: 10,
  },
  timeouts: {
    connection: 30000,
    transaction: 60000,
    faucet: 30000,
  },
};

// Local rippled configuration
export const LOCAL_CONFIG = {
  websocket: 'ws://localhost:6006',
  jsonRpc: 'http://localhost:5005',
  network: {
    networkId: 0,
    reserveBase: 10_000_000,
    reserveIncrement: 2_000_000,
    baseFee: 10,
  },
  timeouts: {
    connection: 5000,
    transaction: 10000,
  },
};
```

### Environment Setup Script

```typescript
// tests/setup/global-setup.ts
import { beforeAll, afterAll } from 'vitest';
import { XRPLClient } from '../../src/xrpl/client';
import { TESTNET_CONFIG } from '../config/testnet';

let globalXRPLClient: XRPLClient | null = null;

export async function setupTestEnvironment(): Promise<void> {
  // Verify testnet connectivity
  const client = new XRPLClient({
    network: 'testnet',
    timeout: TESTNET_CONFIG.timeouts.connection,
  });

  try {
    await client.connect();
    const serverInfo = await client.getServerInfo();
    console.log('Connected to testnet:', serverInfo.info.build_version);
    globalXRPLClient = client;
  } catch (error) {
    console.warn('Testnet connection failed, tests will use mocks:', error);
    await client.disconnect();
  }
}

export async function teardownTestEnvironment(): Promise<void> {
  if (globalXRPLClient) {
    await globalXRPLClient.disconnect();
    globalXRPLClient = null;
  }
}

export function getGlobalXRPLClient(): XRPLClient | null {
  return globalXRPLClient;
}
```

### Vitest Configuration

```typescript
// vitest.config.ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Test directories
    include: ['tests/**/*.test.ts', 'tests/**/*.spec.ts'],
    exclude: ['tests/e2e/**'],

    // Global setup
    globalSetup: ['tests/setup/global-setup.ts'],

    // Environment
    environment: 'node',

    // Timeouts
    testTimeout: 30000,
    hookTimeout: 60000,

    // Parallelization
    pool: 'threads',
    poolOptions: {
      threads: {
        singleThread: false,
        minThreads: 1,
        maxThreads: 4,
      },
    },

    // Coverage
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.d.ts', 'src/types/**'],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 75,
        statements: 80,
      },
    },

    // Reporters
    reporters: ['default', 'json'],
    outputFile: {
      json: 'test-results/results.json',
    },
  },
});
```

### Environment Variables

```bash
# tests/.env.test
# XRPL Network Configuration
XRPL_NETWORK=testnet
XRPL_WEBSOCKET_URL=wss://s.altnet.rippletest.net:51233
XRPL_FAUCET_URL=https://faucet.altnet.rippletest.net/accounts

# Test Configuration
TEST_TIMEOUT=30000
TEST_USE_REAL_NETWORK=false
TEST_CLEANUP_ON_FAILURE=true

# Encryption (use only for testing!)
TEST_ENCRYPTION_PASSWORD=test-password-never-use-in-production
TEST_HMAC_SECRET=test-hmac-secret-32-bytes-long!!

# Logging
LOG_LEVEL=debug
LOG_FORMAT=json
```

---

## Cleanup Procedures

### Test Cleanup Utilities

```typescript
// tests/utils/cleanup.ts
import { rm, readdir } from 'fs/promises';
import { join } from 'path';
import { XRPLClient } from '../../src/xrpl/client';

export interface CleanupContext {
  testDir?: string;
  walletIds?: string[];
  pendingTransactionIds?: string[];
  xrplClient?: XRPLClient;
}

export async function cleanupTestDirectory(testDir: string): Promise<void> {
  try {
    await rm(testDir, { recursive: true, force: true });
    console.log(`Cleaned up test directory: ${testDir}`);
  } catch (error) {
    console.warn(`Failed to cleanup test directory ${testDir}:`, error);
  }
}

export async function cleanupTestWallets(
  keystore: LocalFileKeystoreProvider,
  walletIds: string[]
): Promise<void> {
  for (const walletId of walletIds) {
    try {
      await keystore.deleteWallet(walletId);
    } catch (error) {
      console.warn(`Failed to delete wallet ${walletId}:`, error);
    }
  }
}

export async function cleanupPendingTransactions(
  signingService: SigningService,
  pendingIds: string[]
): Promise<void> {
  for (const pendingId of pendingIds) {
    try {
      await signingService.cancelPending(pendingId);
    } catch (error) {
      console.warn(`Failed to cancel pending tx ${pendingId}:`, error);
    }
  }
}

export async function cleanupAuditLogs(
  auditLogger: AuditLogger,
  options: { olderThan?: Date; eventTypes?: string[] } = {}
): Promise<number> {
  const { olderThan, eventTypes } = options;

  // Only for test environments!
  if (process.env.NODE_ENV !== 'test') {
    throw new Error('Audit log cleanup only allowed in test environment');
  }

  const deletedCount = await auditLogger._testPurge({
    olderThan,
    eventTypes,
  });

  return deletedCount;
}

// Comprehensive cleanup for test context
export async function cleanupTestContext(
  context: CleanupContext
): Promise<void> {
  const errors: Error[] = [];

  // Cleanup in reverse order of creation
  if (context.pendingTransactionIds?.length) {
    try {
      // Cancel any pending transactions
      console.log(`Cleaning up ${context.pendingTransactionIds.length} pending transactions`);
    } catch (error) {
      errors.push(error as Error);
    }
  }

  if (context.xrplClient) {
    try {
      await context.xrplClient.disconnect();
    } catch (error) {
      errors.push(error as Error);
    }
  }

  if (context.testDir) {
    try {
      await cleanupTestDirectory(context.testDir);
    } catch (error) {
      errors.push(error as Error);
    }
  }

  if (errors.length > 0) {
    console.warn(`Cleanup completed with ${errors.length} errors:`, errors);
  }
}
```

### Automatic Cleanup Hook

```typescript
// tests/utils/auto-cleanup.ts
import { afterEach, afterAll } from 'vitest';

const cleanupQueue: Array<() => Promise<void>> = [];

export function registerCleanup(cleanupFn: () => Promise<void>): void {
  cleanupQueue.push(cleanupFn);
}

export function setupAutoCleanup(): void {
  afterEach(async () => {
    // Run cleanup functions in reverse order (LIFO)
    while (cleanupQueue.length > 0) {
      const cleanupFn = cleanupQueue.pop();
      if (cleanupFn) {
        try {
          await cleanupFn();
        } catch (error) {
          console.warn('Cleanup function failed:', error);
        }
      }
    }
  });
}

// Usage in tests:
// registerCleanup(async () => await keystore.deleteWallet(walletId));
```

---

## Test Isolation Strategies

### Strategy 1: Isolated Test Directories

```typescript
// tests/utils/isolation.ts
import { mkdtemp, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';

export async function createIsolatedTestDir(prefix: string = 'xrpl-test-'): Promise<string> {
  const testDir = await mkdtemp(join(tmpdir(), prefix));
  return testDir;
}

export function withIsolatedDir<T>(
  testFn: (testDir: string) => Promise<T>
): () => Promise<T> {
  return async () => {
    const testDir = await createIsolatedTestDir();
    try {
      return await testFn(testDir);
    } finally {
      await rm(testDir, { recursive: true, force: true });
    }
  };
}

// Usage:
// it('should work with isolated directory', withIsolatedDir(async (testDir) => {
//   // Test code here
// }));
```

### Strategy 2: Database Transaction Rollback

```typescript
// tests/utils/db-isolation.ts
import { Database } from 'better-sqlite3';

export function withTransaction<T>(
  db: Database,
  testFn: () => Promise<T>
): () => Promise<T> {
  return async () => {
    db.exec('BEGIN TRANSACTION');
    try {
      const result = await testFn();
      return result;
    } finally {
      db.exec('ROLLBACK');
    }
  };
}

// For async databases with transactions
export async function withAsyncTransaction<T>(
  connection: DatabaseConnection,
  testFn: (trx: Transaction) => Promise<T>
): Promise<T> {
  const trx = await connection.beginTransaction();
  try {
    const result = await testFn(trx);
    return result;
  } finally {
    await trx.rollback();
  }
}
```

### Strategy 3: Unique Identifiers per Test

```typescript
// tests/utils/unique-ids.ts
import { randomBytes } from 'crypto';

let testRunId: string | null = null;

export function getTestRunId(): string {
  if (!testRunId) {
    testRunId = randomBytes(8).toString('hex');
  }
  return testRunId;
}

export function uniqueTestId(base: string): string {
  return `${base}-${getTestRunId()}-${randomBytes(4).toString('hex')}`;
}

export function uniqueWalletName(): string {
  return uniqueTestId('test-wallet');
}

export function uniquePolicyName(): string {
  return uniqueTestId('test-policy');
}

// Usage:
// const walletName = uniqueWalletName();
// await keystore.createWallet(walletName);
```

### Strategy 4: Mock Isolation

```typescript
// tests/utils/mock-isolation.ts
import { vi, Mock } from 'vitest';

export interface MockRegistry {
  register<T>(mock: T): T;
  resetAll(): void;
  restoreAll(): void;
}

export function createMockRegistry(): MockRegistry {
  const mocks: Mock[] = [];

  return {
    register<T>(mock: T): T {
      if (vi.isMockFunction(mock)) {
        mocks.push(mock as unknown as Mock);
      }
      return mock;
    },

    resetAll(): void {
      mocks.forEach(mock => mock.mockReset());
    },

    restoreAll(): void {
      mocks.forEach(mock => mock.mockRestore());
      mocks.length = 0;
    },
  };
}

// Usage with beforeEach/afterEach:
// const mockRegistry = createMockRegistry();
// beforeEach(() => mockRegistry.resetAll());
// afterEach(() => mockRegistry.restoreAll());
```

### Strategy 5: Test Context Isolation

```typescript
// tests/utils/context-isolation.ts
import { beforeEach, afterEach } from 'vitest';

export interface IsolatedTestContext {
  testDir: string;
  testId: string;
  createdResources: string[];
  addResource(id: string): void;
}

export function setupIsolatedContext(): IsolatedTestContext {
  let context: IsolatedTestContext;

  beforeEach(async () => {
    context = {
      testDir: await createIsolatedTestDir(),
      testId: uniqueTestId('test'),
      createdResources: [],
      addResource(id: string) {
        this.createdResources.push(id);
      },
    };
  });

  afterEach(async () => {
    // Cleanup all registered resources
    for (const resourceId of context.createdResources.reverse()) {
      try {
        await cleanupResource(resourceId);
      } catch (error) {
        console.warn(`Failed to cleanup resource ${resourceId}:`, error);
      }
    }

    // Cleanup test directory
    await rm(context.testDir, { recursive: true, force: true });
  });

  return context;
}
```

---

## Async/Await Patterns

### Pattern 1: Retry with Exponential Backoff

```typescript
// tests/utils/retry.ts
export interface RetryOptions {
  maxAttempts: number;
  initialDelayMs: number;
  maxDelayMs: number;
  backoffMultiplier: number;
  retryableErrors?: Array<string | RegExp>;
}

const DEFAULT_RETRY_OPTIONS: RetryOptions = {
  maxAttempts: 3,
  initialDelayMs: 1000,
  maxDelayMs: 30000,
  backoffMultiplier: 2,
};

export async function withRetry<T>(
  operation: () => Promise<T>,
  options: Partial<RetryOptions> = {}
): Promise<T> {
  const opts = { ...DEFAULT_RETRY_OPTIONS, ...options };
  let lastError: Error | null = null;
  let delay = opts.initialDelayMs;

  for (let attempt = 1; attempt <= opts.maxAttempts; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error as Error;

      // Check if error is retryable
      if (opts.retryableErrors) {
        const isRetryable = opts.retryableErrors.some(pattern => {
          if (typeof pattern === 'string') {
            return lastError!.message.includes(pattern);
          }
          return pattern.test(lastError!.message);
        });
        if (!isRetryable) {
          throw lastError;
        }
      }

      if (attempt < opts.maxAttempts) {
        console.log(`Attempt ${attempt} failed, retrying in ${delay}ms...`);
        await sleep(delay);
        delay = Math.min(delay * opts.backoffMultiplier, opts.maxDelayMs);
      }
    }
  }

  throw lastError;
}

// Usage for XRPL operations:
// const result = await withRetry(
//   () => xrplClient.submitAndWait(tx, { wallet }),
//   {
//     maxAttempts: 3,
//     retryableErrors: [/tecCLAIM/, /tefPAST_SEQ/]
//   }
// );
```

### Pattern 2: Timeout Wrapper

```typescript
// tests/utils/timeout.ts
export class TimeoutError extends Error {
  constructor(message: string, public readonly timeoutMs: number) {
    super(message);
    this.name = 'TimeoutError';
  }
}

export async function withTimeout<T>(
  operation: Promise<T>,
  timeoutMs: number,
  operationName: string = 'operation'
): Promise<T> {
  let timeoutId: NodeJS.Timeout;

  const timeoutPromise = new Promise<never>((_, reject) => {
    timeoutId = setTimeout(() => {
      reject(new TimeoutError(
        `${operationName} timed out after ${timeoutMs}ms`,
        timeoutMs
      ));
    }, timeoutMs);
  });

  try {
    return await Promise.race([operation, timeoutPromise]);
  } finally {
    clearTimeout(timeoutId!);
  }
}

// Usage:
// const result = await withTimeout(
//   xrplClient.submitAndWait(tx, { wallet }),
//   60000,
//   'transaction submission'
// );
```

### Pattern 3: Polling with Condition

```typescript
// tests/utils/polling.ts
export interface PollingOptions<T> {
  condition: (result: T) => boolean;
  intervalMs: number;
  timeoutMs: number;
  operation: () => Promise<T>;
}

export async function pollUntil<T>(options: PollingOptions<T>): Promise<T> {
  const { condition, intervalMs, timeoutMs, operation } = options;
  const startTime = Date.now();

  while (true) {
    const result = await operation();

    if (condition(result)) {
      return result;
    }

    const elapsed = Date.now() - startTime;
    if (elapsed >= timeoutMs) {
      throw new TimeoutError(
        `Polling condition not met after ${timeoutMs}ms`,
        timeoutMs
      );
    }

    await sleep(intervalMs);
  }
}

// Usage for waiting for transaction validation:
// const validated = await pollUntil({
//   condition: (result) => result.validated === true,
//   intervalMs: 1000,
//   timeoutMs: 30000,
//   operation: () => xrplClient.getTx(txHash),
// });
```

### Pattern 4: Concurrent Execution with Limit

```typescript
// tests/utils/concurrency.ts
export async function mapConcurrent<T, R>(
  items: T[],
  mapper: (item: T, index: number) => Promise<R>,
  concurrencyLimit: number = 5
): Promise<R[]> {
  const results: R[] = [];
  const executing: Promise<void>[] = [];

  for (let i = 0; i < items.length; i++) {
    const promise = mapper(items[i], i).then(result => {
      results[i] = result;
    });

    executing.push(promise);

    if (executing.length >= concurrencyLimit) {
      await Promise.race(executing);
      // Remove completed promises
      const completed = executing.filter(p =>
        p.then(() => false).catch(() => false)
      );
      executing.length = 0;
      executing.push(...completed);
    }
  }

  await Promise.all(executing);
  return results;
}

// Usage for funding multiple wallets:
// const results = await mapConcurrent(
//   wallets,
//   (wallet) => xrplClient.fundTestnetAccount(wallet.address),
//   3  // Max 3 concurrent faucet requests
// );
```

### Pattern 5: Sequential Chain with Context

```typescript
// tests/utils/chain.ts
export class AsyncChain<T> {
  private context: T;
  private operations: Array<(ctx: T) => Promise<T>>;

  constructor(initialContext: T) {
    this.context = initialContext;
    this.operations = [];
  }

  then(operation: (ctx: T) => Promise<T>): this {
    this.operations.push(operation);
    return this;
  }

  async execute(): Promise<T> {
    for (const operation of this.operations) {
      this.context = await operation(this.context);
    }
    return this.context;
  }
}

// Usage for transaction flow testing:
// const result = await new AsyncChain({ walletId: null, txHash: null })
//   .then(async (ctx) => {
//     const wallet = await keystore.createWallet('test');
//     return { ...ctx, walletId: wallet.id };
//   })
//   .then(async (ctx) => {
//     await xrplClient.fundTestnetAccount(wallet.address);
//     return ctx;
//   })
//   .then(async (ctx) => {
//     const result = await signingService.signTransaction(ctx.walletId, tx);
//     return { ...ctx, txHash: result.hash };
//   })
//   .execute();
```

### Pattern 6: Error Handling Wrapper

```typescript
// tests/utils/error-handling.ts
export interface OperationResult<T> {
  success: boolean;
  data?: T;
  error?: Error;
  duration: number;
}

export async function wrapOperation<T>(
  operation: () => Promise<T>,
  operationName?: string
): Promise<OperationResult<T>> {
  const startTime = Date.now();

  try {
    const data = await operation();
    return {
      success: true,
      data,
      duration: Date.now() - startTime,
    };
  } catch (error) {
    return {
      success: false,
      error: error as Error,
      duration: Date.now() - startTime,
    };
  }
}

// Usage:
// const result = await wrapOperation(
//   () => xrplClient.submitAndWait(tx, { wallet }),
//   'transaction submission'
// );
// if (!result.success) {
//   console.log(`Failed after ${result.duration}ms:`, result.error);
// }
```

---

## Example Integration Test Suite

```typescript
// tests/integration/full-flow.integration.test.ts
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { createFullTestStack, TestStack } from '../fixtures/test-stack';
import { TEST_POLICIES, createTestPolicy } from '../fixtures/policies';
import { withRetry, withTimeout, pollUntil } from '../utils/async';
import { uniqueWalletName } from '../utils/unique-ids';

describe('Full Integration Flow', () => {
  let testStack: TestStack;

  beforeAll(async () => {
    testStack = await createFullTestStack({
      useRealXRPL: process.env.TEST_USE_REAL_NETWORK === 'true',
      network: 'testnet',
    });
  }, 120000);

  afterAll(async () => {
    await testStack.cleanup();
  });

  describe('Complete Wallet Lifecycle', () => {
    it('should create, fund, sign, and submit transaction', async () => {
      const walletName = uniqueWalletName();

      // Step 1: Create wallet
      const createResult = await testStack.server.executeTool('wallet_create', {
        name: walletName,
        network: 'testnet',
      });

      expect(createResult).toMatchObject({
        walletId: expect.any(String),
        address: expect.stringMatching(/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/),
      });

      const walletId = createResult.walletId;

      // Step 2: Fund from faucet
      const fundResult = await withTimeout(
        testStack.server.executeTool('wallet_fund', {
          walletId,
        }),
        60000,
        'faucet funding'
      );

      expect(fundResult.funded).toBe(true);
      expect(fundResult.balance).toBeGreaterThan(0);

      // Step 3: Set policy
      await testStack.policyEngine.setPolicy(walletId, createTestPolicy({
        autonomousLimit: 10_000_000,
      }));

      // Step 4: Get balance to verify funding
      const balanceResult = await testStack.server.executeTool('wallet_get_balance', {
        walletId,
      });

      expect(parseInt(balanceResult.balance)).toBeGreaterThan(0);

      // Step 5: Sign a transaction
      const signResult = await testStack.server.executeTool('wallet_sign', {
        walletId,
        transaction: {
          TransactionType: 'AccountSet',
          SetFlag: 8, // asfDefaultRipple
        },
      });

      expect(signResult).toMatchObject({
        signed: true,
        txBlob: expect.any(String),
      });

      // Step 6: Submit transaction (if using real network)
      if (process.env.TEST_USE_REAL_NETWORK === 'true') {
        const submitResult = await withRetry(
          () => testStack.xrplClient.submitAndWait(signResult.txBlob),
          { maxAttempts: 3, retryableErrors: [/tefPAST_SEQ/] }
        );

        expect(submitResult.result.meta.TransactionResult).toBe('tesSUCCESS');
      }

      // Step 7: Verify audit trail
      const auditEntries = await testStack.auditLogger.query({
        walletId,
      });

      const eventTypes = auditEntries.map(e => e.eventType);
      expect(eventTypes).toContain('WALLET_CREATED');
      expect(eventTypes).toContain('TRANSACTION_SIGNED');

      // Step 8: Verify chain integrity
      const chainVerification = await testStack.auditLogger.verifyChain();
      expect(chainVerification.valid).toBe(true);
    }, 180000);
  });

  describe('Policy Enforcement Flow', () => {
    let walletId: string;

    beforeEach(async () => {
      // Create fresh wallet for each test
      const result = await testStack.server.executeTool('wallet_create', {
        name: uniqueWalletName(),
        network: 'testnet',
      });
      walletId = result.walletId;
    });

    it('should enforce tier-based authorization', async () => {
      // Set tiered policy
      await testStack.policyEngine.setPolicy(walletId, {
        autonomousLimit: 1_000_000,     // 1 XRP
        delayedLimit: 10_000_000,       // 10 XRP
        coSignLimit: 100_000_000,       // 100 XRP
        delayPeriod: 1,                 // 1 second for testing
      });

      // Test Tier 1: Autonomous
      const tier1Result = await testStack.server.executeTool('wallet_sign', {
        walletId,
        transaction: {
          TransactionType: 'Payment',
          Destination: 'rDestination12345678901234567890',
          Amount: '500000', // 0.5 XRP
        },
      });
      expect(tier1Result.tier).toBe('AUTONOMOUS');
      expect(tier1Result.signed).toBe(true);

      // Test Tier 2: Delayed
      const tier2Result = await testStack.server.executeTool('wallet_sign', {
        walletId,
        transaction: {
          TransactionType: 'Payment',
          Destination: 'rDestination12345678901234567890',
          Amount: '5000000', // 5 XRP
        },
      });
      expect(tier2Result.tier).toBe('DELAYED');
      expect(tier2Result.signed).toBe(false);
      expect(tier2Result.pendingId).toBeDefined();

      // Test Tier 4: Prohibited
      await expect(
        testStack.server.executeTool('wallet_sign', {
          walletId,
          transaction: {
            TransactionType: 'Payment',
            Destination: 'rDestination12345678901234567890',
            Amount: '500000000', // 500 XRP
          },
        })
      ).rejects.toThrow('prohibited');
    });

    it('should track and enforce daily limits', async () => {
      await testStack.policyEngine.setPolicy(walletId, {
        autonomousLimit: 10_000_000,
        dailyLimit: 15_000_000,
      });

      // Transaction 1: 10 XRP
      await testStack.server.executeTool('wallet_sign', {
        walletId,
        transaction: {
          TransactionType: 'Payment',
          Destination: 'rDest1',
          Amount: '10000000',
        },
      });

      // Transaction 2: Should exceed daily limit
      await expect(
        testStack.server.executeTool('wallet_sign', {
          walletId,
          transaction: {
            TransactionType: 'Payment',
            Destination: 'rDest2',
            Amount: '10000000',
          },
        })
      ).rejects.toThrow(/daily limit/i);

      // Verify limit state
      const limitState = await testStack.policyEngine.getLimitState(walletId);
      expect(limitState.dailyUsed).toBe(10_000_000);
    });
  });

  describe('Multi-Signature Flow', () => {
    it('should complete multi-signature transaction', async () => {
      // Create primary and co-signer wallets
      const primaryWallet = await testStack.server.executeTool('wallet_create', {
        name: uniqueWalletName(),
        network: 'testnet',
      });

      const coSignerWallet = await testStack.server.executeTool('wallet_create', {
        name: uniqueWalletName(),
        network: 'testnet',
      });

      // Set multi-sig policy
      await testStack.policyEngine.setPolicy(primaryWallet.walletId, {
        autonomousLimit: 0,
        coSignLimit: 100_000_000,
        requiredSignatures: 2,
        coSigners: [coSignerWallet.address],
      });

      // Initiate transaction (gets first signature)
      const initResult = await testStack.server.executeTool('wallet_sign', {
        walletId: primaryWallet.walletId,
        transaction: {
          TransactionType: 'Payment',
          Destination: 'rDestination12345678901234567890',
          Amount: '10000000',
        },
      });

      expect(initResult.tier).toBe('CO_SIGN');
      expect(initResult.collectedSignatures).toBe(1);
      expect(initResult.requiredSignatures).toBe(2);

      // Add co-signer signature
      const completeResult = await testStack.server.executeTool('wallet_co_sign', {
        pendingId: initResult.pendingId,
        coSignerWalletId: coSignerWallet.walletId,
      });

      expect(completeResult.signed).toBe(true);
      expect(completeResult.collectedSignatures).toBe(2);
      expect(completeResult.txBlob).toBeDefined();
    });
  });

  describe('Error Recovery Flow', () => {
    it('should handle XRPL connection failures gracefully', async () => {
      // Simulate connection failure
      await testStack.xrplClient.disconnect();

      const walletId = (await testStack.server.executeTool('wallet_create', {
        name: uniqueWalletName(),
        network: 'testnet',
      })).walletId;

      // Operation should auto-reconnect or fail gracefully
      const result = await testStack.server.executeTool('wallet_get_balance', {
        walletId,
      });

      // Either succeeds (auto-reconnect) or returns cached/error state
      expect(result).toBeDefined();
    });

    it('should maintain audit integrity after errors', async () => {
      const walletId = (await testStack.server.executeTool('wallet_create', {
        name: uniqueWalletName(),
        network: 'testnet',
      })).walletId;

      // Set restrictive policy
      await testStack.policyEngine.setPolicy(walletId, {
        autonomousLimit: 0,
      });

      // Attempt prohibited transaction
      try {
        await testStack.server.executeTool('wallet_sign', {
          walletId,
          transaction: {
            TransactionType: 'Payment',
            Destination: 'rDest',
            Amount: '1000000',
          },
        });
      } catch {
        // Expected to fail
      }

      // Verify audit chain still intact
      const verification = await testStack.auditLogger.verifyChain();
      expect(verification.valid).toBe(true);

      // Verify failure was logged
      const auditEntries = await testStack.auditLogger.query({
        walletId,
        eventType: 'TRANSACTION_REJECTED',
      });
      expect(auditEntries.length).toBeGreaterThan(0);
    });
  });

  describe('Performance Benchmarks', () => {
    it('should meet latency requirements for autonomous transactions', async () => {
      const walletId = (await testStack.server.executeTool('wallet_create', {
        name: uniqueWalletName(),
        network: 'testnet',
      })).walletId;

      await testStack.policyEngine.setPolicy(walletId, {
        autonomousLimit: 100_000_000,
      });

      const iterations = 10;
      const durations: number[] = [];

      for (let i = 0; i < iterations; i++) {
        const start = Date.now();

        await testStack.server.executeTool('wallet_sign', {
          walletId,
          transaction: {
            TransactionType: 'Payment',
            Destination: `rDest${i}`,
            Amount: '1000000',
          },
        });

        durations.push(Date.now() - start);
      }

      const avgDuration = durations.reduce((a, b) => a + b, 0) / iterations;
      const maxDuration = Math.max(...durations);

      console.log(`Average signing duration: ${avgDuration}ms`);
      console.log(`Max signing duration: ${maxDuration}ms`);

      // Performance requirements
      expect(avgDuration).toBeLessThan(500);  // Average < 500ms
      expect(maxDuration).toBeLessThan(1000); // Max < 1s
    });
  });
});
```

---

## Running Integration Tests

### Commands

```bash
# Run all integration tests
npm run test:integration

# Run with real XRPL testnet
TEST_USE_REAL_NETWORK=true npm run test:integration

# Run specific test file
npx vitest run tests/integration/full-flow.integration.test.ts

# Run with coverage
npm run test:integration -- --coverage

# Run in watch mode (development)
npm run test:integration -- --watch

# Run with verbose output
npm run test:integration -- --reporter=verbose
```

### Package.json Scripts

```json
{
  "scripts": {
    "test": "vitest run",
    "test:unit": "vitest run tests/unit",
    "test:integration": "vitest run tests/integration --config vitest.integration.config.ts",
    "test:e2e": "vitest run tests/e2e --config vitest.e2e.config.ts",
    "test:coverage": "vitest run --coverage",
    "test:watch": "vitest watch"
  }
}
```

### CI/CD Integration

```yaml
# .github/workflows/test.yml
name: Test Suite

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npm run test:unit -- --coverage
      - uses: codecov/codecov-action@v4

  integration-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npm run test:integration
        env:
          TEST_USE_REAL_NETWORK: false

  integration-tests-testnet:
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npm run test:integration
        env:
          TEST_USE_REAL_NETWORK: true
        timeout-minutes: 30
```

---

## References

- [Vitest Documentation](https://vitest.dev/)
- [XRPL.js Testing Guide](https://xrpl.org/docs/tutorials/javascript/)
- [XRPL Testnet Faucet](https://xrpl.org/resources/dev-tools/xrp-faucets)
- [MCP Testing Patterns](https://modelcontextprotocol.io/)
